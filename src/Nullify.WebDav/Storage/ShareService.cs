// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Shared;

namespace Nullify.WebDav.Storage;

/// <summary>Creates and maintains folder shares, and keeps them pointing at the right folder when it moves.</summary>
public sealed class ShareService(ConfigStore store, MountResolver mounts, ILogger<ShareService> log)
{
    public sealed class ShareException(string message) : Exception(message);

    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    public bool Enabled => store.Current.Settings.AllowSharing;

    /// <summary>Whether the user may share folders from this mount at all.</summary>
    public bool CanShareFrom(MountAccess m) => Enabled && m.Share == null && m.Mount.AllowSharing && !m.Storage.Impersonate;

    public IReadOnlyList<ShareInfo> Owned(DavPrincipal me)
    {
        var c = store.Current;
        return c.Shares.Where(s => Names.Eq(s.Owner, me.Username))
            .OrderBy(s => s.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(s => ToInfo(c, s, me)).ToList();
    }

    public static ShareInfo ToInfo(ServerConfig c, ShareConfig s, DavPrincipal? owner)
    {
        owner ??= MountResolver.OwnerOf(c, s);
        var mount = c.Mounts.FirstOrDefault(m => Names.Eq(m.Name, s.Mount));
        var ownerAccess = mount == null || owner == null ? null : MountResolver.Evaluate(c, mount, owner);
        // Show the path as the owner sees it inside the mount.
        var path = s.Path;
        if (ownerAccess != null && ownerAccess.RelativePath.Length > 0)
        {
            if (path.Equals(ownerAccess.RelativePath, PathComparison)) path = "";
            else if (path.StartsWith(ownerAccess.RelativePath + "/", PathComparison)) path = path[(ownerAccess.RelativePath.Length + 1)..];
        }
        return new ShareInfo(s.Id, s.Name, s.Mount, path, s.Access == AccessLevel.ReadWrite ? ShareAccess.ReadWrite : ShareAccess.Read,
            [.. s.Users], [.. s.Groups], s.CreatedUtc, MountResolver.ResolveShare(c, s) != null);
    }

    public async Task<ShareInfo> CreateAsync(DavPrincipal me, ShareRequest request)
    {
        if (!Enabled) throw new ShareException("Sharing is turned off on this server.");
        var mount = mounts.Resolve(me, request.Mount ?? "") ?? throw new ShareException("That folder was not found.");
        if (mount.Share != null) throw new ShareException("Folders that were shared with you cannot be shared again.");
        if (!CanShareFrom(mount)) throw new ShareException($"Folders in {mount.Mount.Name} cannot be shared.");

        var segments = PathSafety.SplitRelative(request.Path);
        if (segments == null) throw new ShareException("The folder name is not valid.");
        var physical = PathSafety.Combine(mount.BasePath, segments);
        if (physical == null || !System.IO.Directory.Exists(physical)) throw new ShareException("That folder was not found.");
        if (!mount.Storage.FollowSymlinks && PathSafety.CrossesLink(mount.Storage.Root, physical)) throw new ShareException("Linked folders cannot be shared.");

        var access = ParseAccess(request.Access);
        if (access == AccessLevel.ReadWrite && !mount.CanWrite) throw new ShareException("You can only share this folder read-only, because that is your own access.");
        var name = string.IsNullOrWhiteSpace(request.Name) ? (segments.Length > 0 ? segments[^1] : mount.Mount.Name) : request.Name.Trim();
        name = name.Replace('(', '[').Replace(')', ']');
        if (!ConfigValidator.IsValidShareName(name)) throw new ShareException("Choose a different name for the share.");
        var (users, groups) = Recipients(me, request);

        var share = new ShareConfig
        {
            Name = name,
            Owner = me.Username,
            OwnerProvider = me.Provider,
            OwnerGroups = [.. me.Groups.Order(StringComparer.OrdinalIgnoreCase)],
            Mount = mount.Mount.Name,
            Storage = mount.Storage.Name,
            Path = mount.StoragePath(segments),
            Users = users,
            Groups = groups,
            Access = access,
        };
        string? conflict = null;
        var errors = await store.UpdateAsync(c =>
        {
            if (c.Shares.Any(s => Names.Eq(s.Owner, me.Username) && Names.Eq(s.Name, name)))
                return conflict = $"You already have a share named \"{name}\".";
            c.Shares.Add(share);
            return null;
        });
        if (conflict != null) throw new ShareException(conflict);
        if (errors.Count > 0) throw new ShareException(errors[0]);
        log.LogInformation("{User} shared {Storage}:{Path} as {Name} with {Recipients}", me.Username, share.Storage, share.Path, name,
            string.Join(", ", users.Concat(groups.Select(g => "@" + g))));
        return ToInfo(store.Current, share, me);
    }

    public async Task<ShareInfo> UpdateAsync(DavPrincipal me, string id, ShareRequest request)
    {
        if (!Enabled) throw new ShareException("Sharing is turned off on this server.");
        var access = ParseAccess(request.Access);
        var (users, groups) = Recipients(me, request);
        var name = request.Name?.Trim().Replace('(', '[').Replace(')', ']');
        if (name != null && !ConfigValidator.IsValidShareName(name)) throw new ShareException("Choose a different name for the share.");

        string? problem = null;
        var errors = await store.UpdateAsync(c =>
        {
            var share = c.Shares.FirstOrDefault(s => s.Id == id && Names.Eq(s.Owner, me.Username));
            if (share == null) return problem = "Share not found.";
            if (name != null && !Names.Eq(name, share.Name) && c.Shares.Any(s => Names.Eq(s.Owner, me.Username) && Names.Eq(s.Name, name)))
                return problem = $"You already have a share named \"{name}\".";
            var mount = c.Mounts.FirstOrDefault(m => Names.Eq(m.Name, share.Mount));
            var mine = mount == null ? null : MountResolver.Evaluate(c, mount, me);
            if (access == AccessLevel.ReadWrite && mine?.CanWrite != true)
                return problem = "You can only share this folder read-only, because that is your own access.";
            share.Access = access;
            share.Users = users;
            share.Groups = groups;
            share.OwnerGroups = [.. me.Groups.Order(StringComparer.OrdinalIgnoreCase)];
            share.OwnerProvider = me.Provider;
            if (name != null) share.Name = name;
            return null;
        });
        if (problem != null) throw new ShareException(problem);
        if (errors.Count > 0) throw new ShareException(errors[0]);
        var c2 = store.Current;
        return ToInfo(c2, c2.Shares.First(s => s.Id == id), me);
    }

    /// <summary>Removes a share; the owner or an administrator may.</summary>
    public async Task<bool> DeleteAsync(DavPrincipal me, string id)
    {
        var removed = false;
        await store.UpdateAsync(c =>
        {
            var share = c.Shares.FirstOrDefault(s => s.Id == id && (me.IsAdmin || Names.Eq(s.Owner, me.Username)));
            if (share == null) return "not found";
            c.Shares.Remove(share);
            removed = true;
            return null;
        });
        return removed;
    }

    public PeopleDirectory People(DavPrincipal me)
    {
        var c = store.Current;
        var users = c.Users.Where(u => u.Enabled && !Names.Eq(u.Username, me.Username))
            .Select(u => new PersonInfo(u.Username, MountResolver.Display(u)))
            .OrderBy(p => p.DisplayName, StringComparer.CurrentCultureIgnoreCase).ToList();
        // Groups the user belongs to, plus groups the configuration names; never the full directory.
        var groups = me.Groups
            .Concat(c.Users.SelectMany(u => u.Groups))
            .Concat(c.Mounts.SelectMany(m => m.Rules.SelectMany(r => r.Groups)))
            .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.CurrentCultureIgnoreCase).ToList();
        return new PeopleDirectory(users, groups);
    }

    /// <summary>Keeps shares inside a moved or renamed folder pointing at its new location.</summary>
    public async Task OnMovedAsync(MountAccess from, IEnumerable<string> fromSegments, MountAccess to, IEnumerable<string> toSegments)
    {
        var oldStorage = from.Storage.Name;
        var oldPath = from.StoragePath(fromSegments);
        if (!store.Current.Shares.Any(s => Affected(s, oldStorage, oldPath))) return;
        var newStorage = to.Storage.Name;
        var newPath = to.StoragePath(toSegments);
        await store.UpdateAsync(c =>
        {
            foreach (var s in c.Shares.Where(s => Affected(s, oldStorage, oldPath)))
            {
                s.Storage = newStorage;
                s.Path = newPath + s.Path[oldPath.Length..];
            }
        });
    }

    /// <summary>Removes shares of a deleted folder (or anything inside it).</summary>
    public async Task OnDeletedAsync(MountAccess mount, IEnumerable<string> segments)
    {
        var storage = mount.Storage.Name;
        var path = mount.StoragePath(segments);
        if (!store.Current.Shares.Any(s => Affected(s, storage, path))) return;
        await store.UpdateAsync(c => { c.Shares.RemoveAll(s => Affected(s, storage, path)); });
    }

    private static bool Affected(ShareConfig s, string storage, string path) =>
        Names.Eq(s.Storage, storage) && path.Length > 0 &&
        (s.Path.Equals(path, PathComparison) || s.Path.StartsWith(path + "/", PathComparison));

    private static AccessLevel ParseAccess(string? access) => access switch
    {
        ShareAccess.ReadWrite => AccessLevel.ReadWrite,
        ShareAccess.Read or null or "" => AccessLevel.Read,
        _ => throw new ShareException("Unknown access level."),
    };

    private static (List<string> Users, List<string> Groups) Recipients(DavPrincipal me, ShareRequest request)
    {
        var users = (request.Users ?? []).Select(u => u.Trim()).Where(u => u.Length > 0 && !Names.Eq(u, me.Username))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var groups = (request.Groups ?? []).Select(g => g.Trim()).Where(g => g.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (users.Count + groups.Count == 0) throw new ShareException("Choose at least one person or group to share with.");
        if (users.Count + groups.Count > 200) throw new ShareException("Too many people and groups.");
        var badUser = users.FirstOrDefault(u => !Names.IsValidUsername(u));
        if (badUser != null) throw new ShareException($"\"{badUser}\" is not a valid user name.");
        var badGroup = groups.FirstOrDefault(g => !Names.IsValidGroup(g));
        if (badGroup != null) throw new ShareException($"\"{badGroup}\" is not a valid group name.");
        return (users, groups);
    }
}
