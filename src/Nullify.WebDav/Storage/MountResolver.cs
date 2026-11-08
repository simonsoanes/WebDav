// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Storage;

/// <summary>
/// A mount (or a folder shared with the user) as one user sees it: effective access and the folder it resolves to.
/// <paramref name="RelativePath"/> is the folder's path inside the storage.
/// </summary>
public sealed record MountAccess(MountConfig Mount, StorageConfig Storage, AccessLevel Access, string BasePath, string RelativePath, int RuleIndex)
{
    public bool CanWrite => Access == AccessLevel.ReadWrite;

    /// <summary>Set when this is another user's shared folder rather than a mount.</summary>
    public ShareConfig? Share { get; init; }

    /// <summary>The name under /dav/: the mount name, or "Name (owner)" for a shared folder.</summary>
    public string Name => Share?.Segment ?? Mount.Name;

    /// <summary>Path inside the storage of something below this mount.</summary>
    public string StoragePath(IEnumerable<string> segments) =>
        string.Join('/', (PathSafety.SplitRelative(RelativePath) ?? []).Concat(segments));
}

/// <summary>Applies the mount rules: which mounts a user sees, with what access, and which folder each one maps to.</summary>
public sealed class MountResolver(ConfigStore config)
{
    /// <summary>The URL segment that always refers to the user's default mount.</summary>
    public const string DefaultAlias = "~";

    public IReadOnlyList<MountAccess> MountsFor(DavPrincipal user)
    {
        var c = config.Current;
        return c.Mounts.Select(m => Evaluate(c, m, user)).OfType<MountAccess>().ToList();
    }

    /// <summary>Folders other users shared with this user that are currently reachable.</summary>
    public IReadOnlyList<MountAccess> SharesFor(DavPrincipal user)
    {
        var c = config.Current;
        if (!c.Settings.AllowSharing) return [];
        return c.Shares.Where(s => s.IsRecipient(user.Username, user.Groups))
            .Select(s => ResolveShare(c, s)).OfType<MountAccess>()
            .OrderBy(s => s.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    /// <summary>Everything listed at /dav/: mounts, then shared folders.</summary>
    public IReadOnlyList<MountAccess> EntriesFor(DavPrincipal user) => [.. MountsFor(user), .. SharesFor(user)];

    /// <summary>Resolves a mount by name (or "~") or a shared folder by segment; null when absent or not accessible.</summary>
    public MountAccess? Resolve(DavPrincipal user, string name)
    {
        var c = config.Current;
        if (name == DefaultAlias) name = DefaultMountName(user) ?? "";
        var mount = c.Mounts.FirstOrDefault(m => Names.Eq(m.Name, name));
        if (mount != null) return Evaluate(c, mount, user);
        if (!c.Settings.AllowSharing || !name.EndsWith(')')) return null;
        var share = c.Shares.FirstOrDefault(s => Names.Eq(s.Segment, name) && s.IsRecipient(user.Username, user.Groups));
        return share == null ? null : ResolveShare(c, share);
    }

    /// <summary>The user's own default mount, else the server default, provided the user can access it.</summary>
    public string? DefaultMountName(DavPrincipal user)
    {
        var c = config.Current;
        var own = c.Users.FirstOrDefault(u => Names.Eq(u.Username, user.Username))?.DefaultMount;
        foreach (var candidate in new[] { own, c.Settings.DefaultMount })
        {
            if (string.IsNullOrEmpty(candidate)) continue;
            var mount = c.Mounts.FirstOrDefault(m => Names.Eq(m.Name, candidate));
            if (mount != null && Evaluate(c, mount, user) != null) return mount.Name;
        }
        return null;
    }

    /// <summary>
    /// A share is usable while sharing is allowed, its owner still exists and can still reach the folder through the
    /// mount it was shared from (with at least the shared access), and the folder exists. Shares never impersonate.
    /// </summary>
    public static MountAccess? ResolveShare(ServerConfig c, ShareConfig share)
    {
        if (!c.Settings.AllowSharing) return null;
        var owner = OwnerOf(c, share);
        if (owner == null) return null;
        var mount = c.Mounts.FirstOrDefault(m => Names.Eq(m.Name, share.Mount));
        if (mount is not { AllowSharing: true }) return null;
        var ownerAccess = Evaluate(c, mount, owner);
        if (ownerAccess == null || ownerAccess.Storage.Impersonate || !Names.Eq(ownerAccess.Storage.Name, share.Storage)) return null;

        var segments = PathSafety.SplitRelative(share.Path);
        if (segments == null) return null;
        var physical = PathSafety.Combine(ownerAccess.Storage.Root, segments);
        if (physical == null || !PathSafety.IsWithinOrSame(ownerAccess.BasePath, physical) || !Directory.Exists(physical)) return null;
        if (!ownerAccess.Storage.FollowSymlinks && PathSafety.CrossesLink(ownerAccess.Storage.Root, physical)) return null;

        var access = ownerAccess.CanWrite && share.Access == AccessLevel.ReadWrite ? AccessLevel.ReadWrite : AccessLevel.Read;
        return new MountAccess(mount, ownerAccess.Storage, access, physical, string.Join('/', segments), -1) { Share = share };
    }

    /// <summary>The owner as a principal for re-checking their access; null when they were removed or disabled.</summary>
    public static DavPrincipal? OwnerOf(ServerConfig c, ShareConfig share)
    {
        var groups = new HashSet<string>(share.OwnerGroups, StringComparer.OrdinalIgnoreCase);
        var listed = c.Users.FirstOrDefault(u => Names.Eq(u.Username, share.Owner));
        if (listed != null)
        {
            if (!listed.Enabled) return null;
            groups.UnionWith(listed.Groups);
            return new DavPrincipal { Username = listed.Username, DisplayName = Display(listed), Provider = listed.Provider, Listed = true, Groups = groups };
        }
        var provider = c.AuthProviders.FirstOrDefault(p => Names.Eq(p.Name, share.OwnerProvider));
        if (provider is not { Enabled: true, AcceptUnlisted: true }) return null;
        return new DavPrincipal { Username = share.Owner, DisplayName = share.Owner, Provider = provider.Name, Groups = groups };
    }

    public static string Display(UserConfig u) => string.IsNullOrEmpty(u.DisplayName) ? u.Username : u.DisplayName;

    public static MountAccess? Evaluate(ServerConfig c, MountConfig mount, DavPrincipal user)
    {
        var storage = c.Storages.FirstOrDefault(s => Names.Eq(s.Name, mount.Storage));
        if (storage == null) return null;
        for (var i = 0; i < mount.Rules.Count; i++)
        {
            var rule = mount.Rules[i];
            if (!Matches(rule, user)) continue;
            if (rule.Access == AccessLevel.None) return null;
            var access = mount.ReadOnly || storage.ReadOnly ? AccessLevel.Read : rule.Access;
            var relative = Expand(rule.Path ?? mount.Path, user);
            var segments = PathSafety.SplitRelative(relative);
            if (segments == null) return null;
            var basePath = PathSafety.Combine(storage.Root, segments);
            return basePath == null ? null : new MountAccess(mount, storage, access, basePath, string.Join('/', segments), i);
        }
        return null;
    }

    public static bool Matches(AccessRule rule, DavPrincipal user) =>
        rule.Users.Any(u => u == "*" || Names.Eq(u, user.Username)) ||
        rule.Groups.Any(user.Groups.Contains);

    /// <summary>Substitutes {user}. Usernames are restricted to safe characters, so the result stays one segment.</summary>
    public static string Expand(string? template, DavPrincipal user) =>
        (template ?? "").Replace("{user}", user.Username, StringComparison.Ordinal);
}
