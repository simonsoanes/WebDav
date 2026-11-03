// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Storage;

/// <summary>A mount as one user sees it: effective access and the folder it resolves to.</summary>
public sealed record MountAccess(MountConfig Mount, StorageConfig Storage, AccessLevel Access, string BasePath, string RelativePath, int RuleIndex)
{
    public bool CanWrite => Access == AccessLevel.ReadWrite;
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

    /// <summary>Resolves a mount by name (or "~"); null when it does not exist or the user has no access.</summary>
    public MountAccess? Resolve(DavPrincipal user, string name)
    {
        var c = config.Current;
        if (name == DefaultAlias) name = DefaultMountName(user) ?? "";
        var mount = c.Mounts.FirstOrDefault(m => Names.Eq(m.Name, name));
        return mount == null ? null : Evaluate(c, mount, user);
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

    private static MountAccess? Evaluate(ServerConfig c, MountConfig mount, DavPrincipal user)
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
