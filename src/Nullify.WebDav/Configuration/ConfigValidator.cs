// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text.RegularExpressions;
using Nullify.WebDav.Storage;

namespace Nullify.WebDav.Configuration;

public static partial class Names
{
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    private static partial Regex NameRegex();

    [GeneratedRegex(@"^[\p{L}\p{N}][\p{L}\p{N}._@-]{0,127}$")]
    private static partial Regex UsernameRegex();

    /// <summary>Names of storages, mounts and providers: they appear in URLs and the configuration file.</summary>
    public static bool IsValidName(string? name) => name != null && NameRegex().IsMatch(name);

    public static bool IsValidUsername(string? name) => name != null && UsernameRegex().IsMatch(name);

    /// <summary>Group names may be operating system groups such as "CONTOSO\Domain Users".</summary>
    public static bool IsValidGroup(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Length <= 256 && name == name.Trim() && !name.Any(c => char.IsControl(c) || c == ',');

    /// <summary>Splits a comma or newline separated list as typed in a form.</summary>
    public static List<string> SplitList(string? text) =>
        (text ?? "").Split([',', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    public static string JoinList(IEnumerable<string> items) => string.Join(", ", items);

    public static bool Eq(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}

public static class ConfigValidator
{
    public static List<string> Validate(ServerConfig c)
    {
        var errors = new List<string>();
        c.Settings ??= new GeneralSettings();
        c.AuthProviders ??= [];
        c.Users ??= [];
        c.Storages ??= [];
        c.Mounts ??= [];
        c.Shares ??= [];

        if (c.Settings.MaxUploadMegabytes < 0) errors.Add("Settings.MaxUploadMegabytes cannot be negative.");
        if (c.Settings.MaxLockTimeoutMinutes is < 1 or > 525_600) errors.Add("Settings.MaxLockTimeoutMinutes must be between 1 and 525600.");
        if (!string.IsNullOrEmpty(c.Settings.DefaultMount) && c.Mounts.All(m => !Names.Eq(m.Name, c.Settings.DefaultMount)))
            errors.Add($"Settings.DefaultMount refers to unknown mount '{c.Settings.DefaultMount}'.");

        Unique(errors, "authentication provider", c.AuthProviders.Select(p => p.Name));
        foreach (var p in c.AuthProviders)
        {
            p.DefaultGroups ??= [];
            p.AdminGroups ??= [];
            var label = $"Authentication provider '{p.Name}'";
            if (!Names.IsValidName(p.Name)) errors.Add($"{label}: the name may contain letters, digits, '.', '_' and '-'.");
            if (Names.Eq(p.Name, UserConfig.LocalProvider)) errors.Add($"{label}: '{UserConfig.LocalProvider}' is reserved for local passwords.");
            if (!Enum.IsDefined(p.Type)) errors.Add($"{label}: unknown type.");
            foreach (var g in p.DefaultGroups.Concat(p.AdminGroups))
                if (!Names.IsValidGroup(g)) errors.Add($"{label}: invalid group name '{g}'.");
            if (p.Type is ProviderType.Ldap or ProviderType.Imap)
            {
                if (string.IsNullOrWhiteSpace(p.Host)) errors.Add($"{label}: a host is required.");
                if (p.Port is < 0 or > 65535) errors.Add($"{label}: invalid port.");
                if (!(p.LoginTemplate ?? "").Contains("{user}")) errors.Add($"{label}: the login template must contain {{user}}.");
            }
            if (p.Type == ProviderType.Pam && string.IsNullOrWhiteSpace(p.Service)) errors.Add($"{label}: a PAM service name is required.");
            p.Scopes ??= [];
            if (p.Type == ProviderType.OpenIdConnect)
            {
                if (!Uri.TryCreate(p.Authority, UriKind.Absolute, out var authority) || authority.Scheme is not ("https" or "http") || authority.Query.Length > 0)
                    errors.Add($"{label}: the authority must be the issuer's https:// URL.");
                else if (authority.Scheme == "http" && !authority.IsLoopback)
                    errors.Add($"{label}: the authority must use https (http is only allowed for localhost).");
                if (string.IsNullOrWhiteSpace(p.ClientId)) errors.Add($"{label}: a client ID is required.");
                if (string.IsNullOrWhiteSpace(p.UsernameClaim)) errors.Add($"{label}: a user name claim is required.");
                if (p.ClientSecret == "env:") errors.Add($"{label}: name the environment variable after env:.");
                foreach (var scope in p.Scopes)
                    if (scope.Length == 0 || scope.Any(c => c <= ' ' || c == '"')) errors.Add($"{label}: invalid scope '{scope}'.");
            }
        }

        Unique(errors, "user", c.Users.Select(u => u.Username));
        foreach (var u in c.Users)
        {
            u.Groups ??= [];
            u.ExternalGroups ??= [];
            u.AppPasswords ??= [];
            var label = $"User '{u.Username}'";
            if (!Names.IsValidUsername(u.Username)) errors.Add($"{label}: usernames may contain letters, digits, '.', '_', '-' and '@' and must start with a letter or digit.");
            if (!Names.Eq(u.Provider, UserConfig.LocalProvider) && c.AuthProviders.All(p => !Names.Eq(p.Name, u.Provider)))
                errors.Add($"{label}: unknown authentication provider '{u.Provider}'.");
            if (!string.IsNullOrEmpty(u.DefaultMount) && c.Mounts.All(m => !Names.Eq(m.Name, u.DefaultMount)))
                errors.Add($"{label}: unknown default mount '{u.DefaultMount}'.");
            foreach (var g in u.Groups)
                if (!Names.IsValidGroup(g)) errors.Add($"{label}: invalid group name '{g}'.");
            if (string.IsNullOrEmpty(u.SecurityStamp)) u.SecurityStamp = Guid.NewGuid().ToString("N");
        }
        // A login names one user only, whether it is someone's username or someone else's provider login.
        var logins = c.Users.Where(u => !string.IsNullOrEmpty(u.Login) && !Names.Eq(u.Login, u.Username)).Select(u => u.Login).ToList();
        foreach (var login in logins.Distinct(StringComparer.OrdinalIgnoreCase))
            if (logins.Count(l => Names.Eq(l, login)) + c.Users.Count(u => Names.Eq(u.Username, login)) > 1)
                errors.Add($"The login '{login}' is used by more than one user.");

        Unique(errors, "storage", c.Storages.Select(s => s.Name));
        foreach (var s in c.Storages)
        {
            var label = $"Storage '{s.Name}'";
            if (!Names.IsValidName(s.Name)) errors.Add($"{label}: the name may contain letters, digits, '.', '_' and '-'.");
            if (string.IsNullOrWhiteSpace(s.Root) || !Path.IsPathFullyQualified(s.Root)) errors.Add($"{label}: the root must be an absolute path.");
            if (s.Impersonate && !OperatingSystem.IsWindows()) errors.Add($"{label}: impersonation is only available on Windows.");
        }

        Unique(errors, "mount", c.Mounts.Select(m => m.Name));
        foreach (var m in c.Mounts)
        {
            m.Rules ??= [];
            var label = $"Mount '{m.Name}'";
            if (!Names.IsValidName(m.Name)) errors.Add($"{label}: the name may contain letters, digits, '.', '_' and '-'.");
            if (c.Storages.All(s => !Names.Eq(s.Name, m.Storage))) errors.Add($"{label}: unknown storage '{m.Storage}'.");
            if (!PathSafety.IsValidTemplate(m.Path)) errors.Add($"{label}: invalid path '{m.Path}' (use a relative path; {{user}} is allowed).");
            for (var i = 0; i < m.Rules.Count; i++)
            {
                var r = m.Rules[i];
                r.Users ??= [];
                r.Groups ??= [];
                var rl = $"{label}, rule {i + 1}";
                if (r.Users.Count == 0 && r.Groups.Count == 0) errors.Add($"{rl}: list at least one user, group or '*'.");
                foreach (var u in r.Users)
                    if (u != "*" && !Names.IsValidUsername(u)) errors.Add($"{rl}: invalid user name '{u}'.");
                foreach (var g in r.Groups)
                    if (!Names.IsValidGroup(g)) errors.Add($"{rl}: invalid group name '{g}'.");
                if (!Enum.IsDefined(r.Access)) errors.Add($"{rl}: unknown access level.");
                if (r.Path != null && !PathSafety.IsValidTemplate(r.Path)) errors.Add($"{rl}: invalid path '{r.Path}'.");
            }
        }

        // Shares are written by users: keep them well formed, but a share whose mount or owner has gone away is not an
        // error (it simply stops working), so removing a mount or user never fails because of someone's share.
        Unique(errors, "share id", c.Shares.Select(s => s.Id));
        foreach (var owner in c.Shares.GroupBy(s => s.Owner, StringComparer.OrdinalIgnoreCase))
            foreach (var g in owner.GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
                errors.Add($"User '{owner.Key}' has more than one share named '{g.Key}'.");
        foreach (var s in c.Shares)
        {
            s.Users ??= [];
            s.Groups ??= [];
            s.OwnerGroups ??= [];
            var label = $"Share '{s.Id}'";
            if (string.IsNullOrEmpty(s.Id) || !Names.IsValidName(s.Id)) errors.Add($"{label}: invalid id.");
            if (!Names.IsValidUsername(s.Owner)) errors.Add($"{label}: invalid owner '{s.Owner}'.");
            if (!IsValidShareName(s.Name)) errors.Add($"{label}: invalid name '{s.Name}'.");
            if (PathSafety.SplitRelative(s.Path) == null) errors.Add($"{label}: invalid path '{s.Path}'.");
            if (s.Access is not (AccessLevel.Read or AccessLevel.ReadWrite)) errors.Add($"{label}: access must be Read or ReadWrite.");
            foreach (var u in s.Users)
                if (!Names.IsValidUsername(u)) errors.Add($"{label}: invalid user name '{u}'.");
            foreach (var g in s.Groups.Concat(s.OwnerGroups))
                if (!Names.IsValidGroup(g)) errors.Add($"{label}: invalid group name '{g}'.");
        }
        return errors;
    }

    /// <summary>A share name is one safe path segment without brackets (they mark the owner in the URL).</summary>
    public static bool IsValidShareName(string? name) =>
        name is { Length: > 0 and <= 100 } && name == name.Trim() && PathSafety.IsSafeSegment(name) && name.IndexOfAny(['(', ')']) < 0;

    private static void Unique(List<string> errors, string what, IEnumerable<string> names)
    {
        foreach (var g in names.GroupBy(n => n, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
            errors.Add($"There is more than one {what} named '{g.Key}'.");
    }
}
