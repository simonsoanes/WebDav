// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Auth;

public enum LoginPurpose
{
    /// <summary>WebDAV clients: app passwords are accepted.</summary>
    Dav,
    /// <summary>The web UI: only the account password.</summary>
    Ui,
}

/// <summary>
/// Validates a login and password. Listed users are checked against their own provider (a local hash or an
/// external system) or an app password; unlisted logins are offered to providers that accept unlisted users.
/// Successful checks are cached briefly because WebDAV clients authenticate every request.
/// </summary>
public sealed class CredentialValidator
{
    private static readonly TimeSpan CacheTime = TimeSpan.FromMinutes(5);
    private readonly ConcurrentDictionary<string, (DavPrincipal Principal, DateTime Expires)> _cache = new();
    private readonly ConfigStore _config;
    private readonly ProviderRegistry _providers;
    private readonly LoginThrottle _throttle;
    private readonly ILogger<CredentialValidator> _log;

    public CredentialValidator(ConfigStore config, ProviderRegistry providers, LoginThrottle throttle, ILogger<CredentialValidator> log)
    {
        _config = config;
        _providers = providers;
        _throttle = throttle;
        _log = log;
        // Disabled users, changed passwords or rules must take effect at once.
        config.Changed += _cache.Clear;
    }

    public bool IsBlocked(string clientKey) => _throttle.IsBlocked(clientKey);

    public async Task<DavPrincipal?> ValidateAsync(string login, string password, string clientKey, LoginPurpose purpose, CancellationToken ct)
    {
        login = login.Trim();
        if (login.Length is 0 or > 256 || password.Length is 0 or > 1024 || login.Contains('\0') || password.Contains('\0')) return null;

        var cacheKey = PasswordHasher.Sha256($"{purpose}\0{login.ToLowerInvariant()}\0{password}");
        if (_cache.TryGetValue(cacheKey, out var hit))
        {
            if (hit.Expires > DateTime.UtcNow) return hit.Principal;
            _cache.TryRemove(cacheKey, out _);
        }

        if (_throttle.IsBlocked(clientKey)) return null;

        var principal = await CheckAsync(_config.Current, login, password, purpose, ct);
        if (principal == null)
        {
            _throttle.RecordFailure(clientKey);
            _log.LogInformation("Failed sign-in for {Login} from {Client}", login, clientKey);
            return null;
        }

        _throttle.Reset(clientKey);
        if (_cache.Count > 10_000)
            foreach (var kv in _cache.Where(kv => kv.Value.Expires <= DateTime.UtcNow).ToList())
                _cache.TryRemove(kv.Key, out _);
        _cache[cacheKey] = (principal, DateTime.UtcNow + CacheTime);
        return principal;
    }

    /// <summary>Runs one provider directly, for the admin "test sign-in" tool. Not cached or throttled.</summary>
    public async Task<ProviderResult> TestProviderAsync(AuthProviderConfig provider, string login, string password, CancellationToken ct)
    {
        var impl = _providers.For(provider.Type);
        if (impl is not { IsSupported: true }) return ProviderResult.Unavailable;
        var result = await impl.AuthenticateAsync(provider, login.Trim(), password, ct);
        result.Token?.Dispose();
        return result;
    }

    public static UserConfig? FindUser(ServerConfig c, string login) =>
        c.Users.FirstOrDefault(u => Names.Eq(u.Username, login)) ??
        c.Users.FirstOrDefault(u => !string.IsNullOrEmpty(u.Login) && Names.Eq(u.Login, login));

    private async Task<DavPrincipal?> CheckAsync(ServerConfig c, string login, string password, LoginPurpose purpose, CancellationToken ct)
    {
        var user = FindUser(c, login);
        if (user != null) return user.Enabled ? await CheckListedAsync(c, user, password, purpose, ct) : null;

        foreach (var provider in c.AuthProviders.Where(p => p.Enabled && p.AcceptUnlisted))
        {
            var result = await RunProviderAsync(provider, login, password, ct);
            if (result == null) continue;
            var username = UnlistedName(provider, result.CanonicalName ?? login);
            // An unlisted account must never take over the name (and so the folders) of a listed user.
            if (username == null || FindUser(c, username) != null)
            {
                _log.LogWarning("Rejected unlisted login {Login} via {Provider}: the name {Name} is invalid or belongs to a listed user",
                    login, provider.Name, username);
                result.Token?.Dispose();
                return null;
            }
            var groups = new HashSet<string>(provider.DefaultGroups, StringComparer.OrdinalIgnoreCase);
            if (provider.UseOsGroups && result.Groups != null) groups.UnionWith(result.Groups);
            return new DavPrincipal
            {
                Username = username,
                DisplayName = username,
                Provider = provider.Name,
                Listed = false,
                IsAdmin = provider.AdminGroups.Any(groups.Contains),
                Groups = groups,
                WindowsToken = result.Token,
            };
        }
        return null;
    }

    private async Task<DavPrincipal?> CheckListedAsync(ServerConfig c, UserConfig user, string password, LoginPurpose purpose, CancellationToken ct)
    {
        var groups = new HashSet<string>(user.Groups, StringComparer.OrdinalIgnoreCase);
        DavPrincipal Build(AuthProviderConfig? provider, ProviderResult? result)
        {
            if (provider != null)
            {
                groups.UnionWith(provider.DefaultGroups);
                if (provider.UseOsGroups && result?.Groups != null) groups.UnionWith(result.Groups);
            }
            return new DavPrincipal
            {
                Username = user.Username,
                DisplayName = string.IsNullOrEmpty(user.DisplayName) ? user.Username : user.DisplayName,
                Provider = user.Provider,
                Listed = true,
                IsAdmin = user.IsAdmin || provider?.AdminGroups.Any(groups.Contains) == true,
                Groups = groups,
                SecurityStamp = user.SecurityStamp,
                WindowsToken = result?.Token,
            };
        }

        var external = Names.Eq(user.Provider, UserConfig.LocalProvider)
            ? null
            : c.AuthProviders.FirstOrDefault(p => Names.Eq(p.Name, user.Provider));

        if (purpose == LoginPurpose.Dav && c.Settings.AllowAppPasswords && user.AppPasswords.Count > 0)
        {
            var hash = PasswordHasher.Sha256(password.Trim());
            if (user.AppPasswords.Any(a => PasswordHasher.TokensEqual(a.Hash, hash))) return Build(external, null);
        }

        if (external == null)
            return Names.Eq(user.Provider, UserConfig.LocalProvider) && PasswordHasher.Verify(user.PasswordHash, password) ? Build(null, null) : null;
        if (!external.Enabled) return null;

        var result = await RunProviderAsync(external, string.IsNullOrEmpty(user.Login) ? user.Username : user.Login, password, ct);
        return result == null ? null : Build(external, result);
    }

    private async Task<ProviderResult?> RunProviderAsync(AuthProviderConfig provider, string login, string password, CancellationToken ct)
    {
        var impl = _providers.For(provider.Type);
        if (impl is not { IsSupported: true })
        {
            _log.LogWarning("Authentication provider {Provider} ({Type}) is not supported on this platform", provider.Name, provider.Type);
            return null;
        }
        var result = await impl.AuthenticateAsync(provider, login, password, ct);
        if (result.Outcome == ProviderOutcome.Success) return result;
        result.Token?.Dispose();
        if (result.Outcome == ProviderOutcome.Unavailable)
            _log.LogWarning("Authentication provider {Provider} is unavailable", provider.Name);
        return null;
    }

    private static string? UnlistedName(AuthProviderConfig provider, string name)
    {
        if (provider.StripDomain)
        {
            var slash = name.LastIndexOf('\\');
            if (slash >= 0) name = name[(slash + 1)..];
            var at = name.IndexOf('@');
            if (at > 0) name = name[..at];
        }
        return Names.IsValidUsername(name) ? name : null;
    }
}
