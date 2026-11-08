// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Auth;

/// <summary>
/// OpenID Connect providers. Each enabled provider in the configuration is an authentication scheme ("oidc-{name}")
/// added and removed at run time, so providers can be edited without a restart. The ASP.NET Core handler does the
/// protocol (authorization code flow with PKCE, nonce and state, signature and issuer validation); this class turns
/// the validated identity into one of this server's users.
/// </summary>
public static class OpenIdConnectSetup
{
    public const string SchemePrefix = "oidc-";

    public static string SchemeFor(string providerName) => SchemePrefix + providerName.ToLowerInvariant();

    public static void AddDynamicOpenIdConnect(this IServiceCollection services)
    {
        services.AddSingleton<IConfigureOptions<OpenIdConnectOptions>, OidcOptionsSetup>();
        // Normally added by AddOpenIdConnect(): fills in the configuration manager, state format and so on.
        services.AddSingleton<IPostConfigureOptions<OpenIdConnectOptions>, OpenIdConnectPostConfigureOptions>();
        services.AddSingleton<OidcSchemes>();
        services.AddSingleton<OidcSignIn>();
    }

    /// <summary>Registers schemes for the current configuration and keeps them in step with later changes.</summary>
    public static void UseDynamicOpenIdConnect(this WebApplication app) => app.Services.GetRequiredService<OidcSchemes>().Start();

    /// <summary>
    /// "Sign in with ..." links. A plain GET (not a form), because the pages' CSP form-action 'self' would stop a form
    /// submission from being redirected to the identity provider. Starting a sign-in is harmless: it only leads to the
    /// provider, and its answer is bound to this browser by the state and correlation cookie.
    /// </summary>
    public static void MapExternalSignIn(this WebApplication app) =>
        app.MapGet("/account/external/{provider}", async (string provider, string? returnUrl, HttpContext http, ConfigStore store,
            IAuthenticationSchemeProvider schemes) =>
        {
            var p = store.Current.AuthProviders.FirstOrDefault(x => Names.Eq(x.Name, provider) && x is { Enabled: true, Type: ProviderType.OpenIdConnect });
            if (p == null || await schemes.GetSchemeAsync(SchemeFor(p.Name)) == null) return Results.NotFound();
            var pathBase = http.Request.PathBase.Value ?? "";
            var target = !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//") && !returnUrl.StartsWith("/\\") && returnUrl != "/"
                ? returnUrl : pathBase + "/dav/";
            try
            {
                // Reads the provider's discovery document on first use, so an unreachable provider fails here.
                await http.ChallengeAsync(SchemeFor(p.Name), new AuthenticationProperties { RedirectUri = target });
            }
            catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or IOException && !http.Response.HasStarted)
            {
                http.RequestServices.GetRequiredService<ILogger<OidcSignIn>>().LogWarning(ex, "Could not start sign-in with {Provider}", p.Name);
                var tempData = http.RequestServices.GetRequiredService<ITempDataDictionaryFactory>().GetTempData(http);
                tempData["ErrorMessage"] = $"{(string.IsNullOrWhiteSpace(p.Description) ? p.Name : p.Description)} cannot be reached right now. Please try again later.";
                tempData.Save();
                http.Response.Redirect(pathBase + "/account/login");
            }
            return Results.Empty;
        }).AllowAnonymous();
}

/// <summary>Keeps one authentication scheme per enabled OpenID Connect provider.</summary>
public sealed class OidcSchemes(ConfigStore store, IAuthenticationSchemeProvider schemes, IOptionsMonitorCache<OpenIdConnectOptions> options,
    ILogger<OidcSchemes> log)
{
    private readonly Lock _gate = new();
    private Dictionary<string, string> _registered = new(StringComparer.Ordinal); // scheme -> settings fingerprint

    public void Start()
    {
        Sync();
        store.Changed += Sync;
    }

    private void Sync()
    {
        lock (_gate)
        {
            var wanted = store.Current.AuthProviders
                .Where(p => p is { Enabled: true, Type: ProviderType.OpenIdConnect })
                .ToDictionary(p => OpenIdConnectSetup.SchemeFor(p.Name), Fingerprint, StringComparer.Ordinal);
            foreach (var (scheme, _) in _registered.Where(r => !wanted.ContainsKey(r.Key)))
            {
                schemes.RemoveScheme(scheme);
                options.TryRemove(scheme);
            }
            foreach (var (scheme, print) in wanted)
            {
                if (_registered.TryGetValue(scheme, out var old))
                {
                    if (old == print) continue;
                    // Changed settings: the options (and their cached discovery document) are rebuilt on next use.
                    options.TryRemove(scheme);
                    continue;
                }
                schemes.TryAddScheme(new AuthenticationScheme(scheme, scheme, typeof(OpenIdConnectHandler)));
                log.LogInformation("OpenID Connect provider {Scheme} is active", scheme);
            }
            _registered = wanted;
        }
    }

    private static string Fingerprint(AuthProviderConfig p) => string.Join('\n', p.Authority, p.ClientId, p.ResolveClientSecret(),
        string.Join(' ', p.Scopes), p.UsernameClaim, p.DisplayNameClaim, p.GroupsClaim, p.AllowInvalidCertificates);
}

/// <summary>Builds the handler options of an "oidc-{name}" scheme from that provider's settings.</summary>
public sealed class OidcOptionsSetup(ConfigStore store) : IConfigureNamedOptions<OpenIdConnectOptions>
{
    public void Configure(OpenIdConnectOptions options) { }

    public void Configure(string? name, OpenIdConnectOptions o)
    {
        if (name == null || !name.StartsWith(OpenIdConnectSetup.SchemePrefix, StringComparison.Ordinal)) return;
        var p = store.Current.AuthProviders.FirstOrDefault(x => x.Type == ProviderType.OpenIdConnect && OpenIdConnectSetup.SchemeFor(x.Name) == name);
        if (p == null) return;

        o.TimeProvider = TimeProvider.System;
        o.Authority = p.Authority.TrimEnd('/');
        o.ClientId = p.ClientId;
        var secret = p.ResolveClientSecret();
        o.ClientSecret = secret.Length > 0 ? secret : null;
        o.RequireHttpsMetadata = !Uri.TryCreate(p.Authority, UriKind.Absolute, out var a) || !a.IsLoopback;
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.ResponseMode = OpenIdConnectResponseMode.FormPost;
        o.UsePkce = true;
        o.Scope.Clear();
        o.Scope.Add("openid");
        foreach (var scope in p.Scopes.Where(s => s != "openid")) o.Scope.Add(scope);
        o.CallbackPath = "/signin-oidc/" + p.Name.ToLowerInvariant();
        o.SignedOutCallbackPath = "/signout-callback-oidc/" + p.Name.ToLowerInvariant();
        o.RemoteSignOutPath = "/signout-oidc/" + p.Name.ToLowerInvariant();
        o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.SaveTokens = false;
        o.GetClaimsFromUserInfoEndpoint = true;
        o.MapInboundClaims = false; // keep "sub", "groups", ... as the provider names them
        o.DisableTelemetry = true; // no library name and version in requests to the provider
        o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        o.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        o.TokenValidationParameters.NameClaimType = p.UsernameClaim;
        if (p.AllowInvalidCertificates)
            o.BackchannelHttpHandler = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };

        var providerName = p.Name;
        o.Events = new OpenIdConnectEvents
        {
            OnTokenValidated = async ctx =>
            {
                var signIn = ctx.HttpContext.RequestServices.GetRequiredService<OidcSignIn>();
                var (principal, error) = await signIn.MapAsync(providerName, ctx.Principal!);
                if (principal == null) ctx.Fail(new OidcSignIn.SignInRefused(error!));
                else ctx.Principal = principal;
            },
            OnRemoteFailure = ctx =>
            {
                var message = ctx.Failure is OidcSignIn.SignInRefused refused
                    ? refused.Message
                    : $"Signing in with {providerName} did not work. Please try again.";
                if (ctx.Failure is not OidcSignIn.SignInRefused)
                    ctx.HttpContext.RequestServices.GetRequiredService<ILogger<OidcSignIn>>()
                        .LogWarning(ctx.Failure, "OpenID Connect sign-in with {Provider} failed", providerName);
                var tempData = ctx.HttpContext.RequestServices.GetRequiredService<ITempDataDictionaryFactory>().GetTempData(ctx.HttpContext);
                tempData["ErrorMessage"] = message;
                tempData.Save();
                ctx.Response.Redirect(ctx.Request.PathBase + "/account/login");
                ctx.HandleResponse();
                return Task.CompletedTask;
            },
        };
    }
}

/// <summary>Turns a validated OpenID Connect identity into a user of this server.</summary>
public sealed class OidcSignIn(ConfigStore store, ILogger<OidcSignIn> log)
{
    public sealed class SignInRefused(string message) : Exception(message);

    private const int MaxGroups = 500;

    /// <summary>
    /// Finds (or, with "accept unlisted accounts", creates) the user. Users are bound to the provider's subject: the
    /// first sign-in records "sub" as the user's login, and from then on only that subject signs in as them, so a
    /// renamed or recycled account name at the provider cannot take over someone else's folders.
    /// </summary>
    public async Task<(ClaimsPrincipal? Principal, string? Error)> MapAsync(string providerName, ClaimsPrincipal external)
    {
        var c = store.Current;
        var provider = c.AuthProviders.FirstOrDefault(p => Names.Eq(p.Name, providerName) && p is { Enabled: true, Type: ProviderType.OpenIdConnect });
        if (provider == null) return (null, "This sign-in option is no longer available.");

        var subject = external.FindFirstValue("sub");
        if (string.IsNullOrEmpty(subject) || subject.Length > 255) return (null, "The identity provider did not identify the account.");
        var rawName = external.FindFirstValue(provider.UsernameClaim) ?? external.FindFirstValue("email") ?? "";
        var username = NameFrom(provider, rawName);
        var displayName = (external.FindFirstValue(provider.DisplayNameClaim) ?? "").Trim();
        if (displayName.Length > 200) displayName = displayName[..200];
        var tokenGroups = provider.UseOsGroups
            ? external.FindAll(provider.GroupsClaim).Select(g => g.Value.Trim()).Where(Names.IsValidGroup)
                .Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxGroups).Order(StringComparer.OrdinalIgnoreCase).ToList()
            : [];

        string? refusal = null;
        UserConfig? user = null;
        // The usual case, a known user whose groups have not changed, needs no write to the configuration file.
        var known = c.Users.FirstOrDefault(u => Names.Eq(u.Provider, provider.Name) && u.Login == subject);
        var unchanged = known is { Enabled: true } && known.ExternalGroups.SequenceEqual(tokenGroups, StringComparer.OrdinalIgnoreCase) &&
                        (known.DisplayName.Length > 0 || displayName.Length == 0);
        IReadOnlyList<string> errors = unchanged ? [] : await store.UpdateAsync(cfg =>
        {
            var p = cfg.AuthProviders.First(x => Names.Eq(x.Name, provider.Name));
            var mine = cfg.Users.Where(u => Names.Eq(u.Provider, p.Name)).ToList();
            // 1. A user already bound to this subject.
            user = mine.FirstOrDefault(u => u.Login == subject);
            // 2. A user the administrator listed for this provider by name, not yet bound: bind them now.
            if (user == null && username != null)
            {
                user = mine.FirstOrDefault(u => string.IsNullOrEmpty(u.Login) && Names.Eq(u.Username, username));
                if (user != null) user.Login = subject;
            }
            // 3. Anyone else, when the provider accepts unlisted accounts: create them, bound to the subject.
            if (user == null)
            {
                if (username == null)
                    return refusal = "Your account name from the identity provider cannot be used here.";
                if (CredentialValidator.FindUser(cfg, username) != null)
                    return refusal = $"The user name \"{username}\" already belongs to another account on this server.";
                if (!p.AcceptUnlisted)
                    return refusal = "Your account has not been given access to this server.";
                user = new UserConfig { Username = username, DisplayName = displayName, Provider = p.Name, Login = subject };
                cfg.Users.Add(user);
                log.LogInformation("Created user {User} for {Subject} at {Provider}", username, subject, p.Name);
            }
            if (!user.Enabled) return refusal = "Your account is disabled.";
            if (!user.ExternalGroups.SequenceEqual(tokenGroups, StringComparer.OrdinalIgnoreCase)) user.ExternalGroups = tokenGroups;
            if (string.IsNullOrEmpty(user.DisplayName) && displayName.Length > 0) user.DisplayName = displayName;
            return null;
        });
        if (refusal != null)
        {
            log.LogWarning("Refused OpenID Connect sign-in of {Subject} ({Name}) via {Provider}: {Reason}", subject, rawName, provider.Name, refusal);
            return (null, refusal);
        }
        if (errors.Count > 0)
        {
            log.LogWarning("OpenID Connect sign-in of {Subject} via {Provider} could not be saved: {Errors}", subject, provider.Name, string.Join("; ", errors));
            return (null, "Your account could not be set up. Ask your administrator to check the server log.");
        }

        var saved = store.Current.Users.First(u => Names.Eq(u.Provider, provider.Name) && u.Login == subject);
        var groups = new HashSet<string>(saved.Groups, StringComparer.OrdinalIgnoreCase);
        groups.UnionWith(provider.DefaultGroups);
        groups.UnionWith(saved.ExternalGroups);
        var principal = new DavPrincipal
        {
            Username = saved.Username,
            DisplayName = string.IsNullOrEmpty(saved.DisplayName) ? saved.Username : saved.DisplayName,
            Provider = saved.Provider,
            Listed = true,
            IsAdmin = saved.IsAdmin || provider.AdminGroups.Any(groups.Contains),
            Groups = groups,
            SecurityStamp = saved.SecurityStamp,
        };
        log.LogInformation("{User} signed in with {Provider}", saved.Username, provider.Name);
        return (principal.ToClaimsPrincipal(CookieAuthenticationDefaults.AuthenticationScheme), null);
    }

    private static string? NameFrom(AuthProviderConfig provider, string name)
    {
        name = name.Trim();
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

/// <summary>OpenID Connect accounts have no password this server can check; their WebDAV clients use app passwords.</summary>
public sealed class OidcCredentialProvider : ICredentialProvider
{
    public ProviderType Type => ProviderType.OpenIdConnect;
    public bool IsSupported => true;

    public Task<ProviderResult> AuthenticateAsync(AuthProviderConfig config, string login, string password, CancellationToken ct) =>
        Task.FromResult(ProviderResult.Invalid);
}

/// <summary>The admin "test" button for OpenID Connect: reads the discovery document and checks that it fits.</summary>
public static class OidcDiscovery
{
    public static async Task<(bool Ok, string Message)> CheckAsync(AuthProviderConfig p, CancellationToken ct)
    {
        if (!Uri.TryCreate(p.Authority.Trim(), UriKind.Absolute, out var authority) || authority.Scheme is not ("https" or "http"))
            return (false, "Enter the issuer's URL first.");
        if (authority.Scheme == "http" && !authority.IsLoopback) return (false, "The issuer must use https.");
        using var handler = new HttpClientHandler();
        if (p.AllowInvalidCertificates) handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        var url = authority.AbsoluteUri.TrimEnd('/') + "/.well-known/openid-configuration";
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(await http.GetStringAsync(url, ct));
            string? Get(string name) => doc.RootElement.TryGetProperty(name, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : null;
            var issuer = Get("issuer");
            if (issuer == null || Get("authorization_endpoint") == null || Get("token_endpoint") == null || Get("jwks_uri") == null)
                return (false, $"{url} is not a complete OpenID Connect discovery document.");
            if (!string.Equals(issuer.TrimEnd('/'), authority.AbsoluteUri.TrimEnd('/'), StringComparison.Ordinal))
                return (false, $"The provider calls itself \"{issuer}\"; use exactly that as the issuer, or sign-ins will be rejected.");
            var codeFlow = doc.RootElement.TryGetProperty("response_types_supported", out var types) && types.ValueKind == System.Text.Json.JsonValueKind.Array &&
                           types.EnumerateArray().Any(t => t.GetString() == "code");
            return codeFlow
                ? (true, $"Found {issuer}. Sign-in will use {Get("authorization_endpoint")}.")
                : (false, "The provider does not offer the authorization code flow.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            return (false, $"Could not read {url}: {ex.Message}");
        }
    }
}
