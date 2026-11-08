// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Services;

/// <summary>Cache-busting URLs for the static files (served by MapStaticAssets from the file manager's wwwroot).</summary>
public static class StaticAssets
{
    /// <summary>Changes with every build, so browsers fetch matching scripts and styles after an update.</summary>
    public static readonly string Version = typeof(StaticAssets).Assembly.ManifestModule.ModuleVersionId.ToString("N")[..12];

    public static string Url(string path) => $"{path}?v={Version}";
}

/// <summary>Redirects everything to the first-run setup page until an administrator can sign in.</summary>
public sealed class SetupGateMiddleware(RequestDelegate next)
{
    public static bool IsComplete(ServerConfig c) =>
        c.Users.Any(u => u is { IsAdmin: true, Enabled: true }) || c.AuthProviders.Any(p => p.Enabled && p.AdminGroups.Count > 0);

    public async Task InvokeAsync(HttpContext ctx, ConfigStore config)
    {
        if (!IsComplete(config.Current))
        {
            var path = ctx.Request.Path;
            if (!path.StartsWithSegments("/setup") && !path.StartsWithSegments("/css") && !path.StartsWithSegments("/js") &&
                !path.StartsWithSegments("/health") && !path.StartsWithSegments("/favicon.svg"))
            {
                if (path.StartsWithSegments("/dav") || !HttpMethods.IsGet(ctx.Request.Method))
                {
                    ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                    await ctx.Response.WriteAsync("Server setup has not been completed.");
                    return;
                }
                ctx.Response.Redirect(ctx.Request.PathBase + "/setup");
                return;
            }
        }
        await next(ctx);
    }
}

public static class CookieValidation
{
    /// <summary>Signs out browser sessions of users that were removed, disabled or had their credentials changed.</summary>
    public static async Task ValidateAsync(CookieValidatePrincipalContext ctx)
    {
        var principal = ctx.Principal == null ? null : DavPrincipal.FromClaims(ctx.Principal);
        var config = ctx.HttpContext.RequestServices.GetRequiredService<ConfigStore>().Current;
        if (principal == null || !StillValid(config, principal))
        {
            ctx.RejectPrincipal();
            await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return;
        }
        if (principal.Listed)
        {
            // Refresh name and roles from the configuration.
            var user = config.Users.First(u => Names.Eq(u.Username, principal.Username));
            var provider = config.AuthProviders.FirstOrDefault(p => Names.Eq(p.Name, user.Provider));
            var groups = new HashSet<string>(principal.Groups, StringComparer.OrdinalIgnoreCase);
            groups.UnionWith(user.Groups);
            var isAdmin = user.IsAdmin || provider?.AdminGroups.Any(groups.Contains) == true;
            var displayName = string.IsNullOrEmpty(user.DisplayName) ? user.Username : user.DisplayName;
            if (isAdmin != principal.IsAdmin || displayName != principal.DisplayName)
            {
                var refreshed = new DavPrincipal
                {
                    Username = user.Username,
                    DisplayName = displayName,
                    Provider = user.Provider,
                    Listed = true,
                    IsAdmin = isAdmin,
                    Groups = groups,
                    SecurityStamp = user.SecurityStamp,
                };
                ctx.ReplacePrincipal(refreshed.ToClaimsPrincipal(CookieAuthenticationDefaults.AuthenticationScheme));
                ctx.ShouldRenew = true;
            }
        }
    }

    private static bool StillValid(ServerConfig c, DavPrincipal p)
    {
        if (p.Listed)
        {
            var user = c.Users.FirstOrDefault(u => Names.Eq(u.Username, p.Username));
            return user is { Enabled: true } && user.SecurityStamp == p.SecurityStamp && Names.Eq(user.Provider, p.Provider);
        }
        var provider = c.AuthProviders.FirstOrDefault(x => Names.Eq(x.Name, p.Provider));
        return provider is { Enabled: true, AcceptUnlisted: true } && CredentialValidator.FindUser(c, p.Username) == null;
    }
}
