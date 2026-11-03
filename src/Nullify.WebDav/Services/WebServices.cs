// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Services;

/// <summary>Serves the embedded stylesheet and icon, so the server is a single file with no wwwroot folder.</summary>
public static class StaticAssets
{
    private sealed record Asset(byte[] Content, string ContentType, string ETag);

    private static readonly ConcurrentDictionary<string, Asset?> Cache = new(StringComparer.OrdinalIgnoreCase);

    private static Asset? Load(string path) => Cache.GetOrAdd(path, p =>
    {
        var assembly = typeof(StaticAssets).Assembly;
        var name = assembly.GetManifestResourceNames().FirstOrDefault(n => n.Replace('\\', '/').Equals("wwwroot" + p, StringComparison.OrdinalIgnoreCase));
        if (name == null) return null;
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        var bytes = ms.ToArray();
        var type = p.EndsWith(".css", StringComparison.Ordinal) ? "text/css; charset=utf-8" : p.EndsWith(".svg", StringComparison.Ordinal) ? "image/svg+xml" : "application/octet-stream";
        return new Asset(bytes, type, "\"" + Convert.ToHexString(SHA256.HashData(bytes))[..16] + "\"");
    });

    /// <summary>URL with a content hash, so browsers can cache it indefinitely.</summary>
    public static string Url(string path) => Load(path) is { } a ? $"{path}?v={a.ETag.Trim('"')}" : path;

    public static void MapStaticAssets(this WebApplication app)
    {
        foreach (var path in new[] { "/css/site.css", "/favicon.svg" })
        {
            app.MapMethods(path, ["GET", "HEAD"], (HttpContext ctx) =>
            {
                var asset = Load(path);
                if (asset == null) return Results.NotFound();
                ctx.Response.Headers.ETag = asset.ETag;
                ctx.Response.Headers.CacheControl = ctx.Request.Query.ContainsKey("v") ? "public, max-age=31536000, immutable" : "public, max-age=3600";
                if (ctx.Request.Headers.IfNoneMatch == asset.ETag) return Results.StatusCode(StatusCodes.Status304NotModified);
                return Results.Bytes(asset.Content, asset.ContentType);
            }).AllowAnonymous();
        }
    }
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
            if (!path.StartsWithSegments("/setup") && !path.StartsWithSegments("/css") &&
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
