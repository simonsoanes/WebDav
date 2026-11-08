// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Dav;
using Nullify.WebDav.Shared;
using Nullify.WebDav.Storage;

namespace Nullify.WebDav.Services;

/// <summary>
/// The small JSON API behind the browser file manager. Files themselves go through the WebDAV endpoint; this covers
/// what WebDAV has no words for: who is signed in, which folders they have, and sharing.
/// </summary>
public static class FileApi
{
    public static void MapFileApi(this WebApplication app)
    {
        var api = app.MapGroup("/api").RequireAuthorization();
        // Every API request must come from the file manager itself (see ApiHeaders); GETs included, so other
        // sites cannot read the JSON either.
        api.AddEndpointFilter(async (ctx, next) =>
            DavHandler.IsFileManagerRequest(ctx.HttpContext.Request) ? await next(ctx) : Results.StatusCode(StatusCodes.Status403Forbidden));
        api.AddEndpointFilter(async (ctx, next) =>
        {
            ctx.HttpContext.Response.Headers.CacheControl = "no-store";
            try { return await next(ctx); }
            catch (ShareService.ShareException ex) { return Results.Json(new ApiError(ex.Message), ApiJson.Default.ApiError, statusCode: 400); }
        });

        api.MapGet("/session", (HttpContext http, MountResolver mounts, ShareService shares, ConfigStore store) =>
        {
            var me = Me(http);
            var c = store.Current;
            var defaultMount = mounts.DefaultMountName(me);
            var pathBase = http.Request.PathBase.Value ?? "";
            var davUrl = $"{http.Request.Scheme}://{http.Request.Host}{pathBase}/dav/";
            var list = mounts.MountsFor(me).Select(m => new MountInfo(
                m.Mount.Name, m.Mount.Description, m.CanWrite, Names.Eq(m.Mount.Name, defaultMount), shares.CanShareFrom(m),
                m.Storage.Impersonate ? "This folder is accessed as your Windows account. Open it with a WebDAV client (see Connect)." : null)).ToList();
            var shared = mounts.SharesFor(me).Select(m =>
            {
                var owner = c.Users.FirstOrDefault(u => Names.Eq(u.Username, m.Share!.Owner));
                return new SharedFolderInfo(m.Name, m.Share!.Name, m.Share.Owner, owner == null ? m.Share.Owner : MountResolver.Display(owner), m.CanWrite);
            }).ToList();
            var maxUpload = c.Settings.MaxUploadMegabytes > 0 ? c.Settings.MaxUploadMegabytes * 1024 * 1024 : 0;
            return Results.Json(new SessionInfo(me.Username, me.DisplayName, me.IsAdmin, defaultMount, shares.Enabled, maxUpload, davUrl, list, shared),
                ApiJson.Default.SessionInfo);
        });

        api.MapGet("/shares", (HttpContext http, ShareService shares) =>
            Results.Json(shares.Owned(Me(http)).ToList(), ApiJson.Default.ListShareInfo));

        api.MapPost("/shares", async (HttpContext http, ShareService shares) =>
        {
            var request = await http.Request.ReadFromJsonAsync(ApiJson.Default.ShareRequest) ?? throw new ShareService.ShareException("Missing request.");
            return Results.Json(await shares.CreateAsync(Me(http), request), ApiJson.Default.ShareInfo, statusCode: StatusCodes.Status201Created);
        });

        api.MapPut("/shares/{id}", async (string id, HttpContext http, ShareService shares) =>
        {
            var request = await http.Request.ReadFromJsonAsync(ApiJson.Default.ShareRequest) ?? throw new ShareService.ShareException("Missing request.");
            return Results.Json(await shares.UpdateAsync(Me(http), id, request), ApiJson.Default.ShareInfo);
        });

        api.MapDelete("/shares/{id}", async (string id, HttpContext http, ShareService shares) =>
            await shares.DeleteAsync(Me(http), id) ? Results.NoContent() : Results.NotFound());

        api.MapGet("/people", (HttpContext http, ShareService shares) =>
            shares.Enabled ? Results.Json(shares.People(Me(http)), ApiJson.Default.PeopleDirectory) : Results.NotFound());

        api.MapPost("/logout", async (HttpContext http) =>
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.NoContent();
        });
    }

    private static DavPrincipal Me(HttpContext http) =>
        DavPrincipal.FromClaims(http.User) ?? throw new InvalidOperationException("Not signed in");
}
