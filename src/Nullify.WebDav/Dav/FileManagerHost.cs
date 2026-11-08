// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Text;
using Nullify.WebDav.Services;

namespace Nullify.WebDav.Dav;

public sealed partial class DavHandler
{
    /// <summary>Content security policy for the file manager page: WebAssembly needs 'wasm-unsafe-eval', nothing else is relaxed.</summary>
    public const string FileManagerPolicy =
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
        "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'";

    /// <summary>
    /// A browser opening a folder gets the Blazor WebAssembly file manager. It runs at the folder's own URL, so links
    /// can be shared and bookmarked, and it reads and writes through these same WebDAV URLs.
    /// </summary>
    private async Task WriteFileManagerAsync(bool head)
    {
        if (!_viaCookie)
        {
            // Basic credentials (a WebDAV client, or a browser's password prompt): the file manager needs a browser session.
            var appBase = AppBase(Request.PathBase.Value);
            Response.Redirect(appBase + "/account/login?ReturnUrl=" + Uri.EscapeDataString((Request.PathBase + Request.Path).ToUriComponent()));
            return;
        }
        var html = FileManagerPage(AppBase(Request.PathBase.Value));
        Response.StatusCode = StatusCodes.Status200OK;
        Response.ContentType = "text/html; charset=utf-8";
        Response.Headers.ContentSecurityPolicy = FileManagerPolicy;
        Response.Headers.CacheControl = "no-store";
        var bytes = Encoding.UTF8.GetBytes(html);
        Response.ContentLength = bytes.Length;
        if (!head) await Response.Body.WriteAsync(bytes, Ct);
    }

    public static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? $"{bytes} B" : value.ToString(value < 10 ? "0.#" : "0", System.Globalization.CultureInfo.InvariantCulture) + " " + units[unit];
    }

    public static string FileManagerPage(string appBase)
    {
        static string E(string s) => WebUtility.HtmlEncode(s);
        var b = E(appBase + "/");
        return $"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
                <meta name="color-scheme" content="light dark" />
                <title>Files · Nullify.WebDav</title>
                <base href="{b}" />
                <script src="{E(StaticAssets.Url("js/theme.js"))}"></script>
                <link rel="stylesheet" href="{E(StaticAssets.Url("css/app.css"))}" />
                <link rel="icon" type="image/svg+xml" href="{E(StaticAssets.Url("favicon.svg"))}" />
            </head>
            <body>
                <div id="app"><div class="boot"><span class="spinner"></span> Loading your files…</div></div>
                <div id="blazor-error-ui">Something went wrong. <a href="" class="reload">Reload</a></div>
                <noscript><div class="boot">The file manager needs JavaScript and WebAssembly. Your folders remain reachable with any WebDAV client.</div></noscript>
                <script src="{E(StaticAssets.Url("js/files.js"))}"></script>
                <script src="_framework/blazor.webassembly.js"></script>
            </body>
            </html>
            """;
    }
}
