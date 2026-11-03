// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Net;
using System.Text;
using Nullify.WebDav.Services;

namespace Nullify.WebDav.Dav;

public sealed partial class DavHandler
{
    /// <summary>Read-only HTML view of a folder for browsers, styled like the management UI.</summary>
    private async Task WriteListingAsync(DavTarget t, bool head)
    {
        var rows = new List<(string Href, string Name, bool Dir, long? Size, DateTime? Modified)>();
        string title;
        if (t.IsRoot)
        {
            title = "All folders";
            rows.AddRange(_mounts.MountsFor(_user).Select(m => (HrefFor(m.Mount.Name, [], true), m.Mount.Name, true, (long?)null, (DateTime?)null)));
        }
        else
        {
            var dir = new DirectoryInfo(t.Physical);
            title = t.Segments.Length == 0 ? t.Mount!.Mount.Name : t.Segments[^1];
            var selfHref = Href(t, true);
            foreach (var entry in Children(dir, t.Mount!.Storage).OrderBy(e => e is FileInfo).ThenBy(e => e.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                var isDir = entry is DirectoryInfo;
                rows.Add((ChildHref(selfHref, entry.Name, isDir), entry.Name, isDir, (entry as FileInfo)?.Length, entry.LastWriteTimeUtc));
            }
        }

        var pathBase = Request.PathBase.Value ?? "";
        var appBase = pathBase.EndsWith("/dav", StringComparison.OrdinalIgnoreCase) ? pathBase[..^4] : pathBase;
        static string E(string s) => WebUtility.HtmlEncode(s);

        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
          .Append("<meta name=\"color-scheme\" content=\"light dark\"><title>").Append(E(title)).Append(" · Nullify.WebDav</title>")
          .Append("<link rel=\"icon\" href=\"").Append(E(appBase + StaticAssets.Url("/favicon.svg"))).Append("\" type=\"image/svg+xml\">")
          .Append("<link rel=\"stylesheet\" href=\"").Append(E(appBase + StaticAssets.Url("/css/site.css"))).Append("\"></head><body>")
          .Append("<header class=\"topbar\"><a class=\"brand\" href=\"").Append(E(appBase + "/")).Append("\">").Append(BrandIcon)
          .Append("<span>Nullify<b>.WebDav</b></span></a></header><main class=\"container\">");

        // Breadcrumb
        sb.Append("<div class=\"page-head\"><div><h1>").Append(E(title)).Append("</h1><p class=\"crumbs\"><a href=\"").Append(E(_base + "/")).Append("\">dav</a>");
        if (!t.IsRoot)
        {
            var parts = new List<string>();
            sb.Append(" / <a href=\"").Append(E(HrefFor(t.MountSegment, [], true))).Append("\">").Append(E(t.MountSegment)).Append("</a>");
            foreach (var s in t.Segments)
            {
                parts.Add(s);
                sb.Append(" / <a href=\"").Append(E(HrefFor(t.MountSegment, parts, true))).Append("\">").Append(E(s)).Append("</a>");
            }
        }
        sb.Append("</p></div>");
        if (t.Mount != null) sb.Append("<span class=\"badge").Append(t.Mount.CanWrite ? " accent\">read &amp; write" : "\">read only").Append("</span>");
        sb.Append("</div><div class=\"card\">");

        if (rows.Count == 0) sb.Append("<p class=\"empty\">This folder is empty.</p>");
        else
        {
            sb.Append("<table class=\"files\"><thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead><tbody>");
            foreach (var r in rows)
            {
                sb.Append("<tr><td><a href=\"").Append(E(r.Href)).Append("\">").Append(r.Dir ? FolderIcon : FileIcon).Append(E(r.Name)).Append(r.Dir ? "/" : "").Append("</a></td>")
                  .Append("<td class=\"muted\">").Append(r.Size is { } size ? E(FormatSize(size)) : "").Append("</td>")
                  .Append("<td class=\"muted\">").Append(r.Modified is { } m ? E(m.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture)) : "").Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }
        sb.Append("</div><p class=\"muted small\">Browse-only view. Connect a WebDAV client to <code>")
          .Append(E($"{Request.Scheme}://{Request.Host}{Href(t, true)}")).Append("</code> to upload and edit.</p></main></body></html>");

        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        Response.StatusCode = StatusCodes.Status200OK;
        Response.ContentType = "text/html; charset=utf-8";
        Response.ContentLength = bytes.Length;
        Response.Headers.CacheControl = "private, no-cache";
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
        return unit == 0 ? $"{bytes} B" : value.ToString(value < 10 ? "0.0" : "0", CultureInfo.InvariantCulture) + " " + units[unit];
    }

    public const string BrandIcon = "<svg viewBox=\"0 0 24 24\" width=\"22\" height=\"22\" aria-hidden=\"true\"><path d=\"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linejoin=\"round\"/><path d=\"M9 14l3-3 3 3M12 11v6\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>";

    private const string FolderIcon = "<svg class=\"ficon\" viewBox=\"0 0 24 24\" width=\"16\" height=\"16\" aria-hidden=\"true\"><path d=\"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z\" fill=\"currentColor\" opacity=\".85\"/></svg>";

    private const string FileIcon = "<svg class=\"ficon\" viewBox=\"0 0 24 24\" width=\"16\" height=\"16\" aria-hidden=\"true\"><path d=\"M6 3h8l4 4v14H6z\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linejoin=\"round\"/><path d=\"M14 3v4h4\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linejoin=\"round\"/></svg>";
}
