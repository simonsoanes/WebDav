// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Xml.Linq;

namespace Nullify.WebDav.Client.Services;

public sealed record DavEntry(string Name, string Url, bool IsFolder, long? Size, DateTimeOffset? Modified, string? ETag, string? ContentType);

public sealed record DavFolder(string Url, List<DavEntry> Items, long? QuotaUsed, long? QuotaAvailable);

public sealed class DavException(HttpStatusCode status, string message) : Exception(message)
{
    public HttpStatusCode Status { get; } = status;
}

/// <summary>The file manager's WebDAV client. URLs are relative to the app base, e.g. "dav/home/Photos/".</summary>
public sealed class DavClient(HttpClient http)
{
    private static readonly XNamespace D = "DAV:";
    private static readonly HttpMethod Propfind = new("PROPFIND");
    private static readonly HttpMethod Mkcol = new("MKCOL");
    private static readonly HttpMethod Move = new("MOVE");
    private static readonly HttpMethod Copy = new("COPY");

    private const string PropfindBody = """
        <?xml version="1.0" encoding="utf-8"?>
        <D:propfind xmlns:D="DAV:"><D:prop>
          <D:resourcetype/><D:getcontentlength/><D:getlastmodified/><D:getetag/><D:getcontenttype/>
          <D:quota-used-bytes/><D:quota-available-bytes/>
        </D:prop></D:propfind>
        """;

    /// <summary>Raised when the browser session has ended; the app sends the user to the login page.</summary>
    public event Action? SignedOut;

    public async Task<DavFolder> ListAsync(string folderUrl, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(Propfind, folderUrl) { Content = new StringContent(PropfindBody, Encoding.UTF8, "application/xml") };
        request.Headers.Add("Depth", "1");
        using var response = await SendAsync(request, ct);
        var xml = XDocument.Parse(await response.Content.ReadAsStringAsync(ct));

        var self = Uri.UnescapeDataString(new Uri(http.BaseAddress!, folderUrl).AbsolutePath).TrimEnd('/');
        var items = new List<DavEntry>();
        long? used = null, available = null;
        foreach (var r in xml.Root!.Elements(D + "response"))
        {
            var href = r.Element(D + "href")?.Value;
            if (href == null) continue;
            // Only http(s) hrefs are absolute: on WebAssembly "/dav/x" would otherwise parse as a file:// URI.
            var raw = href.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || href.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? new Uri(href).AbsolutePath : href;
            var path = Uri.UnescapeDataString(raw);
            var props = r.Elements(D + "propstat")
                .Where(ps => (ps.Element(D + "status")?.Value ?? "").Contains(" 200"))
                .SelectMany(ps => ps.Element(D + "prop")?.Elements() ?? []).ToList();
            XElement? P(string n) => props.FirstOrDefault(p => p.Name == D + n);

            if (string.Equals(path.TrimEnd('/'), self, StringComparison.Ordinal))
            {
                used = Long(P("quota-used-bytes"));
                available = Long(P("quota-available-bytes"));
                continue;
            }
            var isFolder = P("resourcetype")?.Element(D + "collection") != null;
            var trimmed = path.TrimEnd('/');
            var name = trimmed[(trimmed.LastIndexOf('/') + 1)..];
            DateTimeOffset? modified = DateTimeOffset.TryParse(P("getlastmodified")?.Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var m) ? m : null;
            items.Add(new DavEntry(name, Child(folderUrl, name, isFolder), isFolder, isFolder ? null : Long(P("getcontentlength")),
                modified, P("getetag")?.Value, P("getcontenttype")?.Value));
        }
        return new DavFolder(folderUrl, items, used, available);
    }

    public async Task CreateFolderAsync(string url)
    {
        using var request = new HttpRequestMessage(Mkcol, url);
        using var _ = await SendAsync(request);
    }

    /// <summary>Creates a file; fails with 412 if something with that name exists.</summary>
    public async Task CreateFileAsync(string url, string content)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, url) { Content = new StringContent(content, new UTF8Encoding(false), "text/plain") };
        request.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Any);
        using var _ = await SendAsync(request);
    }

    public async Task<(string Text, string? ETag)> ReadTextAsync(string url)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await SendAsync(request);
        var bytes = await response.Content.ReadAsByteArrayAsync();
        return (new UTF8Encoding(false).GetString(bytes).TrimStart('﻿'), response.Headers.ETag?.ToString());
    }

    /// <summary>Saves text, failing with 412 when someone else changed the file since <paramref name="etag"/>. Returns the new ETag.</summary>
    public async Task<string?> SaveTextAsync(string url, string text, string? etag)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, url) { Content = new StringContent(text, new UTF8Encoding(false), "text/plain") };
        if (etag != null && EntityTagHeaderValue.TryParse(etag, out var tag)) request.Headers.IfMatch.Add(tag);
        using var response = await SendAsync(request);
        return response.Headers.ETag?.ToString();
    }

    public Task MoveAsync(string from, string to, bool overwrite) => Transfer(Move, from, to, overwrite);

    public Task CopyAsync(string from, string to, bool overwrite) => Transfer(Copy, from, to, overwrite);

    private async Task Transfer(HttpMethod method, string from, string to, bool overwrite)
    {
        using var request = new HttpRequestMessage(method, from);
        request.Headers.Add("Destination", new Uri(http.BaseAddress!, to).AbsoluteUri);
        request.Headers.Add("Overwrite", overwrite ? "T" : "F");
        using var _ = await SendAsync(request);
    }

    public async Task DeleteAsync(string url)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, url);
        using var response = await SendAsync(request);
        if (response.StatusCode == HttpStatusCode.MultiStatus)
            throw new DavException(HttpStatusCode.MultiStatus, "Some items could not be deleted (they may be locked or in use).");
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct = default)
    {
        var response = await http.SendAsync(request, ct);
        if (response.IsSuccessStatusCode) return response;
        using (response)
        {
            if (response.StatusCode == HttpStatusCode.Unauthorized) SignedOut?.Invoke();
            var detail = response.Content.Headers.ContentType?.MediaType == "text/plain" ? (await response.Content.ReadAsStringAsync(ct)).Trim() : "";
            throw new DavException(response.StatusCode, detail.Length is > 0 and < 400 ? detail : Describe(response.StatusCode));
        }
    }

    public static string Describe(HttpStatusCode status) => (int)status switch
    {
        401 => "Your session has ended. Please sign in again.",
        403 => "You do not have permission to do that here.",
        404 => "It no longer exists. It may have been moved or deleted.",
        405 => "Something with that name already exists.",
        409 => "The folder it belongs in no longer exists.",
        412 => "Something with that name already exists.",
        423 => "It is locked, probably because it is open somewhere else.",
        507 => "There is not enough free space.",
        _ => $"The server answered {(int)status} {status}.",
    };

    /// <summary>The URL of a child: names are escaped, folders end with '/'.</summary>
    public static string Child(string folderUrl, string name, bool isFolder) =>
        (folderUrl.EndsWith('/') ? folderUrl : folderUrl + "/") + Uri.EscapeDataString(name) + (isFolder ? "/" : "");

    private static long? Long(XElement? e) => long.TryParse(e?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
}
