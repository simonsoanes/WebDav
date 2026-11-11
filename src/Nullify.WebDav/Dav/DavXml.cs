// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.WebUtilities;

namespace Nullify.WebDav.Dav;

public static class Ns
{
    public static readonly XNamespace D = "DAV:";
    /// <summary>Properties the Windows WebDAV redirector reads and writes.</summary>
    public static readonly XNamespace MS = "urn:schemas-microsoft-com:";

    public static XAttribute[] Declarations() =>
    [
        new(XNamespace.Xmlns + "d", D.NamespaceName),
    ];
}

/// <summary>Raised to abort a DAV request with a status code and optional precondition element.</summary>
public sealed class DavException(int status, XName? precondition = null, string? message = null, XElement? detail = null)
    : Exception(message ?? $"HTTP {status}")
{
    public int Status { get; } = status;
    public XName? Precondition { get; } = precondition;
    public XElement? Detail { get; } = detail;

    /// <summary>"bytes */length" on a 416, which the error response keeps (RFC 2616 14.16).</summary>
    public string? ContentRange { get; init; }
}

public static class DavXml
{
    private const int MaxBodyBytes = 1 << 20;

    private static readonly XmlReaderSettings ReaderSettings = new()
    {
        Async = true,
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        MaxCharactersInDocument = MaxBodyBytes,
    };

    /// <summary>Reads the request body as XML. Returns null for an empty body.</summary>
    public static async Task<XDocument?> ReadBodyAsync(HttpRequest request, CancellationToken ct)
    {
        if (request.ContentLength > MaxBodyBytes) throw new DavException(StatusCodes.Status413PayloadTooLarge);
        using var ms = new MemoryStream();
        var buffer = new byte[16384];
        int read;
        while ((read = await request.Body.ReadAsync(buffer, ct)) > 0)
        {
            if (ms.Length + read > MaxBodyBytes) throw new DavException(StatusCodes.Status413PayloadTooLarge);
            ms.Write(buffer, 0, read);
        }
        if (ms.Length == 0 || ms.ToArray().All(b => b is (byte)' ' or (byte)'\r' or (byte)'\n' or (byte)'\t')) return null;
        ms.Position = 0;
        try
        {
            using var reader = XmlReader.Create(ms, ReaderSettings);
            return await XDocument.LoadAsync(reader, LoadOptions.None, ct);
        }
        catch (XmlException ex)
        {
            throw new DavException(StatusCodes.Status400BadRequest, message: "Malformed XML: " + ex.Message);
        }
    }

    public static string StatusLine(int code) => $"HTTP/1.1 {code} {ReasonPhrases.GetReasonPhrase(code)}";

    public static XElement Href(string href) => new(Ns.D + "href", href);

    public static async Task WriteAsync(HttpResponse response, int status, XElement root, CancellationToken ct)
    {
        foreach (var a in Ns.Declarations())
            if (root.Attribute(a.Name) == null) root.Add(a);
        response.StatusCode = status;
        response.ContentType = "application/xml; charset=utf-8";
        var settings = new XmlWriterSettings { Encoding = new UTF8Encoding(false), Async = true, Indent = false };
        using var ms = new MemoryStream();
        await using (var writer = XmlWriter.Create(ms, settings))
        {
            new XDocument(new XDeclaration("1.0", "utf-8", null), root).Save(writer);
        }
        response.ContentLength = ms.Length;
        ms.Position = 0;
        await ms.CopyToAsync(response.Body, ct);
    }

    public static XElement Error(XName precondition, XElement? detail = null)
    {
        var el = new XElement(precondition);
        if (detail != null) el.Add(detail);
        return new XElement(Ns.D + "error", el);
    }
}

/// <summary>Accumulates DAV:response elements for a 207 Multi-Status reply.</summary>
public sealed class MultiStatus
{
    private readonly List<XElement> _responses = [];

    public int Count => _responses.Count;

    public void AddPropStat(string href, IEnumerable<(XElement Prop, int Status)> props)
    {
        var resp = new XElement(Ns.D + "response", DavXml.Href(href));
        foreach (var group in props.GroupBy(p => p.Status).OrderBy(g => g.Key))
        {
            resp.Add(new XElement(Ns.D + "propstat",
                new XElement(Ns.D + "prop", group.Select(g => g.Prop)),
                new XElement(Ns.D + "status", DavXml.StatusLine(group.Key))));
        }
        if (!resp.Elements(Ns.D + "propstat").Any())
        {
            resp.Add(new XElement(Ns.D + "propstat", new XElement(Ns.D + "prop"),
                new XElement(Ns.D + "status", DavXml.StatusLine(200))));
        }
        _responses.Add(resp);
    }

    public void AddStatus(string href, int status, XElement? error = null)
    {
        var resp = new XElement(Ns.D + "response", DavXml.Href(href), new XElement(Ns.D + "status", DavXml.StatusLine(status)));
        if (error != null) resp.Add(error);
        _responses.Add(resp);
    }

    public XElement ToXml() => new(Ns.D + "multistatus", _responses);
}
