// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Text.RegularExpressions;
using Nullify.WebDav.Dav;
using static Nullify.WebDav.Tests.TestHost;

namespace Nullify.WebDav.Tests;

/// <summary>Byte ranges on GET (RFC 2616 14.35, 19.2) and partial PUT with Content-Range (RFC 2616 9.6, 14.16).</summary>
[TestClass]
public sealed class RangeTests
{
    private const string Content = "0123456789abcdefghijklmnopqrstuvwxyz"; // 36 bytes

    private static async Task<(HttpClient Client, string Url)> FileAsync(string content = Content)
    {
        var c = await ClientAsync("alice", "alice-password");
        var url = $"/dav/home/range-{Guid.NewGuid():N}.txt";
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(c, "PUT", url, content)).Status);
        return (c, url);
    }

    private static string Disk(string url) => File.ReadAllText(Path.Combine(FilesDir, "home", "alice", url[(url.LastIndexOf('/') + 1)..]));

    // ------------------------------------------------------------------ GET

    [TestMethod]
    public async Task SingleRangesSuffixesAndOpenEnds()
    {
        var (c, url) = await FileAsync();
        foreach (var (range, expected, contentRange) in new[]
        {
            ("bytes=0-3", "0123", "bytes 0-3/36"),
            ("bytes=30-", "uvwxyz", "bytes 30-35/36"),
            ("bytes=-4", "wxyz", "bytes 32-35/36"),
            ("bytes=34-1000", "yz", "bytes 34-35/36"),
            ("bytes=-1000", Content, "bytes 0-35/36"),
            ("BYTES = 1-2", "12", "bytes 1-2/36"),
        })
        {
            var (status, body, resp) = await SendAsync(c, "GET", url, null, ("Range", range));
            Assert.AreEqual(HttpStatusCode.PartialContent, status, range);
            Assert.AreEqual(expected, body, range);
            Assert.AreEqual(contentRange, resp.Content.Headers.ContentRange!.ToString(), range);
            Assert.AreEqual(expected.Length, resp.Content.Headers.ContentLength, range);
        }
    }

    [TestMethod]
    public async Task SeveralRangesAreSentAsMultipartByteranges()
    {
        var (c, url) = await FileAsync();
        var (status, body, resp) = await SendAsync(c, "GET", url, null, ("Range", "bytes=30-31, 0-1,-2"));
        Assert.AreEqual(HttpStatusCode.PartialContent, status);
        var type = resp.Content.Headers.ContentType!;
        Assert.AreEqual("multipart/byteranges", type.MediaType);
        var boundary = type.Parameters.Single(p => p.Name == "boundary").Value!;
        Assert.AreEqual(body.Length, resp.Content.Headers.ContentLength, "Content-Length is exact");
        Assert.IsNull(resp.Content.Headers.ContentRange, "the parts carry the ranges");

        // In file order, each part with its own headers.
        var parts = body.Split("--" + boundary);
        Assert.AreEqual("--\r\n", parts[^1], "closing delimiter");
        var bodies = parts[1..^1].Select(p =>
        {
            var m = Regex.Match(p, "^\r\nContent-Type: text/plain\r\nContent-Range: (bytes [0-9-]+/36)\r\n\r\n(.*)\r\n$", RegexOptions.Singleline);
            Assert.IsTrue(m.Success, p);
            return (Range: m.Groups[1].Value, Data: m.Groups[2].Value);
        }).ToList();
        CollectionAssert.AreEqual(new[] { "bytes 0-1/36", "bytes 30-31/36", "bytes 34-35/36" }, bodies.Select(b => b.Range).ToList());
        CollectionAssert.AreEqual(new[] { "01", "uv", "yz" }, bodies.Select(b => b.Data).ToList());

        // HEAD describes the same response without the body.
        var head = new HttpRequestMessage(HttpMethod.Head, url);
        head.Headers.TryAddWithoutValidation("Range", "bytes=30-31, 0-1,-2");
        var h = await c.SendAsync(head);
        Assert.AreEqual(HttpStatusCode.PartialContent, h.StatusCode);
        Assert.AreEqual("multipart/byteranges", h.Content.Headers.ContentType!.MediaType);
        Assert.AreEqual(body.Length, h.Content.Headers.ContentLength);
    }

    [TestMethod]
    public async Task OverlappingAndUnsatisfiableRanges()
    {
        var (c, url) = await FileAsync();
        // Overlapping and adjacent ranges are merged into one: no byte is sent twice.
        var (status, body, resp) = await SendAsync(c, "GET", url, null, ("Range", "bytes=0-4,3-9,10-11"));
        Assert.AreEqual(HttpStatusCode.PartialContent, status);
        Assert.AreEqual("0123456789ab", body);
        Assert.AreEqual("bytes 0-11/36", resp.Content.Headers.ContentRange!.ToString());

        // Ranges beyond the end are dropped while others remain...
        (status, body, _) = await SendAsync(c, "GET", url, null, ("Range", "bytes=1000-,5-6"));
        Assert.AreEqual(HttpStatusCode.PartialContent, status);
        Assert.AreEqual("56", body);

        // ...and when none remains the request is unsatisfiable, with the length for the client.
        foreach (var range in new[] { "bytes=36-", "bytes=1000-2000,40-", "bytes=-0", "bytes=99999999999999999999-" })
        {
            (status, _, resp) = await SendAsync(c, "GET", url, null, ("Range", range));
            Assert.AreEqual(HttpStatusCode.RequestedRangeNotSatisfiable, status, range);
            Assert.AreEqual("bytes */36", resp.Content.Headers.ContentRange!.ToString(), range);
        }
    }

    [TestMethod]
    public async Task InvalidOrUnwantedRangeHeadersAreIgnored()
    {
        var (c, url) = await FileAsync();
        var many = "bytes=" + string.Join(',', Enumerable.Range(0, ByteRanges.MaxRanges + 1).Select(i => $"{i % 36}-{i % 36}"));
        foreach (var range in new[] { "bytes=5-2", "bytes=abc", "bytes=1-2,x", "items=0-1", "bytes=", "bytes 0-1", many })
        {
            var (status, body, _) = await SendAsync(c, "GET", url, null, ("Range", range));
            Assert.AreEqual(HttpStatusCode.OK, status, range);
            Assert.AreEqual(Content, body, range);
        }

        // If-Range: a stale validator gets the whole file.
        var (_, _, first) = await SendAsync(c, "GET", url);
        var etag = first.Headers.ETag!.ToString();
        var (s1, _, _) = await SendAsync(c, "GET", url, null, ("Range", "bytes=0-1"), ("If-Range", etag));
        Assert.AreEqual(HttpStatusCode.PartialContent, s1);
        var (s2, b2, _) = await SendAsync(c, "GET", url, null, ("Range", "bytes=0-1"), ("If-Range", "\"stale\""));
        Assert.AreEqual(HttpStatusCode.OK, s2);
        Assert.AreEqual(Content, b2);
    }

    [TestMethod]
    public async Task EmptyFilesHaveNoSatisfiableRange()
    {
        var (c, url) = await FileAsync("");
        var (status, _, resp) = await SendAsync(c, "GET", url, null, ("Range", "bytes=0-"));
        Assert.AreEqual(HttpStatusCode.RequestedRangeNotSatisfiable, status);
        Assert.AreEqual("bytes */0", resp.Content.Headers.ContentRange!.ToString());
    }

    // ------------------------------------------------------------------ PUT

    [TestMethod]
    public async Task PartialPutBuildsAndResumesAnUpload()
    {
        var c = await ClientAsync("alice", "alice-password");
        var url = $"/dav/home/upload-{Guid.NewGuid():N}.bin";
        var (status, _, resp) = await SendAsync(c, "PUT", url, "01234", ("Content-Range", "bytes 0-4/10"));
        Assert.AreEqual(HttpStatusCode.Created, status);
        Assert.IsNotNull(resp.Headers.ETag);
        Assert.AreEqual("01234", Disk(url));

        // Resuming beyond what is there is refused, telling the client how much arrived.
        (status, _, resp) = await SendAsync(c, "PUT", url, "789", ("Content-Range", "bytes 7-9/10"));
        Assert.AreEqual(HttpStatusCode.RequestedRangeNotSatisfiable, status);
        Assert.AreEqual("bytes */5", resp.Content.Headers.ContentRange!.ToString());

        (status, _, _) = await SendAsync(c, "PUT", url, "56789", ("Content-Range", "bytes 5-9/10"));
        Assert.AreEqual(HttpStatusCode.NoContent, status);
        Assert.AreEqual("0123456789", Disk(url));
        var (_, body, _) = await SendAsync(c, "GET", url);
        Assert.AreEqual("0123456789", body);
    }

    [TestMethod]
    public async Task PartialPutPatchesInPlaceAndTruncatesToTheCompleteLength()
    {
        var (c, url) = await FileAsync();
        var (_, _, before) = await SendAsync(c, "GET", url);
        var etag = before.Headers.ETag!.ToString();

        var (status, _, _) = await SendAsync(c, "PUT", url, "AB", ("Content-Range", "bytes 2-3/*"), ("If-Match", etag));
        Assert.AreEqual(HttpStatusCode.NoContent, status);
        Assert.AreEqual("01AB456789abcdefghijklmnopqrstuvwxyz", Disk(url));

        // The old ETag no longer matches: a concurrent writer is detected.
        (status, _, _) = await SendAsync(c, "PUT", url, "CD", ("Content-Range", "bytes 2-3/*"), ("If-Match", etag));
        Assert.AreEqual(HttpStatusCode.PreconditionFailed, status);
        Assert.AreEqual("01AB456789abcdefghijklmnopqrstuvwxyz", Disk(url));

        // Writing past the end grows the file; a complete length shorter than the file cuts it down.
        (status, _, _) = await SendAsync(c, "PUT", url, "!!", ("Content-Range", "bytes 36-37/*"));
        Assert.AreEqual(HttpStatusCode.NoContent, status);
        Assert.AreEqual(38, Disk(url).Length);
        (status, _, _) = await SendAsync(c, "PUT", url, "xy", ("Content-Range", "bytes 0-1/4"));
        Assert.AreEqual(HttpStatusCode.NoContent, status);
        Assert.AreEqual("xyAB", Disk(url));
    }

    [TestMethod]
    public async Task MalformedPartialPutsChangeNothing()
    {
        var (c, url) = await FileAsync();
        foreach (var (range, body) in new[]
        {
            ("bytes 0-4/*", "01"),       // body shorter than the range
            ("bytes 0-1/*", "01234"),    // body longer than the range
            ("bytes 5-2/*", "0123"),     // last before first
            ("bytes 0-9/5", "0123456789"), // complete length too small
            ("bytes */36", "x"),         // no range at all
            ("items 0-0/*", "x"),
            ("bytes 0-0", "x"),
        })
        {
            var (status, _, _) = await SendAsync(c, "PUT", url, body, ("Content-Range", range));
            Assert.AreEqual(HttpStatusCode.BadRequest, status, range);
            Assert.AreEqual(Content, Disk(url), range);
        }

        // Partial writes need write access like any other.
        var bob = await ClientAsync("bob", "bob-password");
        var (s, _, _) = await SendAsync(bob, "PUT", $"/dav/shared/partial-{Guid.NewGuid():N}.txt", "x", ("Content-Range", "bytes 0-0/*"));
        Assert.AreEqual(HttpStatusCode.Forbidden, s);
    }
}
