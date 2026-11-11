// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text;

namespace Nullify.WebDav.Dav;

/// <summary>
/// Byte ranges (RFC 2616 section 14.35, with RFC 7233's clarifications): parsing a Range header against a file's
/// length, and the multipart/byteranges body (RFC 2616 section 19.2) for requests that ask for several ranges.
/// </summary>
public static class ByteRanges
{
    /// <summary>More ranges than this in one request is not a client fetching parts of a file: the whole file is sent.</summary>
    public const int MaxRanges = 64;

    public readonly record struct ByteRange(long Start, long Length)
    {
        public long End => Start + Length - 1;
    }

    /// <summary>The outcome of a Range header.</summary>
    /// <param name="Ignore">Send the whole file: no header, another unit, invalid syntax or too many ranges.</param>
    /// <param name="Ranges">The satisfiable ranges, merged and in file order; empty means 416.</param>
    public sealed record RangeSet(bool Ignore, IReadOnlyList<ByteRange> Ranges)
    {
        public static readonly RangeSet None = new(true, []);
        public bool Unsatisfiable => !Ignore && Ranges.Count == 0;
    }

    /// <summary>
    /// Parses "bytes=a-b, c-, -d". A syntactically invalid header is ignored as a whole (RFC 2616: "the recipient
    /// MUST ignore" it); ranges that start beyond the end are dropped, and if none is left the request is
    /// unsatisfiable. Overlapping and adjacent ranges are merged, so no byte is sent twice.
    /// </summary>
    public static RangeSet Parse(string? header, long size)
    {
        if (string.IsNullOrWhiteSpace(header)) return RangeSet.None;
        var eq = header.IndexOf('=');
        if (eq < 0 || !header[..eq].Trim().Equals("bytes", StringComparison.OrdinalIgnoreCase)) return RangeSet.None;

        var specs = header[(eq + 1)..].Split(',');
        var nonEmpty = specs.Select(s => s.Trim()).Where(s => s.Length > 0).ToList();
        if (nonEmpty.Count == 0) return RangeSet.None;
        if (nonEmpty.Count > MaxRanges) return RangeSet.None;

        var ranges = new List<ByteRange>();
        foreach (var spec in nonEmpty)
        {
            var dash = spec.IndexOf('-');
            if (dash < 0) return RangeSet.None;
            var first = spec[..dash].Trim();
            var last = spec[(dash + 1)..].Trim();
            if (first.Length == 0)
            {
                // suffix-byte-range-spec: the last N bytes.
                if (!TryNumber(last, out var suffix)) return RangeSet.None;
                if (suffix == 0 || size == 0) continue;
                suffix = Math.Min(suffix, size);
                ranges.Add(new ByteRange(size - suffix, suffix));
                continue;
            }
            if (!TryNumber(first, out var start)) return RangeSet.None;
            var end = size - 1;
            if (last.Length > 0)
            {
                if (!TryNumber(last, out end)) return RangeSet.None;
                if (end < start) return RangeSet.None; // invalid syntax: the whole header is ignored
                end = Math.Min(end, size - 1);
            }
            if (start >= size) continue; // unsatisfiable on its own
            ranges.Add(new ByteRange(start, end - start + 1));
        }
        return new RangeSet(false, Merge(ranges));
    }

    /// <summary>Digits only; numbers too large for a long are "beyond any file" rather than invalid.</summary>
    private static bool TryNumber(string s, out long value)
    {
        value = 0;
        if (s.Length == 0 || !s.All(char.IsAsciiDigit)) return false;
        value = long.TryParse(s, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : long.MaxValue;
        return true;
    }

    private static List<ByteRange> Merge(List<ByteRange> ranges)
    {
        var merged = new List<ByteRange>();
        foreach (var r in ranges.OrderBy(r => r.Start))
        {
            if (merged.Count > 0 && r.Start <= merged[^1].End + 1)
            {
                var last = merged[^1];
                var end = Math.Max(last.End, r.End);
                merged[^1] = new ByteRange(last.Start, end - last.Start + 1);
            }
            else merged.Add(r);
        }
        return merged;
    }

    /// <summary>The range a partial PUT writes; CompleteLength is the whole file's length when the client knows it.</summary>
    public readonly record struct PutRange(long Start, long End, long? CompleteLength)
    {
        public long Length => End - Start + 1;
    }

    /// <summary>Parses a PUT's "Content-Range: bytes first-last/length" (or "/*"); null when malformed or inconsistent.</summary>
    public static PutRange? ParseContentRange(string header)
    {
        header = header.Trim();
        var space = header.IndexOf(' ');
        if (space < 0 || !header[..space].Equals("bytes", StringComparison.OrdinalIgnoreCase)) return null;
        var spec = header[(space + 1)..].Trim();
        var slash = spec.IndexOf('/');
        var dash = spec.IndexOf('-');
        if (slash < 0 || dash < 0 || dash > slash) return null;
        if (!TryNumber(spec[..dash].Trim(), out var first) || !TryNumber(spec[(dash + 1)..slash].Trim(), out var last)) return null;
        if (last < first || last == long.MaxValue) return null;
        var lengthPart = spec[(slash + 1)..].Trim();
        long? complete = null;
        if (lengthPart != "*")
        {
            if (!TryNumber(lengthPart, out var c) || c <= last) return null;
            complete = c;
        }
        return new PutRange(first, last, complete);
    }

    public static string ContentRange(ByteRange r, long size) => $"bytes {r.Start}-{r.End}/{size}";

    /// <summary>The header block before one part of a multipart/byteranges body.</summary>
    public static byte[] PartHeader(string boundary, string contentType, ByteRange r, long size) =>
        Encoding.ASCII.GetBytes($"--{boundary}\r\nContent-Type: {contentType}\r\nContent-Range: {ContentRange(r, size)}\r\n\r\n");

    public static readonly byte[] CrLf = "\r\n"u8.ToArray();

    public static byte[] Closing(string boundary) => Encoding.ASCII.GetBytes($"--{boundary}--\r\n");

    /// <summary>Exact length of the multipart body, so it can be sent with a Content-Length.</summary>
    public static long MultipartLength(string boundary, string contentType, IReadOnlyList<ByteRange> ranges, long size) =>
        ranges.Sum(r => PartHeader(boundary, contentType, r, size).Length + r.Length + CrLf.Length) + Closing(boundary).Length;

    /// <summary>A boundary that cannot occur in the file's bytes by accident (RFC 2046: up to 70 characters).</summary>
    public static string NewBoundary() => "nullify-" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
}
