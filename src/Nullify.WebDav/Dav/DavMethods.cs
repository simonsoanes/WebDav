// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Headers;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Net.Http.Headers;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Storage;

namespace Nullify.WebDav.Dav;

public sealed partial class DavHandler
{
    private static readonly FileExtensionContentTypeProvider ContentTypes = new();

    /// <summary>Downloads are rendered in a sandbox: uploaded HTML or SVG can never run script on this origin.</summary>
    private const string DownloadPolicy = "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'";

    public static string ContentTypeFor(string name) =>
        ContentTypes.TryGetContentType(name, out var type) ? type : "application/octet-stream";

    // ------------------------------------------------------------------ GET / HEAD

    private async Task GetAsync(DavTarget t, bool head)
    {
        if (t.IsRoot || Directory.Exists(t.Physical))
        {
            if (!_config.Settings.BrowserListing) throw new DavException(StatusCodes.Status405MethodNotAllowed, message: "Folder listings are disabled.");
            await WriteListingAsync(t, head);
            return;
        }
        var file = new FileInfo(t.Physical);
        if (!file.Exists) throw new DavException(StatusCodes.Status404NotFound);

        var etag = ETag(file);
        var lastModified = new DateTimeOffset(file.LastWriteTimeUtc.Ticks - file.LastWriteTimeUtc.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
        var headers = Request.GetTypedHeaders();

        if (headers.IfMatch.Count > 0 && !headers.IfMatch.Any(e => e.Equals(EntityTagHeaderValue.Any) || IfHeader.ETagMatches(etag, e.ToString())))
            throw new DavException(StatusCodes.Status412PreconditionFailed);
        if (headers.IfUnmodifiedSince is { } ius && lastModified > ius)
            throw new DavException(StatusCodes.Status412PreconditionFailed);

        Response.Headers.ETag = etag;
        Response.Headers.LastModified = lastModified.ToString("R");
        Response.Headers.AcceptRanges = "bytes";
        Response.Headers.ContentSecurityPolicy = DownloadPolicy;
        Response.Headers.CacheControl = "private, no-cache";

        var notModified = headers.IfNoneMatch.Count > 0
            ? headers.IfNoneMatch.Any(e => e.Equals(EntityTagHeaderValue.Any) || IfHeader.ETagMatches(etag, e.ToString()))
            : headers.IfModifiedSince is { } ims && lastModified <= ims;
        if (notModified)
        {
            Response.StatusCode = StatusCodes.Status304NotModified;
            return;
        }

        long start = 0, length = file.Length;
        var range = ParseRange(Request.Headers.Range.ToString(), file.Length);
        if (range != null && IfRangeAllows(headers, etag, lastModified))
        {
            if (range.Value.Start < 0)
            {
                Response.Headers.ContentRange = $"bytes */{file.Length}";
                throw new DavException(StatusCodes.Status416RangeNotSatisfiable);
            }
            (start, length) = range.Value;
            Response.StatusCode = StatusCodes.Status206PartialContent;
            Response.Headers.ContentRange = $"bytes {start}-{start + length - 1}/{file.Length}";
        }
        else
        {
            Response.StatusCode = StatusCodes.Status200OK;
        }

        Response.ContentType = ContentTypeFor(file.Name);
        Response.ContentLength = length;
        if (head) return;

        await using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        stream.Seek(start, SeekOrigin.Begin);
        var buffer = new byte[81920];
        var remaining = length;
        while (remaining > 0)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)), Ct);
            if (read == 0) break;
            await Response.Body.WriteAsync(buffer.AsMemory(0, read), Ct);
            remaining -= read;
        }
    }

    /// <summary>Single byte range only; multiple ranges get the whole file. Start = -1 means unsatisfiable.</summary>
    private static (long Start, long Length)? ParseRange(string header, long size)
    {
        if (!header.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase)) return null;
        var spec = header[6..].Trim();
        if (spec.Contains(',')) return null;
        var dash = spec.IndexOf('-');
        if (dash < 0) return null;
        var first = spec[..dash].Trim();
        var last = spec[(dash + 1)..].Trim();
        if (first.Length == 0)
        {
            if (!long.TryParse(last, NumberStyles.None, CultureInfo.InvariantCulture, out var suffix)) return null;
            if (suffix == 0 || size == 0) return (-1, 0);
            suffix = Math.Min(suffix, size);
            return (size - suffix, suffix);
        }
        if (!long.TryParse(first, NumberStyles.None, CultureInfo.InvariantCulture, out var start)) return null;
        long end = size - 1;
        if (last.Length > 0)
        {
            if (!long.TryParse(last, NumberStyles.None, CultureInfo.InvariantCulture, out end) || end < start) return null;
            end = Math.Min(end, size - 1);
        }
        if (start >= size) return (-1, 0);
        return (start, end - start + 1);
    }

    private static bool IfRangeAllows(RequestHeaders headers, string etag, DateTimeOffset lastModified)
    {
        var ifRange = headers.IfRange;
        if (ifRange == null) return true;
        if (ifRange.EntityTag != null) return !ifRange.EntityTag.IsWeak && ifRange.EntityTag.ToString() == etag;
        return ifRange.LastModified is { } date && lastModified <= date;
    }

    // ------------------------------------------------------------------ PUT

    private async Task PutAsync(DavTarget t)
    {
        RequireWrite(t);
        if (t.IsMountRoot || Directory.Exists(t.Physical)) throw new DavException(StatusCodes.Status405MethodNotAllowed, message: "A folder cannot be overwritten with a file.");
        if (!Directory.Exists(t.Parent)) throw new DavException(StatusCodes.Status409Conflict, message: "The parent folder does not exist.");
        if (Request.Headers.ContentRange.Count > 0) throw new DavException(StatusCodes.Status400BadRequest, message: "Partial uploads (Content-Range) are not supported.");

        var exists = File.Exists(t.Physical);
        var headers = Request.GetTypedHeaders();
        var etag = exists ? ETag(new FileInfo(t.Physical)) : null;
        if (headers.IfNoneMatch.Any(e => e.Equals(EntityTagHeaderValue.Any)) && exists) throw new DavException(StatusCodes.Status412PreconditionFailed);
        if (headers.IfMatch.Count > 0 && !headers.IfMatch.Any(e => e.Equals(EntityTagHeaderValue.Any) ? exists : IfHeader.ETagMatches(etag, e.ToString())))
            throw new DavException(StatusCodes.Status412PreconditionFailed);
        CheckIfHeader(t);
        RequireUnlocked(exists ? _locks.Covering(t.Physical) : MemberLocks(t));

        var limit = _config.Settings.MaxUploadMegabytes > 0 ? _config.Settings.MaxUploadMegabytes * 1024 * 1024 : long.MaxValue;
        var declared = Request.ContentLength ??
                       (long.TryParse(Request.Headers["X-Expected-Entity-Length"], out var expected) ? expected : null);
        if (declared > limit) throw new DavException(StatusCodes.Status413PayloadTooLarge, message: "The file is larger than the upload limit.");
        if (declared != null && FreeSpace(t.Parent) is { } free && declared > free) throw new DavException(StatusCodes.Status507InsufficientStorage);

        if (_http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } bodyLimit) bodyLimit.MaxRequestBodySize = null;

        var temp = Path.Combine(t.Parent, PathSafety.TempPrefix + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                var buffer = new byte[81920];
                long total = 0;
                int read;
                while ((read = await Request.Body.ReadAsync(buffer, Ct)) > 0)
                {
                    total += read;
                    if (total > limit) throw new DavException(StatusCodes.Status413PayloadTooLarge, message: "The file is larger than the upload limit.");
                    await output.WriteAsync(buffer.AsMemory(0, read), Ct);
                }
            }
            File.Move(temp, t.Physical, overwrite: true);
        }
        catch
        {
            TryDelete(temp);
            throw;
        }

        // ownCloud/Nextcloud convention used by rclone and sync clients to preserve modification times.
        if (long.TryParse(Request.Headers["X-OC-Mtime"], out var mtime) && mtime is > 0 and < 253402300800)
        {
            File.SetLastWriteTimeUtc(t.Physical, DateTimeOffset.FromUnixTimeSeconds(mtime).UtcDateTime);
            Response.Headers["X-OC-Mtime"] = "accepted";
        }
        Response.Headers.ETag = ETag(new FileInfo(t.Physical));
        Response.StatusCode = exists ? StatusCodes.Status204NoContent : StatusCodes.Status201Created;
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static long? FreeSpace(string path)
    {
        try
        {
            var root = OperatingSystem.IsWindows() ? Path.GetPathRoot(path) : path;
            if (string.IsNullOrEmpty(root) || root.StartsWith(@"\\", StringComparison.Ordinal)) return null;
            return new DriveInfo(root).AvailableFreeSpace;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static (long Used, long Available)? Quota(string path)
    {
        try
        {
            var root = OperatingSystem.IsWindows() ? Path.GetPathRoot(path) : path;
            if (string.IsNullOrEmpty(root) || root.StartsWith(@"\\", StringComparison.Ordinal)) return null;
            var drive = new DriveInfo(root);
            return (drive.TotalSize - drive.TotalFreeSpace, drive.AvailableFreeSpace);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    // ------------------------------------------------------------------ DELETE

    private async Task DeleteAsync(DavTarget t)
    {
        RequireWrite(t);
        if (t.IsMountRoot) throw new DavException(StatusCodes.Status403Forbidden, message: "The root folder of a mount cannot be deleted.");
        var isDir = Directory.Exists(t.Physical);
        if (!isDir && !File.Exists(t.Physical)) throw new DavException(StatusCodes.Status404NotFound);
        var depth = Request.Headers["Depth"].ToString();
        if (isDir && depth.Length > 0 && !depth.Equals("infinity", StringComparison.OrdinalIgnoreCase))
            throw new DavException(StatusCodes.Status400BadRequest, message: "Folders can only be deleted with Depth: infinity.");

        CheckIfHeader(t);
        RequireUnlocked(_locks.Within(t.Physical).Concat(MemberLocks(t)));

        if (!isDir)
        {
            DeleteFile(new FileInfo(t.Physical));
        }
        else
        {
            var failures = new MultiStatus();
            DeleteTree(new DirectoryInfo(t.Physical), Href(t, true), failures, t.Mount!.Storage);
            if (failures.Count > 0)
            {
                _locks.RemoveWithin(t.Physical);
                await DavXml.WriteAsync(Response, StatusCodes.Status207MultiStatus, failures.ToXml(), Ct);
                return;
            }
        }
        _locks.RemoveWithin(t.Physical);
        Response.StatusCode = StatusCodes.Status204NoContent;
    }

    private static void DeleteFile(FileInfo file)
    {
        if (file.IsReadOnly) file.IsReadOnly = false;
        file.Delete();
    }

    /// <summary>Deletes depth-first, recording members that could not be removed (RFC 4918 §9.6.1).</summary>
    private static bool DeleteTree(DirectoryInfo dir, string href, MultiStatus failures, StorageConfig storage)
    {
        var ok = true;
        foreach (var entry in dir.EnumerateFileSystemInfos("*", ListOptions).ToList())
        {
            var isDir = entry is DirectoryInfo;
            var childHref = ChildHref(href, entry.Name, isDir);
            try
            {
                if (isDir && !PathSafety.IsLink(entry))
                {
                    ok &= DeleteTree((DirectoryInfo)entry, childHref, failures, storage);
                    continue;
                }
                if (entry is FileInfo f) DeleteFile(f);
                else ((DirectoryInfo)entry).Delete(); // a link: removes the link, not its target
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failures.AddStatus(childHref, ex is UnauthorizedAccessException ? StatusCodes.Status403Forbidden : StatusCodes.Status423Locked);
                ok = false;
            }
        }
        if (!ok) return false;
        try
        {
            dir.Delete();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            failures.AddStatus(href, ex is UnauthorizedAccessException ? StatusCodes.Status403Forbidden : StatusCodes.Status423Locked);
            return false;
        }
    }

    // ------------------------------------------------------------------ MKCOL

    private Task MkcolAsync(DavTarget t)
    {
        RequireWrite(t);
        if (t.IsMountRoot || Directory.Exists(t.Physical) || File.Exists(t.Physical))
            throw new DavException(StatusCodes.Status405MethodNotAllowed, message: "Something with this name already exists.");
        if (Request.ContentLength > 0 || Request.Headers.TransferEncoding.Count > 0)
            throw new DavException(StatusCodes.Status415UnsupportedMediaType);
        if (!Directory.Exists(t.Parent)) throw new DavException(StatusCodes.Status409Conflict, message: "The parent folder does not exist.");
        CheckIfHeader(t);
        RequireUnlocked(MemberLocks(t));
        Directory.CreateDirectory(t.Physical);
        Response.StatusCode = StatusCodes.Status201Created;
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------ COPY / MOVE

    private Task CopyMoveAsync(DavTarget src, bool move)
    {
        if (src.IsRoot || move && src.IsMountRoot) throw new DavException(StatusCodes.Status403Forbidden);
        if (move) RequireWrite(src);

        var destination = Request.Headers["Destination"].ToString();
        if (destination.Length == 0) throw new DavException(StatusCodes.Status400BadRequest, message: "Missing Destination header.");
        var dst = TryParseUrl(destination);
        if (dst == null) throw new DavException(StatusCodes.Status502BadGateway, message: "The destination is not on this server, or not accessible.");
        if (dst.IsRoot || dst.IsMountRoot) throw new DavException(StatusCodes.Status403Forbidden);
        RequireWrite(dst);
        if (src.Mount!.Storage.Impersonate != dst.Mount!.Storage.Impersonate)
            throw new DavException(StatusCodes.Status403Forbidden, message: "Copy or move between impersonated and non-impersonated storage is not supported.");
        EnsureMountFolder(dst.Mount);

        var srcIsDir = Directory.Exists(src.Physical);
        if (!srcIsDir && !File.Exists(src.Physical)) throw new DavException(StatusCodes.Status404NotFound);

        var depth = Request.Headers["Depth"].ToString().ToLowerInvariant();
        var shallow = depth == "0";
        if (srcIsDir && (move ? depth is not ("" or "infinity") : depth is not ("" or "0" or "infinity")))
            throw new DavException(StatusCodes.Status400BadRequest, message: "Invalid Depth for this request.");
        var overwrite = !Request.Headers["Overwrite"].ToString().Equals("F", StringComparison.OrdinalIgnoreCase);

        if (string.Equals(src.Physical, dst.Physical, StringComparison.Ordinal))
            throw new DavException(StatusCodes.Status403Forbidden, message: "Source and destination are the same.");
        // On case-insensitive file systems a different spelling of the same path is a rename, not an overwrite.
        var caseRename = PathSafety.SamePath(src.Physical, dst.Physical);
        if (!caseRename && srcIsDir && PathSafety.IsDescendant(src.Physical, dst.Physical))
            throw new DavException(StatusCodes.Status403Forbidden, message: "A folder cannot be copied or moved into itself.");
        if (!Directory.Exists(dst.Parent)) throw new DavException(StatusCodes.Status409Conflict, message: "The destination folder does not exist.");

        var dstExists = !caseRename && (Directory.Exists(dst.Physical) || File.Exists(dst.Physical));
        if (dstExists && !overwrite) throw new DavException(StatusCodes.Status412PreconditionFailed);

        CheckIfHeader(src);
        var required = MemberLocks(dst).Concat(dstExists ? _locks.Within(dst.Physical) : []);
        if (move) required = required.Concat(_locks.Within(src.Physical)).Concat(MemberLocks(src));
        RequireUnlocked(required);

        if (dstExists)
        {
            if (Directory.Exists(dst.Physical))
            {
                var failures = new MultiStatus();
                if (!DeleteTree(new DirectoryInfo(dst.Physical), Href(dst, true), failures, dst.Mount.Storage))
                    throw new DavException(StatusCodes.Status423Locked, message: "The existing destination could not be removed.");
            }
            else DeleteFile(new FileInfo(dst.Physical));
            _locks.RemoveWithin(dst.Physical);
        }

        if (move)
        {
            MoveEntry(src.Physical, dst.Physical, srcIsDir, caseRename, src.Mount.Storage);
            _locks.RemoveWithin(src.Physical);
        }
        else if (srcIsDir)
        {
            CopyTree(new DirectoryInfo(src.Physical), dst.Physical, shallow, src.Mount.Storage);
        }
        else
        {
            File.Copy(src.Physical, dst.Physical, overwrite: false);
        }

        Response.StatusCode = dstExists ? StatusCodes.Status204NoContent : StatusCodes.Status201Created;
        return Task.CompletedTask;
    }

    private static void MoveEntry(string from, string to, bool isDir, bool caseRename, StorageConfig storage)
    {
        if (caseRename)
        {
            // Two steps so case-only renames work on every file system.
            var temp = Path.Combine(Path.GetDirectoryName(to)!, PathSafety.TempPrefix + Guid.NewGuid().ToString("N"));
            if (isDir) { Directory.Move(from, temp); Directory.Move(temp, to); }
            else { File.Move(from, temp); File.Move(temp, to); }
            return;
        }
        if (!isDir)
        {
            File.Move(from, to);
            return;
        }
        try
        {
            Directory.Move(from, to);
        }
        catch (IOException) when (!SameVolume(from, to))
        {
            // Directory.Move cannot cross volumes: copy, then remove the source.
            CopyTree(new DirectoryInfo(from), to, shallow: false, storage);
            Directory.Delete(from, recursive: true);
        }
    }

    private static bool SameVolume(string a, string b) =>
        string.Equals(Path.GetPathRoot(a), Path.GetPathRoot(b), StringComparison.OrdinalIgnoreCase) && OperatingSystem.IsWindows();

    private static void CopyTree(DirectoryInfo source, string destination, bool shallow, StorageConfig storage)
    {
        Directory.CreateDirectory(destination);
        if (shallow) return;
        foreach (var entry in Children(source, storage))
        {
            var target = Path.Combine(destination, entry.Name);
            if (entry is DirectoryInfo d) CopyTree(d, target, shallow: false, storage);
            else ((FileInfo)entry).CopyTo(target, overwrite: false);
        }
    }
}
