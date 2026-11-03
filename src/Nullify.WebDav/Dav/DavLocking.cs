// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Xml.Linq;
using static Nullify.WebDav.Dav.Ns;

namespace Nullify.WebDav.Dav;

public sealed partial class DavHandler
{
    private const int DefaultLockSeconds = 3600;

    // ------------------------------------------------------------------ LOCK

    private async Task LockAsync(DavTarget t)
    {
        if (t.IsRoot) throw new DavException(StatusCodes.Status403Forbidden);
        RequireWrite(t);
        var timeout = ParseTimeout(Request.Headers["Timeout"].ToString());
        var body = await DavXml.ReadBodyAsync(Request, Ct);

        if (body == null)
        {
            // Refresh: the If header names the lock.
            var submitted = If?.SubmittedTokens.ToList() ?? [];
            var existing = _locks.Covering(t.Physical).FirstOrDefault(l => submitted.Contains(l.Token));
            if (existing == null)
                throw new DavException(StatusCodes.Status412PreconditionFailed, D + "lock-token-matches-request-uri");
            if (!Configuration.Names.Eq(existing.Principal, _user.Username)) throw new DavException(StatusCodes.Status403Forbidden);
            _locks.Refresh(existing, timeout);
            await WriteLockAsync(existing, StatusCodes.Status200OK, includeHeader: false);
            return;
        }

        var info = body.Root;
        if (info?.Name != D + "lockinfo") throw new DavException(StatusCodes.Status400BadRequest, message: "Expected DAV:lockinfo.");
        var exclusive = info.Element(D + "lockscope")?.Element(D + "exclusive") != null;
        if (!exclusive && info.Element(D + "lockscope")?.Element(D + "shared") == null)
            throw new DavException(StatusCodes.Status400BadRequest, message: "Missing lockscope.");
        if (info.Element(D + "locktype")?.Element(D + "write") == null)
            throw new DavException(StatusCodes.Status400BadRequest, message: "Only write locks are supported.");
        var depth = Request.Headers["Depth"].ToString().ToLowerInvariant();
        if (depth is not ("" or "0" or "infinity")) throw new DavException(StatusCodes.Status400BadRequest, message: "Lock depth must be 0 or infinity.");

        CheckIfHeader(t);
        var isDir = Directory.Exists(t.Physical);
        var created = false;
        if (!isDir && !File.Exists(t.Physical))
        {
            // Locking an unmapped URL creates an empty resource (RFC 4918 §9.10.4); Windows and macOS rely on it.
            if (t.IsMountRoot || !Directory.Exists(t.Parent)) throw new DavException(StatusCodes.Status409Conflict);
            RequireUnlocked(_locks.Covering(t.Parent));
            await using (new FileStream(t.Physical, FileMode.CreateNew, FileAccess.Write)) { }
            created = true;
        }

        var owner = info.Element(D + "owner");
        var candidate = new DavLock
        {
            Token = "opaquelocktoken:" + Guid.NewGuid(),
            Path = t.Physical,
            RootHref = Href(t, isDir),
            Principal = _user.Username,
            Infinite = isDir && depth != "0",
            Exclusive = exclusive,
            Owner = owner == null ? null : new XElement(owner),
            TimeoutSeconds = timeout,
            ExpiresUtc = DateTime.UtcNow.AddSeconds(timeout),
        };
        var conflict = _locks.TryAdd(candidate);
        if (conflict != null)
        {
            if (created) TryDelete(t.Physical);
            throw new DavException(StatusCodes.Status423Locked, D + "no-conflicting-lock", detail: DavXml.Href(conflict.RootHref));
        }
        await WriteLockAsync(candidate, created ? StatusCodes.Status201Created : StatusCodes.Status200OK, includeHeader: true);
    }

    private async Task WriteLockAsync(DavLock l, int status, bool includeHeader)
    {
        if (includeHeader) Response.Headers["Lock-Token"] = $"<{l.Token}>";
        var prop = new XElement(D + "prop", new XElement(D + "lockdiscovery", ActiveLock(l)));
        await DavXml.WriteAsync(Response, status, prop, Ct);
    }

    private static XElement ActiveLock(DavLock l)
    {
        var remaining = Math.Max(0, (int)(l.ExpiresUtc - DateTime.UtcNow).TotalSeconds);
        return new XElement(D + "activelock",
            new XElement(D + "locktype", new XElement(D + "write")),
            new XElement(D + "lockscope", new XElement(l.Exclusive ? D + "exclusive" : D + "shared")),
            new XElement(D + "depth", l.Infinite ? "infinity" : "0"),
            l.Owner,
            new XElement(D + "timeout", "Second-" + remaining.ToString(CultureInfo.InvariantCulture)),
            new XElement(D + "locktoken", DavXml.Href(l.Token)),
            new XElement(D + "lockroot", DavXml.Href(l.RootHref)));
    }

    /// <summary>Parses "Second-n, Infinite"; the first acceptable value wins, capped by the server maximum.</summary>
    private int ParseTimeout(string header)
    {
        var max = _config.Settings.MaxLockTimeoutMinutes * 60;
        foreach (var part in header.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.Equals("Infinite", StringComparison.OrdinalIgnoreCase)) return max;
            if (part.StartsWith("Second-", StringComparison.OrdinalIgnoreCase) &&
                long.TryParse(part[7..], NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds > 0)
                return (int)Math.Min(seconds, max);
        }
        return Math.Min(DefaultLockSeconds, max);
    }

    // ------------------------------------------------------------------ UNLOCK

    private Task UnlockAsync(DavTarget t)
    {
        if (t.IsRoot) throw new DavException(StatusCodes.Status403Forbidden);
        var header = Request.Headers["Lock-Token"].ToString().Trim();
        if (header.Length < 3 || header[0] != '<' || header[^1] != '>')
            throw new DavException(StatusCodes.Status400BadRequest, message: "Missing Lock-Token header.");
        var token = header[1..^1];
        var l = _locks.Covering(t.Physical).FirstOrDefault(x => x.Token == token);
        if (l == null) throw new DavException(StatusCodes.Status409Conflict, D + "lock-token-matches-request-uri");
        // Administrators may break stale locks held by others.
        if (!Configuration.Names.Eq(l.Principal, _user.Username) && !_user.IsAdmin) throw new DavException(StatusCodes.Status403Forbidden);
        _locks.Remove(token);
        Response.StatusCode = StatusCodes.Status204NoContent;
        return Task.CompletedTask;
    }
}
