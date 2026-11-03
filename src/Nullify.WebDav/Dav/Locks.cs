// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Xml.Linq;
using Nullify.WebDav.Storage;

namespace Nullify.WebDav.Dav;

/// <summary>A WebDAV write lock (RFC 4918 §6, §7). Keyed by physical path so every mount of a folder shares it.</summary>
public sealed class DavLock
{
    public required string Token { get; init; }
    public required string Path { get; init; }
    public required string RootHref { get; init; }
    public required string Principal { get; init; }
    public bool Infinite { get; init; }
    public bool Exclusive { get; init; }
    public XElement? Owner { get; init; }
    public int TimeoutSeconds { get; set; }
    public DateTime ExpiresUtc { get; set; }
}

/// <summary>In-memory lock table. Locks are short-lived client state and do not survive a restart.</summary>
public sealed class LockManager
{
    private readonly Lock _sync = new();
    private readonly Dictionary<string, DavLock> _locks = new(StringComparer.Ordinal);

    public IReadOnlyList<DavLock> All()
    {
        lock (_sync)
        {
            Purge();
            return _locks.Values.OrderBy(l => l.Path).ToList();
        }
    }

    public DavLock? Get(string token)
    {
        lock (_sync)
        {
            Purge();
            return _locks.GetValueOrDefault(token);
        }
    }

    /// <summary>Locks on the path itself or on an ancestor with depth infinity.</summary>
    public IReadOnlyList<DavLock> Covering(string path)
    {
        lock (_sync)
        {
            Purge();
            return _locks.Values.Where(l => PathSafety.SamePath(l.Path, path) || l.Infinite && PathSafety.IsDescendant(l.Path, path)).ToList();
        }
    }

    /// <summary>Locks directly on the path (any depth).</summary>
    public IReadOnlyList<DavLock> On(string path)
    {
        lock (_sync)
        {
            Purge();
            return _locks.Values.Where(l => PathSafety.SamePath(l.Path, path)).ToList();
        }
    }

    /// <summary>Locks on the path or anywhere below it.</summary>
    public IReadOnlyList<DavLock> Within(string path)
    {
        lock (_sync)
        {
            Purge();
            return _locks.Values.Where(l => PathSafety.SamePath(l.Path, path) || PathSafety.IsDescendant(path, l.Path)).ToList();
        }
    }

    /// <summary>Creates a lock unless it conflicts with an existing one; returns the conflicting lock otherwise.</summary>
    public DavLock? TryAdd(DavLock candidate)
    {
        lock (_sync)
        {
            Purge();
            var related = _locks.Values.Where(l =>
                PathSafety.SamePath(l.Path, candidate.Path) ||
                l.Infinite && PathSafety.IsDescendant(l.Path, candidate.Path) ||
                candidate.Infinite && PathSafety.IsDescendant(candidate.Path, l.Path));
            var conflict = related.FirstOrDefault(l => l.Exclusive || candidate.Exclusive);
            if (conflict != null) return conflict;
            _locks[candidate.Token] = candidate;
            return null;
        }
    }

    public void Refresh(DavLock l, int timeoutSeconds)
    {
        lock (_sync)
        {
            l.TimeoutSeconds = timeoutSeconds;
            l.ExpiresUtc = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        }
    }

    public bool Remove(string token)
    {
        lock (_sync) return _locks.Remove(token);
    }

    /// <summary>Drops every lock on or below a path (after DELETE or MOVE).</summary>
    public void RemoveWithin(string path)
    {
        lock (_sync)
            foreach (var l in _locks.Values.Where(l => PathSafety.SamePath(l.Path, path) || PathSafety.IsDescendant(path, l.Path)).ToList())
                _locks.Remove(l.Token);
    }

    private void Purge()
    {
        var now = DateTime.UtcNow;
        foreach (var l in _locks.Values.Where(l => l.ExpiresUtc <= now).ToList()) _locks.Remove(l.Token);
    }
}

/// <summary>Parsed WebDAV If header (RFC 4918 §10.4).</summary>
public sealed class IfHeader
{
    public sealed record Condition(bool Not, string? Token, string? ETag);

    public sealed record ConditionList(string? Resource, IReadOnlyList<Condition> Conditions);

    public IReadOnlyList<ConditionList> Lists { get; }

    private IfHeader(IReadOnlyList<ConditionList> lists) => Lists = lists;

    /// <summary>Every state token that appears positively: these count as "submitted" lock tokens.</summary>
    public IEnumerable<string> SubmittedTokens =>
        Lists.SelectMany(l => l.Conditions).Where(c => c is { Not: false, Token: not null }).Select(c => c.Token!);

    /// <summary>Parses the header; null means a syntax error (400).</summary>
    public static IfHeader? Parse(string header)
    {
        var lists = new List<ConditionList>();
        string? resource = null;
        var i = 0;
        var tagged = false;
        while (true)
        {
            SkipSpace(header, ref i);
            if (i >= header.Length) break;
            if (header[i] == '<')
            {
                if (lists.Count > 0 && !tagged) return null; // mixing untagged and tagged lists
                tagged = true;
                var end = header.IndexOf('>', i);
                if (end < 0) return null;
                resource = header[(i + 1)..end];
                i = end + 1;
                SkipSpace(header, ref i);
                if (i >= header.Length || header[i] != '(') return null;
                continue;
            }
            if (header[i] != '(') return null;
            i++;
            var conditions = new List<Condition>();
            while (true)
            {
                SkipSpace(header, ref i);
                if (i >= header.Length) return null;
                if (header[i] == ')') { i++; break; }
                var not = false;
                if (string.Compare(header, i, "Not", 0, 3, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    not = true;
                    i += 3;
                    SkipSpace(header, ref i);
                    if (i >= header.Length) return null;
                }
                if (header[i] == '<')
                {
                    var end = header.IndexOf('>', i);
                    if (end < 0) return null;
                    conditions.Add(new Condition(not, header[(i + 1)..end], null));
                    i = end + 1;
                }
                else if (header[i] == '[')
                {
                    var end = header.IndexOf(']', i);
                    if (end < 0) return null;
                    conditions.Add(new Condition(not, null, header[(i + 1)..end].Trim()));
                    i = end + 1;
                }
                else return null;
            }
            if (conditions.Count == 0) return null;
            lists.Add(new ConditionList(tagged ? resource : null, conditions));
        }
        return lists.Count == 0 ? null : new IfHeader(lists);
    }

    private static void SkipSpace(string s, ref int i)
    {
        while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
    }

    public static bool ETagMatches(string? current, string condition)
    {
        if (current == null) return false;
        static string Strip(string e) => e.StartsWith("W/", StringComparison.Ordinal) ? e[2..] : e;
        return Strip(current) == Strip(condition);
    }
}
