// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Xml.Linq;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Storage;
using static Nullify.WebDav.Dav.Ns;

namespace Nullify.WebDav.Dav;

public sealed partial class DavHandler
{
    /// <summary>Something a PROPFIND reports on: the virtual root, a mount, a folder or a file.</summary>
    private sealed record DavItem(string Href, string Name, bool IsCollection, FileSystemInfo? Info, MountAccess? Mount, string? Physical);

    private static readonly XName[] AllProps =
    [
        D + "displayname", D + "resourcetype", D + "getcontentlength", D + "getcontenttype", D + "getlastmodified",
        D + "creationdate", D + "getetag", D + "supportedlock", D + "lockdiscovery",
    ];

    /// <summary>Not part of allprop, but reported when asked for (RFC 4331, RFC 3744 and the Windows redirector).</summary>
    private static readonly XName[] ExtraProps =
    [
        D + "quota-available-bytes", D + "quota-used-bytes", D + "current-user-privilege-set",
        D + "iscollection", D + "ishidden", D + "isreadonly",
        MS + "Win32FileAttributes", MS + "Win32CreationTime", MS + "Win32LastAccessTime", MS + "Win32LastModifiedTime",
    ];

    private static readonly HashSet<XName> Win32Props =
        [MS + "Win32FileAttributes", MS + "Win32CreationTime", MS + "Win32LastAccessTime", MS + "Win32LastModifiedTime"];

    // ------------------------------------------------------------------ PROPFIND

    /// <summary>Deepest folder nesting a Depth: infinity listing follows (a guard against link loops and absurd trees).</summary>
    private const int MaxInfinityNesting = 64;

    /// <summary>The PROPFIND Depth header: 0, 1 or infinity (RFC 4918 9.1: no header means infinity).</summary>
    private static int ParseDepth(string value) => value.Trim().ToLowerInvariant() switch
    {
        "0" => 0,
        "1" => 1,
        "" or "infinity" => int.MaxValue,
        _ => throw new DavException(StatusCodes.Status400BadRequest, message: "Depth must be 0, 1 or infinity."),
    };

    private async Task PropfindAsync(DavTarget t)
    {
        var depth = ParseDepth(Request.Headers["Depth"].ToString());
        if (depth == int.MaxValue && !_config.Settings.AllowDepthInfinity)
            throw new DavException(StatusCodes.Status403Forbidden, D + "propfind-finite-depth");

        var body = await DavXml.ReadBodyAsync(Request, Ct);
        var root = body?.Root;
        if (root != null && root.Name != D + "propfind") throw new DavException(StatusCodes.Status400BadRequest, message: "Expected DAV:propfind.");
        var propName = root?.Element(D + "propname") != null;
        var requested = root?.Element(D + "prop")?.Elements().Select(e => e.Name).ToList();
        var include = root?.Element(D + "include")?.Elements().Select(e => e.Name) ?? [];

        var self = ItemFor(t);
        var items = new List<DavItem> { self };
        if (depth == 1 && self.IsCollection) items.AddRange(ChildItems(t, self));
        if (depth == int.MaxValue && self.IsCollection) items.AddRange(TreeItems(t, self, _config.Settings.MaxDepthInfinityItems - 1));

        var ms = new MultiStatus();
        foreach (var item in items)
        {
            if (propName)
            {
                ms.AddPropStat(item.Href, AllProps.Concat(ExtraProps).Select(n => (new XElement(n), 200)));
                continue;
            }
            var names = requested ?? AllProps.Concat(include).Distinct().ToList();
            var props = new List<(XElement, int)>();
            foreach (var name in names)
            {
                var value = LiveProp(item, name);
                if (value != null) props.Add((value, 200));
                else if (requested != null) props.Add((new XElement(name), 404));
            }
            ms.AddPropStat(item.Href, props);
        }
        await DavXml.WriteAsync(Response, StatusCodes.Status207MultiStatus, ms.ToXml(), Ct);
    }

    private DavItem ItemFor(DavTarget t)
    {
        if (t.IsRoot) return new DavItem(_base + "/", "", true, null, null, null);
        FileSystemInfo info = Directory.Exists(t.Physical) ? new DirectoryInfo(t.Physical) : new FileInfo(t.Physical);
        if (!info.Exists) throw new DavException(StatusCodes.Status404NotFound);
        var isDir = info is DirectoryInfo;
        var name = t.Segments.Length == 0 ? t.Mount!.Name : t.Segments[^1];
        return new DavItem(Href(t, isDir), name, isDir, info, t.Mount, t.Physical);
    }

    private IEnumerable<DavItem> ChildItems(DavTarget t, DavItem self)
    {
        if (t.IsRoot)
        {
            // Mounts are virtual at this level: listing them never touches their (possibly impersonated) storage.
            foreach (var m in _mounts.EntriesFor(_user))
                yield return new DavItem(HrefFor(m.Name, [], true), m.Name, true, null, m, null);
            yield break;
        }
        foreach (var entry in Children((DirectoryInfo)self.Info!, t.Mount!.Storage))
        {
            var isDir = entry is DirectoryInfo;
            yield return new DavItem(ChildHref(self.Href, entry.Name, isDir), entry.Name, isDir, entry, t.Mount, entry.FullName);
        }
    }

    /// <summary>
    /// Everything below a collection, for Depth: infinity: depth first, so a folder is followed by its contents. Throws
    /// 403 propfind-finite-depth (RFC 4918 9.1) when the tree has more than <paramref name="limit"/> entries.
    /// </summary>
    private List<DavItem> TreeItems(DavTarget t, DavItem self, int limit)
    {
        var items = new List<DavItem>();
        void Add(DavItem item)
        {
            if (items.Count >= limit) throw new DavException(StatusCodes.Status403Forbidden, D + "propfind-finite-depth");
            items.Add(item);
        }

        if (t.IsRoot)
        {
            foreach (var m in _mounts.EntriesFor(_user))
            {
                var href = HrefFor(m.Name, [], true);
                // At /dav/ the request does not run as the user, so storage accessed as the user's Windows account is
                // listed but not entered; a PROPFIND on the mount itself lists it under the user's own token.
                if (m.Storage.Impersonate || !Directory.Exists(m.BasePath) ||
                    !m.Storage.FollowSymlinks && PathSafety.CrossesLink(m.Storage.Root, m.BasePath))
                {
                    Add(new DavItem(href, m.Name, true, null, m, null));
                    continue;
                }
                var dir = new DirectoryInfo(m.BasePath);
                Add(new DavItem(href, m.Name, true, dir, m, m.BasePath));
                Walk(dir, href, m, 1);
            }
            return items;
        }

        Walk((DirectoryInfo)self.Info!, self.Href, t.Mount!, 1);
        return items;

        void Walk(DirectoryInfo dir, string href, MountAccess mount, int level)
        {
            if (level > MaxInfinityNesting) throw new DavException(StatusCodes.Status403Forbidden, D + "propfind-finite-depth");
            List<FileSystemInfo> children;
            // A folder the server may not read is still reported, just without its contents.
            try { children = Children(dir, mount.Storage).OrderBy(e => e.Name, StringComparer.Ordinal).ToList(); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return; }
            foreach (var entry in children)
            {
                var isDir = entry is DirectoryInfo;
                var childHref = ChildHref(href, entry.Name, isDir);
                Add(new DavItem(childHref, entry.Name, isDir, entry, mount, entry.FullName));
                if (isDir) Walk((DirectoryInfo)entry, childHref, mount, level + 1);
            }
        }
    }

    private XElement? LiveProp(DavItem item, XName name)
    {
        var info = item.Info;
        var file = info as FileInfo;
        var writable = item.Mount?.CanWrite == true;
        switch (name.LocalName)
        {
            case "displayname" when name.Namespace == D:
                return Prop(name, item.Name);
            case "resourcetype" when name.Namespace == D:
                return Prop(name, item.IsCollection ? new XElement(D + "collection") : null);
            case "getcontentlength" when name.Namespace == D && file != null:
                return Prop(name, file.Length);
            case "getcontenttype" when name.Namespace == D && file != null:
                return Prop(name, ContentTypeFor(file.Name));
            case "getlastmodified" when name.Namespace == D && info != null:
                return Prop(name, info.LastWriteTimeUtc.ToString("R", CultureInfo.InvariantCulture));
            case "creationdate" when name.Namespace == D && info != null:
                return Prop(name, info.CreationTimeUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
            case "getetag" when name.Namespace == D && info != null:
                return Prop(name, ETag(info));
            case "supportedlock" when name.Namespace == D && item.Physical != null:
                return Prop(name, LockEntry(D + "exclusive"), LockEntry(D + "shared"));
            case "lockdiscovery" when name.Namespace == D && item.Physical != null:
                return Prop(name, _locks.Covering(item.Physical).Select(ActiveLock));
            case "quota-available-bytes" or "quota-used-bytes" when name.Namespace == D && item.IsCollection && item.Physical != null:
                if (Quota(item.Physical) is not { } quota) return null;
                return Prop(name, name.LocalName == "quota-used-bytes" ? quota.Used : quota.Available);
            case "current-user-privilege-set" when name.Namespace == D:
                var privileges = new List<XElement> { Privilege("read"), Privilege("read-current-user-privilege-set") };
                if (writable) privileges.AddRange([Privilege("write"), Privilege("write-content"), Privilege("write-properties"), Privilege("bind"), Privilege("unbind"), Privilege("unlock")]);
                return Prop(name, privileges);
            case "iscollection" when name.Namespace == D:
                return Prop(name, item.IsCollection ? 1 : 0);
            case "ishidden" when name.Namespace == D:
                return Prop(name, info != null && ((info.Attributes & FileAttributes.Hidden) != 0 || info.Name.StartsWith('.')) ? 1 : 0);
            case "isreadonly" when name.Namespace == D:
                return Prop(name, !writable || file?.IsReadOnly == true ? 1 : 0);
            case "Win32FileAttributes" when name.Namespace == MS && info != null:
                return Prop(name, ((int)info.Attributes & 0x37).ToString("X8", CultureInfo.InvariantCulture));
            case "Win32CreationTime" when name.Namespace == MS && info != null:
                return Prop(name, info.CreationTimeUtc.ToString("R", CultureInfo.InvariantCulture));
            case "Win32LastAccessTime" when name.Namespace == MS && info != null:
                return Prop(name, info.LastAccessTimeUtc.ToString("R", CultureInfo.InvariantCulture));
            case "Win32LastModifiedTime" when name.Namespace == MS && info != null:
                return Prop(name, info.LastWriteTimeUtc.ToString("R", CultureInfo.InvariantCulture));
            default:
                return null;
        }

        static XElement Privilege(string p) => new(D + "privilege", new XElement(D + p));
    }

    private static XElement Prop(XName name, params object?[] content) => new(name, content);

    private static XElement LockEntry(XName scope) =>
        new(D + "lockentry", new XElement(D + "lockscope", new XElement(scope)), new XElement(D + "locktype", new XElement(D + "write")));

    // ------------------------------------------------------------------ PROPPATCH

    /// <summary>
    /// Only the Win32 properties the Windows redirector sets are supported; they are applied to the file itself.
    /// Arbitrary dead properties are refused (403) rather than silently dropped.
    /// </summary>
    private async Task ProppatchAsync(DavTarget t)
    {
        RequireWrite(t);
        var item = ItemFor(t);
        var body = await DavXml.ReadBodyAsync(Request, Ct);
        if (body?.Root?.Name != D + "propertyupdate") throw new DavException(StatusCodes.Status400BadRequest, message: "Expected DAV:propertyupdate.");
        CheckIfHeader(t);
        RequireUnlocked(_locks.Covering(t.Physical));

        var results = new List<(XElement Prop, int Status)>();
        var actions = new List<Action>();
        foreach (var op in body.Root.Elements())
        {
            var set = op.Name == D + "set";
            if (!set && op.Name != D + "remove") continue;
            foreach (var prop in op.Element(D + "prop")?.Elements() ?? [])
            {
                if (!Win32Props.Contains(prop.Name))
                {
                    results.Add((new XElement(prop.Name), StatusCodes.Status403Forbidden));
                    continue;
                }
                if (!set)
                {
                    results.Add((new XElement(prop.Name), StatusCodes.Status200OK));
                    continue;
                }
                var action = Win32Action(item.Info!, prop.Name.LocalName, prop.Value.Trim());
                results.Add((new XElement(prop.Name), action == null ? StatusCodes.Status409Conflict : StatusCodes.Status200OK));
                if (action != null) actions.Add(action);
            }
        }

        if (results.Any(r => r.Status != StatusCodes.Status200OK))
        {
            // PROPPATCH is atomic: nothing is applied when anything fails.
            results = results.Select(r => r.Status == StatusCodes.Status200OK ? (r.Prop, StatusCodes.Status424FailedDependency) : r).ToList();
        }
        else
        {
            foreach (var action in actions) action();
        }
        var ms = new MultiStatus();
        ms.AddPropStat(item.Href, results);
        await DavXml.WriteAsync(Response, StatusCodes.Status207MultiStatus, ms.ToXml(), Ct);
    }

    private static Action? Win32Action(FileSystemInfo info, string property, string value)
    {
        if (property == "Win32FileAttributes")
        {
            if (!int.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var bits)) return null;
            // Read-only, hidden and archive are the only attributes a client may change.
            const FileAttributes settable = FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.Archive;
            return () =>
            {
                if (!OperatingSystem.IsWindows()) return;
                var attributes = ((info.Attributes & ~settable) | ((FileAttributes)bits & settable)) & ~FileAttributes.Directory;
                File.SetAttributes(info.FullName, attributes == 0 ? FileAttributes.Normal : attributes);
            };
        }
        if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var time)) return null;
        return property switch
        {
            "Win32CreationTime" => () => info.CreationTimeUtc = time,
            "Win32LastAccessTime" => () => info.LastAccessTimeUtc = time,
            "Win32LastModifiedTime" => () => info.LastWriteTimeUtc = time,
            _ => null,
        };
    }

    // ------------------------------------------------------------------ Server root

    private async Task ServerRootAsync()
    {
        if (!string.Equals(Request.Method, "PROPFIND", StringComparison.OrdinalIgnoreCase))
            throw new DavException(StatusCodes.Status405MethodNotAllowed);
        // The server root only exists for the Windows redirector's probe; whole-tree listings start at /dav/.
        var depth = ParseDepth(Request.Headers["Depth"].ToString());
        if (depth == int.MaxValue) throw new DavException(StatusCodes.Status403Forbidden, D + "propfind-finite-depth");
        await DavXml.ReadBodyAsync(Request, Ct);
        var pathBase = Request.PathBase.ToUriComponent().TrimEnd('/');
        var ms = new MultiStatus();
        ms.AddPropStat(pathBase + "/", [(new XElement(D + "resourcetype", new XElement(D + "collection")), 200), (new XElement(D + "displayname", ""), 200)]);
        if (depth == 1)
            ms.AddPropStat(pathBase + "/dav/", [(new XElement(D + "resourcetype", new XElement(D + "collection")), 200), (new XElement(D + "displayname", "dav"), 200)]);
        await DavXml.WriteAsync(Response, StatusCodes.Status207MultiStatus, ms.ToXml(), Ct);
    }
}
