// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Features;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Storage;
using static Nullify.WebDav.Dav.Ns;

namespace Nullify.WebDav.Dav;

/// <summary>
/// Entry point for every request below the DAV mount point. Implements WebDAV class 1 and 2 (RFC 4918) over the
/// configured mounts, plus quota properties (RFC 4331) and the Windows redirector's Win32 properties.
/// </summary>
public sealed partial class DavHandler
{
    public const string Realm = "Nullify.WebDav";
    public const string DavCapabilities = "1, 2";
    private const string AllowedMethods = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK";

    private readonly HttpContext _http;
    private readonly DavPrincipal _user;
    private readonly MountResolver _mounts;
    private readonly LockManager _locks;
    private readonly ServerConfig _config;
    private readonly ILogger _log;
    private readonly bool _viaCookie;
    private IfHeader? _if;

    private ShareService Shares => _http.RequestServices.GetRequiredService<ShareService>();
    private HttpRequest Request => _http.Request;
    private HttpResponse Response => _http.Response;
    private CancellationToken Ct => _http.RequestAborted;

    /// <summary>Escaped URL prefix of the DAV root, e.g. "/dav".</summary>
    private readonly string _base;

    private DavHandler(HttpContext http, DavPrincipal user, bool viaCookie)
    {
        _http = http;
        _user = user;
        _viaCookie = viaCookie;
        var services = http.RequestServices;
        _mounts = services.GetRequiredService<MountResolver>();
        _locks = services.GetRequiredService<LockManager>();
        _config = services.GetRequiredService<ConfigStore>().Current;
        _log = services.GetRequiredService<ILoggerFactory>().CreateLogger("Nullify.WebDav.Dav");
        _base = http.Request.PathBase.ToUriComponent().TrimEnd('/');
    }

    /// <summary>A resolved request URL: the DAV root, a mount root or something inside a mount.</summary>
    private sealed class DavTarget
    {
        public MountAccess? Mount { get; init; }
        /// <summary>The mount segment as the client wrote it ("~" stays "~", so hrefs match the request).</summary>
        public string MountSegment { get; init; } = "";
        public string[] Segments { get; init; } = [];
        public string Physical { get; init; } = "";

        public bool IsRoot => Mount == null;
        public bool IsMountRoot => Mount != null && Segments.Length == 0;
        public string Parent => Path.GetDirectoryName(Physical)!;
    }

    public static Task HandleAsync(HttpContext http) => HandleCoreAsync(http, serverRoot: false);

    /// <summary>PROPFIND and OPTIONS on "/" itself: the Windows redirector probes the server root before the share.</summary>
    public static Task HandleServerRootAsync(HttpContext http) => HandleCoreAsync(http, serverRoot: true);

    private static async Task HandleCoreAsync(HttpContext http, bool serverRoot)
    {
        var services = http.RequestServices;
        var config = services.GetRequiredService<ConfigStore>().Current;
        http.Response.Headers["DAV"] = DavCapabilities;
        http.Response.Headers["MS-Author-Via"] = "DAV";

        if (HttpMethods.IsOptions(http.Request.Method))
        {
            http.Response.Headers.Allow = serverRoot ? "OPTIONS, PROPFIND" : AllowedMethods;
            http.Response.StatusCode = StatusCodes.Status200OK;
            http.Response.ContentLength = 0;
            return;
        }

        if (!http.Request.IsHttps && !IsLocal(http.Connection.RemoteIpAddress) && !config.Settings.AllowInsecureHttp)
        {
            // Never ask for Basic credentials over plain HTTP.
            await WritePlainAsync(http, StatusCodes.Status403Forbidden,
                "HTTPS is required. Behind a reverse proxy, make sure it sends X-Forwarded-Proto and is listed in ReverseProxy__KnownNetworks.");
            return;
        }

        var (user, viaCookie) = await AuthenticateAsync(http, services.GetRequiredService<CredentialValidator>());
        if (user == null)
        {
            if (!serverRoot && IsBrowserNavigation(http.Request) && !http.Request.Headers.ContainsKey("Authorization"))
            {
                // A person opening a /dav/ link in a browser signs in on the login page rather than in a Basic prompt.
                var appBase = AppBase(http.Request.PathBase.Value);
                http.Response.Redirect(appBase + "/account/login?ReturnUrl=" + Uri.EscapeDataString((http.Request.PathBase + http.Request.Path).ToUriComponent()));
                return;
            }
            http.Response.StatusCode = StatusCodes.Status401Unauthorized;
            http.Response.Headers.WWWAuthenticate = $"Basic realm=\"{Realm}\", charset=\"UTF-8\"";
            return;
        }

        var handler = new DavHandler(http, user, viaCookie);
        try
        {
            if (serverRoot)
            {
                await handler.ServerRootAsync();
                return;
            }
            var target = handler.ParseTarget(RawSegments(http, SegmentCount(http.Request.PathBase.Value)));
            if (target.Mount?.Storage.Impersonate == true)
            {
                if (!OperatingSystem.IsWindows() || !user.CanImpersonate)
                    throw new DavException(StatusCodes.Status403Forbidden,
                        message: viaCookie
                            ? "This folder is accessed as your Windows account, which the web browser cannot do. Connect to it with a WebDAV client."
                            : "This folder is accessed as your Windows account: sign in with your Windows password (not an app password).");
                await WindowsIdentity.RunImpersonatedAsync(user.WindowsToken!, () => handler.DispatchAsync(target));
            }
            else
            {
                await handler.DispatchAsync(target);
            }
        }
        catch (Exception ex) when (!http.Response.HasStarted && Translate(ex) is { } dav)
        {
            http.Response.Clear();
            http.Response.Headers["DAV"] = DavCapabilities;
            if (dav.ContentRange != null) http.Response.Headers.ContentRange = dav.ContentRange;
            if (dav.Precondition != null)
            {
                await DavXml.WriteAsync(http.Response, dav.Status, DavXml.Error(dav.Precondition, dav.Detail), http.RequestAborted);
            }
            else
            {
                if (dav.Status == StatusCodes.Status405MethodNotAllowed) http.Response.Headers.Allow = AllowedMethods;
                await WritePlainAsync(http, dav.Status, dav.Status >= 400 ? dav.Message : null);
            }
            var log = services.GetRequiredService<ILoggerFactory>().CreateLogger("Nullify.WebDav.Dav");
            if (ex is DavException) log.LogDebug("{Method} {Path} -> {Status}: {Message}", http.Request.Method, http.Request.Path, dav.Status, dav.Message);
            else log.LogInformation("{Method} {Path} -> {Status}: {Message}", http.Request.Method, http.Request.Path, dav.Status, ex.Message);
        }
    }

    /// <summary>Maps file system errors to the closest WebDAV status.</summary>
    private static DavException? Translate(Exception ex) => ex switch
    {
        DavException dav => dav,
        UnauthorizedAccessException => new DavException(StatusCodes.Status403Forbidden, message: "Access denied by the file system."),
        FileNotFoundException => new DavException(StatusCodes.Status404NotFound),
        DirectoryNotFoundException => new DavException(StatusCodes.Status409Conflict, message: "A parent folder does not exist."),
        PathTooLongException => new DavException(StatusCodes.Status414UriTooLong),
        IOException io when IsDiskFull(io) => new DavException(StatusCodes.Status507InsufficientStorage),
        IOException io when (io.HResult & 0xFFFF) is 0x20 or 0x21 => new DavException(StatusCodes.Status423Locked, message: "The file is in use."),
        _ => null,
    };

    private static bool IsDiskFull(IOException ex) => (ex.HResult & 0xFFFF) is 0x70 or 0x27 || ex.HResult == 28 /* ENOSPC */;

    private static bool IsLocal(IPAddress? address) => address == null || IPAddress.IsLoopback(address);

    private static async Task WritePlainAsync(HttpContext http, int status, string? message)
    {
        http.Response.StatusCode = status;
        if (string.IsNullOrEmpty(message)) return;
        http.Response.ContentType = "text/plain; charset=utf-8";
        await http.Response.WriteAsync(message, http.RequestAborted);
    }

    private static async Task<(DavPrincipal? User, bool ViaCookie)> AuthenticateAsync(HttpContext http, CredentialValidator validator)
    {
        var header = http.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            byte[] bytes;
            try { bytes = Convert.FromBase64String(header[6..].Trim()); }
            catch (FormatException) { return (null, false); }
            // Most clients send UTF-8; older Windows clients use the ANSI code page.
            var decoded = Encoding.UTF8.GetString(bytes);
            if (decoded.Contains('�')) decoded = Encoding.Latin1.GetString(bytes);
            var colon = decoded.IndexOf(':');
            if (colon <= 0) return (null, false);
            var clientKey = "dav:" + (http.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return (await validator.ValidateAsync(decoded[..colon], decoded[(colon + 1)..], clientKey, LoginPurpose.Dav, http.RequestAborted), false);
        }

        // A signed-in browser may read (open links, download); the file manager may also change things, because its
        // requests carry a header that a cross-site page cannot send without a CORS preflight, which is never granted.
        if (HttpMethods.IsGet(http.Request.Method) || HttpMethods.IsHead(http.Request.Method) || IsFileManagerRequest(http.Request))
        {
            var result = await http.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (result.Succeeded) return (DavPrincipal.FromClaims(result.Principal!), true);
        }
        return (null, false);
    }

    /// <summary>A same-origin request from the browser file manager (see <see cref="Shared.ApiHeaders"/>).</summary>
    public static bool IsFileManagerRequest(HttpRequest request)
    {
        if (request.Headers[Shared.ApiHeaders.Request] != Shared.ApiHeaders.RequestValue) return false;
        var site = request.Headers["Sec-Fetch-Site"].ToString();
        if (site.Length > 0 && site != "same-origin") return false;
        var origin = request.Headers.Origin.ToString();
        return origin.Length == 0 || origin.Equals($"{request.Scheme}://{request.Host}", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A person navigating a browser tab, as opposed to a WebDAV client fetching a file.</summary>
    private static bool IsBrowserNavigation(HttpRequest request)
    {
        if (!HttpMethods.IsGet(request.Method)) return false;
        var dest = request.Headers["Sec-Fetch-Dest"].ToString();
        if (dest.Length > 0) return dest == "document";
        return request.Headers.Accept.ToString().Contains("text/html", StringComparison.OrdinalIgnoreCase) &&
               request.Headers.UserAgent.ToString().StartsWith("Mozilla/", StringComparison.Ordinal);
    }

    /// <summary>The application's base path (the DAV path base without "/dav").</summary>
    private static string AppBase(string? davPathBase)
    {
        var b = (davPathBase ?? "").TrimEnd('/');
        return b.EndsWith("/dav", StringComparison.OrdinalIgnoreCase) ? b[..^4] : b;
    }

    // ------------------------------------------------------------------ URL handling

    private static int SegmentCount(string? path) => (path ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries).Length;

    /// <summary>Decoded segments of the raw request target, after skipping the path base.</summary>
    private static string[] RawSegments(HttpContext http, int skip)
    {
        var raw = http.Features.Get<IHttpRequestFeature>()?.RawTarget;
        string path;
        if (string.IsNullOrEmpty(raw)) path = (http.Request.PathBase + http.Request.Path).ToUriComponent();
        else if (raw[0] == '/') path = raw;
        else if (Uri.TryCreate(raw, UriKind.Absolute, out var abs)) path = abs.AbsolutePath;
        else path = (http.Request.PathBase + http.Request.Path).ToUriComponent();
        return SplitEscaped(path).Skip(skip).ToArray();
    }

    private static IEnumerable<string> SplitEscaped(string path)
    {
        var q = path.IndexOfAny(['?', '#']);
        if (q >= 0) path = path[..q];
        return path.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Uri.UnescapeDataString);
    }

    private DavTarget ParseTarget(string[] segments)
    {
        if (segments.Length == 0) return new DavTarget();
        var mount = _mounts.Resolve(_user, segments[0]) ?? throw new DavException(StatusCodes.Status404NotFound);
        var rest = segments[1..];
        if (!rest.All(PathSafety.IsSafeSegment))
            throw new DavException(StatusCodes.Status400BadRequest, message: "The name contains characters that are not allowed.");
        var physical = PathSafety.Combine(mount.BasePath, rest) ?? throw new DavException(StatusCodes.Status403Forbidden);
        if (!mount.Storage.FollowSymlinks && PathSafety.CrossesLink(mount.Storage.Root, physical))
            throw new DavException(StatusCodes.Status403Forbidden, message: "Symbolic links are not followed on this storage.");
        return new DavTarget { Mount = mount, MountSegment = segments[0], Segments = rest, Physical = physical };
    }

    /// <summary>Resolves an absolute or server-relative URL (Destination, If resource tags); null when it is not ours.</summary>
    private DavTarget? TryParseUrl(string url)
    {
        string path;
        if (Uri.TryCreate(url, UriKind.Absolute, out var abs) && abs.Scheme is "http" or "https") path = abs.AbsolutePath;
        else if (url.StartsWith('/')) path = url;
        else return null;
        var segments = SplitEscaped(path).ToArray();
        var prefix = SplitEscaped(_base).ToArray();
        if (segments.Length < prefix.Length || !prefix.Zip(segments).All(p => Names.Eq(p.First, p.Second))) return null;
        try { return ParseTarget(segments[prefix.Length..]); }
        catch (DavException) { return null; }
    }

    private string Href(DavTarget t, bool collection) => HrefFor(t.MountSegment, t.Segments, collection);

    private string HrefFor(string mountSegment, IEnumerable<string> segments, bool collection)
    {
        var sb = new StringBuilder(_base).Append('/');
        if (mountSegment.Length == 0) return sb.ToString();
        sb.Append(Uri.EscapeDataString(mountSegment));
        foreach (var s in segments) sb.Append('/').Append(Uri.EscapeDataString(s));
        if (collection) sb.Append('/');
        return sb.ToString();
    }

    private static string ChildHref(string parentHref, string name, bool collection) =>
        (parentHref.EndsWith('/') ? parentHref : parentHref + "/") + Uri.EscapeDataString(name) + (collection ? "/" : "");

    // ------------------------------------------------------------------ Dispatch

    private async Task DispatchAsync(DavTarget target)
    {
        var method = Request.Method.ToUpperInvariant();
        if (!target.IsRoot) EnsureMountFolder(target.Mount!);

        switch (method)
        {
            case "GET":
            case "HEAD":
                await GetAsync(target, head: method == "HEAD");
                break;
            case "PROPFIND":
                await PropfindAsync(target);
                break;
            case "PROPPATCH":
                await ProppatchAsync(target);
                break;
            case "PUT":
                await PutAsync(target);
                break;
            case "DELETE":
                await DeleteAsync(target);
                break;
            case "MKCOL":
                await MkcolAsync(target);
                break;
            case "COPY":
                await CopyMoveAsync(target, move: false);
                break;
            case "MOVE":
                await CopyMoveAsync(target, move: true);
                break;
            case "LOCK":
                await LockAsync(target);
                break;
            case "UNLOCK":
                await UnlockAsync(target);
                break;
            default:
                throw new DavException(StatusCodes.Status405MethodNotAllowed);
        }
    }

    /// <summary>Creates a missing mount folder when the mount allows it (per-user home folders).</summary>
    private void EnsureMountFolder(MountAccess mount)
    {
        if (Directory.Exists(mount.BasePath)) return;
        if (mount.Share != null) throw new DavException(StatusCodes.Status404NotFound, message: "The shared folder no longer exists.");
        if (!mount.Mount.CreateMissing || mount.Storage.ReadOnly)
            throw new DavException(StatusCodes.Status404NotFound, message: "The folder for this mount does not exist.");
        if (!Directory.Exists(mount.Storage.Root))
            throw new DavException(StatusCodes.Status404NotFound, message: "The storage root does not exist.");
        Directory.CreateDirectory(mount.BasePath);
        _log.LogInformation("Created folder {Path} for mount {Mount} (user {User})", mount.BasePath, mount.Mount.Name, _user.Username);
    }

    private static void RequireWrite(DavTarget t)
    {
        if (t.IsRoot || !t.Mount!.CanWrite)
            throw new DavException(StatusCodes.Status403Forbidden, message: "You have read-only access here.");
    }

    // ------------------------------------------------------------------ If header and lock enforcement

    private IfHeader? If
    {
        get
        {
            if (_if != null) return _if;
            var raw = Request.Headers["If"].ToString();
            if (string.IsNullOrWhiteSpace(raw)) return null;
            _if = IfHeader.Parse(raw) ?? throw new DavException(StatusCodes.Status400BadRequest, message: "Malformed If header.");
            return _if;
        }
    }

    /// <summary>Evaluates the If header (412 when no list matches).</summary>
    private void CheckIfHeader(DavTarget target)
    {
        var header = If;
        if (header == null) return;
        foreach (var list in header.Lists)
        {
            string? path = null;
            if (list.Resource == null) path = target.IsRoot ? null : target.Physical;
            else if (TryParseUrl(list.Resource) is { IsRoot: false } tagged) path = tagged.Physical;

            var etag = path == null ? null : ETagOf(path);
            var ok = list.Conditions.All(c =>
            {
                var match = c.Token != null
                    ? path != null && _locks.Covering(path).Any(l => l.Token == c.Token)
                    : IfHeader.ETagMatches(etag, c.ETag!);
                return match != c.Not;
            });
            if (ok) return;
        }
        throw new DavException(StatusCodes.Status412PreconditionFailed);
    }

    /// <summary>423 unless the client submitted the token of every lock, and owns each of them.</summary>
    private void RequireUnlocked(IEnumerable<DavLock> locks)
    {
        var submitted = If?.SubmittedTokens.ToHashSet(StringComparer.Ordinal) ?? [];
        foreach (var l in locks.DistinctBy(l => l.Token))
        {
            if (submitted.Contains(l.Token) && Names.Eq(l.Principal, _user.Username)) continue;
            throw new DavException(StatusCodes.Status423Locked, D + "lock-token-submitted", detail: DavXml.Href(l.RootHref));
        }
    }

    private IEnumerable<DavLock> MemberLocks(DavTarget t) =>
        t.IsMountRoot ? _locks.Covering(t.Physical) : _locks.Covering(t.Physical).Concat(_locks.Covering(t.Parent));

    // ------------------------------------------------------------------ Shared helpers

    private static string? ETagOf(string path)
    {
        if (File.Exists(path)) return ETag(new FileInfo(path));
        if (Directory.Exists(path)) return ETag(new DirectoryInfo(path));
        return null;
    }

    private static string ETag(FileSystemInfo info) => info is FileInfo f
        ? $"\"{f.LastWriteTimeUtc.Ticks:x}-{f.Length:x}\""
        : $"\"{info.LastWriteTimeUtc.Ticks:x}\"";

    private static EnumerationOptions ListOptions => new()
    {
        AttributesToSkip = 0,
        IgnoreInaccessible = true,
        RecurseSubdirectories = false,
        ReturnSpecialDirectories = false,
    };

    /// <summary>Children that may be shown and addressed: unsafe names, upload temp files and (optionally) links are hidden.</summary>
    private static IEnumerable<FileSystemInfo> Children(DirectoryInfo dir, StorageConfig storage) =>
        dir.EnumerateFileSystemInfos("*", ListOptions)
            .Where(i => PathSafety.IsSafeSegment(i.Name) && (storage.FollowSymlinks || !PathSafety.IsLink(i)));
}
