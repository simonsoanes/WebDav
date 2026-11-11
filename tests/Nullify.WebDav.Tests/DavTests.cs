// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Nullify.WebDav.Configuration;
using static Nullify.WebDav.Tests.TestHost;

namespace Nullify.WebDav.Tests;

[TestClass]
public sealed class DavTests
{
    private static readonly XNamespace D = "DAV:";

    [ClassInitialize]
    public static async Task Init(TestContext _) => await GetAsync();

    private static async Task<HttpClient> Alice() => await ClientAsync("alice", "alice-password");
    private static async Task<HttpClient> Bob() => await ClientAsync("bob", "bob-password");
    private static string Unique(string name) => $"{Guid.NewGuid():N}-{name}";

    private static List<string> Hrefs(string multistatus) =>
        XDocument.Parse(multistatus).Descendants(D + "href").Where(h => h.Parent?.Name == D + "response").Select(h => h.Value).ToList();

    [TestMethod]
    public async Task OptionsAdvertisesClass2WithoutCredentials()
    {
        var c = await ClientAsync();
        var (status, _, resp) = await SendAsync(c, "OPTIONS", "/dav/");
        Assert.AreEqual(HttpStatusCode.OK, status);
        Assert.AreEqual("1, 2", resp.Headers.GetValues("DAV").Single());
        StringAssert.Contains(string.Join(",", resp.Content.Headers.Allow), "LOCK");
    }

    [TestMethod]
    public async Task RequestsWithoutValidCredentialsAreChallenged()
    {
        var (status, _, resp) = await SendAsync(await ClientAsync(), "PROPFIND", "/dav/", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, status);
        StringAssert.StartsWith(resp.Headers.WwwAuthenticate.ToString(), "Basic");

        (status, _, _) = await SendAsync(await ClientAsync("alice", "wrong"), "PROPFIND", "/dav/", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, status);
        (status, _, _) = await SendAsync(await ClientAsync("mallory", "mallory-password"), "PROPFIND", "/dav/", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, status, "disabled users cannot sign in");
    }

    [TestMethod]
    public async Task RootListsOnlyAccessibleMounts()
    {
        var (status, body, _) = await SendAsync(await Bob(), "PROPFIND", "/dav/", null, ("Depth", "1"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);
        CollectionAssert.AreEquivalent(new[] { "/dav/", "/dav/home/", "/dav/shared/" }, Hrefs(body));

        (_, body, _) = await SendAsync(await Alice(), "PROPFIND", "/dav/", null, ("Depth", "1"));
        CollectionAssert.AreEquivalent(new[] { "/dav/", "/dav/home/", "/dav/shared/", "/dav/teams/" }, Hrefs(body));

        var (secret, _, _) = await SendAsync(await Alice(), "PROPFIND", "/dav/secret/", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.NotFound, secret, "a None rule hides the mount");
    }

    [TestMethod]
    public async Task PutGetHeadAndConditionalRequests()
    {
        var c = await Alice();
        // Its own folder: other tests upload to the home folder at the same time, and leave temp files there while they do.
        var dir = Unique("cond");
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(c, "MKCOL", $"/dav/home/{dir}/")).Status);
        var name = dir + "/hello.txt";
        var (put, _, putResp) = await SendAsync(c, "PUT", $"/dav/home/{name}", "Hello, world");
        Assert.AreEqual(HttpStatusCode.Created, put);
        var etag = putResp.Headers.ETag!.Tag;
        Assert.IsTrue(File.Exists(Path.Combine(FilesDir, "home", "alice", dir, "hello.txt")), "home/{user} resolves per user");

        var (get, body, getResp) = await SendAsync(c, "GET", $"/dav/home/{name}");
        Assert.AreEqual(HttpStatusCode.OK, get);
        Assert.AreEqual("Hello, world", body);
        Assert.AreEqual(etag, getResp.Headers.ETag!.Tag);
        StringAssert.Contains(getResp.Headers.GetValues("Content-Security-Policy").Single(), "sandbox");

        var (range, part, rangeResp) = await SendAsync(c, "GET", $"/dav/home/{name}", null, ("Range", "bytes=7-"));
        Assert.AreEqual(HttpStatusCode.PartialContent, range);
        Assert.AreEqual("world", part);
        Assert.AreEqual("bytes 7-11/12", rangeResp.Content.Headers.ContentRange!.ToString());

        var (notModified, _, _) = await SendAsync(c, "GET", $"/dav/home/{name}", null, ("If-None-Match", etag));
        Assert.AreEqual(HttpStatusCode.NotModified, notModified);

        var (head, headBody, headResp) = await SendAsync(c, "HEAD", $"/dav/home/{name}");
        Assert.AreEqual(HttpStatusCode.OK, head);
        Assert.AreEqual("", headBody);
        Assert.AreEqual(12, headResp.Content.Headers.ContentLength);

        var (overwrite, _, _) = await SendAsync(c, "PUT", $"/dav/home/{name}", "changed", ("If-Match", etag));
        Assert.AreEqual(HttpStatusCode.NoContent, overwrite);
        var (stale, _, _) = await SendAsync(c, "PUT", $"/dav/home/{name}", "again", ("If-Match", etag));
        Assert.AreEqual(HttpStatusCode.PreconditionFailed, stale);
        var (createOnly, _, _) = await SendAsync(c, "PUT", $"/dav/home/{name}", "again", ("If-None-Match", "*"));
        Assert.AreEqual(HttpStatusCode.PreconditionFailed, createOnly);

        Assert.AreEqual(0, Directory.GetFiles(Path.Combine(FilesDir, "home", "alice", dir), ".nullify-upload-*").Length, "no temp files left behind");
    }

    [TestMethod]
    public async Task UsersCannotSeeEachOthersHomeFolders()
    {
        var name = Unique("private.txt");
        await SendAsync(await Alice(), "PUT", $"/dav/home/{name}", "alice only");
        var (status, _, _) = await SendAsync(await Bob(), "GET", $"/dav/home/{name}");
        Assert.AreEqual(HttpStatusCode.NotFound, status);
    }

    [TestMethod]
    public async Task ReadOnlyRuleBlocksWrites()
    {
        var name = Unique("notes.txt");
        var (alice, _, _) = await SendAsync(await Alice(), "PUT", $"/dav/shared/{name}", "from alice");
        Assert.AreEqual(HttpStatusCode.Created, alice);

        var bob = await Bob();
        var (read, body, _) = await SendAsync(bob, "GET", $"/dav/shared/{name}");
        Assert.AreEqual(HttpStatusCode.OK, read);
        Assert.AreEqual("from alice", body);
        foreach (var (method, extra) in new[] { ("PUT", ""), ("DELETE", ""), ("MKCOL", "-dir"), ("PROPPATCH", "") })
        {
            var (status, _, _) = await SendAsync(bob, method, $"/dav/shared/{name}{extra}", method == "PUT" ? "bob" : null);
            Assert.AreEqual(HttpStatusCode.Forbidden, status, method);
        }

        var (_, props, _) = await SendAsync(bob, "PROPFIND", $"/dav/shared/{name}",
            "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-privilege-set/></d:prop></d:propfind>", ("Depth", "0"));
        Assert.IsFalse(props.Contains("write-content"), props);
    }

    [TestMethod]
    public async Task GroupRuleMapsToItsOwnPath()
    {
        var name = Unique("budget.txt");
        var (status, _, _) = await SendAsync(await Alice(), "PUT", $"/dav/teams/{name}", "numbers");
        Assert.AreEqual(HttpStatusCode.Created, status);
        Assert.IsTrue(File.Exists(Path.Combine(FilesDir, "teams", "finance", name)), "the finance rule's path is used");
        Assert.IsFalse(File.Exists(Path.Combine(FilesDir, "teams", "general", name)));
    }

    [TestMethod]
    public async Task TildeIsTheUsersDefaultMount()
    {
        var name = Unique("default.txt");
        await SendAsync(await Alice(), "PUT", $"/dav/~/{name}", "x");
        Assert.IsTrue(File.Exists(Path.Combine(FilesDir, "home", "alice", name)), "server default (home)");

        var (status, body, _) = await SendAsync(await Bob(), "PROPFIND", "/dav/~/", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);
        Assert.AreEqual("/dav/~/", Hrefs(body).Single(), "hrefs keep the alias the client used");
        var (shared, _, _) = await SendAsync(await Bob(), "PUT", $"/dav/~/{name}", "x");
        Assert.AreEqual(HttpStatusCode.Forbidden, shared, "bob's default is the read-only shared mount");
    }

    [TestMethod]
    public async Task TraversalAndUnsafeNamesAreRejected()
    {
        var c = await Alice();
        File.WriteAllText(Path.Combine(FilesDir, "outside.txt"), "top secret");
        foreach (var url in new[] { "/dav/home/..%2F..%2Foutside.txt", "/dav/home/%2e%2e/%2e%2e/outside.txt", "/dav/home/a%5C..%5C..%5Coutside.txt" })
        {
            var (status, body, _) = await SendAsync(c, "GET", url);
            Assert.IsTrue(status is HttpStatusCode.BadRequest or HttpStatusCode.NotFound or HttpStatusCode.Forbidden, $"{url} -> {status}");
            Assert.IsFalse(body.Contains("top secret"), url);
        }
        var (temp, _, _) = await SendAsync(c, "PUT", "/dav/home/.nullify-upload-evil.tmp", "x");
        Assert.AreEqual(HttpStatusCode.BadRequest, temp, "internal temp names are reserved");
        if (OperatingSystem.IsWindows())
        {
            var (ads, _, _) = await SendAsync(c, "PUT", "/dav/home/file.txt%3Astream", "x");
            Assert.AreEqual(HttpStatusCode.BadRequest, ads, "NTFS alternate data streams");
            var (device, _, _) = await SendAsync(c, "PUT", "/dav/home/NUL.txt", "x");
            Assert.AreEqual(HttpStatusCode.BadRequest, device, "device names");
        }
    }

    [TestMethod]
    public async Task SymlinksAreNotFollowedByDefault()
    {
        var outside = NewTempDir("outside");
        File.WriteAllText(Path.Combine(outside, "secret.txt"), "outside the root");
        var home = Path.Combine(FilesDir, "home", "alice");
        Directory.CreateDirectory(home);
        var link = Path.Combine(home, Unique("link"));
        try { Directory.CreateSymbolicLink(link, outside); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Assert.Inconclusive("Creating symbolic links is not permitted here: " + ex.Message);
        }
        var c = await Alice();
        var (status, _, _) = await SendAsync(c, "GET", $"/dav/home/{Path.GetFileName(link)}/secret.txt");
        Assert.AreEqual(HttpStatusCode.Forbidden, status);
        var (_, listing, _) = await SendAsync(c, "PROPFIND", "/dav/home/", null, ("Depth", "1"));
        Assert.IsFalse(listing.Contains(Path.GetFileName(link)), "links are hidden from listings");
    }

    [TestMethod]
    public async Task CollectionsCopyMoveAndDelete()
    {
        var c = await Alice();
        var dir = Unique("folder");
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(c, "MKCOL", $"/dav/home/{dir}")).Status);
        Assert.AreEqual(HttpStatusCode.MethodNotAllowed, (await SendAsync(c, "MKCOL", $"/dav/home/{dir}")).Status);
        Assert.AreEqual(HttpStatusCode.Conflict, (await SendAsync(c, "MKCOL", $"/dav/home/{dir}/missing/child")).Status);
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(c, "PUT", $"/dav/home/{dir}/a.txt", "A")).Status);
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(c, "MKCOL", $"/dav/home/{dir}/sub")).Status);
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(c, "PUT", $"/dav/home/{dir}/sub/b.txt", "B")).Status);

        var (copy, _, _) = await SendAsync(c, "COPY", $"/dav/home/{dir}/", null, ("Destination", $"http://localhost/dav/home/{dir}-copy/"));
        Assert.AreEqual(HttpStatusCode.Created, copy);
        Assert.AreEqual("B", (await SendAsync(c, "GET", $"/dav/home/{dir}-copy/sub/b.txt")).Body);

        var (noOverwrite, _, _) = await SendAsync(c, "COPY", $"/dav/home/{dir}/a.txt", null,
            ("Destination", $"/dav/home/{dir}-copy/a.txt"), ("Overwrite", "F"));
        Assert.AreEqual(HttpStatusCode.PreconditionFailed, noOverwrite);

        var (intoItself, _, _) = await SendAsync(c, "MOVE", $"/dav/home/{dir}/", null, ("Destination", $"/dav/home/{dir}/sub/x/"));
        Assert.AreEqual(HttpStatusCode.Forbidden, intoItself);

        // Across mounts: home -> shared.
        var (move, _, _) = await SendAsync(c, "MOVE", $"/dav/home/{dir}-copy/", null, ("Destination", $"/dav/shared/{dir}-moved/"));
        Assert.AreEqual(HttpStatusCode.Created, move);
        Assert.IsTrue(Directory.Exists(Path.Combine(FilesDir, "shared", dir + "-moved", "sub")));
        Assert.IsFalse(Directory.Exists(Path.Combine(FilesDir, "home", "alice", dir + "-copy")));

        var (rename, _, _) = await SendAsync(c, "MOVE", $"/dav/home/{dir}/a.txt", null, ("Destination", $"/dav/home/{dir}/renamed.txt"));
        Assert.AreEqual(HttpStatusCode.Created, rename);
        Assert.AreEqual("A", (await SendAsync(c, "GET", $"/dav/home/{dir}/renamed.txt")).Body);

        var (outside, _, _) = await SendAsync(c, "COPY", $"/dav/home/{dir}/renamed.txt", null, ("Destination", "https://elsewhere.example/other/x.txt"));
        Assert.AreEqual(HttpStatusCode.BadGateway, outside);

        Assert.AreEqual(HttpStatusCode.NoContent, (await SendAsync(c, "DELETE", $"/dav/home/{dir}/")).Status);
        Assert.IsFalse(Directory.Exists(Path.Combine(FilesDir, "home", "alice", dir)));
        Assert.AreEqual(HttpStatusCode.Forbidden, (await SendAsync(c, "DELETE", "/dav/home/")).Status, "mount roots cannot be deleted");
    }

    [TestMethod]
    public async Task CaseOnlyRenameKeepsTheFile()
    {
        var c = await Alice();
        var name = Unique("case.txt");
        await SendAsync(c, "PUT", $"/dav/home/{name}", "content");
        var upper = name.ToUpperInvariant();
        var (status, _, _) = await SendAsync(c, "MOVE", $"/dav/home/{name}", null, ("Destination", $"/dav/home/{upper}"));
        Assert.IsTrue(status is HttpStatusCode.Created or HttpStatusCode.NoContent, status.ToString());
        Assert.AreEqual("content", (await SendAsync(c, "GET", $"/dav/home/{upper}")).Body);
    }

    [TestMethod]
    public async Task PropfindReportsLiveProperties()
    {
        var c = await Alice();
        var name = Unique("props.txt");
        await SendAsync(c, "PUT", $"/dav/home/{name}", "12345");
        var (status, body, _) = await SendAsync(c, "PROPFIND", $"/dav/home/{name}", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);
        var doc = XDocument.Parse(body);
        Assert.AreEqual("5", doc.Descendants(D + "getcontentlength").Single().Value);
        Assert.AreEqual("text/plain", doc.Descendants(D + "getcontenttype").Single().Value);
        Assert.IsNotNull(doc.Descendants(D + "supportedlock").SingleOrDefault());

        var (dir, dirBody, _) = await SendAsync(c, "PROPFIND", "/dav/home/",
            "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/><d:quota-available-bytes/><d:nonexistent/></d:prop></d:propfind>", ("Depth", "1"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, dir);
        StringAssert.Contains(dirBody, "HTTP/1.1 404");
        Assert.IsTrue(Hrefs(dirBody).Contains($"/dav/home/{name}"));

        var (bad, _, _) = await SendAsync(c, "PROPFIND", "/dav/home/", null, ("Depth", "2"));
        Assert.AreEqual(HttpStatusCode.BadRequest, bad);
    }

    [TestMethod]
    public async Task PropfindDepthInfinityListsTheWholeTree()
    {
        var c = await Alice();
        var top = Unique("tree");
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(c, "MKCOL", $"/dav/home/{top}/")).Status);
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(c, "MKCOL", $"/dav/home/{top}/a/")).Status);
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(c, "MKCOL", $"/dav/home/{top}/a/b c/")).Status);
        await SendAsync(c, "PUT", $"/dav/home/{top}/a/b%20c/deep.txt", "x");
        await SendAsync(c, "PUT", $"/dav/home/{top}/top.txt", "y");

        var expected = new[]
        {
            $"/dav/home/{top}/", $"/dav/home/{top}/a/", $"/dav/home/{top}/a/b%20c/", $"/dav/home/{top}/a/b%20c/deep.txt", $"/dav/home/{top}/top.txt",
        };
        var (status, body, _) = await SendAsync(c, "PROPFIND", $"/dav/home/{top}/", null, ("Depth", "infinity"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);
        CollectionAssert.AreEquivalent(expected, Hrefs(body));
        var doc = XDocument.Parse(body);
        var deep = doc.Descendants(D + "response").Single(r => r.Element(D + "href")!.Value.EndsWith("deep.txt"));
        Assert.AreEqual("1", deep.Descendants(D + "getcontentlength").Single().Value);

        // RFC 4918: no Depth header means infinity; the value is case-insensitive.
        (status, body, _) = await SendAsync(c, "PROPFIND", $"/dav/home/{top}/");
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);
        CollectionAssert.AreEquivalent(expected, Hrefs(body));
        (status, _, _) = await SendAsync(c, "PROPFIND", $"/dav/home/{top}/", null, ("Depth", "Infinity"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);

        // From /dav/ it walks every mount the user can see, and never lists mounts they cannot.
        (status, body, _) = await SendAsync(c, "PROPFIND", "/dav/", null, ("Depth", "infinity"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);
        var all = Hrefs(body);
        CollectionAssert.IsSubsetOf(expected, all);
        Assert.IsFalse(all.Any(h => h.StartsWith("/dav/secret/")));

        // The server root stays finite.
        (status, body, _) = await SendAsync(c, "PROPFIND", "/", null, ("Depth", "infinity"));
        Assert.AreEqual(HttpStatusCode.Forbidden, status);
        StringAssert.Contains(body, "propfind-finite-depth");
    }

    [TestMethod]
    [DoNotParallelize] // changes server-wide settings other PROPFIND tests depend on
    public async Task PropfindDepthInfinityIsLimited()
    {
        var c = await Alice();
        var top = Unique("big");
        await SendAsync(c, "MKCOL", $"/dav/home/{top}/");
        for (var i = 0; i < 5; i++) await SendAsync(c, "PUT", $"/dav/home/{top}/f{i}.txt", "x");
        var store = (await GetAsync()).Services.GetRequiredService<ConfigStore>();
        try
        {
            await store.UpdateAsync(cfg => cfg.Settings.MaxDepthInfinityItems = 3);
            var (status, body, _) = await SendAsync(c, "PROPFIND", $"/dav/home/{top}/", null, ("Depth", "infinity"));
            Assert.AreEqual(HttpStatusCode.Forbidden, status, "too many entries: the client should fall back to Depth: 1");
            StringAssert.Contains(body, "propfind-finite-depth");
            (status, _, _) = await SendAsync(c, "PROPFIND", $"/dav/home/{top}/", null, ("Depth", "1"));
            Assert.AreEqual(HttpStatusCode.MultiStatus, status);

            await store.UpdateAsync(cfg => { cfg.Settings.MaxDepthInfinityItems = 20_000; cfg.Settings.AllowDepthInfinity = false; });
            (status, body, _) = await SendAsync(c, "PROPFIND", $"/dav/home/{top}/", null, ("Depth", "infinity"));
            Assert.AreEqual(HttpStatusCode.Forbidden, status);
            StringAssert.Contains(body, "propfind-finite-depth");
        }
        finally
        {
            await store.UpdateAsync(cfg => { cfg.Settings.MaxDepthInfinityItems = 20_000; cfg.Settings.AllowDepthInfinity = true; });
        }
    }

    [TestMethod]
    public async Task ProppatchSetsWin32TimesAndRefusesDeadProperties()
    {
        var c = await Alice();
        var name = Unique("times.txt");
        await SendAsync(c, "PUT", $"/dav/home/{name}", "x");
        var (status, body, _) = await SendAsync(c, "PROPPATCH", $"/dav/home/{name}", """
            <d:propertyupdate xmlns:d="DAV:" xmlns:z="urn:schemas-microsoft-com:"><d:set><d:prop>
            <z:Win32LastModifiedTime>Mon, 01 Jan 2024 10:00:00 GMT</z:Win32LastModifiedTime>
            </d:prop></d:set></d:propertyupdate>
            """);
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);
        StringAssert.Contains(body, "HTTP/1.1 200");
        Assert.AreEqual(new DateTime(2024, 1, 1, 10, 0, 0, DateTimeKind.Utc), File.GetLastWriteTimeUtc(Path.Combine(FilesDir, "home", "alice", name)));

        var (_, dead, _) = await SendAsync(c, "PROPPATCH", $"/dav/home/{name}", """
            <d:propertyupdate xmlns:d="DAV:" xmlns:z="urn:schemas-microsoft-com:" xmlns:x="urn:example"><d:set><d:prop>
            <z:Win32LastModifiedTime>Tue, 02 Jan 2024 10:00:00 GMT</z:Win32LastModifiedTime><x:colour>blue</x:colour>
            </d:prop></d:set></d:propertyupdate>
            """);
        StringAssert.Contains(dead, "HTTP/1.1 403");
        StringAssert.Contains(dead, "HTTP/1.1 424");
        Assert.AreEqual(new DateTime(2024, 1, 1, 10, 0, 0, DateTimeKind.Utc), File.GetLastWriteTimeUtc(Path.Combine(FilesDir, "home", "alice", name)), "atomic: nothing applied");
    }

    [TestMethod]
    public async Task MtimeHeaderIsHonoured()
    {
        var c = await Alice();
        var name = Unique("mtime.txt");
        var (_, _, resp) = await SendAsync(c, "PUT", $"/dav/home/{name}", "x", ("X-OC-Mtime", "1700000000"));
        Assert.AreEqual("accepted", resp.Headers.GetValues("X-OC-Mtime").Single());
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(1700000000).UtcDateTime, File.GetLastWriteTimeUtc(Path.Combine(FilesDir, "home", "alice", name)));
    }

    private const string ExclusiveLock = """<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype><d:owner>tests</d:owner></d:lockinfo>""";

    [TestMethod]
    public async Task LocksProtectResourcesUntilUnlocked()
    {
        var alice = await Alice();
        var carol = await ClientAsync("carol", "ldap-secret");
        var name = Unique("locked.txt");
        var url = $"/dav/shared/{name}";

        // Locking an unmapped URL creates an empty file.
        var (status, body, resp) = await SendAsync(alice, "LOCK", url, ExclusiveLock, ("Timeout", "Second-600"));
        Assert.AreEqual(HttpStatusCode.Created, status);
        var token = resp.Headers.GetValues("Lock-Token").Single().Trim('<', '>');
        StringAssert.Contains(body, token);
        Assert.IsTrue(File.Exists(Path.Combine(FilesDir, "shared", name)));

        Assert.AreEqual(HttpStatusCode.Locked, (await SendAsync(alice, "PUT", url, "no token")).Status);
        Assert.AreEqual(HttpStatusCode.NoContent, (await SendAsync(alice, "PUT", url, "with token", ("If", $"(<{token}>)"))).Status);
        Assert.AreEqual(HttpStatusCode.Locked, (await SendAsync(carol, "PUT", url, "stolen token", ("If", $"(<{token}>)"))).Status, "tokens belong to their owner");
        Assert.AreEqual(HttpStatusCode.Locked, (await SendAsync(carol, "LOCK", url, ExclusiveLock)).Status, "exclusive locks conflict");
        Assert.AreEqual(HttpStatusCode.Locked, (await SendAsync(alice, "DELETE", url)).Status);

        var (refresh, _, _) = await SendAsync(alice, "LOCK", url, null, ("If", $"(<{token}>)"), ("Timeout", "Second-120"));
        Assert.AreEqual(HttpStatusCode.OK, refresh);

        var (discovery, props, _) = await SendAsync(carol, "PROPFIND", url, null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, discovery);
        StringAssert.Contains(props, token);

        Assert.AreEqual(HttpStatusCode.Forbidden, (await SendAsync(carol, "UNLOCK", url, null, ("Lock-Token", $"<{token}>"))).Status);
        Assert.AreEqual(HttpStatusCode.NoContent, (await SendAsync(alice, "UNLOCK", url, null, ("Lock-Token", $"<{token}>"))).Status);
        Assert.AreEqual(HttpStatusCode.NoContent, (await SendAsync(carol, "PUT", url, "carol now")).Status);
    }

    [TestMethod]
    public async Task DepthInfinityLockCoversMembers()
    {
        var alice = await Alice();
        var dir = Unique("lockdir");
        await SendAsync(alice, "MKCOL", $"/dav/home/{dir}");
        var (status, _, resp) = await SendAsync(alice, "LOCK", $"/dav/home/{dir}/", ExclusiveLock, ("Depth", "infinity"));
        Assert.AreEqual(HttpStatusCode.OK, status);
        var token = resp.Headers.GetValues("Lock-Token").Single().Trim('<', '>');

        Assert.AreEqual(HttpStatusCode.Locked, (await SendAsync(alice, "PUT", $"/dav/home/{dir}/new.txt", "x")).Status);
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(alice, "PUT", $"/dav/home/{dir}/new.txt", "x",
            ("If", $"</dav/home/{dir}/> (<{token}>)"))).Status, "tagged list naming the lock root");
        var (wrongEtag, _, _) = await SendAsync(alice, "PUT", $"/dav/home/{dir}/new.txt", "y", ("If", $"(<{token}> [\"nope\"])"));
        Assert.AreEqual(HttpStatusCode.PreconditionFailed, wrongEtag);
        Assert.AreEqual(HttpStatusCode.Locked, (await SendAsync(alice, "DELETE", $"/dav/home/{dir}/")).Status);
        Assert.AreEqual(HttpStatusCode.NoContent, (await SendAsync(alice, "DELETE", $"/dav/home/{dir}/", null, ("If", $"(<{token}>)"))).Status);
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(alice, "MKCOL", $"/dav/home/{dir}")).Status, "locks go away with the resource");
    }

    [TestMethod]
    public async Task ExternalProvidersAuthenticate()
    {
        var (carol, _, _) = await SendAsync(await ClientAsync("carol", "ldap-secret"), "PUT", $"/dav/home/{Unique("c.txt")}", "ldap");
        Assert.AreEqual(HttpStatusCode.Created, carol);
        Assert.IsTrue(Directory.Exists(Path.Combine(FilesDir, "home", "carol")));

        var (dave, _, _) = await SendAsync(await ClientAsync("dave", "imap-secret"), "PROPFIND", "/dav/home/", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, dave);

        // Not listed, accepted by the "dir" provider, which adds the "directory" group (read access to teams).
        var erin = await ClientAsync("erin", "erin-secret");
        var (_, root, _) = await SendAsync(erin, "PROPFIND", "/dav/", null, ("Depth", "1"));
        CollectionAssert.Contains(Hrefs(root), "/dav/teams/");
        Assert.AreEqual(HttpStatusCode.Forbidden, (await SendAsync(erin, "PUT", $"/dav/teams/{Unique("x")}", "x")).Status);
        Assert.AreEqual(HttpStatusCode.Created, (await SendAsync(erin, "PUT", $"/dav/home/{Unique("e.txt")}", "x")).Status);
        Assert.IsTrue(Directory.Exists(Path.Combine(FilesDir, "home", "erin")));
    }

    [TestMethod]
    public async Task UnlistedLoginsCannotUseListedNamesOrEmptyPasswords()
    {
        // alice is listed with a local password; her LDAP password must not work.
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await SendAsync(await ClientAsync("alice", "alice-ldap"), "PROPFIND", "/dav/", null, ("Depth", "0"))).Status);
        // The fake directory accepts empty passwords (an unauthenticated bind); the provider must not.
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await SendAsync(await ClientAsync("zed", ""), "PROPFIND", "/dav/", null, ("Depth", "0"))).Status);
    }

    [TestMethod]
    public async Task AppPasswordsWorkForDav()
    {
        var (status, _, _) = await SendAsync(await ClientAsync("bob", AppPassword), "PROPFIND", "/dav/", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);
    }

    [TestMethod]
    public async Task BrowsersWithBasicCredentialsAreSentToSignInAndServerRoot()
    {
        var c = await Alice();
        // The file manager needs a browser session; Basic credentials alone get the sign-in page.
        var (status, _, resp) = await SendAsync(c, "GET", "/dav/home/");
        Assert.AreEqual(HttpStatusCode.Redirect, status);
        StringAssert.Contains(resp.Headers.Location!.ToString(), "/account/login?ReturnUrl=%2Fdav%2Fhome%2F");

        var (root, body, _) = await SendAsync(c, "PROPFIND", "/", null, ("Depth", "1"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, root);
        CollectionAssert.AreEquivalent(new[] { "/", "/dav/" }, Hrefs(body));
    }

    [TestMethod]
    public async Task ManagementUiRequiresSignIn()
    {
        var c = await ClientAsync();
        var (status, _, resp) = await SendAsync(c, "GET", "/");
        Assert.AreEqual(HttpStatusCode.Redirect, status);
        StringAssert.Contains(resp.Headers.Location!.ToString(), "/account/login");
        var (login, html, _) = await SendAsync(c, "GET", "/account/login");
        Assert.AreEqual(HttpStatusCode.OK, login);
        StringAssert.Contains(html, "<h1>Nullify.WebDav</h1>");
        var (setup, _, _) = await SendAsync(c, "GET", "/setup");
        Assert.AreEqual(HttpStatusCode.Redirect, setup, "setup is closed once an administrator exists");
        Assert.AreEqual(HttpStatusCode.OK, (await SendAsync(c, "GET", "/css/app.css")).Status);
        Assert.AreEqual(HttpStatusCode.OK, (await SendAsync(c, "GET", "/health")).Status);
    }
}
