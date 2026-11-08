// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Shared;
using static Nullify.WebDav.Tests.TestHost;

namespace Nullify.WebDav.Tests;

/// <summary>The browser file manager: how it is served, how it may write, and its API including sharing.</summary>
[TestClass]
public sealed partial class FileManagerTests
{
    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex TokenRegex();

    private static readonly XNamespace D = "DAV:";

    /// <summary>A browser signed in through the login form, sending the file manager's header like the real app.</summary>
    private static async Task<HttpClient> BrowserAsync(string user, string password, bool appHeader = true)
    {
        var factory = await GetAsync();
        var c = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        var page = await c.GetStringAsync("/account/login");
        var token = WebUtility.HtmlDecode(TokenRegex().Match(page).Groups[1].Value);
        var resp = await c.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Username"] = user, ["Password"] = password, ["__RequestVerificationToken"] = token,
        }));
        Assert.AreEqual(HttpStatusCode.Redirect, resp.StatusCode);
        if (appHeader) c.DefaultRequestHeaders.Add(ApiHeaders.Request, ApiHeaders.RequestValue);
        return c;
    }

    private static string Unique(string name) => $"{name}-{Guid.NewGuid():N}"[..(name.Length + 9)];

    private static async Task<HttpStatusCode> MkcolAsync(HttpClient c, string url) =>
        (await SendAsync(c, "MKCOL", url)).Status;

    private static async Task<ShareInfo> ShareAsync(HttpClient c, ShareRequest request)
    {
        var resp = await c.PostAsJsonAsync("/api/shares", request, ApiJson.Default.ShareRequest);
        Assert.AreEqual(HttpStatusCode.Created, resp.StatusCode, await resp.Content.ReadAsStringAsync());
        return (await resp.Content.ReadFromJsonAsync(ApiJson.Default.ShareInfo))!;
    }

    private static async Task<string> ShareErrorAsync(HttpClient c, ShareRequest request)
    {
        var resp = await c.PostAsJsonAsync("/api/shares", request, ApiJson.Default.ShareRequest);
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode);
        return (await resp.Content.ReadFromJsonAsync(ApiJson.Default.ApiError))!.Error;
    }

    private static string Seg(string name, string owner) => Uri.EscapeDataString($"{name} ({owner})");

    // ------------------------------------------------------------------ serving the app

    [TestMethod]
    public async Task SignInLandsOnTheFileManager()
    {
        var factory = await GetAsync();
        var c = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        var page = await c.GetStringAsync("/account/login");
        var token = WebUtility.HtmlDecode(TokenRegex().Match(page).Groups[1].Value);
        var resp = await c.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Username"] = "bob", ["Password"] = "bob-password", ["__RequestVerificationToken"] = token,
        }));
        Assert.AreEqual("/dav/", resp.Headers.Location!.ToString());

        var app = await c.GetAsync("/dav/");
        Assert.AreEqual(HttpStatusCode.OK, app.StatusCode);
        Assert.AreEqual("text/html", app.Content.Headers.ContentType!.MediaType);
        var html = await app.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "_framework/blazor.webassembly.js");
        StringAssert.Contains(html, "<base href=\"/\" />");
        StringAssert.Contains(app.Headers.GetValues("Content-Security-Policy").Single(), "'wasm-unsafe-eval'");

        // The overview with connection details stays one click away.
        var overview = await c.GetStringAsync("/");
        StringAssert.Contains(overview, "Connect your devices");
    }

    [TestMethod]
    public async Task FrameworkFilesAndStylesheetAreServed()
    {
        var c = await ClientAsync();
        foreach (var path in new[] { "/_framework/blazor.webassembly.js", "/css/app.css", "/js/files.js", "/js/theme.js", "/favicon.svg" })
            Assert.AreEqual(HttpStatusCode.OK, (await SendAsync(c, "GET", path)).Status, path);
    }

    [TestMethod]
    public async Task AnonymousBrowsersAreSentToSignInButDavClientsGetAChallenge()
    {
        var c = await ClientAsync();
        var (status, _, resp) = await SendAsync(c, "GET", "/dav/home/Docs/", null, ("Sec-Fetch-Dest", "document"));
        Assert.AreEqual(HttpStatusCode.Redirect, status);
        Assert.AreEqual("/account/login?ReturnUrl=%2Fdav%2Fhome%2FDocs%2F", resp.Headers.Location!.ToString());

        (status, _, resp) = await SendAsync(c, "GET", "/dav/home/file.txt");
        Assert.AreEqual(HttpStatusCode.Unauthorized, status);
        StringAssert.StartsWith(resp.Headers.WwwAuthenticate.ToString(), "Basic");
        (status, _, _) = await SendAsync(c, "PROPFIND", "/dav/", null, ("Depth", "0"), ("Sec-Fetch-Dest", "document"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, status);
    }

    // ------------------------------------------------------------------ writing with a browser session

    [TestMethod]
    public async Task BrowserSessionsWriteOnlyFromTheFileManager()
    {
        var plain = await BrowserAsync("bob", "bob-password", appHeader: false);
        var name = Unique("cookie") + ".txt";
        var resp = await plain.PutAsync($"/dav/home/{name}", new StringContent("x"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, resp.StatusCode, "a cookie alone never authorises changes");

        var app = await BrowserAsync("bob", "bob-password");
        resp = await app.PutAsync($"/dav/home/{name}", new StringContent("hello"));
        Assert.AreEqual(HttpStatusCode.Created, resp.StatusCode);
        Assert.AreEqual("hello", File.ReadAllText(Path.Combine(FilesDir, "home", "bob", name)));

        // A page on another site cannot borrow the session even if it managed to send the header.
        var (status, _, _) = await SendAsync(app, "DELETE", $"/dav/home/{name}", null, ("Origin", "https://evil.example"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, status);
        (status, _, _) = await SendAsync(app, "DELETE", $"/dav/home/{name}", null, ("Sec-Fetch-Site", "cross-site"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, status);
        (status, _, _) = await SendAsync(app, "DELETE", $"/dav/home/{name}", null, ("Origin", "https://localhost"), ("Sec-Fetch-Site", "same-origin"));
        Assert.AreEqual(HttpStatusCode.NoContent, status);

        // Read-only access still applies.
        (status, _, _) = await SendAsync(app, "PUT", $"/dav/shared/{name}", "x");
        Assert.AreEqual(HttpStatusCode.Forbidden, status);
    }

    [TestMethod]
    public async Task ApiNeedsSessionAndHeader()
    {
        var anonymous = await ClientAsync();
        var (status, _, _) = await SendAsync(anonymous, "GET", "/api/session", null, (ApiHeaders.Request, ApiHeaders.RequestValue));
        Assert.AreEqual(HttpStatusCode.Unauthorized, status);

        var noHeader = await BrowserAsync("bob", "bob-password", appHeader: false);
        Assert.AreEqual(HttpStatusCode.Forbidden, (await noHeader.GetAsync("/api/session")).StatusCode);

        var app = await BrowserAsync("bob", "bob-password");
        var session = (await app.GetFromJsonAsync("/api/session", ApiJson.Default.SessionInfo))!;
        Assert.AreEqual("bob", session.Username);
        Assert.AreEqual("shared", session.DefaultMount);
        Assert.AreEqual("https://localhost/dav/", session.DavUrl);
        CollectionAssert.AreEquivalent(new[] { "home", "shared" }, session.Mounts.Select(m => m.Name).ToArray());
        Assert.IsFalse(session.Mounts.Single(m => m.Name == "shared").CanWrite);
        Assert.IsTrue(session.SharingEnabled);
    }

    // ------------------------------------------------------------------ sharing

    [TestMethod]
    public async Task SharedFolderLifecycle()
    {
        var alice = await BrowserAsync("alice", "alice-password");
        var folder = Unique("Project");
        Assert.AreEqual(HttpStatusCode.Created, await MkcolAsync(alice, $"/dav/home/{folder}/"));

        var share = await ShareAsync(alice, new ShareRequest("home", folder, null, ShareAccess.ReadWrite, ["bob"], []));
        Assert.AreEqual(folder, share.Name);
        Assert.AreEqual(folder, share.Path);
        Assert.IsTrue(share.Available);

        // Bob sees it next to his mounts, over WebDAV and in the file manager.
        var bob = await ClientAsync("bob", "bob-password");
        var (_, listing, _) = await SendAsync(bob, "PROPFIND", "/dav/", null, ("Depth", "1"));
        var hrefs = XDocument.Parse(listing).Descendants(D + "href").Select(h => h.Value).ToList();
        CollectionAssert.Contains(hrefs, $"/dav/{Seg(folder, "alice")}/");
        var bobApp = await BrowserAsync("bob", "bob-password");
        var session = (await bobApp.GetFromJsonAsync("/api/session", ApiJson.Default.SessionInfo))!;
        var shared = session.SharedWithMe.Single(s => s.Name == folder);
        Assert.AreEqual("alice", shared.Owner);
        Assert.AreEqual("Alice", shared.OwnerName);
        Assert.IsTrue(shared.CanWrite);

        // He can write into it; the file lands in Alice's folder.
        var (status, _, _) = await SendAsync(bob, "PUT", $"/dav/{Seg(folder, "alice")}/from-bob.txt", "hi");
        Assert.AreEqual(HttpStatusCode.Created, status);
        Assert.IsTrue(File.Exists(Path.Combine(FilesDir, "home", "alice", folder, "from-bob.txt")));
        // The share's root cannot be removed or renamed by a recipient.
        (status, _, _) = await SendAsync(bob, "DELETE", $"/dav/{Seg(folder, "alice")}/");
        Assert.AreEqual(HttpStatusCode.Forbidden, status);

        // Carol was not invited.
        var carol = await ClientAsync("carol", "ldap-secret");
        (status, _, _) = await SendAsync(carol, "PROPFIND", $"/dav/{Seg(folder, "alice")}/", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.NotFound, status);

        // Renaming the folder keeps the share pointing at it.
        var renamed = folder + "-renamed";
        (status, _, _) = await SendAsync(alice, "MOVE", $"/dav/home/{folder}/", null, ("Destination", $"https://localhost/dav/home/{renamed}/"));
        Assert.AreEqual(HttpStatusCode.Created, status);
        (status, _, _) = await SendAsync(bob, "GET", $"/dav/{Seg(folder, "alice")}/from-bob.txt");
        Assert.AreEqual(HttpStatusCode.OK, status);
        var mine = (await alice.GetFromJsonAsync("/api/shares", ApiJson.Default.ListShareInfo))!.Single(s => s.Id == share.Id);
        Assert.AreEqual(renamed, mine.Path);

        // Read only from now on.
        var update = await alice.PutAsJsonAsync($"/api/shares/{share.Id}", new ShareRequest("", "", folder, ShareAccess.Read, ["bob"], []), ApiJson.Default.ShareRequest);
        Assert.AreEqual(HttpStatusCode.OK, update.StatusCode);
        (status, _, _) = await SendAsync(bob, "PUT", $"/dav/{Seg(folder, "alice")}/second.txt", "x");
        Assert.AreEqual(HttpStatusCode.Forbidden, status);

        // Only the owner (or an admin) can remove it; then it is gone for Bob.
        Assert.AreEqual(HttpStatusCode.NotFound, (await bobApp.DeleteAsync($"/api/shares/{share.Id}")).StatusCode);
        Assert.AreEqual(HttpStatusCode.NoContent, (await alice.DeleteAsync($"/api/shares/{share.Id}")).StatusCode);
        (status, _, _) = await SendAsync(bob, "GET", $"/dav/{Seg(folder, "alice")}/from-bob.txt");
        Assert.AreEqual(HttpStatusCode.NotFound, status);
    }

    [TestMethod]
    public async Task SharesWithGroupsAndDeletedFolders()
    {
        var alice = await BrowserAsync("alice", "alice-password");
        var folder = Unique("Team");
        await MkcolAsync(alice, $"/dav/home/{folder}/");
        await ShareAsync(alice, new ShareRequest("~", folder, "Team notes", ShareAccess.Read, [], ["directory"]));

        // Carol is in the "directory" group (her provider's default group).
        var carol = await ClientAsync("carol", "ldap-secret");
        var (status, _, _) = await SendAsync(carol, "PROPFIND", $"/dav/{Seg("Team notes", "alice")}/", null, ("Depth", "1"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, status);
        (status, _, _) = await SendAsync(carol, "PUT", $"/dav/{Seg("Team notes", "alice")}/x.txt", "x");
        Assert.AreEqual(HttpStatusCode.Forbidden, status);

        // Deleting the folder removes its share.
        (status, _, _) = await SendAsync(alice, "DELETE", $"/dav/home/{folder}/");
        Assert.AreEqual(HttpStatusCode.NoContent, status);
        var store = (await GetAsync()).Services.GetRequiredService<ConfigStore>();
        Assert.IsFalse(store.Current.Shares.Any(s => s.Name == "Team notes" && s.Owner == "alice"));
    }

    [TestMethod]
    public async Task SharingIsLimitedToWhatTheOwnerMayDo()
    {
        var bob = await BrowserAsync("bob", "bob-password");
        var folder = Unique("Pub");
        var alice = await ClientAsync("alice", "alice-password");
        Assert.AreEqual(HttpStatusCode.Created, await MkcolAsync(alice, $"/dav/shared/{folder}/"));

        // Bob can only read "shared", so he cannot hand out write access to it.
        StringAssert.Contains(await ShareErrorAsync(bob, new ShareRequest("shared", folder, null, ShareAccess.ReadWrite, ["carol"], [])), "read-only");
        var readOnly = await ShareAsync(bob, new ShareRequest("shared", folder, null, ShareAccess.Read, ["carol"], []));
        Assert.AreEqual(ShareAccess.Read, readOnly.Access);

        StringAssert.Contains(await ShareErrorAsync(bob, new ShareRequest("home", "does-not-exist", null, ShareAccess.Read, ["carol"], [])), "not found");
        StringAssert.Contains(await ShareErrorAsync(bob, new ShareRequest("home", "../alice", null, ShareAccess.Read, ["carol"], [])), "not valid");
        StringAssert.Contains(await ShareErrorAsync(bob, new ShareRequest("secret", "", null, ShareAccess.Read, ["carol"], [])), "not found");
        StringAssert.Contains(await ShareErrorAsync(bob, new ShareRequest("home", "", null, ShareAccess.Read, [], [])), "at least one");
        StringAssert.Contains(await ShareErrorAsync(bob, new ShareRequest("shared", folder, null, ShareAccess.Read, ["dave"], [])), "already have a share");

        // Shared folders cannot be shared on.
        var carolApp = await BrowserAsync("carol", "ldap-secret");
        var seg = $"{folder} (bob)";
        StringAssert.Contains(await ShareErrorAsync(carolApp, new ShareRequest(seg, "", null, ShareAccess.Read, ["dave"], [])), "cannot be shared again");

        // When the mount stops allowing shares, existing shares stop working too.
        var store = (await GetAsync()).Services.GetRequiredService<ConfigStore>();
        var carol = await ClientAsync("carol", "ldap-secret");
        Assert.AreEqual(HttpStatusCode.MultiStatus, (await SendAsync(carol, "PROPFIND", $"/dav/{Uri.EscapeDataString(seg)}/", null, ("Depth", "0"))).Status);
        await store.UpdateAsync(c => { c.Mounts.Single(m => m.Name == "shared").AllowSharing = false; });
        try
        {
            Assert.AreEqual(HttpStatusCode.NotFound, (await SendAsync(carol, "PROPFIND", $"/dav/{Uri.EscapeDataString(seg)}/", null, ("Depth", "0"))).Status);
        }
        finally
        {
            await store.UpdateAsync(c => { c.Mounts.Single(m => m.Name == "shared").AllowSharing = true; });
        }
    }

    [TestMethod]
    public async Task PeopleDirectoryListsUsersButNotTheCaller()
    {
        var bob = await BrowserAsync("bob", "bob-password");
        var people = (await bob.GetFromJsonAsync("/api/people", ApiJson.Default.PeopleDirectory))!;
        var names = people.Users.Select(u => u.Username).ToList();
        CollectionAssert.Contains(names, "alice");
        CollectionAssert.DoesNotContain(names, "bob");
        CollectionAssert.DoesNotContain(names, "mallory", "disabled accounts are hidden");
        CollectionAssert.Contains(people.Groups, "finance");
    }
}
