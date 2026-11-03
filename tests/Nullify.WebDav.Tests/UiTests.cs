// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Nullify.WebDav.Configuration;
using static Nullify.WebDav.Tests.TestHost;

namespace Nullify.WebDav.Tests;

[TestClass]
public sealed partial class UiTests
{
    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex TokenRegex();

    /// <summary>A browser-like client (HTTPS, so the Secure cookie is kept) signed in through the login form.</summary>
    private static async Task<HttpClient> SignInAsync(string user, string password)
    {
        var factory = await GetAsync();
        var c = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        var resp = await PostFormAsync(c, "/account/login", new() { ["Username"] = user, ["Password"] = password });
        Assert.AreEqual(HttpStatusCode.Redirect, resp.StatusCode, await resp.Content.ReadAsStringAsync());
        return c;
    }

    private static async Task<HttpResponseMessage> PostFormAsync(HttpClient c, string url, Dictionary<string, string> fields)
    {
        var page = await c.GetStringAsync(url);
        fields["__RequestVerificationToken"] = WebUtility.HtmlDecode(TokenRegex().Match(page).Groups[1].Value);
        return await c.PostAsync(url, new FormUrlEncodedContent(fields));
    }

    [TestMethod]
    public async Task AdminCreatesMountWithEmptyOptionalFields()
    {
        var c = await SignInAsync("alice", "alice-password");
        var name = "ui" + Guid.NewGuid().ToString("N")[..8];
        var resp = await PostFormAsync(c, "/admin/mounts/edit", new()
        {
            ["MountName"] = name, ["Description"] = "", ["Storage"] = "files", ["MountPath"] = "ui/{user}", ["CreateMissing"] = "true",
            ["Rules[0].Order"] = "1", ["Rules[0].Users"] = "dave", ["Rules[0].Groups"] = "", ["Rules[0].Access"] = "Read", ["Rules[0].Path"] = "",
            ["Rules[1].Order"] = "2", ["Rules[1].Users"] = "", ["Rules[1].Groups"] = "", ["Rules[1].Access"] = "ReadWrite", ["Rules[1].Path"] = "",
        });
        Assert.AreEqual(HttpStatusCode.Redirect, resp.StatusCode, await resp.Content.ReadAsStringAsync());

        var store = (await GetAsync()).Services.GetRequiredService<ConfigStore>();
        var mount = store.Current.Mounts.Single(m => m.Name == name);
        Assert.AreEqual("", mount.Description);
        Assert.HasCount(1, mount.Rules, "empty rows are dropped");
        Assert.AreEqual(AccessLevel.Read, mount.Rules[0].Access);
        Assert.IsNull(mount.Rules[0].Path);

        var dave = await ClientAsync("dave", "imap-secret");
        var (status, _, _) = await SendAsync(dave, "PROPFIND", $"/dav/{name}/", null, ("Depth", "0"));
        Assert.AreEqual(HttpStatusCode.MultiStatus, status, "takes effect without a restart");
        Assert.IsTrue(Directory.Exists(Path.Combine(FilesDir, "ui", "dave")));
    }

    [TestMethod]
    public async Task NonAdminsCannotReachAdminPages()
    {
        var c = await SignInAsync("bob", "bob-password");
        var overview = await c.GetStringAsync("/");
        StringAssert.Contains(overview, "Hello, Bob");
        StringAssert.Contains(overview, "/dav/~/");
        var admin = await c.GetAsync("/admin/settings");
        Assert.AreEqual(HttpStatusCode.Redirect, admin.StatusCode);
        StringAssert.Contains(admin.Headers.Location!.ToString(), "/account/denied");
    }

    [TestMethod]
    public async Task SignedInBrowserCanReadButNotWriteThroughDav()
    {
        var c = await SignInAsync("bob", "bob-password");
        Assert.AreEqual(HttpStatusCode.OK, (await c.GetAsync("/dav/shared/")).StatusCode);
        var put = await c.PutAsync("/dav/shared/x.txt", new StringContent("x"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, put.StatusCode, "changes need Basic credentials");
    }

    [TestMethod]
    public async Task AppPasswordsDoNotSignInToTheUi()
    {
        var factory = await GetAsync();
        var c = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        var resp = await PostFormAsync(c, "/account/login", new() { ["Username"] = "bob", ["Password"] = AppPassword });
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        StringAssert.Contains(await resp.Content.ReadAsStringAsync(), "Invalid username or password");
    }
}
