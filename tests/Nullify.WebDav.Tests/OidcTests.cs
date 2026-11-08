// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Shared;
using static Nullify.WebDav.Tests.TestHost;

namespace Nullify.WebDav.Tests;

/// <summary>Single sign-on through the "corp" OpenID Connect provider (see <see cref="FakeOidcServer"/>).</summary>
[TestClass]
public sealed class OidcTests
{
    private static string Rand() => Guid.NewGuid().ToString("N")[..8];

    /// <summary>Runs the whole browser flow: the sign-in link, the provider (faked), and the form post back.</summary>
    private static async Task<(HttpClient Browser, HttpResponseMessage Callback)> SignInAsync(Dictionary<string, object> claims, bool forged = false)
    {
        var factory = await GetAsync();
        var c = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        var challenge = await c.GetAsync("/account/external/corp");
        Assert.AreEqual(HttpStatusCode.Redirect, challenge.StatusCode);
        var authorize = challenge.Headers.Location!;
        StringAssert.StartsWith(authorize.ToString(), Oidc.Issuer + "/authorize?");
        var q = QueryHelpers.ParseQuery(authorize.Query);
        Assert.AreEqual(FakeOidcServer.ClientId, q["client_id"].ToString());
        Assert.AreEqual("code", q["response_type"].ToString());
        Assert.AreEqual("S256", q["code_challenge_method"].ToString());
        Assert.AreEqual("https://localhost/signin-oidc/corp", q["redirect_uri"].ToString());

        var code = Oidc.Issue(q["nonce"].ToString(), q["code_challenge"].ToString(), claims, forged);
        var callback = await c.PostAsync("/signin-oidc/corp", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["code"] = code, ["state"] = q["state"].ToString(),
        }));
        c.DefaultRequestHeaders.Add(ApiHeaders.Request, ApiHeaders.RequestValue);
        return (c, callback);
    }

    private static async Task<SessionInfo?> SessionAsync(HttpClient c)
    {
        var resp = await c.GetAsync("/api/session");
        return resp.IsSuccessStatusCode ? await resp.Content.ReadFromJsonAsync(ApiJson.Default.SessionInfo) : null;
    }

    private static async Task<string> LoginPageErrorAsync(HttpClient c) => await c.GetStringAsync("/account/login");

    [TestMethod]
    public async Task LoginPageOffersSingleSignOn()
    {
        var c = await ClientAsync();
        var (status, html, _) = await SendAsync(c, "GET", "/account/login");
        Assert.AreEqual(HttpStatusCode.OK, status);
        StringAssert.Contains(html, "/account/external/corp");
        StringAssert.Contains(html, "Sign in with Corp SSO");
        Assert.AreEqual(HttpStatusCode.NotFound, (await SendAsync(c, "GET", "/account/external/nope")).Status);
        Assert.AreEqual(HttpStatusCode.NotFound, (await SendAsync(c, "GET", "/account/external/dir")).Status, "password providers have no sign-in link");
    }

    [TestMethod]
    public async Task UnlistedAccountIsCreatedBoundToItsSubjectAndCanUseAppPasswords()
    {
        var name = "olivia" + Rand();
        var subject = "sub-" + Rand();
        var (browser, callback) = await SignInAsync(new()
        {
            ["sub"] = subject, ["preferred_username"] = name + "@corp.example", ["name"] = "Olivia Test", ["groups"] = new[] { "finance", "bad,group" },
        });
        Assert.AreEqual(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.AreEqual("/dav/", callback.Headers.Location!.ToString());

        var session = await SessionAsync(browser);
        Assert.IsNotNull(session);
        Assert.AreEqual(name, session.Username, "the domain is dropped");
        Assert.AreEqual("Olivia Test", session.DisplayName);
        Assert.IsFalse(session.IsAdmin);
        CollectionAssert.Contains(session.Mounts.Select(m => m.Name).ToList(), "teams", "groups from the token grant access");

        var store = (await GetAsync()).Services.GetRequiredService<ConfigStore>();
        var user = store.Current.Users.Single(u => u.Username == name);
        Assert.AreEqual("corp", user.Provider);
        Assert.AreEqual(subject, user.Login);
        CollectionAssert.AreEqual(new[] { "finance" }, user.ExternalGroups, "invalid group names are dropped");

        // WebDAV clients: no password exists, but app passwords work and keep the token's groups.
        var appPassword = PasswordHasher.GenerateToken();
        await store.UpdateAsync(c => c.Users.Single(u => u.Username == name).AppPasswords.Add(new AppPasswordConfig { Name = "laptop", Hash = PasswordHasher.Sha256(appPassword) }));
        var dav = await ClientAsync(name, appPassword);
        Assert.AreEqual(HttpStatusCode.MultiStatus, (await SendAsync(dav, "PROPFIND", "/dav/teams/", null, ("Depth", "0"))).Status);
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await SendAsync(await ClientAsync(name, "any-password"), "PROPFIND", "/dav/", null, ("Depth", "0"))).Status);

        // Signing in again with the same subject finds the same user, even under a new name at the provider.
        var (again, back) = await SignInAsync(new() { ["sub"] = subject, ["preferred_username"] = "renamed" + Rand() });
        Assert.AreEqual(HttpStatusCode.Redirect, back.StatusCode);
        Assert.AreEqual(name, (await SessionAsync(again))!.Username);
    }

    [TestMethod]
    public async Task NamesOfOtherAccountsCannotBeTaken()
    {
        var (browser, callback) = await SignInAsync(new() { ["sub"] = "sub-" + Rand(), ["preferred_username"] = "alice" });
        Assert.AreEqual("/account/login", callback.Headers.Location!.ToString());
        Assert.IsNull(await SessionAsync(browser), "no session");
        StringAssert.Contains(await LoginPageErrorAsync(browser), "already belongs to another account");
    }

    [TestMethod]
    public async Task ListedUsersAreBoundToTheFirstSubject()
    {
        // "frank" is listed for this provider without a subject; whoever signs in first as frank binds it.
        var store = (await GetAsync()).Services.GetRequiredService<ConfigStore>();
        var first = store.Current.Users.Single(u => u.Username == "frank").Login;
        var subject = string.IsNullOrEmpty(first) ? "sub-frank" : first;
        var (browser, callback) = await SignInAsync(new() { ["sub"] = subject, ["preferred_username"] = "frank" });
        Assert.AreEqual("/dav/", callback.Headers.Location!.ToString());
        Assert.AreEqual("Frank", (await SessionAsync(browser))!.DisplayName);
        Assert.AreEqual(subject, store.Current.Users.Single(u => u.Username == "frank").Login);

        var (other, refused) = await SignInAsync(new() { ["sub"] = "sub-impostor-" + Rand(), ["preferred_username"] = "frank" });
        Assert.AreEqual("/account/login", refused.Headers.Location!.ToString());
        Assert.IsNull(await SessionAsync(other));
    }

    [TestMethod]
    public async Task AdminGroupsMakeAdministrators()
    {
        var (browser, _) = await SignInAsync(new() { ["sub"] = "sub-" + Rand(), ["preferred_username"] = "ada" + Rand(), ["groups"] = new[] { "idp-admins" } });
        Assert.IsTrue((await SessionAsync(browser))!.IsAdmin);
        Assert.AreEqual(HttpStatusCode.OK, (await browser.GetAsync("/admin/settings")).StatusCode);
    }

    [TestMethod]
    public async Task ForgedOrReplayedSignInsAreRejected()
    {
        var name = "mallet" + Rand();
        var (browser, callback) = await SignInAsync(new() { ["sub"] = "sub-" + Rand(), ["preferred_username"] = name }, forged: true);
        Assert.AreEqual("/account/login", callback.Headers.Location!.ToString());
        Assert.IsNull(await SessionAsync(browser));
        var store = (await GetAsync()).Services.GetRequiredService<ConfigStore>();
        Assert.IsFalse(store.Current.Users.Any(u => u.Username == name));

        // A callback without the browser's correlation cookie (another browser, or a replay) is refused.
        var factory = await GetAsync();
        var stranger = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        var resp = await stranger.PostAsync("/signin-oidc/corp", new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = "x", ["state"] = "y" }));
        Assert.AreEqual("/account/login", resp.Headers.Location!.ToString());
    }

    [TestMethod]
    public async Task ProvidersCanBeAddedAndDisabledWithoutARestart()
    {
        var store = (await GetAsync()).Services.GetRequiredService<ConfigStore>();
        var c = await ClientAsync();
        Assert.AreEqual(HttpStatusCode.NotFound, (await SendAsync(c, "GET", "/account/external/second")).Status);
        await store.UpdateAsync(cfg => cfg.AuthProviders.Add(new AuthProviderConfig
        {
            Name = "second", Type = ProviderType.OpenIdConnect, Authority = Oidc.Issuer, ClientId = FakeOidcServer.ClientId,
        }));
        try
        {
            var (status, _, resp) = await SendAsync(c, "GET", "/account/external/second");
            Assert.AreEqual(HttpStatusCode.Redirect, status);
            StringAssert.Contains(resp.Headers.Location!.ToString(), "%2Fsignin-oidc%2Fsecond&");
            Assert.IsFalse(resp.Headers.Location!.ToString().Contains("x-client-"), "no library telemetry is sent to the provider");
            await store.UpdateAsync(cfg => cfg.AuthProviders.Single(p => p.Name == "second").Enabled = false);
            Assert.AreEqual(HttpStatusCode.NotFound, (await SendAsync(c, "GET", "/account/external/second")).Status);
        }
        finally
        {
            await store.UpdateAsync(cfg => cfg.AuthProviders.RemoveAll(p => p.Name == "second"));
        }
    }

    [TestMethod]
    public async Task UnreachableProvidersShowAMessage()
    {
        var store = (await GetAsync()).Services.GetRequiredService<ConfigStore>();
        await store.UpdateAsync(cfg => cfg.AuthProviders.Add(new AuthProviderConfig
        {
            Name = "gone", Description = "Gone SSO", Type = ProviderType.OpenIdConnect, Authority = "http://127.0.0.1:9/", ClientId = "x",
        }));
        try
        {
            var factory = await GetAsync();
            var c = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
            var resp = await c.GetAsync("/account/external/gone");
            Assert.AreEqual(HttpStatusCode.Redirect, resp.StatusCode);
            Assert.AreEqual("/account/login", resp.Headers.Location!.ToString());
            StringAssert.Contains(await c.GetStringAsync("/account/login"), "Gone SSO cannot be reached");
        }
        finally
        {
            await store.UpdateAsync(cfg => cfg.AuthProviders.RemoveAll(p => p.Name == "gone"));
        }
    }

    [TestMethod]
    public async Task ValidationRequiresHttpsAuthority()
    {
        var c = new ServerConfig
        {
            AuthProviders = [new AuthProviderConfig { Name = "x", Type = ProviderType.OpenIdConnect, Authority = "http://idp.example.com", ClientId = "a" }],
        };
        CollectionAssert.Contains(ConfigValidator.Validate(c).Select(e => e.Contains("https")).ToList(), true);
        c.AuthProviders[0].Authority = "https://idp.example.com/realms/x";
        Assert.HasCount(0, ConfigValidator.Validate(c));
    }
}
