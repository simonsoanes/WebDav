// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Dav;
using Nullify.WebDav.Storage;

namespace Nullify.WebDav.Tests;

[TestClass]
public sealed class PathSafetyTests
{
    [TestMethod]
    [DataRow("..")]
    [DataRow(".")]
    [DataRow("")]
    [DataRow("a/b")]
    [DataRow("a\\b")]
    [DataRow("nul\0l")]
    [DataRow(".nullify-upload-123.tmp")]
    public void RejectsUnsafeSegments(string name) => Assert.IsFalse(PathSafety.IsSafeSegment(name));

    [TestMethod]
    [DataRow("report.pdf")]
    [DataRow(".hidden")]
    [DataRow("Ünïcødé 名前")]
    [DataRow("a..b")]
    public void AcceptsOrdinaryNames(string name) => Assert.IsTrue(PathSafety.IsSafeSegment(name));

    [TestMethod]
    public void RejectsWindowsSpecificNames()
    {
        if (!OperatingSystem.IsWindows()) Assert.Inconclusive("Windows rules only");
        foreach (var name in new[] { "CON", "nul.txt", "COM1", "file.txt:stream", "trailing.", "trailing ", "a*b", "LPT9.log" })
            Assert.IsFalse(PathSafety.IsSafeSegment(name), name);
    }

    [TestMethod]
    public void CombineStaysInsideTheRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "root");
        Assert.AreEqual(Path.Combine(root, "a", "b"), PathSafety.Combine(root, ["a", "b"]));
        Assert.IsNull(PathSafety.Combine(root, ["..", "x"]));
        Assert.IsNull(PathSafety.Combine(root, ["a", "..", "..", "x"]));
        Assert.IsFalse(PathSafety.IsWithinOrSame(root, root + "-sibling"));
        Assert.IsTrue(PathSafety.IsDescendant(root, Path.Combine(root, "child")));
    }

    [TestMethod]
    public void TemplatesMustBeRelativeAndSafe()
    {
        Assert.IsTrue(PathSafety.IsValidTemplate("home/{user}"));
        Assert.IsTrue(PathSafety.IsValidTemplate(""));
        Assert.IsFalse(PathSafety.IsValidTemplate("../{user}"));
        Assert.IsFalse(PathSafety.IsValidTemplate("/etc"));
        Assert.IsFalse(PathSafety.IsValidTemplate("{group}"));
    }
}

[TestClass]
public sealed class IfHeaderTests
{
    [TestMethod]
    public void ParsesUntaggedAndTaggedLists()
    {
        var h = IfHeader.Parse("(<urn:uuid:1> [\"etag\"]) (Not <DAV:no-lock>)")!;
        Assert.HasCount(2, h.Lists);
        Assert.AreEqual("urn:uuid:1", h.Lists[0].Conditions[0].Token);
        Assert.AreEqual("\"etag\"", h.Lists[0].Conditions[1].ETag);
        Assert.IsTrue(h.Lists[1].Conditions[0].Not);
        CollectionAssert.AreEqual(new[] { "urn:uuid:1" }, h.SubmittedTokens.ToArray());

        var tagged = IfHeader.Parse("<http://x/dav/a/> (<opaquelocktoken:abc>) <http://x/dav/b> ([W/\"1\"])")!;
        Assert.AreEqual("http://x/dav/a/", tagged.Lists[0].Resource);
        Assert.AreEqual("http://x/dav/b", tagged.Lists[1].Resource);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("(")]
    [DataRow("()")]
    [DataRow("(<a> ")]
    [DataRow("(<a>) <http://x> (<b>)")]
    [DataRow("<http://x>")]
    public void RejectsMalformedHeaders(string header) => Assert.IsNull(IfHeader.Parse(header));

    [TestMethod]
    public void WeakAndStrongEtagsCompare() => Assert.IsTrue(IfHeader.ETagMatches("\"1\"", "W/\"1\""));
}

[TestClass]
public sealed class ConfigTests
{
    private static ServerConfig Valid() => new()
    {
        Users = [new UserConfig { Username = "alice", PasswordHash = "x", IsAdmin = true }],
        Storages = [new StorageConfig { Name = "files", Root = Path.GetTempPath() }],
        Mounts = [new MountConfig { Name = "home", Storage = "files", Path = "home/{user}", Rules = [new AccessRule { Users = ["*"] }] }],
    };

    [TestMethod]
    public void ValidConfigHasNoErrors() => Assert.IsEmpty(ConfigValidator.Validate(Valid()));

    [TestMethod]
    public void ReportsBrokenReferencesAndUnsafeValues()
    {
        var c = Valid();
        c.Mounts.Add(new MountConfig { Name = "bad", Storage = "missing", Path = "../escape", Rules = [new AccessRule { Users = ["no/slash"] }] });
        c.Mounts.Add(new MountConfig { Name = "home", Storage = "files" });
        c.Users.Add(new UserConfig { Username = "..", Provider = "nope" });
        c.Storages.Add(new StorageConfig { Name = "rel", Root = "relative/path" });
        c.AuthProviders.Add(new AuthProviderConfig { Name = "ldap", Type = ProviderType.Ldap, LoginTemplate = "fixed" });
        var errors = string.Join("\n", ConfigValidator.Validate(c));
        foreach (var expected in new[] { "unknown storage 'missing'", "invalid path '../escape'", "invalid user name 'no/slash'", "more than one mount named 'home'",
                     "User '..'", "unknown authentication provider 'nope'", "must be an absolute path", "a host is required", "must contain {user}" })
            StringAssert.Contains(errors, expected);
    }

    [TestMethod]
    public void LoginsMustBeUnique()
    {
        var c = Valid();
        c.Users.Add(new UserConfig { Username = "asmith", Login = "alice" });
        StringAssert.Contains(string.Join("\n", ConfigValidator.Validate(c)), "login 'alice' is used by more than one user");
    }

    [TestMethod]
    public void RulesMatchInOrderAndExpandTemplates()
    {
        var c = Valid();
        c.Mounts[0].Rules = [new AccessRule { Users = ["bob"], Access = AccessLevel.None }, new AccessRule { Groups = ["staff"], Access = AccessLevel.Read, Path = "staff/{user}" }, new AccessRule { Users = ["*"] }];
        var dir = TestHost.NewTempDir("rules");
        var store = new ConfigStore(Path.Combine(dir, "c.json"), () => c, NullLogger<ConfigStore>.Instance);
        var resolver = new MountResolver(store);
        DavPrincipal P(string name, params string[] groups) => new() { Username = name, DisplayName = name, Provider = "local", Groups = groups.ToHashSet() };

        Assert.IsNull(resolver.Resolve(P("bob"), "home"));
        var staff = resolver.Resolve(P("carol", "staff"), "home")!;
        Assert.AreEqual(AccessLevel.Read, staff.Access);
        Assert.AreEqual(Path.Combine(Path.GetTempPath(), "staff", "carol"), staff.BasePath);
        var other = resolver.Resolve(P("dan"), "~");
        Assert.IsNull(other, "no default mount configured");
        Assert.AreEqual(AccessLevel.ReadWrite, resolver.Resolve(P("dan"), "home")!.Access);
        store.Dispose();
    }

    [TestMethod]
    public async Task HandEditedFileIsReloadedAndInvalidEditsIgnored()
    {
        var dir = TestHost.NewTempDir("reload");
        var path = Path.Combine(dir, "c.json");
        using var store = new ConfigStore(path, Valid, NullLogger<ConfigStore>.Instance);
        var changed = new TaskCompletionSource();
        store.Changed += () => changed.TrySetResult();

        var edited = Valid();
        edited.Settings.MaxUploadMegabytes = 42;
        await File.WriteAllTextAsync(path, ConfigStore.Serialize(edited));
        await changed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.AreEqual(42, store.Current.Settings.MaxUploadMegabytes);

        await File.WriteAllTextAsync(path, "{ \"Mounts\": [ { \"Name\": \"x\", \"Storage\": \"nope\" } ] }");
        await Task.Delay(1500);
        Assert.AreEqual(42, store.Current.Settings.MaxUploadMegabytes, "the previous configuration stays active");
    }
}

[TestClass]
public sealed class ProviderTests
{
    [TestMethod]
    public async Task LdapBindChecksPasswordsAndRefusesEmptyOnes()
    {
        await TestHost.GetAsync();
        var ldap = new LdapProvider(NullLogger<LdapProvider>.Instance);
        var config = new AuthProviderConfig
        {
            Name = "t", Type = ProviderType.Ldap, Host = "127.0.0.1", Port = TestHost.Ldap.Port, Security = TransportSecurity.None,
            LoginTemplate = "uid={user},ou=people,dc=example,dc=com",
        };
        Assert.AreEqual(ProviderOutcome.Success, (await ldap.AuthenticateAsync(config, "carol", "ldap-secret", default)).Outcome);
        Assert.AreEqual(ProviderOutcome.InvalidCredentials, (await ldap.AuthenticateAsync(config, "carol", "wrong", default)).Outcome);
        var before = TestHost.Ldap.Binds;
        Assert.AreEqual(ProviderOutcome.InvalidCredentials, (await ldap.AuthenticateAsync(config, "carol", "", default)).Outcome);
        Assert.AreEqual(ProviderOutcome.InvalidCredentials, (await ldap.AuthenticateAsync(config, "x,dc=evil", "pw", default)).Outcome, "DN injection");
        Assert.AreEqual(before, TestHost.Ldap.Binds, "neither reaches the server");
        Assert.AreEqual(ProviderOutcome.Unavailable, (await ldap.AuthenticateAsync(new AuthProviderConfig
        {
            Name = "t", Type = ProviderType.Ldap, Host = "127.0.0.1", Port = 1, Security = TransportSecurity.None, LoginTemplate = "{user}",
        }, "carol", "x", default)).Outcome);
    }

    [TestMethod]
    public void PasswordHashesVerify()
    {
        var hash = PasswordHasher.Hash("correct horse");
        Assert.IsTrue(PasswordHasher.Verify(hash, "correct horse"));
        Assert.IsFalse(PasswordHasher.Verify(hash, "Correct horse"));
        Assert.IsFalse(PasswordHasher.Verify(hash, ""));
        Assert.IsFalse(PasswordHasher.Verify("garbage", "x"));
    }
}

[TestClass]
public sealed class SetupTests
{
    [TestMethod]
    public async Task FreshInstallRequiresSetupAndSeedsDefaultMounts()
    {
        var dir = TestHost.NewTempDir("fresh");
        using var factory = TestHost.CreateFactory(dir);
        var c = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var home = await c.GetAsync("/");
        Assert.AreEqual(HttpStatusCode.Redirect, home.StatusCode);
        Assert.AreEqual("/setup", home.Headers.Location!.ToString());
        var setup = await c.GetStringAsync("/setup");
        StringAssert.Contains(setup, "Create administrator");
        var dav = await c.SendAsync(new HttpRequestMessage(new HttpMethod("PROPFIND"), "/dav/"));
        Assert.AreEqual(HttpStatusCode.ServiceUnavailable, dav.StatusCode);

        var config = ConfigStore.Parse(await File.ReadAllTextAsync(Path.Combine(dir, "nullify-webdav.json")), out _)!;
        CollectionAssert.AreEquivalent(new[] { "home", "shared" }, config.Mounts.Select(m => m.Name).ToArray());
        Assert.AreEqual(Path.Combine(dir, "files"), config.Storages.Single().Root);
    }
}
