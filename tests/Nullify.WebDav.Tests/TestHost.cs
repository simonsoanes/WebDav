// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Tests;

/// <summary>One application instance (with fake LDAP and IMAP servers) shared by the integration tests.</summary>
[TestClass]
public static class TestHost
{
    private static readonly SemaphoreSlim Init = new(1, 1);
    private static WebApplicationFactory<Program>? _factory;
    private static readonly List<string> TempDirs = [];

    public static FakeLdapServer Ldap { get; } = new();
    public static FakeImapServer Imap { get; } = new();
    public static string DataDir { get; private set; } = null!;
    public static string FilesDir { get; private set; } = null!;
    public static string AppPassword { get; } = PasswordHasher.GenerateToken();

    public static string NewTempDir(string purpose)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"nullify-webdav-{purpose}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        lock (TempDirs) TempDirs.Add(dir);
        return dir;
    }

    public static WebApplicationFactory<Program> CreateFactory(string dataDir, string? filesDir = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Storage:DataDirectory", dataDir);
            if (filesDir != null) b.UseSetting("Storage:FilesDirectory", filesDir);
        });

    public static async Task<WebApplicationFactory<Program>> GetAsync()
    {
        if (_factory != null) return _factory;
        await Init.WaitAsync();
        try
        {
            if (_factory != null) return _factory;
            DataDir = NewTempDir("data");
            FilesDir = Path.Combine(DataDir, "files");
            Directory.CreateDirectory(FilesDir);
            File.WriteAllText(Path.Combine(DataDir, "nullify-webdav.json"), ConfigStore.Serialize(Config()));
            var factory = CreateFactory(DataDir);
            _ = factory.Server; // start
            _factory = factory;
            return factory;
        }
        finally
        {
            Init.Release();
        }
    }

    private static ServerConfig Config() => new()
    {
        Settings = new GeneralSettings { DefaultMount = "home", MaxLockTimeoutMinutes = 60 },
        AuthProviders =
        [
            new AuthProviderConfig { Name = "dir", Type = ProviderType.Ldap, Host = "127.0.0.1", Port = Ldap.Port, Security = TransportSecurity.None,
                LoginTemplate = "uid={user},ou=people,dc=example,dc=com", AcceptUnlisted = true, DefaultGroups = ["directory"] },
            new AuthProviderConfig { Name = "mail", Type = ProviderType.Imap, Host = "127.0.0.1", Port = Imap.Port, Security = TransportSecurity.None,
                LoginTemplate = "{user}@example.com" },
        ],
        Users =
        [
            new UserConfig { Username = "alice", DisplayName = "Alice", PasswordHash = PasswordHasher.Hash("alice-password"), IsAdmin = true, Groups = ["finance"] },
            new UserConfig { Username = "bob", DisplayName = "Bob", PasswordHash = PasswordHasher.Hash("bob-password"), DefaultMount = "shared",
                AppPasswords = [new AppPasswordConfig { Name = "phone", Hash = PasswordHasher.Sha256(AppPassword) }] },
            new UserConfig { Username = "carol", Provider = "dir" },
            new UserConfig { Username = "dave", Provider = "mail" },
            new UserConfig { Username = "mallory", PasswordHash = PasswordHasher.Hash("mallory-password"), Enabled = false },
        ],
        Storages = [new StorageConfig { Name = "files", Root = FilesDir }],
        Mounts =
        [
            new MountConfig { Name = "home", Storage = "files", Path = "home/{user}", CreateMissing = true, Rules = [new AccessRule { Users = ["*"] }] },
            new MountConfig { Name = "shared", Storage = "files", Path = "shared", CreateMissing = true,
                Rules = [new AccessRule { Users = ["bob"], Access = AccessLevel.Read }, new AccessRule { Users = ["*"] }] },
            new MountConfig { Name = "teams", Storage = "files", Path = "teams/general", CreateMissing = true,
                Rules = [new AccessRule { Groups = ["finance"], Path = "teams/finance" }, new AccessRule { Groups = ["directory"], Access = AccessLevel.Read }] },
            new MountConfig { Name = "secret", Storage = "files", Path = "secret", CreateMissing = true,
                Rules = [new AccessRule { Users = ["*"], Access = AccessLevel.None }] },
        ],
    };

    [AssemblyCleanup]
    public static void Cleanup()
    {
        _factory?.Dispose();
        Ldap.Dispose();
        Imap.Dispose();
        lock (TempDirs)
            foreach (var dir in TempDirs)
                try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    public static async Task<HttpClient> ClientAsync(string? user = null, string? password = null)
    {
        var factory = await GetAsync();
        var c = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        if (user != null)
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}")));
        return c;
    }

    public static async Task<(HttpStatusCode Status, string Body, HttpResponseMessage Response)> SendAsync(HttpClient c, string method, string url,
        string? body = null, params (string, string)[] headers)
    {
        var req = new HttpRequestMessage(new HttpMethod(method), url);
        if (body != null) req.Content = new StringContent(body, Encoding.UTF8, body.StartsWith('<') ? "application/xml" : "text/plain");
        foreach (var (k, v) in headers)
            if (!req.Headers.TryAddWithoutValidation(k, v)) req.Content?.Headers.TryAddWithoutValidation(k, v);
        var resp = await c.SendAsync(req);
        return (resp.StatusCode, await resp.Content.ReadAsStringAsync(), resp);
    }
}

/// <summary>Accepts LDAP simple binds for uid=carol (ldap-secret) and uid=erin (erin-secret).</summary>
public sealed class FakeLdapServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    public int Port { get; }
    public int Binds;

    public FakeLdapServer()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = AcceptLoop();
    }

    private static readonly Dictionary<string, string> Accounts = new()
    {
        ["uid=carol,ou=people,dc=example,dc=com"] = "ldap-secret",
        ["uid=erin,ou=people,dc=example,dc=com"] = "erin-secret",
        ["uid=alice,ou=people,dc=example,dc=com"] = "alice-ldap",
    };

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(_cts.Token); }
            catch { return; }
            _ = Handle(client);
        }
    }

    private async Task Handle(TcpClient client)
    {
        using var _ = client;
        var stream = client.GetStream();
        try
        {
            while (true)
            {
                var message = await LdapProvider.Ber.ReadElementAsync(stream, 0x30, _cts.Token);
                var reader = new LdapProvider.Ber.Reader(message);
                var id = reader.Read(0x02);
                var (tag, op) = reader.ReadAny();
                if (tag != 0x60) return; // unbind or anything else ends the session
                var bind = new LdapProvider.Ber.Reader(op);
                bind.Read(0x02);
                var dn = Encoding.UTF8.GetString(bind.Read(0x04));
                var password = Encoding.UTF8.GetString(bind.Read(0x80));
                Interlocked.Increment(ref Binds);
                var code = password.Length == 0 ? 0 : Accounts.TryGetValue(dn, out var expected) && expected == password ? 0 : 49;
                var response = LdapProvider.Ber.Element(0x30, LdapProvider.Ber.Element(0x02, id),
                    LdapProvider.Ber.Element(0x61, LdapProvider.Ber.Element(0x0A, [(byte)code]), LdapProvider.Ber.Element(0x04, []), LdapProvider.Ber.Element(0x04, [])));
                await stream.WriteAsync(response, _cts.Token);
            }
        }
        catch (Exception) { }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
    }
}

/// <summary>Tiny IMAP server accepting dave@example.com / imap-secret.</summary>
public sealed class FakeImapServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();

    public int Port { get; }

    public FakeImapServer()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = AcceptLoop();
    }

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(_cts.Token); }
            catch { return; }
            _ = Handle(client);
        }
    }

    private static bool Check(string user, string pass) => user == "dave@example.com" && pass == "imap-secret";

    private static async Task Handle(TcpClient client)
    {
        using var _ = client;
        var stream = client.GetStream();
        var reader = new StreamReader(stream, Encoding.UTF8);
        var writer = new StreamWriter(stream, new UTF8Encoding(false)) { NewLine = "\r\n", AutoFlush = true };
        await writer.WriteLineAsync("* OK Fake IMAP ready");
        while (await reader.ReadLineAsync() is { } line)
        {
            var sp = line.IndexOf(' ');
            var tag = line[..sp];
            var cmd = line[(sp + 1)..];
            if (cmd.Equals("CAPABILITY", StringComparison.OrdinalIgnoreCase))
            {
                await writer.WriteLineAsync("* CAPABILITY IMAP4rev1 AUTH=PLAIN");
                await writer.WriteLineAsync($"{tag} OK done");
            }
            else if (cmd.Equals("AUTHENTICATE PLAIN", StringComparison.OrdinalIgnoreCase))
            {
                await writer.WriteLineAsync("+ ");
                var parts = Encoding.UTF8.GetString(Convert.FromBase64String((await reader.ReadLineAsync())!)).Split('\0');
                await writer.WriteLineAsync(Check(parts[1], parts[2]) ? $"{tag} OK welcome" : $"{tag} NO [AUTHENTICATIONFAILED] nope");
            }
            else if (cmd.Equals("LOGOUT", StringComparison.OrdinalIgnoreCase))
            {
                await writer.WriteLineAsync("* BYE");
                await writer.WriteLineAsync($"{tag} OK bye");
                return;
            }
            else await writer.WriteLineAsync($"{tag} BAD unknown");
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
    }
}
