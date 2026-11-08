// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

namespace Nullify.WebDav.Tests;

/// <summary>
/// A minimal OpenID Connect provider on 127.0.0.1: discovery, JWKS and a token endpoint that checks the client
/// secret and PKCE and returns RS256 ID tokens. Tests skip the provider's login page: they register the claims for
/// a sign-in with <see cref="Issue"/> and post the code back themselves.
/// </summary>
public sealed class FakeOidcServer : IAsyncDisposable
{
    public const string ClientId = "webdav-test";
    public const string ClientSecret = "test-client-secret";

    private sealed record Grant(string Nonce, string Challenge, Dictionary<string, object> Claims, bool Forged);

    private readonly RSA _key = RSA.Create(2048);
    private readonly RSA _forger = RSA.Create(2048);
    private readonly ConcurrentDictionary<string, Grant> _codes = new();
    private WebApplication? _app;
    // RSA instances are not safe to share between threads; tests sign in in parallel.
    private readonly Lock _gate = new();

    public string Issuer { get; private set; } = "";

    public async Task StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        app.MapGet("/.well-known/openid-configuration", () => Results.Json(new Dictionary<string, object>
        {
            ["issuer"] = Issuer,
            ["authorization_endpoint"] = Issuer + "/authorize",
            ["token_endpoint"] = Issuer + "/token",
            ["jwks_uri"] = Issuer + "/jwks",
            ["response_types_supported"] = new[] { "code" },
            ["subject_types_supported"] = new[] { "public" },
            ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
            ["code_challenge_methods_supported"] = new[] { "S256" },
        }));
        app.MapGet("/jwks", () =>
        {
            RSAParameters p;
            lock (_gate) p = _key.ExportParameters(false);
            return Results.Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = "k1", n = B64(p.Modulus!), e = B64(p.Exponent!) } } });
        });
        app.MapPost("/token", async (HttpRequest request) =>
        {
            var form = await request.ReadFormAsync();
            if (form["client_id"] != ClientId || form["client_secret"] != ClientSecret) return Results.Json(new { error = "invalid_client" }, statusCode: 401);
            if (form["grant_type"] != "authorization_code" || !_codes.TryRemove(form["code"].ToString(), out var grant))
                return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
            var verifier = form["code_verifier"].ToString();
            if (B64(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))) != grant.Challenge) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
            return Results.Json(new { access_token = "fake-access-token", token_type = "Bearer", expires_in = 300, id_token = IdToken(grant) });
        });
        await app.StartAsync();
        _app = app;
        Issuer = app.Urls.First().TrimEnd('/');
    }

    /// <summary>Registers a sign-in for the request a challenge sent to the provider; returns the authorization code.</summary>
    public string Issue(string nonce, string codeChallenge, Dictionary<string, object> claims, bool forged = false)
    {
        var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        _codes[code] = new Grant(nonce, codeChallenge, claims, forged);
        return code;
    }

    private string IdToken(Grant grant)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new Dictionary<string, object>(grant.Claims)
        {
            ["iss"] = Issuer,
            ["aud"] = ClientId,
            ["iat"] = now,
            ["nbf"] = now,
            ["exp"] = now + 300,
            ["nonce"] = grant.Nonce,
        };
        var header = B64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", kid = "k1", typ = "JWT" }));
        var body = B64(JsonSerializer.SerializeToUtf8Bytes(payload));
        var signer = grant.Forged ? _forger : _key;
        byte[] signature;
        lock (_gate) signature = signer.SignData(Encoding.ASCII.GetBytes(header + "." + body), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{header}.{body}.{B64(signature)}";
    }

    private static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public async ValueTask DisposeAsync()
    {
        if (_app != null) await _app.DisposeAsync();
        _key.Dispose();
        _forger.Dispose();
    }
}
