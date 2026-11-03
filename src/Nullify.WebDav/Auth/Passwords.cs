// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Nullify.WebDav.Auth;

/// <summary>PBKDF2-SHA256 password hashes in the form <c>pbkdf2-sha256$iterations$salt$hash</c>.</summary>
public static class PasswordHasher
{
    public const int MinimumLength = 8;
    private const int Iterations = 600_000;
    private const string Scheme = "pbkdf2-sha256";

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, 32);
        return $"{Scheme}${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string? stored, string password)
    {
        if (string.IsNullOrEmpty(stored) || password.Length == 0) return false;
        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != Scheme || !int.TryParse(parts[1], out var iterations) || iterations < 10_000) return false;
        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static string? ValidateStrength(string? password) =>
        string.IsNullOrEmpty(password) || password.Length < MinimumLength ? $"Password must be at least {MinimumLength} characters." : null;

    public static string Sha256(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Generates an app password such as "abcd-efgh-ijkl-mnop-qrst-uvwx".</summary>
    public static string GenerateToken()
    {
        const string alphabet = "abcdefghijkmnpqrstuvwxyz23456789";
        var chars = new char[29];
        for (var i = 0; i < chars.Length; i++)
            chars[i] = (i + 1) % 5 == 0 ? '-' : alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        return new string(chars);
    }

    public static bool TokensEqual(string? a, string? b) =>
        a != null && b != null &&
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a.Trim()), Encoding.UTF8.GetBytes(b.Trim()));
}

/// <summary>Simple in-memory brute force protection keyed by client address.</summary>
public sealed class LoginThrottle
{
    private const int MaxFailures = 10;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    private readonly ConcurrentDictionary<string, (int Count, DateTime First)> _failures = new();

    public bool IsBlocked(string key) =>
        _failures.TryGetValue(key, out var e) && e.Count >= MaxFailures && DateTime.UtcNow - e.First < Window;

    public void RecordFailure(string key)
    {
        var now = DateTime.UtcNow;
        _failures.AddOrUpdate(key, (1, now), (_, e) => now - e.First > Window ? (1, now) : (e.Count + 1, e.First));
        if (_failures.Count > 10_000)
            foreach (var kv in _failures.Where(kv => now - kv.Value.First > Window).ToList())
                _failures.TryRemove(kv.Key, out _);
    }

    public void Reset(string key) => _failures.TryRemove(key, out _);
}
