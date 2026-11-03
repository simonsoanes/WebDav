// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.Win32.SafeHandles;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Auth;

public enum ProviderOutcome
{
    Success,
    InvalidCredentials,
    Unavailable,
}

/// <param name="CanonicalName">The account name as the provider spells it (e.g. "CONTOSO\alice"), when known.</param>
/// <param name="Groups">Operating system or directory groups of the account.</param>
/// <param name="Token">Windows logon token for impersonation; owned by the caller.</param>
public sealed record ProviderResult(ProviderOutcome Outcome, string? CanonicalName = null, IReadOnlyList<string>? Groups = null, SafeAccessTokenHandle? Token = null)
{
    public static readonly ProviderResult Invalid = new(ProviderOutcome.InvalidCredentials);
    public static readonly ProviderResult Unavailable = new(ProviderOutcome.Unavailable);
}

/// <summary>Verifies a login and password against an external system.</summary>
public interface ICredentialProvider
{
    ProviderType Type { get; }

    /// <summary>Whether the provider can work on this machine (e.g. Windows logons need Windows).</summary>
    bool IsSupported { get; }

    Task<ProviderResult> AuthenticateAsync(AuthProviderConfig config, string login, string password, CancellationToken ct);
}

public sealed class ProviderRegistry(IEnumerable<ICredentialProvider> providers)
{
    private readonly Dictionary<ProviderType, ICredentialProvider> _byType = providers.ToDictionary(p => p.Type);

    public ICredentialProvider? For(ProviderType type) => _byType.GetValueOrDefault(type);

    public bool IsSupported(ProviderType type) => For(type)?.IsSupported == true;

    /// <summary>
    /// Builds the login sent to an LDAP or IMAP server. The user part is restricted to characters that cannot
    /// change the meaning of a DN or of the login, so no escaping is needed.
    /// </summary>
    public static string? ApplyTemplate(string template, string user)
    {
        if (user.Length is 0 or > 256 || !user.All(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '@')) return null;
        return template.Replace("{user}", user, StringComparison.Ordinal);
    }

    public static int DefaultPort(ProviderType type, TransportSecurity security) => type switch
    {
        ProviderType.Ldap => security == TransportSecurity.Tls ? 636 : 389,
        ProviderType.Imap => security == TransportSecurity.Tls ? 993 : 143,
        _ => 0,
    };
}
