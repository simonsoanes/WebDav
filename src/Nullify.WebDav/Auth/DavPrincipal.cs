// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Security.Claims;
using Microsoft.Win32.SafeHandles;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Auth;

public static class AppClaims
{
    public const string Stamp = "nullify:stamp";
    public const string Provider = "nullify:provider";
    public const string Listed = "nullify:listed";
    public const string Group = "nullify:group";
    public const string DisplayName = "display_name";
    public const string AdminRole = "admin";
    public const string AdminPolicy = "Admin";
}

/// <summary>An authenticated user as seen by the DAV handler and the UI.</summary>
public sealed class DavPrincipal
{
    public required string Username { get; init; }
    public required string DisplayName { get; init; }
    /// <summary>"local" or the name of the authentication provider that verified the password.</summary>
    public required string Provider { get; init; }
    /// <summary>False for accounts accepted through a provider's "accept unlisted users" option.</summary>
    public bool Listed { get; init; }
    public bool IsAdmin { get; init; }
    public IReadOnlySet<string> Groups { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public string SecurityStamp { get; init; } = "";
    /// <summary>Windows logon token, present when a Windows provider verified the password. Used for impersonation.</summary>
    public SafeAccessTokenHandle? WindowsToken { get; init; }

    public bool CanImpersonate => WindowsToken is { IsClosed: false };

    public ClaimsPrincipal ToClaimsPrincipal(string authenticationType)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, Username),
            new(AppClaims.DisplayName, DisplayName),
            new(AppClaims.Provider, Provider),
            new(AppClaims.Listed, Listed ? "1" : "0"),
            new(AppClaims.Stamp, SecurityStamp),
        };
        claims.AddRange(Groups.Select(g => new Claim(AppClaims.Group, g)));
        if (IsAdmin) claims.Add(new Claim(ClaimTypes.Role, AppClaims.AdminRole));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType, ClaimTypes.Name, ClaimTypes.Role));
    }

    public static DavPrincipal? FromClaims(ClaimsPrincipal user)
    {
        if (user.Identity?.IsAuthenticated != true || user.Identity.Name is not { Length: > 0 } name) return null;
        return new DavPrincipal
        {
            Username = name,
            DisplayName = user.FindFirstValue(AppClaims.DisplayName) ?? name,
            Provider = user.FindFirstValue(AppClaims.Provider) ?? UserConfig.LocalProvider,
            Listed = user.FindFirstValue(AppClaims.Listed) == "1",
            IsAdmin = user.IsInRole(AppClaims.AdminRole),
            Groups = user.FindAll(AppClaims.Group).Select(c => c.Value).ToHashSet(StringComparer.OrdinalIgnoreCase),
            SecurityStamp = user.FindFirstValue(AppClaims.Stamp) ?? "",
        };
    }
}
