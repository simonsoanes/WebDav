// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Auth;

/// <summary>
/// Verifies Windows accounts (local, domain or UPN logins) with <c>LogonUser</c>. The resulting token supplies the
/// account's groups and, for storages with impersonation enabled, is used to access files as that user.
/// </summary>
public sealed partial class WindowsLogonProvider(ILogger<WindowsLogonProvider> log) : ICredentialProvider
{
    private const int Logon32LogonNetwork = 3;
    private const int Logon32LogonNetworkCleartext = 8;
    private const int Logon32ProviderDefault = 0;
    private const int ErrorLogonFailure = 1326;

    public ProviderType Type => ProviderType.Windows;
    public bool IsSupported => OperatingSystem.IsWindows();

    public Task<ProviderResult> AuthenticateAsync(AuthProviderConfig config, string login, string password, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Task.FromResult(ProviderResult.Unavailable);
        // LogonUser blocks (it may contact a domain controller), so keep it off the request thread.
        return Task.Run(() => OperatingSystem.IsWindows() ? Logon(config, login, password) : ProviderResult.Unavailable, ct);
    }

    [SupportedOSPlatform("windows")]
    private ProviderResult Logon(AuthProviderConfig config, string login, string password)
    {
        string user = login;
        string? domain = string.IsNullOrWhiteSpace(config.Domain) ? null : config.Domain.Trim();
        var slash = login.IndexOf('\\');
        if (slash > 0)
        {
            domain = login[..slash];
            user = login[(slash + 1)..];
        }
        else if (login.Contains('@'))
        {
            domain = null; // UPN
        }
        if (user.Length == 0 || user.Contains('\\')) return ProviderResult.Invalid;

        var type = config.CleartextLogon ? Logon32LogonNetworkCleartext : Logon32LogonNetwork;
        if (!LogonUser(user, domain, password, type, Logon32ProviderDefault, out var token))
        {
            var error = Marshal.GetLastPInvokeError();
            token.Dispose();
            if (error == ErrorLogonFailure) return ProviderResult.Invalid;
            // Disabled, expired, locked out or not allowed to log on over the network: treated as a failed login.
            log.LogInformation("Windows logon for {Login} failed with error {Error}", login, error);
            return error is 1311 or 1722 or 1355 ? ProviderResult.Unavailable : ProviderResult.Invalid;
        }

        using var identity = new WindowsIdentity(token.DangerousGetHandle());
        var groups = new List<string>();
        if (config.UseOsGroups && identity.Groups != null)
        {
            foreach (var sid in identity.Groups)
            {
                try
                {
                    var name = sid.Translate(typeof(NTAccount)).Value;
                    groups.Add(name);
                    var shortName = name[(name.IndexOf('\\') + 1)..];
                    if (shortName != name) groups.Add(shortName);
                }
                catch (IdentityNotMappedException) { }
                catch (SystemException) { }
            }
        }
        return new ProviderResult(ProviderOutcome.Success, identity.Name, groups, token);
    }

    [LibraryImport("advapi32.dll", EntryPoint = "LogonUserW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LogonUser(string user, string? domain, string password, int logonType, int logonProvider, out SafeAccessTokenHandle token);
}
