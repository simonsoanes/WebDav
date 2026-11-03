// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebDav.Configuration;

public enum AccessLevel
{
    None,
    Read,
    ReadWrite,
}

public enum ProviderType
{
    /// <summary>Windows accounts (local or domain) via LogonUser; can impersonate the user for file access.</summary>
    Windows,
    /// <summary>Linux/Unix accounts via PAM.</summary>
    Pam,
    /// <summary>LDAP simple bind (Active Directory, OpenLDAP, Samba AD, FreeIPA, ...).</summary>
    Ldap,
    /// <summary>IMAP login, e.g. against the mail server that owns the accounts.</summary>
    Imap,
}

public enum TransportSecurity
{
    Tls,
    StartTls,
    None,
}

public enum StorageType
{
    FileSystem,
}

/// <summary>
/// The whole server configuration. Stored as JSON in the data directory, edited from the admin UI or by hand
/// (changes to the file are picked up automatically). Instances handed out by <see cref="ConfigStore"/> must be
/// treated as read-only; changes go through <see cref="ConfigStore.UpdateAsync"/>.
/// </summary>
public sealed class ServerConfig
{
    public int Version { get; set; } = 1;
    public GeneralSettings Settings { get; set; } = new();
    public List<AuthProviderConfig> AuthProviders { get; set; } = [];
    public List<UserConfig> Users { get; set; } = [];
    public List<StorageConfig> Storages { get; set; } = [];
    public List<MountConfig> Mounts { get; set; } = [];
}

public sealed class GeneralSettings
{
    /// <summary>Mount served at <c>/dav/~/</c> for users that have no default of their own.</summary>
    public string DefaultMount { get; set; } = "";
    /// <summary>Render an HTML listing when a browser opens a folder.</summary>
    public bool BrowserListing { get; set; } = true;
    public bool AllowAppPasswords { get; set; } = true;
    /// <summary>Largest accepted upload in MiB; 0 means only limited by free space.</summary>
    public long MaxUploadMegabytes { get; set; }
    public int MaxLockTimeoutMinutes { get; set; } = 1440;
    /// <summary>Accept Basic credentials over plain HTTP from non-loopback clients. Only for testing.</summary>
    public bool AllowInsecureHttp { get; set; }
}

public sealed class AuthProviderConfig
{
    public string Name { get; set; } = "";
    public ProviderType Type { get; set; }
    public bool Enabled { get; set; } = true;
    public string Description { get; set; } = "";
    /// <summary>Accept accounts that are not listed under Users, as long as the provider verifies them.</summary>
    public bool AcceptUnlisted { get; set; }
    /// <summary>For unlisted accounts: use "alice" rather than "CONTOSO\alice" or "alice@contoso.com" as the user name.</summary>
    public bool StripDomain { get; set; } = true;
    /// <summary>Include operating system groups (Windows token groups, Unix groups) in the user's groups.</summary>
    public bool UseOsGroups { get; set; } = true;
    public List<string> DefaultGroups { get; set; } = [];
    /// <summary>Members of any of these groups are administrators of this server.</summary>
    public List<string> AdminGroups { get; set; } = [];

    // Windows
    /// <summary>Domain used when the login has none; empty searches the local machine then trusted domains.</summary>
    public string Domain { get; set; } = "";
    /// <summary>Network-cleartext logon (as IIS Basic authentication does) so impersonated access to UNC paths works.</summary>
    public bool CleartextLogon { get; set; } = true;

    // PAM
    public string Service { get; set; } = "login";

    // LDAP / IMAP
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public TransportSecurity Security { get; set; } = TransportSecurity.Tls;
    public bool AllowInvalidCertificates { get; set; }
    /// <summary>Login sent to the server: {user} is replaced, e.g. "{user}@example.com" or "uid={user},ou=people,dc=example,dc=com".</summary>
    public string LoginTemplate { get; set; } = "{user}";
}

public sealed class UserConfig
{
    public string Username { get; set; } = "";
    public string DisplayName { get; set; } = "";
    /// <summary>"local" (password hash stored here) or the name of an authentication provider.</summary>
    public string Provider { get; set; } = LocalProvider;
    /// <summary>Login at the provider when it differs from the username, e.g. "CONTOSO\asmith".</summary>
    public string Login { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public bool IsAdmin { get; set; }
    public List<string> Groups { get; set; } = [];
    /// <summary>Mount served at <c>/dav/~/</c> for this user.</summary>
    public string DefaultMount { get; set; } = "";
    /// <summary>Changes whenever credentials change, which signs out browser sessions.</summary>
    public string SecurityStamp { get; set; } = Guid.NewGuid().ToString("N");
    public List<AppPasswordConfig> AppPasswords { get; set; } = [];

    public const string LocalProvider = "local";
}

public sealed class AppPasswordConfig
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public string Name { get; set; } = "";
    public string Hash { get; set; } = "";
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

/// <summary>A storage service: somewhere files live. Mounts expose paths inside it.</summary>
public sealed class StorageConfig
{
    public string Name { get; set; } = "";
    public StorageType Type { get; set; } = StorageType.FileSystem;
    public string Description { get; set; } = "";
    /// <summary>Absolute directory (or UNC share on Windows) that contains everything this storage serves.</summary>
    public string Root { get; set; } = "";
    public bool ReadOnly { get; set; }
    /// <summary>Windows only: access files as the signed-in Windows user, so NTFS/share permissions apply.</summary>
    public bool Impersonate { get; set; }
    /// <summary>Follow symbolic links and junctions. Off by default so links cannot escape the root.</summary>
    public bool FollowSymlinks { get; set; }
}

/// <summary>A folder under <c>/dav/</c> mapped to a path on a storage, with access rules.</summary>
public sealed class MountConfig
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Storage { get; set; } = "";
    /// <summary>Default path inside the storage; may use {user}. Rules can override it per user or group.</summary>
    public string Path { get; set; } = "";
    public bool ReadOnly { get; set; }
    /// <summary>Create the resolved folder on first access (e.g. per-user home folders).</summary>
    public bool CreateMissing { get; set; }
    /// <summary>Evaluated in order; the first rule that matches the user decides access and path.</summary>
    public List<AccessRule> Rules { get; set; } = [];
}

public sealed class AccessRule
{
    /// <summary>User names; "*" matches every signed-in user.</summary>
    public List<string> Users { get; set; } = [];
    public List<string> Groups { get; set; } = [];
    public AccessLevel Access { get; set; } = AccessLevel.ReadWrite;
    /// <summary>Optional path inside the storage for the matched users, replacing the mount's default path.</summary>
    public string? Path { get; set; }
}
