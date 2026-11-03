# Nullify.WebDav

A self-hosted, multi-user **WebDAV file server** built on .NET 10 with no third-party dependencies, a focus on security and a single configuration file. It maps **users and groups** to **paths** on one or more **storage services**, gives each user a **default folder**, and can verify passwords against the **operating system** (Windows or Linux), an **LDAP directory** or an **IMAP server** — and on Windows access files **as the signed-in user**, so NTFS and share permissions apply.

- **WebDAV class 1 and 2** (RFC 4918): `PROPFIND`, `PROPPATCH`, `GET`/`HEAD` with ranges and conditional requests, `PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`, `LOCK`/`UNLOCK` with a complete `If` header implementation
- Works with **Windows Explorer** (mapped drives, Win32 properties, Office locking), **macOS Finder**, **GNOME/KDE**, **davfs2**, **rclone**, **Cyberduck**, **WinSCP** and mobile file managers
- **Storage services** → **mounts** → **access rules**: the first rule matching a user or group decides read/write access and which folder the user gets (`home/{user}`, `teams/finance`, ...)
- **Default folder** per user and server-wide, always reachable at `/dav/~/`
- **Authentication**: local PBKDF2 passwords, **Windows** (`LogonUser`, local or domain), **PAM**, **LDAP** simple bind (Active Directory, OpenLDAP, FreeIPA, Samba), **IMAP**; per-device **app passwords**; optionally accept **unlisted accounts** that a provider verifies, with **operating system groups**
- **Windows impersonation**: storage can be accessed with the user's own Windows token, including UNC shares on another file server
- **Web management UI** with first-run admin setup, users, mounts and rules, storage, providers (with a *test sign-in* tool), settings, active locks and a validated raw JSON editor
- Browser **folder listings** for quick read-only access
- **Easy deployment**: Docker + Caddy, a self-contained single-file executable, a **Windows service** installer or a hardened **systemd** unit
- Configuration is **one JSON file**, editable in the UI or by hand (reloaded automatically, validated before use); no database

## Quick start (Docker + Caddy)

```bash
cp .env.example .env        # set DAV_HOST (and FILES_PATH)
docker compose up -d --build
```

The compose file runs the app and [Caddy](https://caddyserver.com) with automatic HTTPS ([Caddyfile](Caddyfile)). The app port is not published; only Caddy listens on 80/443. Open `https://<DAV_HOST>/`; on first start you are redirected to **/setup** to create the first administrator. Set `SETUP_TOKEN` in `.env` if the server is reachable before you finish setup.

- The `webdav-data` volume holds `nullify-webdav.json` (the configuration) and `keys/` (the key ring protecting sign-in cookies). Back both up.
- `FILES_PATH` (default `./files`) is mounted at `/files`, the root of the default `files` storage. It must be writable by UID 1654, the image's non-root `app` user.
- Out of the box every user gets `/dav/home/` (their own folder, `home/<username>`, created on first use and also served at `/dav/~/`) and `/dav/shared/` (one folder for everyone).

## Running on Windows

From an elevated PowerShell prompt in the repository root:

```powershell
.\deploy\Install-NullifyWebDav.ps1 -CertificateSubject files.contoso.com
```

This publishes a self-contained `Nullify.WebDav.exe`, installs it in `C:\Program Files\Nullify.WebDav`, and registers the **Nullify.WebDav** service running as the virtual account `NT SERVICE\Nullify.WebDav`. Kestrel serves HTTPS on port 443 with the named certificate from `LocalMachine\My`. Data lives in `C:\ProgramData\Nullify.WebDav`. Use `-Urls http://127.0.0.1:8080` instead to sit behind IIS (ARR) or another proxy. Re-run the script to upgrade.

Then, as administrator in the UI, add a **Windows** provider under *Authentication*. Typical domain set-up:

| Setting | Value |
|---|---|
| Default domain | `CONTOSO` |
| Accept accounts that are not listed | on |
| Administrator groups | `CONTOSO\Domain Admins` |

and a storage with **Access files as the signed-in Windows user** on, pointing at `D:\Shares` or `\\fileserver\users`. Every domain user can now connect with their normal password and sees exactly what NTFS lets them see.

## Running on Linux (systemd)

```bash
dotnet publish src/Nullify.WebDav -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o /opt/nullify-webdav
useradd --system --home /var/lib/nullify-webdav --shell /usr/sbin/nologin nullify-webdav
install -d -o nullify-webdav -g nullify-webdav -m 750 /var/lib/nullify-webdav /srv/webdav
cp deploy/nullify-webdav.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now nullify-webdav
```

The unit ([deploy/nullify-webdav.service](deploy/nullify-webdav.service)) listens on `127.0.0.1:8080` for a local reverse proxy, uses `Type=notify` and is sandboxed (`ProtectSystem=strict`, writable paths limited to the data directory and `/srv/webdav`; add further storage roots to `ReadWritePaths`). For PAM authentication see [PAM](#pam).

### Running locally

```bash
dotnet run --project src/Nullify.WebDav
```

Data is written to `src/Nullify.WebDav/data` unless `Storage__DataDirectory` is set. Plain HTTP is accepted from loopback, so `http://localhost:5031/dav/` works for testing.

## Concepts

```
Storage  "files"    /srv/files                  where files live (a folder or, on Windows, a UNC share)
  Mount  "home"     path home/{user}            a folder under /dav/
    rule  *          read & write                first matching rule wins
  Mount  "teams"    path teams/general
    rule  @finance   read & write → teams/finance   users in "finance" get a different folder
    rule  alice      read only
    rule  *          no access
```

- A **storage** is a root folder. Nothing outside it can be reached through any mount: names are validated per segment, resolved paths are checked against the root, and symbolic links and junctions are not followed unless the storage allows it.
- A **mount** is a folder at `/dav/<name>/` mapped to a path inside a storage. The path may use `{user}`. With *create on first access* missing folders (typically home folders) are created when the user first connects.
- **Rules** map lists of users and groups to an access level (`ReadWrite`, `Read` or `None`) and optionally to a different path. They are evaluated top to bottom; users no rule matches do not see the mount at all. `*` matches every signed-in user.
- Each user may have a **default mount**, else the server default applies. `/dav/~/` always opens it, so the same URL (or mapped drive) works for everyone.
- **Groups** come from the user's entry, from the provider's *default groups*, and — for Windows and PAM providers — from the operating system (`CONTOSO\Finance`, `Finance`, `staff`, ...).

## Configuration file

Everything lives in `nullify-webdav.json` in the data directory. Edit it in the UI (*Settings → Configuration file* shows and validates the raw JSON) or by hand: the file is watched, re-validated and applied without a restart; an invalid edit is logged and ignored. An invalid file at start-up stops the server with a list of the problems. On Linux the file is created with mode 600.

```json
{
  "Settings": { "DefaultMount": "home", "MaxUploadMegabytes": 0, "BrowserListing": true, "AllowAppPasswords": true },
  "AuthProviders": [
    { "Name": "ad", "Type": "Ldap", "Host": "dc1.contoso.com", "Security": "Tls",
      "LoginTemplate": "{user}@contoso.com", "AcceptUnlisted": true, "DefaultGroups": ["staff"] }
  ],
  "Users": [
    { "Username": "admin", "PasswordHash": "pbkdf2-sha256$600000$...", "IsAdmin": true },
    { "Username": "asmith", "Provider": "ad", "Groups": ["finance"], "DefaultMount": "teams" }
  ],
  "Storages": [
    { "Name": "files", "Root": "/srv/files" },
    { "Name": "archive", "Root": "/mnt/archive", "ReadOnly": true }
  ],
  "Mounts": [
    { "Name": "home", "Storage": "files", "Path": "home/{user}", "CreateMissing": true,
      "Rules": [ { "Users": ["*"], "Access": "ReadWrite" } ] },
    { "Name": "teams", "Storage": "files", "Path": "teams/general", "CreateMissing": true,
      "Rules": [ { "Groups": ["finance"], "Access": "ReadWrite", "Path": "teams/finance" },
                 { "Groups": ["staff"], "Access": "Read" } ] },
    { "Name": "archive", "Storage": "archive", "Rules": [ { "Groups": ["staff"], "Access": "Read" } ] }
  ]
}
```

### Environment / appsettings

| Variable | Default | Purpose |
|----------|---------|---------|
| `Storage__DataDirectory` | `./data`; `/data` in Docker | Configuration file and key ring |
| `Storage__FilesDirectory` | `<data>/files`; `/files` in Docker | Root of the `files` storage created on first start |
| `Storage__ConfigFile` | `<data>/nullify-webdav.json` | Use a configuration file elsewhere |
| `Setup__Token` | *(empty)* | If set, the first-run setup page requires this token |
| `ReverseProxy__Enabled` | `true` | Process `X-Forwarded-*` headers |
| `ReverseProxy__KnownNetworks` | private ranges | Comma-separated CIDR ranges of trusted proxies |
| `ReverseProxy__KnownProxies` | | Comma-separated trusted proxy IPs |
| `ReverseProxy__TrustAll` | `false` | Trust forwarded headers from any address |
| `ReverseProxy__ForwardLimit` | `1` | Number of proxy hops to process (`0` = unlimited) |
| `ReverseProxy__AllowedHosts` | | Restrict accepted forwarded host names |
| `PathBase` | | Serve under a sub-path, e.g. `/files` |
| `ASPNETCORE_HTTP_PORTS` / `Urls` | `8080` in Docker | Listening ports/URLs |
| `Kestrel__Certificates__Default__Path` (or `__Subject`, `__Store`) | | Serve HTTPS directly, without a proxy |

## Authentication

Every request from a WebDAV client carries HTTP Basic credentials, which is why the server refuses them over plain HTTP from anything but loopback (*Settings → Accept passwords over plain HTTP* exists for testing only). Behind a proxy, `X-Forwarded-Proto` must reach the app: the defaults trust loopback and private networks, which covers Caddy in Docker.

How a login is checked:

1. A **listed user** (by username or their *login at provider*) is verified by their own provider: the local PBKDF2-SHA256 hash (600,000 iterations), or the external provider. App passwords are accepted too, for WebDAV clients only.
2. Otherwise every enabled provider with **accept unlisted accounts** is tried in order. The account's user name (without the domain, unless configured otherwise) may not be the name of a listed user, so a directory account can never take over a listed user's folders.
3. Successful checks are cached for five minutes, as clients authenticate every request; any configuration change clears the cache. Ten failures from one address within 15 minutes block that address for the rest of the window.
4. Browser sessions are signed out when the user is disabled, removed or their password or provider changes.

| Provider | Checks against | Groups | Notes |
|---|---|---|---|
| **Windows** | `LogonUser` (local accounts, domain `DOMAIN\user`, UPN `user@domain`) | Windows token groups | Windows only. The token is used for impersonation. Network-cleartext logon by default (as IIS Basic authentication), which impersonated access to UNC paths needs. Users need the *Access this computer from the network* right. |
| **Pam** | `pam_authenticate` + `pam_acct_mgmt` | Unix groups (`getgrouplist`) | Linux only. See below. |
| **Ldap** | Simple bind over LDAPS (636) or StartTLS (389) | — | `LoginTemplate` builds the bind name: `{user}@contoso.com` (AD) or `uid={user},ou=people,dc=example,dc=com`. Empty passwords (anonymous binds) are refused before contacting the server, and user names are limited to characters that cannot alter a DN. |
| **Imap** | IMAP login (TLS, STARTTLS, `AUTHENTICATE PLAIN` or `LOGIN`) | — | `LoginTemplate` such as `{user}@example.com`. |

*Authentication → (provider) → Test sign-in* tries a login with the settings on the form and shows the groups found, without saving or caching anything.

### PAM

PAM must be allowed to check other users' passwords. With `pam_unix` either run the service as root (not recommended) or add it to the `shadow` group (`SupplementaryGroups=shadow` in the unit). A dedicated service file keeps policy separate:

```
# /etc/pam.d/nullify-webdav
auth    required  pam_unix.so
account required  pam_unix.so
```

and set the provider's *PAM service* to `nullify-webdav`. Inside the Docker image only the container's own accounts exist, so use LDAP or IMAP there.

### Windows impersonation

With *Access files as the signed-in Windows user* on a storage, each request runs under the user's Windows token: file permissions, auditing and ownership are the user's, and UNC shares on other servers are accessed with the user's credentials. Such storage requires users verified by a Windows provider with their Windows password (app passwords and browser sessions carry no token, so they are refused there). Copying or moving between impersonated and non-impersonated storage is refused. On non-Windows systems the option is rejected by validation.

## Connecting clients

| Client | How |
|---|---|
| Windows Explorer | *Map network drive*: `\\files.example.com@SSL\dav\~` (or `https://files.example.com/dav/~/`). From a prompt: `net use * https://files.example.com/dav/~/ /user:alice`. Uploads over 50 MB need the WebClient service's `FileSizeLimitInBytes` raised; HTTPS is required by Windows for Basic authentication. |
| macOS Finder | *Go → Connect to Server*: `https://files.example.com/dav/~/` |
| GNOME Files / Dolphin | `davs://files.example.com/dav/~/` |
| davfs2 | `mount -t davfs https://files.example.com/dav/~/ /mnt/files` |
| rclone | `rclone config` → WebDAV, vendor *Other*, URL `https://files.example.com/dav/`. Modification times are kept via `X-OC-Mtime`. |
| Cyberduck, WinSCP, mobile apps | WebDAV (HTTPS), server `files.example.com`, path `/dav/~/` |

Each user's overview page shows their own URLs and the matching commands.

## Security notes

- **Path handling**: every URL segment is validated (no `.`/`..`, separators, control characters; on Windows also no `:` streams, reserved device names or trailing dots/spaces), the combined path must stay inside the storage root, and links are not followed by default (and are hidden from listings).
- **Uploads** go to a temporary file in the target folder and replace the target only when complete, so a failed upload never leaves a truncated file. Optional size limit; uploads that would not fit get `507`.
- **Downloads** are served with `Content-Security-Policy: sandbox` and `nosniff`: an uploaded HTML or SVG file cannot run script in the server's origin. Browser sessions may only read through `/dav/`; every change needs Basic credentials, and WebDAV methods cannot be sent cross-site without a CORS preflight, which the server never grants.
- **Locks** are owned by the user who created them; tokens of other users are rejected. Administrators can release stale locks under *Settings*. Locks are kept in memory and cleared by a restart.
- The management UI uses cookie authentication (`HttpOnly`, `Secure`, `SameSite=Lax`, 12-hour sliding expiry), antiforgery tokens, CSP, `X-Frame-Options: DENY` and HSTS.
- The configuration file contains password hashes, never passwords. LDAP and IMAP providers bind with the user's own credentials, so there are no service-account secrets to store.

## Protocol support

- WebDAV (RFC 4918) class 1 and 2: `OPTIONS`, `GET`, `HEAD`, `PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE` (with `Depth`, `Overwrite`, cross-mount), `PROPFIND` (`allprop`, `propname`, `prop`, `include`; depth 0 and 1), `PROPPATCH`, `LOCK` (exclusive and shared write locks, depth 0/infinity, refresh, lock-null resources), `UNLOCK`, the `If` header (tagged and untagged lists, `Not`, state tokens and ETags)
- HTTP: strong ETags, `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, single byte ranges with `If-Range`
- Quota properties (RFC 4331), `current-user-privilege-set` (RFC 3744), the Windows redirector's `Win32*` properties (applied to file times and attributes) and legacy `ishidden`/`isreadonly`/`iscollection`, `X-OC-Mtime`, `X-Expected-Entity-Length`
- `OPTIONS` and `PROPFIND` on the server root for the Windows redirector

Not implemented: arbitrary dead properties (`PROPPATCH` of other properties returns `403`, nothing is silently dropped), `PROPFIND` with `Depth: infinity`, multiple byte ranges, partial `PUT`, Digest/NTLM/Kerberos authentication, group lookups from LDAP, server-side search (`SEARCH`), versioning (DeltaV), ACL changes over WebDAV, and storage backends other than the file system (including remote SMB without Windows impersonation).

## CI/CD

[.gitea/workflows/WebDav.yml](.gitea/workflows/WebDav.yml) runs on Gitea Actions for pushes to `main`, `v*` tags, pull requests and manual runs:

1. `docker build --target test .` runs the whole test suite inside the SDK image (the runner needs no .NET).
2. Builds the image (version from the tag, otherwise `0.0.0-ci.<sha>`) and smoke-tests it: `/health`, the first-run setup page, and the DAV endpoints being gated until setup.
3. Except for pull requests, pushes `git.nullify.net/simon/nullify-webdav:<sha>`; `main` also pushes `:latest`, and a `v1.2.3` tag pushes `:1.2.3`, `:1.2` and `:latest`.
4. On `main` and tags, calls the Portainer webhook if one is configured.

Repository secrets: `GITEADOCKERTOKEN` (token with package write for the registry user) and, optionally, `WEBDAV_PORTAINER_WEBHOOK`. To run the image from the registry, replace `build: .` in `docker-compose.yml` with `image: git.nullify.net/simon/nullify-webdav:latest`.

## Development

```bash
dotnet test        # unit + integration tests (fake LDAP and IMAP servers included)
```

```
src/Nullify.WebDav
├── Dav/            WebDAV protocol: handler, methods, properties, locks and If header, HTML listings
├── Storage/        Path validation and mount/rule resolution
├── Auth/           Credential validation, password hashing, Windows/PAM/LDAP/IMAP providers
├── Configuration/  Configuration model, validation, file store with hot reload
├── Services/       Setup gate, cookie validation, embedded static assets
└── Pages/          Razor Pages management UI
```

### Dependencies

The server uses only the .NET and ASP.NET Core shared frameworks plus `Microsoft.Extensions.Hosting.WindowsServices` and `Microsoft.Extensions.Hosting.Systemd`, two small Microsoft packages that let the same binary run as a Windows service or a systemd unit. The WebDAV implementation, LDAP and IMAP clients, PAM and Windows logon interop are part of this project. There is no database: the configuration is a JSON file and locks are kept in memory.

## License

Copyright 2026 Simon Soanes.

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attribution and third-party components. Unless required by applicable law or agreed to in writing, the software is distributed on an "AS IS" basis, without warranties or conditions of any kind.
