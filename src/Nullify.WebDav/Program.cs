// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Dav;
using Nullify.WebDav.Services;
using Nullify.WebDav.Storage;

// A published server finds its wwwroot (the file manager) next to the executable, whatever the working directory;
// under "dotnet run" there is none there and the project folder stays the content root.
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = Directory.Exists(Path.Combine(AppContext.BaseDirectory, "wwwroot")) ? AppContext.BaseDirectory : null,
});
var config = builder.Configuration;

// Runs as a Windows service or systemd unit when started by one; a normal console app otherwise.
builder.Host.UseWindowsService(o => o.ServiceName = "Nullify.WebDav");
builder.Host.UseSystemd();
builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);

// ------------------------------------------------------------------ Storage
var dataDir = config["Storage:DataDirectory"];
if (string.IsNullOrWhiteSpace(dataDir))
    dataDir = Path.Combine(builder.Environment.ContentRootPath, "data");
dataDir = Path.GetFullPath(dataDir);
Directory.CreateDirectory(dataDir);
var configFile = config["Storage:ConfigFile"];
configFile = string.IsNullOrWhiteSpace(configFile) ? Path.Combine(dataDir, "nullify-webdav.json") : Path.GetFullPath(configFile);
var filesDir = config["Storage:FilesDirectory"];
filesDir = Path.GetFullPath(string.IsNullOrWhiteSpace(filesDir) ? Path.Combine(dataDir, "files") : filesDir);

var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("Nullify.WebDav")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "keys")));
if (OperatingSystem.IsWindows()) dataProtection.ProtectKeysWithDpapi(protectToLocalMachine: true);

// ------------------------------------------------------------------ Services
builder.Services.AddSingleton(sp => new ConfigStore(configFile, () => DefaultConfig.Create(filesDir), sp.GetRequiredService<ILogger<ConfigStore>>()));
builder.Services.AddSingleton<LoginThrottle>();
builder.Services.AddSingleton<ImapAuthenticator>();
builder.Services.AddSingleton<ICredentialProvider, WindowsLogonProvider>();
builder.Services.AddSingleton<ICredentialProvider, PamProvider>();
builder.Services.AddSingleton<ICredentialProvider, LdapProvider>();
builder.Services.AddSingleton<ICredentialProvider, ImapProvider>();
builder.Services.AddSingleton<ICredentialProvider, OidcCredentialProvider>();
builder.Services.AddDynamicOpenIdConnect();
builder.Services.AddSingleton<ProviderRegistry>();
builder.Services.AddSingleton<CredentialValidator>();
builder.Services.AddSingleton<MountResolver>();
builder.Services.AddSingleton<LockManager>();
builder.Services.AddSingleton<ShareService>();

// ------------------------------------------------------------------ Authentication (management UI)
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/account/login";
        o.LogoutPath = "/account/logout";
        o.AccessDeniedPath = "/account/denied";
        o.Cookie.Name = "nullify.webdav.auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.ExpireTimeSpan = TimeSpan.FromHours(12);
        o.SlidingExpiration = true;
        o.Events.OnValidatePrincipal = CookieValidation.ValidateAsync;
        // The file manager's API answers with status codes rather than redirects to the login page.
        o.Events.OnRedirectToLogin = ctx => ApiAwareRedirect(ctx, StatusCodes.Status401Unauthorized);
        o.Events.OnRedirectToAccessDenied = ctx => ApiAwareRedirect(ctx, StatusCodes.Status403Forbidden);
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(AppClaims.AdminPolicy, p => p.RequireRole(AppClaims.AdminRole));

builder.Services.AddRazorPages(o =>
{
    o.Conventions.AuthorizeFolder("/");
    o.Conventions.AuthorizeFolder("/Admin", AppClaims.AdminPolicy);
    o.Conventions.AllowAnonymousToPage("/Setup");
    o.Conventions.AllowAnonymousToPage("/Account/Login");
    o.Conventions.AllowAnonymousToPage("/Account/Denied");
    o.Conventions.AllowAnonymousToPage("/Error");
}).AddMvcOptions(o =>
{
    // Optional form fields are plain strings: an empty input binds as "" and is not implicitly required.
    o.SuppressImplicitRequiredAttributeForNonNullableReferenceTypes = true;
    o.ModelMetadataDetailsProviders.Add(new EmptyStringsStayEmpty());
});
builder.Services.AddRouting(o => o.LowercaseUrls = true);
builder.Services.AddHealthChecks();

// ------------------------------------------------------------------ Reverse proxy support
// By default the app expects to run behind a TLS-terminating reverse proxy (e.g. Caddy) and trusts
// X-Forwarded-* headers from loopback and private networks (Docker bridge networks included).
var reverseProxyEnabled = config.GetValue("ReverseProxy:Enabled", true);
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    if (config["ReverseProxy:ForwardLimit"] is { } limit) o.ForwardLimit = int.TryParse(limit, out var l) && l > 0 ? l : null;
    if (config.GetValue<bool>("ReverseProxy:TrustAll"))
    {
        o.KnownIPNetworks.Clear();
        o.KnownProxies.Clear();
    }
    foreach (var proxy in (config["ReverseProxy:KnownProxies"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        if (IPAddress.TryParse(proxy, out var ip)) o.KnownProxies.Add(ip);
    foreach (var network in (config["ReverseProxy:KnownNetworks"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        if (System.Net.IPNetwork.TryParse(network, out var net)) o.KnownIPNetworks.Add(net);
    var hosts = config["ReverseProxy:AllowedHosts"];
    if (!string.IsNullOrWhiteSpace(hosts)) o.AllowedHosts = hosts.Split(',', StringSplitOptions.TrimEntries);
});

var app = builder.Build();

// Load (and validate) the configuration now, so a broken file stops start-up with a clear message.
var store = app.Services.GetRequiredService<ConfigStore>();
app.Logger.LogInformation("Using configuration {Path}", store.FilePath);
foreach (var provider in store.Current.AuthProviders.Where(p => p.Enabled))
    if (!app.Services.GetRequiredService<ProviderRegistry>().IsSupported(provider.Type))
        app.Logger.LogWarning("Authentication provider {Name} ({Type}) is not supported on this platform and will reject every login", provider.Name, provider.Type);

// ------------------------------------------------------------------ Pipeline
var pathBase = config["PathBase"];
if (!string.IsNullOrWhiteSpace(pathBase)) app.UsePathBase(pathBase);

if (reverseProxyEnabled) app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers.XContentTypeOptions = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "same-origin";
    ctx.Response.Headers.ContentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'";
    ctx.Response.Headers.XFrameOptions = "DENY";
    await next();
});

app.UseDynamicOpenIdConnect();
app.UseMiddleware<SetupGateMiddleware>();

// The Windows redirector probes the server root with OPTIONS and PROPFIND before opening the share.
app.MapWhen(ctx => ctx.Request.Path == "/" && ctx.Request.Method is "PROPFIND" or "OPTIONS",
    a => a.Run(DavHandler.HandleServerRootAsync));
app.Map("/dav", dav => dav.Run(DavHandler.HandleAsync));

// The file manager (Blazor WebAssembly), its stylesheet and scripts; the Razor pages share the stylesheet.
app.MapStaticAssets();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapHealthChecks("/health").AllowAnonymous();
app.MapRazorPages();
app.MapFileApi();
app.MapExternalSignIn();

app.Run();

static Task ApiAwareRedirect(Microsoft.AspNetCore.Authentication.RedirectContext<CookieAuthenticationOptions> ctx, int status)
{
    if (ctx.Request.Path.StartsWithSegments("/api")) ctx.Response.StatusCode = status;
    else ctx.Response.Redirect(ctx.RedirectUri);
    return Task.CompletedTask;
}

public partial class Program;

internal sealed class EmptyStringsStayEmpty : Microsoft.AspNetCore.Mvc.ModelBinding.Metadata.IDisplayMetadataProvider
{
    public void CreateDisplayMetadata(Microsoft.AspNetCore.Mvc.ModelBinding.Metadata.DisplayMetadataProviderContext context)
    {
        if (context.Key.ModelType == typeof(string)) context.DisplayMetadata.ConvertEmptyStringToNull = false;
    }
}

internal static class DefaultConfig
{
    /// <summary>A working first configuration: a home folder per user plus one shared folder.</summary>
    public static ServerConfig Create(string filesDir)
    {
        Directory.CreateDirectory(filesDir);
        return new ServerConfig
        {
            Settings = new GeneralSettings { DefaultMount = "home" },
            Storages = [new StorageConfig { Name = "files", Description = "Local files", Root = filesDir }],
            Mounts =
            [
                new MountConfig
                {
                    Name = "home", Description = "Your personal folder", Storage = "files", Path = "home/{user}", CreateMissing = true,
                    Rules = [new AccessRule { Users = ["*"], Access = AccessLevel.ReadWrite }],
                },
                new MountConfig
                {
                    Name = "shared", Description = "Shared with everyone", Storage = "files", Path = "shared", CreateMissing = true,
                    Rules = [new AccessRule { Users = ["*"], Access = AccessLevel.ReadWrite }],
                },
            ],
        };
    }
}
