// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Mvc;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Services;

namespace Nullify.WebDav.Pages.Admin.Providers;

public class EditModel(ConfigStore store, ProviderRegistry registry, CredentialValidator credentials) : AppPageModel
{
    [BindProperty(SupportsGet = true)] public string? Name { get; set; }

    [BindProperty] public string ProviderName { get; set; } = "";
    [BindProperty] public ProviderType Type { get; set; } = OperatingSystem.IsWindows() ? ProviderType.Windows : ProviderType.Pam;
    [BindProperty] public string Description { get; set; } = "";
    [BindProperty] public bool Enabled { get; set; } = true;
    [BindProperty] public bool AcceptUnlisted { get; set; }
    [BindProperty] public bool StripDomain { get; set; } = true;
    [BindProperty] public bool UseOsGroups { get; set; } = true;
    [BindProperty] public string DefaultGroups { get; set; } = "";
    [BindProperty] public string AdminGroups { get; set; } = "";
    [BindProperty] public string Domain { get; set; } = "";
    [BindProperty] public bool CleartextLogon { get; set; } = true;
    [BindProperty] public string Service { get; set; } = "login";
    [BindProperty] public string Host { get; set; } = "";
    [BindProperty] public int Port { get; set; }
    [BindProperty] public TransportSecurity Security { get; set; } = TransportSecurity.Tls;
    [BindProperty] public bool AllowInvalidCertificates { get; set; }
    [BindProperty] public string LoginTemplate { get; set; } = "{user}";
    [BindProperty] public string Authority { get; set; } = "";
    [BindProperty] public string ClientId { get; set; } = "";
    /// <summary>Left empty on the form to keep the saved secret; never sent back to the browser.</summary>
    [BindProperty] public string ClientSecret { get; set; } = "";
    [BindProperty] public bool ClearClientSecret { get; set; }
    [BindProperty] public string Scopes { get; set; } = "profile email";
    [BindProperty] public string UsernameClaim { get; set; } = "preferred_username";
    [BindProperty] public string DisplayNameClaim { get; set; } = "name";
    [BindProperty] public string GroupsClaim { get; set; } = "groups";

    [BindProperty] public string? TestLogin { get; set; }
    [BindProperty] public string? TestPassword { get; set; }

    public bool IsNew => string.IsNullOrEmpty(Name);
    public AuthProviderConfig? Existing { get; private set; }
    public bool Supported => registry.IsSupported(Type);
    public string? TestResult { get; private set; }
    public bool TestOk { get; private set; }
    public bool HasClientSecret => Existing?.ClientSecret.Length > 0;
    public string SecretSource => Existing?.ClientSecret.StartsWith("env:", StringComparison.Ordinal) == true ? Existing.ClientSecret : "stored";

    /// <summary>The redirect URI to register at the identity provider.</summary>
    public string CallbackUrl => $"{ServerUrl}/signin-oidc/{(string.IsNullOrWhiteSpace(ProviderName) ? "<name>" : ProviderName.Trim().ToLowerInvariant())}";

    private void Load() => Existing = IsNew ? null : store.Current.AuthProviders.FirstOrDefault(p => Names.Eq(p.Name, Name));

    public IActionResult OnGet()
    {
        Load();
        if (!IsNew && Existing == null) return NotFound();
        if (Existing != null) Fill(Existing);
        return Page();
    }

    private void Fill(AuthProviderConfig p)
    {
        ProviderName = p.Name;
        Type = p.Type;
        Description = p.Description;
        Enabled = p.Enabled;
        AcceptUnlisted = p.AcceptUnlisted;
        StripDomain = p.StripDomain;
        UseOsGroups = p.UseOsGroups;
        DefaultGroups = Names.JoinList(p.DefaultGroups);
        AdminGroups = Names.JoinList(p.AdminGroups);
        Domain = p.Domain;
        CleartextLogon = p.CleartextLogon;
        Service = p.Service;
        Host = p.Host;
        Port = p.Port;
        Security = p.Security;
        AllowInvalidCertificates = p.AllowInvalidCertificates;
        LoginTemplate = p.LoginTemplate;
        Authority = p.Authority;
        ClientId = p.ClientId;
        ClientSecret = "";
        Scopes = string.Join(' ', p.Scopes);
        UsernameClaim = p.UsernameClaim;
        DisplayNameClaim = p.DisplayNameClaim;
        GroupsClaim = p.GroupsClaim;
    }

    private void Apply(AuthProviderConfig p)
    {
        p.Type = Type;
        p.Description = Description.Trim();
        p.Enabled = Enabled;
        p.AcceptUnlisted = AcceptUnlisted;
        p.StripDomain = StripDomain;
        p.UseOsGroups = UseOsGroups;
        p.DefaultGroups = Names.SplitList(DefaultGroups);
        p.AdminGroups = Names.SplitList(AdminGroups);
        p.Domain = Domain.Trim();
        p.CleartextLogon = CleartextLogon;
        p.Service = Service.Trim();
        p.Host = Host.Trim();
        p.Port = Port;
        p.Security = Security;
        p.AllowInvalidCertificates = AllowInvalidCertificates;
        p.LoginTemplate = string.IsNullOrWhiteSpace(LoginTemplate) ? "{user}" : LoginTemplate.Trim();
        p.Authority = Authority.Trim();
        p.ClientId = ClientId.Trim();
        if (ClearClientSecret) p.ClientSecret = "";
        else if (!string.IsNullOrWhiteSpace(ClientSecret)) p.ClientSecret = ClientSecret.Trim();
        p.Scopes = Scopes.Split([' ', ',', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(s => s != "openid").Distinct(StringComparer.Ordinal).ToList();
        p.UsernameClaim = UsernameClaim.Trim();
        p.DisplayNameClaim = DisplayNameClaim.Trim();
        p.GroupsClaim = GroupsClaim.Trim();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Load();
        if (!IsNew && Existing == null) return NotFound();
        var name = IsNew ? ProviderName.Trim() : Existing!.Name;
        if (IsNew && store.Current.AuthProviders.Any(p => Names.Eq(p.Name, name)))
            ModelState.AddModelError(nameof(ProviderName), "A provider with this name already exists.");
        if (!ModelState.IsValid) return Page();

        var errors = await store.UpdateAsync(c =>
        {
            var p = c.AuthProviders.FirstOrDefault(x => Names.Eq(x.Name, name));
            if (p == null)
            {
                p = new AuthProviderConfig { Name = name };
                c.AuthProviders.Add(p);
            }
            Apply(p);
            // Users of this provider must sign in again when it changes.
            foreach (var u in c.Users.Where(u => Names.Eq(u.Provider, name))) u.SecurityStamp = Guid.NewGuid().ToString("N");
        });
        if (errors.Count > 0)
        {
            AddErrors(errors);
            return Page();
        }
        StatusMessage = $"Provider {name} has been saved.";
        return RedirectToPage(new { name });
    }

    /// <summary>Tries a login with the settings on the form (saved or not).</summary>
    public async Task<IActionResult> OnPostTestAsync()
    {
        Load();
        ModelState.Clear();
        var probe = new AuthProviderConfig { Name = string.IsNullOrWhiteSpace(ProviderName) ? "test" : ProviderName.Trim() };
        Apply(probe);
        if (Type == ProviderType.OpenIdConnect)
        {
            (TestOk, TestResult) = await OidcDiscovery.CheckAsync(probe, HttpContext.RequestAborted);
            return Page();
        }
        if (string.IsNullOrWhiteSpace(TestLogin) || string.IsNullOrEmpty(TestPassword))
        {
            TestResult = "Enter a login and password to test.";
            return Page();
        }
        var result = await credentials.TestProviderAsync(probe, TestLogin, TestPassword, HttpContext.RequestAborted);
        TestOk = result.Outcome == ProviderOutcome.Success;
        TestResult = result.Outcome switch
        {
            ProviderOutcome.Success => $"Signed in as {result.CanonicalName ?? TestLogin}." +
                                       (result.Groups is { Count: > 0 } g ? $" Groups: {string.Join(", ", g.Distinct(StringComparer.OrdinalIgnoreCase))}." : ""),
            ProviderOutcome.InvalidCredentials => "The provider rejected the login or password.",
            _ => Supported ? "The provider could not be reached; see the server log for details." : "This provider type is not supported on this server.",
        };
        TestPassword = null;
        return Page();
    }

    public async Task<IActionResult> OnPostDeleteAsync()
    {
        Load();
        if (Existing == null) return NotFound();
        var errors = await store.UpdateAsync(c =>
        {
            c.AuthProviders.RemoveAll(p => Names.Eq(p.Name, Existing.Name));
            return SetupGateMiddleware.IsComplete(c) ? null : "Removing this provider would leave no administrator.";
        });
        if (errors.Count > 0)
        {
            ErrorMessage = string.Join(" ", errors);
            return RedirectToPage(new { name = Name });
        }
        StatusMessage = $"Provider {Existing.Name} has been removed.";
        return RedirectToPage("Index");
    }
}
