// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Pages.Account;

public class LoginModel(CredentialValidator credentials, ConfigStore store) : AppPageModel
{
    [BindProperty, Required] public string Username { get; set; } = "";
    [BindProperty, Required, DataType(DataType.Password)] public string Password { get; set; } = "";
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

    public bool HasProviders => store.Current.AuthProviders.Any(p => p.Enabled);

    /// <summary>Enabled single sign-on providers: (name, button label).</summary>
    public List<(string Name, string Label)> SingleSignOn => store.Current.AuthProviders
        .Where(p => p is { Enabled: true, Type: ProviderType.OpenIdConnect })
        .Select(p => (p.Name, string.IsNullOrWhiteSpace(p.Description) ? p.Name : p.Description)).ToList();

    /// <summary>Whether anyone can sign in with a password: local users exist, or a password-checking provider is enabled.</summary>
    public bool HasPasswordProviders =>
        store.Current.Users.Any(u => u.Enabled && Names.Eq(u.Provider, UserConfig.LocalProvider)) ||
        store.Current.AuthProviders.Any(p => p.Enabled && p.Type != ProviderType.OpenIdConnect);

    public IActionResult OnGet() => User.Identity?.IsAuthenticated == true ? Landing() : Page();

    /// <summary>Where the user asked to go, else straight to their files.</summary>
    private IActionResult Landing() =>
        !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) && ReturnUrl != "/" ? LocalRedirect(ReturnUrl) : LocalRedirect("~/dav/");

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();
        if (credentials.IsBlocked(ClientKey))
        {
            ModelState.AddModelError("", "Too many failed attempts. Please try again later.");
            return Page();
        }

        var principal = await credentials.ValidateAsync(Username, Password, ClientKey, LoginPurpose.Ui, HttpContext.RequestAborted);
        if (principal == null)
        {
            ModelState.AddModelError("", "Invalid username or password.");
            return Page();
        }

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            principal.ToClaimsPrincipal(CookieAuthenticationDefaults.AuthenticationScheme));
        return Landing();
    }
}
