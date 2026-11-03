// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Pages.Account;

public class ProfileModel(ConfigStore store) : AppPageModel
{
    public DavPrincipal Account { get; private set; } = null!;
    public UserConfig? Listed { get; private set; }
    public bool IsLocal => Listed != null && Names.Eq(Listed.Provider, UserConfig.LocalProvider);
    public bool AppPasswordsAvailable => Listed != null && store.Current.Settings.AllowAppPasswords;
    public string? NewAppPassword { get; private set; }

    [BindProperty] public string? CurrentPassword { get; set; }
    [BindProperty] public string? NewPassword { get; set; }
    [BindProperty] public string? ConfirmPassword { get; set; }
    [BindProperty] public string? AppPasswordName { get; set; }

    private void Load()
    {
        Account = Me;
        Listed = store.Current.Users.FirstOrDefault(u => Names.Eq(u.Username, Account.Username));
    }

    public void OnGet() => Load();

    public async Task<IActionResult> OnPostPasswordAsync()
    {
        Load();
        if (!IsLocal) return Forbid();
        if (!PasswordHasher.Verify(Listed!.PasswordHash, CurrentPassword ?? ""))
            ModelState.AddModelError(nameof(CurrentPassword), "The current password is incorrect.");
        if (PasswordHasher.ValidateStrength(NewPassword) is { } error) ModelState.AddModelError(nameof(NewPassword), error);
        if (NewPassword != ConfirmPassword) ModelState.AddModelError(nameof(ConfirmPassword), "Passwords do not match.");
        if (!ModelState.IsValid) return Page();

        var hash = PasswordHasher.Hash(NewPassword!);
        var stamp = Guid.NewGuid().ToString("N");
        var errors = await store.UpdateAsync(c =>
        {
            var u = c.Users.First(x => Names.Eq(x.Username, Account.Username));
            u.PasswordHash = hash;
            u.SecurityStamp = stamp;
        });
        if (errors.Count > 0)
        {
            AddErrors(errors);
            return Page();
        }
        // Keep this browser signed in with the new security stamp.
        Load();
        var principal = new DavPrincipal
        {
            Username = Account.Username, DisplayName = Account.DisplayName, Provider = Account.Provider, Listed = true,
            IsAdmin = Account.IsAdmin, Groups = Account.Groups, SecurityStamp = stamp,
        };
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal.ToClaimsPrincipal(CookieAuthenticationDefaults.AuthenticationScheme));
        StatusMessage = "Your password has been changed.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostCreateAppPasswordAsync()
    {
        Load();
        if (!AppPasswordsAvailable) return Forbid();
        var name = string.IsNullOrWhiteSpace(AppPasswordName) ? "Device" : AppPasswordName.Trim();
        if (name.Length > 100) name = name[..100];
        var token = PasswordHasher.GenerateToken();
        var errors = await store.UpdateAsync(c =>
            c.Users.First(x => Names.Eq(x.Username, Account.Username)).AppPasswords.Add(new AppPasswordConfig { Name = name, Hash = PasswordHasher.Sha256(token) }));
        if (errors.Count > 0)
        {
            AddErrors(errors);
            return Page();
        }
        Load();
        NewAppPassword = token;
        return Page();
    }

    public async Task<IActionResult> OnPostRevokeAppPasswordAsync(string id)
    {
        Load();
        if (Listed == null) return Forbid();
        await store.UpdateAsync(c => c.Users.First(x => Names.Eq(x.Username, Account.Username)).AppPasswords.RemoveAll(a => a.Id == id));
        StatusMessage = "The app password has been revoked.";
        return RedirectToPage();
    }
}
