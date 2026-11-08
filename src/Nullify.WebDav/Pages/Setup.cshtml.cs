// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Services;

namespace Nullify.WebDav.Pages;

public class SetupModel(ConfigStore store, IConfiguration config) : AppPageModel
{
    [BindProperty, Required, Display(Name = "Username")] public string Username { get; set; } = "admin";
    [BindProperty, Display(Name = "Display name")] public string? DisplayName { get; set; }
    [BindProperty, Required, DataType(DataType.Password)] public string Password { get; set; } = "";
    [BindProperty, Required, DataType(DataType.Password), Display(Name = "Confirm password")] public string ConfirmPassword { get; set; } = "";
    [BindProperty, Display(Name = "Setup token")] public string? SetupToken { get; set; }

    public bool TokenRequired => !string.IsNullOrEmpty(config["Setup:Token"]);

    public IActionResult OnGet() => SetupGateMiddleware.IsComplete(store.Current) ? RedirectToPage("/Index") : Page();

    public async Task<IActionResult> OnPostAsync()
    {
        if (SetupGateMiddleware.IsComplete(store.Current)) return RedirectToPage("/Index");
        if (TokenRequired && !PasswordHasher.TokensEqual(SetupToken, config["Setup:Token"]))
            ModelState.AddModelError(nameof(SetupToken), "The setup token is incorrect.");
        if (!Names.IsValidUsername(Username?.Trim()))
            ModelState.AddModelError(nameof(Username), "Usernames may contain letters, digits, '.', '_', '-' and '@'.");
        if (PasswordHasher.ValidateStrength(Password) is { } pwError) ModelState.AddModelError(nameof(Password), pwError);
        if (Password != ConfirmPassword) ModelState.AddModelError(nameof(ConfirmPassword), "Passwords do not match.");
        if (!ModelState.IsValid) return Page();

        var user = new UserConfig
        {
            Username = Username!.Trim(),
            DisplayName = DisplayName?.Trim() ?? "",
            PasswordHash = PasswordHasher.Hash(Password),
            IsAdmin = true,
        };
        var completed = false;
        var errors = await store.UpdateAsync(c =>
        {
            if (SetupGateMiddleware.IsComplete(c)) return;
            c.Users.RemoveAll(u => Names.Eq(u.Username, user.Username));
            c.Users.Add(user);
            completed = true;
        });
        if (errors.Count > 0)
        {
            AddErrors(errors);
            return Page();
        }
        if (!completed) return RedirectToPage("/Index");

        var principal = new DavPrincipal
        {
            Username = user.Username,
            DisplayName = string.IsNullOrEmpty(user.DisplayName) ? user.Username : user.DisplayName,
            Provider = UserConfig.LocalProvider,
            Listed = true,
            IsAdmin = true,
            SecurityStamp = user.SecurityStamp,
        };
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            principal.ToClaimsPrincipal(CookieAuthenticationDefaults.AuthenticationScheme));
        return LocalRedirect("~/dav/");
    }
}
