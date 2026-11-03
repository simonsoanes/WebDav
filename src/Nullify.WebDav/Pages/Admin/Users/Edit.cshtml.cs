// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Mvc;
using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Services;
using Nullify.WebDav.Storage;

namespace Nullify.WebDav.Pages.Admin.Users;

public class EditModel(ConfigStore store) : AppPageModel
{
    [BindProperty(SupportsGet = true)] public string? Name { get; set; }

    [BindProperty] public string Username { get; set; } = "";
    [BindProperty] public string DisplayName { get; set; } = "";
    [BindProperty] public string Provider { get; set; } = UserConfig.LocalProvider;
    [BindProperty] public string Login { get; set; } = "";
    [BindProperty] public bool Enabled { get; set; } = true;
    [BindProperty] public bool IsAdmin { get; set; }
    [BindProperty] public string Groups { get; set; } = "";
    [BindProperty] public string DefaultMount { get; set; } = "";
    [BindProperty] public string? NewPassword { get; set; }

    public bool IsNew => string.IsNullOrEmpty(Name);
    public UserConfig? Existing { get; private set; }
    public List<string> Providers { get; private set; } = [];
    public List<string> MountNames { get; private set; } = [];
    public List<(string Mount, string Access, string Path, string Storage)> Effective { get; private set; } = [];

    private void LoadLists()
    {
        var c = store.Current;
        Providers = [UserConfig.LocalProvider, .. c.AuthProviders.Select(p => p.Name)];
        MountNames = c.Mounts.Select(m => m.Name).ToList();
        Existing = IsNew ? null : c.Users.FirstOrDefault(u => Names.Eq(u.Username, Name));
        if (Existing == null) return;

        // Effective access from the configured groups (operating system groups are only known at sign-in).
        var principal = new DavPrincipal
        {
            Username = Existing.Username,
            DisplayName = Existing.Username,
            Provider = Existing.Provider,
            Listed = true,
            Groups = Existing.Groups.Concat(c.AuthProviders.FirstOrDefault(p => Names.Eq(p.Name, Existing.Provider))?.DefaultGroups ?? [])
                .ToHashSet(StringComparer.OrdinalIgnoreCase),
        };
        Effective = new MountResolver(store).MountsFor(principal)
            .Select(m => (m.Mount.Name, m.CanWrite ? "Read & write" : "Read only", m.BasePath, m.Storage.Name)).ToList();
    }

    public IActionResult OnGet()
    {
        LoadLists();
        if (!IsNew && Existing == null) return NotFound();
        if (Existing != null)
        {
            Username = Existing.Username;
            DisplayName = Existing.DisplayName;
            Provider = Existing.Provider;
            Login = Existing.Login;
            Enabled = Existing.Enabled;
            IsAdmin = Existing.IsAdmin;
            Groups = Names.JoinList(Existing.Groups);
            DefaultMount = Existing.DefaultMount;
        }
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        LoadLists();
        if (!IsNew && Existing == null) return NotFound();
        var username = IsNew ? Username.Trim() : Existing!.Username;
        var isLocal = Names.Eq(Provider, UserConfig.LocalProvider);
        if (isLocal && !string.IsNullOrEmpty(NewPassword) && PasswordHasher.ValidateStrength(NewPassword) is { } pwError)
            ModelState.AddModelError(nameof(NewPassword), pwError);
        if (isLocal && IsNew && string.IsNullOrEmpty(NewPassword))
            ModelState.AddModelError(nameof(NewPassword), "Set a password for a local account.");
        if (IsNew && store.Current.Users.Any(u => Names.Eq(u.Username, username)))
            ModelState.AddModelError(nameof(Username), "A user with this name already exists.");
        if (!ModelState.IsValid) return Page();

        var hash = isLocal && !string.IsNullOrEmpty(NewPassword) ? PasswordHasher.Hash(NewPassword) : null;
        var errors = await store.UpdateAsync(c =>
        {
            var u = c.Users.FirstOrDefault(x => Names.Eq(x.Username, username));
            if (u == null)
            {
                u = new UserConfig { Username = username };
                c.Users.Add(u);
            }
            var credentialsChanged = hash != null || !Names.Eq(u.Provider, Provider) || u.Login != Login.Trim() || u.Enabled != Enabled;
            u.DisplayName = DisplayName.Trim();
            u.Provider = Provider;
            u.Login = Login.Trim();
            u.Enabled = Enabled;
            u.IsAdmin = IsAdmin;
            u.Groups = Names.SplitList(Groups);
            u.DefaultMount = DefaultMount;
            if (!isLocal) u.PasswordHash = "";
            if (hash != null) u.PasswordHash = hash;
            if (credentialsChanged) u.SecurityStamp = Guid.NewGuid().ToString("N");
            return SetupGateMiddleware.IsComplete(c) ? null : "At least one enabled administrator must remain.";
        });
        if (errors.Count == 0)
        {
            StatusMessage = IsNew ? $"User {username} has been created." : $"User {username} has been saved.";
            return RedirectToPage("Index");
        }
        AddErrors(errors);
        return Page();
    }

    public async Task<IActionResult> OnPostDeleteAsync()
    {
        LoadLists();
        if (Existing == null) return NotFound();
        var errors = await store.UpdateAsync(c =>
        {
            c.Users.RemoveAll(u => Names.Eq(u.Username, Existing.Username));
            return SetupGateMiddleware.IsComplete(c) ? null : "The last administrator cannot be deleted.";
        });
        if (errors.Count > 0)
        {
            ErrorMessage = string.Join(" ", errors);
            return RedirectToPage(new { name = Name });
        }
        StatusMessage = $"User {Existing.Username} has been deleted.";
        return RedirectToPage("Index");
    }
}
