// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Mvc;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Dav;
using Nullify.WebDav.Services;

namespace Nullify.WebDav.Pages.Admin;

public class SettingsModel(ConfigStore store, LockManager locks) : AppPageModel
{
    [BindProperty] public string DefaultMount { get; set; } = "";
    [BindProperty] public bool BrowserListing { get; set; }
    [BindProperty] public bool AllowAppPasswords { get; set; }
    [BindProperty] public long MaxUploadMegabytes { get; set; }
    [BindProperty] public int MaxLockTimeoutMinutes { get; set; }
    [BindProperty] public bool AllowInsecureHttp { get; set; }
    [BindProperty] public bool AllowSharing { get; set; }
    [BindProperty] public bool AllowDepthInfinity { get; set; }
    [BindProperty] public int MaxDepthInfinityItems { get; set; }
    [BindProperty] public string RawConfig { get; set; } = "";

    public List<string> MountNames { get; private set; } = [];
    public IReadOnlyList<DavLock> Locks { get; private set; } = [];
    public string ConfigPath => store.FilePath;

    private void Load(bool fill)
    {
        var c = store.Current;
        MountNames = c.Mounts.Select(m => m.Name).ToList();
        Locks = locks.All();
        if (!fill) return;
        DefaultMount = c.Settings.DefaultMount;
        BrowserListing = c.Settings.BrowserListing;
        AllowAppPasswords = c.Settings.AllowAppPasswords;
        MaxUploadMegabytes = c.Settings.MaxUploadMegabytes;
        MaxLockTimeoutMinutes = c.Settings.MaxLockTimeoutMinutes;
        AllowInsecureHttp = c.Settings.AllowInsecureHttp;
        AllowSharing = c.Settings.AllowSharing;
        AllowDepthInfinity = c.Settings.AllowDepthInfinity;
        MaxDepthInfinityItems = c.Settings.MaxDepthInfinityItems;
        RawConfig = ConfigStore.Serialize(c);
    }

    public void OnGet() => Load(fill: true);

    public async Task<IActionResult> OnPostAsync()
    {
        var errors = await store.UpdateAsync(c =>
        {
            c.Settings.DefaultMount = DefaultMount;
            c.Settings.BrowserListing = BrowserListing;
            c.Settings.AllowAppPasswords = AllowAppPasswords;
            c.Settings.MaxUploadMegabytes = MaxUploadMegabytes;
            c.Settings.MaxLockTimeoutMinutes = MaxLockTimeoutMinutes;
            c.Settings.AllowInsecureHttp = AllowInsecureHttp;
            c.Settings.AllowSharing = AllowSharing;
            c.Settings.AllowDepthInfinity = AllowDepthInfinity;
            c.Settings.MaxDepthInfinityItems = MaxDepthInfinityItems;
        });
        if (errors.Count > 0)
        {
            AddErrors(errors);
            Load(fill: false);
            RawConfig = ConfigStore.Serialize(store.Current);
            return Page();
        }
        StatusMessage = "Settings saved.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostRawAsync()
    {
        Load(fill: false);
        var parsed = ConfigStore.Parse(RawConfig, out var parseError);
        IReadOnlyList<string> errors = parsed == null ? [parseError!]
            : SetupGateMiddleware.IsComplete(parsed) ? await store.ReplaceAsync(parsed)
            : ["The configuration must keep at least one enabled administrator."];
        if (errors.Count > 0)
        {
            AddErrors(errors);
            var c = store.Current;
            DefaultMount = c.Settings.DefaultMount;
            BrowserListing = c.Settings.BrowserListing;
            AllowAppPasswords = c.Settings.AllowAppPasswords;
            MaxUploadMegabytes = c.Settings.MaxUploadMegabytes;
            MaxLockTimeoutMinutes = c.Settings.MaxLockTimeoutMinutes;
            AllowInsecureHttp = c.Settings.AllowInsecureHttp;
            AllowSharing = c.Settings.AllowSharing;
            AllowDepthInfinity = c.Settings.AllowDepthInfinity;
            MaxDepthInfinityItems = c.Settings.MaxDepthInfinityItems;
            return Page();
        }
        StatusMessage = "Configuration saved.";
        return RedirectToPage();
    }

    public IActionResult OnPostReleaseLock(string token)
    {
        locks.Remove(token);
        StatusMessage = "The lock has been released.";
        return RedirectToPage();
    }
}
