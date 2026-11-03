// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Mvc;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Pages.Admin.Storages;

public class EditModel(ConfigStore store) : AppPageModel
{
    [BindProperty(SupportsGet = true)] public string? Name { get; set; }

    [BindProperty] public string StorageName { get; set; } = "";
    [BindProperty] public string Description { get; set; } = "";
    [BindProperty] public string Root { get; set; } = "";
    [BindProperty] public bool ReadOnly { get; set; }
    [BindProperty] public bool Impersonate { get; set; }
    [BindProperty] public bool FollowSymlinks { get; set; }
    [BindProperty] public bool CreateRoot { get; set; }

    public bool IsNew => string.IsNullOrEmpty(Name);
    public StorageConfig? Existing { get; private set; }
    public List<string> UsedBy { get; private set; } = [];
    public bool IsWindows => OperatingSystem.IsWindows();
    public (bool Exists, string? Free)? Status { get; private set; }

    private void Load()
    {
        var c = store.Current;
        Existing = IsNew ? null : c.Storages.FirstOrDefault(s => Names.Eq(s.Name, Name));
        if (Existing == null) return;
        UsedBy = c.Mounts.Where(m => Names.Eq(m.Storage, Existing.Name)).Select(m => m.Name).ToList();
        var exists = IndexModel.SafeExists(Existing.Root);
        string? free = null;
        try
        {
            if (exists && !Existing.Root.StartsWith(@"\\", StringComparison.Ordinal))
                free = Dav.DavHandler.FormatSize(new DriveInfo(OperatingSystem.IsWindows() ? Path.GetPathRoot(Existing.Root)! : Existing.Root).AvailableFreeSpace);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException) { }
        Status = (exists, free);
    }

    public IActionResult OnGet()
    {
        Load();
        if (!IsNew && Existing == null) return NotFound();
        if (Existing != null)
        {
            StorageName = Existing.Name;
            Description = Existing.Description;
            Root = Existing.Root;
            ReadOnly = Existing.ReadOnly;
            Impersonate = Existing.Impersonate;
            FollowSymlinks = Existing.FollowSymlinks;
        }
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Load();
        if (!IsNew && Existing == null) return NotFound();
        var name = IsNew ? StorageName.Trim() : Existing!.Name;
        if (IsNew && store.Current.Storages.Any(s => Names.Eq(s.Name, name)))
            ModelState.AddModelError(nameof(StorageName), "A storage with this name already exists.");
        if (!ModelState.IsValid) return Page();

        var root = Root.Trim();
        if (CreateRoot && Path.IsPathFullyQualified(root))
        {
            try { Directory.CreateDirectory(root); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                ModelState.AddModelError(nameof(Root), "The folder could not be created: " + ex.Message);
                return Page();
            }
        }

        var errors = await store.UpdateAsync(c =>
        {
            var s = c.Storages.FirstOrDefault(x => Names.Eq(x.Name, name));
            if (s == null)
            {
                s = new StorageConfig { Name = name };
                c.Storages.Add(s);
            }
            s.Description = Description.Trim();
            s.Root = root;
            s.ReadOnly = ReadOnly;
            s.Impersonate = Impersonate;
            s.FollowSymlinks = FollowSymlinks;
        });
        if (errors.Count > 0)
        {
            AddErrors(errors);
            return Page();
        }
        StatusMessage = $"Storage {name} has been saved.";
        return RedirectToPage("Index");
    }

    public async Task<IActionResult> OnPostDeleteAsync()
    {
        Load();
        if (Existing == null) return NotFound();
        if (UsedBy.Count > 0)
        {
            ErrorMessage = $"Remove or change the mounts that use it first: {string.Join(", ", UsedBy)}.";
            return RedirectToPage(new { name = Name });
        }
        await store.UpdateAsync(c => c.Storages.RemoveAll(s => Names.Eq(s.Name, Existing.Name)));
        StatusMessage = $"Storage {Existing.Name} has been removed. Its files were not touched.";
        return RedirectToPage("Index");
    }
}
