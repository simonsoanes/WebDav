// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Mvc;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Pages.Admin.Mounts;

public class EditModel(ConfigStore store) : AppPageModel
{
    public sealed class RuleRow
    {
        public string Users { get; set; } = "";
        public string Groups { get; set; } = "";
        public AccessLevel Access { get; set; } = AccessLevel.ReadWrite;
        public string Path { get; set; } = "";
        public int Order { get; set; }
        public bool Remove { get; set; }
    }

    [BindProperty(SupportsGet = true)] public string? Name { get; set; }

    [BindProperty] public string MountName { get; set; } = "";
    [BindProperty] public string Description { get; set; } = "";
    [BindProperty] public string Storage { get; set; } = "";
    [BindProperty] public string MountPath { get; set; } = "";
    [BindProperty] public bool ReadOnly { get; set; }
    [BindProperty] public bool CreateMissing { get; set; }
    [BindProperty] public bool AllowSharing { get; set; }
    [BindProperty] public bool IsDefault { get; set; }
    [BindProperty] public List<RuleRow> Rules { get; set; } = [];

    public bool IsNew => string.IsNullOrEmpty(Name);
    public MountConfig? Existing { get; private set; }
    public List<string> StorageNames { get; private set; } = [];

    private void Load()
    {
        StorageNames = store.Current.Storages.Select(s => s.Name).ToList();
        Existing = IsNew ? null : store.Current.Mounts.FirstOrDefault(m => Names.Eq(m.Name, Name));
    }

    private void AddBlankRows()
    {
        var next = Rules.Count == 0 ? 1 : Rules.Max(r => r.Order) + 1;
        for (var i = 0; i < 2; i++) Rules.Add(new RuleRow { Order = next + i });
    }

    public IActionResult OnGet()
    {
        Load();
        if (!IsNew && Existing == null) return NotFound();
        if (Existing != null)
        {
            MountName = Existing.Name;
            Description = Existing.Description;
            Storage = Existing.Storage;
            MountPath = Existing.Path;
            ReadOnly = Existing.ReadOnly;
            CreateMissing = Existing.CreateMissing;
            AllowSharing = Existing.AllowSharing;
            IsDefault = Names.Eq(store.Current.Settings.DefaultMount, Existing.Name);
            Rules = Existing.Rules.Select((r, i) => new RuleRow
            {
                Users = Names.JoinList(r.Users), Groups = Names.JoinList(r.Groups), Access = r.Access, Path = r.Path ?? "", Order = i + 1,
            }).ToList();
        }
        else
        {
            CreateMissing = true;
            AllowSharing = true;
            Storage = StorageNames.FirstOrDefault() ?? "";
        }
        AddBlankRows();
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Load();
        if (!IsNew && Existing == null) return NotFound();
        var name = IsNew ? MountName.Trim() : Existing!.Name;
        if (IsNew && store.Current.Mounts.Any(m => Names.Eq(m.Name, name)))
            ModelState.AddModelError(nameof(MountName), "A mount with this name already exists.");
        if (!ModelState.IsValid)
        {
            AddBlankRows();
            return Page();
        }

        var rules = Rules
            .Where(r => !r.Remove && (!string.IsNullOrWhiteSpace(r.Users) || !string.IsNullOrWhiteSpace(r.Groups)))
            .OrderBy(r => r.Order)
            .Select(r => new AccessRule
            {
                Users = Names.SplitList(r.Users),
                Groups = Names.SplitList(r.Groups),
                Access = r.Access,
                Path = string.IsNullOrWhiteSpace(r.Path) ? null : r.Path.Trim().Trim('/', '\\'),
            }).ToList();

        var errors = await store.UpdateAsync(c =>
        {
            var m = c.Mounts.FirstOrDefault(x => Names.Eq(x.Name, name));
            if (m == null)
            {
                m = new MountConfig { Name = name };
                c.Mounts.Add(m);
            }
            m.Description = Description.Trim();
            m.Storage = Storage;
            m.Path = MountPath.Trim().Trim('/', '\\');
            m.ReadOnly = ReadOnly;
            m.CreateMissing = CreateMissing;
            m.AllowSharing = AllowSharing;
            m.Rules = rules;
            if (IsDefault) c.Settings.DefaultMount = name;
            else if (Names.Eq(c.Settings.DefaultMount, name)) c.Settings.DefaultMount = "";
        });
        if (errors.Count > 0)
        {
            AddErrors(errors);
            AddBlankRows();
            return Page();
        }
        StatusMessage = $"Mount {name} has been saved.";
        return RedirectToPage("Index");
    }

    public async Task<IActionResult> OnPostDeleteAsync()
    {
        Load();
        if (Existing == null) return NotFound();
        var errors = await store.UpdateAsync(c =>
        {
            c.Mounts.RemoveAll(m => Names.Eq(m.Name, Existing.Name));
            if (Names.Eq(c.Settings.DefaultMount, Existing.Name)) c.Settings.DefaultMount = "";
            foreach (var u in c.Users.Where(u => Names.Eq(u.DefaultMount, Existing.Name))) u.DefaultMount = "";
        });
        if (errors.Count > 0)
        {
            ErrorMessage = string.Join(" ", errors);
            return RedirectToPage(new { name = Name });
        }
        StatusMessage = $"Mount {Existing.Name} has been removed. Its files were not touched.";
        return RedirectToPage("Index");
    }
}
