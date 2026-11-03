// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Pages.Admin.Storages;

public class IndexModel(ConfigStore store) : AppPageModel
{
    public List<(StorageConfig Storage, bool Exists, int Mounts)> Storages { get; private set; } = [];

    public void OnGet()
    {
        var c = store.Current;
        Storages = c.Storages.Select(s => (s, SafeExists(s.Root), c.Mounts.Count(m => Names.Eq(m.Storage, s.Name)))).ToList();
    }

    public static bool SafeExists(string path)
    {
        try { return Directory.Exists(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }
}
