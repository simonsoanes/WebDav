// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Pages.Admin.Users;

public class IndexModel(ConfigStore store) : AppPageModel
{
    public List<UserConfig> Users { get; private set; } = [];
    public List<string> UnlistedProviders { get; private set; } = [];

    public void OnGet()
    {
        Users = store.Current.Users.OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase).ToList();
        UnlistedProviders = store.Current.AuthProviders.Where(p => p is { Enabled: true, AcceptUnlisted: true }).Select(p => p.Name).ToList();
    }
}
