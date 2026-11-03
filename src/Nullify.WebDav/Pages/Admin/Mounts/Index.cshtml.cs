// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Pages.Admin.Mounts;

public class IndexModel(ConfigStore store) : AppPageModel
{
    public List<MountConfig> Mounts { get; private set; } = [];
    public string DefaultMount { get; private set; } = "";

    public void OnGet()
    {
        Mounts = store.Current.Mounts.ToList();
        DefaultMount = store.Current.Settings.DefaultMount;
    }

    public static string Describe(AccessRule r)
    {
        var who = r.Users.Select(u => u == "*" ? "everyone" : u).Concat(r.Groups.Select(g => "@" + g));
        var access = r.Access switch { AccessLevel.ReadWrite => "read & write", AccessLevel.Read => "read only", _ => "no access" };
        return $"{string.Join(", ", who)}: {access}" + (r.Path != null ? $" → {r.Path}" : "");
    }
}
