// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebDav.Configuration;
using Nullify.WebDav.Storage;

namespace Nullify.WebDav.Pages;

public class IndexModel(MountResolver mounts, ConfigStore store) : AppPageModel
{
    public sealed record MountRow(string Name, string Description, string Url, bool CanWrite, bool IsDefault, bool Impersonated);

    public string DisplayName { get; private set; } = "";
    public string Username { get; private set; } = "";
    public List<MountRow> Mounts { get; } = [];
    public MountRow? Default { get; private set; }
    public bool NeedsWindowsPassword { get; private set; }
    public bool AppPasswordsAvailable { get; private set; }

    public void OnGet()
    {
        var me = Me;
        DisplayName = me.DisplayName;
        Username = me.Username;
        var defaultName = mounts.DefaultMountName(me);
        foreach (var m in mounts.MountsFor(me))
        {
            var isDefault = Names.Eq(m.Mount.Name, defaultName);
            var row = new MountRow(m.Mount.Name, m.Mount.Description, DavUrl + Uri.EscapeDataString(m.Mount.Name) + "/", m.CanWrite, isDefault, m.Storage.Impersonate);
            Mounts.Add(row);
            if (isDefault) Default = row with { Url = DavUrl + "~/" };
        }
        NeedsWindowsPassword = Mounts.Any(m => m.Impersonated);
        AppPasswordsAvailable = me.Listed && store.Current.Settings.AllowAppPasswords;
    }

    /// <summary>Windows Explorer path for a DAV URL, e.g. \\host@SSL\dav\home.</summary>
    public string UncPath(string url)
    {
        var uri = new Uri(url);
        var host = uri.Host + (uri.Scheme == "https" ? "@SSL" : "") + (uri.IsDefaultPort ? "" : "@" + uri.Port);
        return @"\\" + host + Uri.UnescapeDataString(uri.AbsolutePath).TrimEnd('/').Replace('/', '\\');
    }
}
