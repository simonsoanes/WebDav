// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Mvc;
using Nullify.WebDav.Configuration;
using Nullify.WebDav.Shared;
using Nullify.WebDav.Storage;

namespace Nullify.WebDav.Pages.Admin;

/// <summary>Every folder users have shared, with the option to remove any of them.</summary>
public class SharesModel(ConfigStore store, ShareService shares) : AppPageModel
{
    public sealed record Row(ShareConfig Share, ShareInfo Info);

    public List<Row> Rows { get; private set; } = [];
    public bool SharingEnabled { get; private set; }

    public void OnGet()
    {
        var c = store.Current;
        SharingEnabled = c.Settings.AllowSharing;
        Rows = c.Shares.OrderBy(s => s.Owner, StringComparer.OrdinalIgnoreCase).ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .Select(s => new Row(s, ShareService.ToInfo(c, s, null))).ToList();
    }

    public async Task<IActionResult> OnPostRemoveAsync(string id)
    {
        if (await shares.DeleteAsync(Me, id)) StatusMessage = "Share removed.";
        else ErrorMessage = "That share no longer exists.";
        return RedirectToPage();
    }
}
