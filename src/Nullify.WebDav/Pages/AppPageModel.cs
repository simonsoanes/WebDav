// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Nullify.WebDav.Auth;

namespace Nullify.WebDav.Pages;

public abstract class AppPageModel : PageModel
{
    [TempData] public string? StatusMessage { get; set; }
    [TempData] public string? ErrorMessage { get; set; }

    protected DavPrincipal Me => DavPrincipal.FromClaims(User) ?? throw new InvalidOperationException("Not signed in");

    /// <summary>Absolute base URL of the server as seen by the browser (honours forwarded headers).</summary>
    public string ServerUrl => $"{Request.Scheme}://{Request.Host}{Request.PathBase}";

    public string DavUrl => ServerUrl + "/dav/";

    protected IActionResult LocalRedirectSafe(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? LocalRedirect(returnUrl) : RedirectToPage("/Index");

    protected string ClientKey => "ui:" + (HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");

    protected void AddErrors(IEnumerable<string> errors)
    {
        foreach (var e in errors) ModelState.AddModelError("", e);
    }
}
