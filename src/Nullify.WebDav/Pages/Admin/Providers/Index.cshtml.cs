// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Nullify.WebDav.Auth;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Pages.Admin.Providers;

public class IndexModel(ConfigStore store, ProviderRegistry registry) : AppPageModel
{
    public List<(AuthProviderConfig Provider, bool Supported, int Users)> Providers { get; private set; } = [];

    public void OnGet()
    {
        var c = store.Current;
        Providers = c.AuthProviders.Select(p => (p, registry.IsSupported(p.Type), c.Users.Count(u => Names.Eq(u.Provider, p.Name)))).ToList();
    }

    public static string Summary(AuthProviderConfig p) => p.Type switch
    {
        ProviderType.Windows => string.IsNullOrEmpty(p.Domain) ? "This computer and trusted domains" : "Domain " + p.Domain,
        ProviderType.Pam => "PAM service " + p.Service,
        ProviderType.Ldap or ProviderType.Imap => $"{p.Host}:{(p.Port > 0 ? p.Port : ProviderRegistry.DefaultPort(p.Type, p.Security))} ({p.Security}) as {p.LoginTemplate}",
        ProviderType.OpenIdConnect => $"{p.Authority} (client {p.ClientId})",
        _ => "",
    };
}
