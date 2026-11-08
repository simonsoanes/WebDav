// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Nullify.WebDav.Client;
using Nullify.WebDav.Client.Services;
using Nullify.WebDav.Shared;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(_ =>
{
    var http = new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) };
    // Marks requests as coming from the file manager; the server only accepts cookie sign-in for changes with it.
    http.DefaultRequestHeaders.Add(ApiHeaders.Request, ApiHeaders.RequestValue);
    return http;
});
builder.Services.AddScoped<DavClient>();
builder.Services.AddScoped<ApiClient>();
builder.Services.AddScoped<AppState>();

await builder.Build().RunAsync();
