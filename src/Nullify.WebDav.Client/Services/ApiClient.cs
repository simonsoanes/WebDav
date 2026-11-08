// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Net.Http.Json;
using Nullify.WebDav.Shared;

namespace Nullify.WebDav.Client.Services;

/// <summary>The server's JSON API: the session, and sharing.</summary>
public sealed class ApiClient(HttpClient http)
{
    public sealed class ApiException(string message, HttpStatusCode status) : Exception(message)
    {
        public HttpStatusCode Status { get; } = status;
    }

    public Task<SessionInfo> SessionAsync() => GetAsync("api/session", ApiJson.Default.SessionInfo);

    public Task<List<ShareInfo>> SharesAsync() => GetAsync("api/shares", ApiJson.Default.ListShareInfo);

    public Task<PeopleDirectory> PeopleAsync() => GetAsync("api/people", ApiJson.Default.PeopleDirectory);

    public async Task<ShareInfo> CreateShareAsync(ShareRequest request) =>
        await ReadAsync(await http.PostAsJsonAsync("api/shares", request, ApiJson.Default.ShareRequest), ApiJson.Default.ShareInfo);

    public async Task<ShareInfo> UpdateShareAsync(string id, ShareRequest request) =>
        await ReadAsync(await http.PutAsJsonAsync("api/shares/" + Uri.EscapeDataString(id), request, ApiJson.Default.ShareRequest), ApiJson.Default.ShareInfo);

    public async Task DeleteShareAsync(string id)
    {
        using var response = await http.DeleteAsync("api/shares/" + Uri.EscapeDataString(id));
        await EnsureAsync(response);
    }

    public async Task LogoutAsync()
    {
        using var response = await http.PostAsync("api/logout", null);
    }

    private async Task<T> GetAsync<T>(string url, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type) =>
        await ReadAsync(await http.GetAsync(url), type);

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type)
    {
        using (response)
        {
            await EnsureAsync(response);
            return (await response.Content.ReadFromJsonAsync(type))!;
        }
    }

    private static async Task EnsureAsync(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode) return;
        string message;
        try { message = (await response.Content.ReadFromJsonAsync(ApiJson.Default.ApiError))?.Error ?? ""; }
        catch { message = ""; }
        if (message.Length == 0) message = DavClient.Describe(response.StatusCode);
        throw new ApiException(message, response.StatusCode);
    }
}
