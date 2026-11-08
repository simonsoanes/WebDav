// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nullify.WebDav.Shared;

/// <summary>Header the browser file manager sends with every changing request; it cannot be sent cross-site without CORS.</summary>
public static class ApiHeaders
{
    public const string Request = "X-Nullify-Request";
    public const string RequestValue = "1";
}

public static class ShareAccess
{
    public const string Read = "Read";
    public const string ReadWrite = "ReadWrite";
}

/// <summary>Who is signed in and what they can see.</summary>
public sealed record SessionInfo(
    string Username,
    string DisplayName,
    bool IsAdmin,
    string? DefaultMount,
    bool SharingEnabled,
    long MaxUploadBytes,
    string DavUrl,
    List<MountInfo> Mounts,
    List<SharedFolderInfo> SharedWithMe);

/// <summary>A mount as the user sees it. <paramref name="Unavailable"/> explains why it cannot be opened in the browser.</summary>
public sealed record MountInfo(string Name, string Description, bool CanWrite, bool IsDefault, bool CanShare, string? Unavailable);

/// <summary>A folder another user shared with this user; it appears under /dav/ as <see cref="Segment"/>.</summary>
public sealed record SharedFolderInfo(string Segment, string Name, string Owner, string OwnerName, bool CanWrite);

/// <summary>A share the user owns.</summary>
public sealed record ShareInfo(
    string Id,
    string Name,
    string Mount,
    string Path,
    string Access,
    List<string> Users,
    List<string> Groups,
    DateTime CreatedUtc,
    bool Available);

/// <summary>Creates a share (POST) or changes one (PUT; Mount and Path are then ignored).</summary>
public sealed record ShareRequest(string Mount, string Path, string? Name, string Access, List<string> Users, List<string> Groups);

public sealed record PersonInfo(string Username, string DisplayName);

/// <summary>People and groups a folder can be shared with.</summary>
public sealed record PeopleDirectory(List<PersonInfo> Users, List<string> Groups);

public sealed record ApiError(string Error);

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(SessionInfo))]
[JsonSerializable(typeof(ShareInfo))]
[JsonSerializable(typeof(List<ShareInfo>))]
[JsonSerializable(typeof(ShareRequest))]
[JsonSerializable(typeof(PeopleDirectory))]
[JsonSerializable(typeof(ApiError))]
public sealed partial class ApiJson : JsonSerializerContext;
