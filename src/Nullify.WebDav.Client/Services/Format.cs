// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;

namespace Nullify.WebDav.Client.Services;

public static class Format
{
    public static string Size(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = bytes;
        var i = 0;
        while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
        return i == 0 ? $"{bytes} B" : v.ToString(v < 10 ? "0.#" : "0", CultureInfo.InvariantCulture) + " " + units[i];
    }

    /// <summary>Today: time; this year: day and month; older: date.</summary>
    public static string When(DateTimeOffset? value)
    {
        if (value is not { } v) return "";
        var local = v.ToLocalTime();
        var now = DateTimeOffset.Now;
        if (local.Date == now.Date) return local.ToString("HH:mm", CultureInfo.InvariantCulture);
        if (local.Year == now.Year) return local.ToString("d MMM", CultureInfo.InvariantCulture);
        return local.ToString("d MMM yyyy", CultureInfo.InvariantCulture);
    }

    public static string Full(DateTimeOffset? value) =>
        value?.ToLocalTime().ToString("dddd d MMMM yyyy, HH:mm", CultureInfo.InvariantCulture) ?? "";

    public static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".md", ".markdown", ".csv", ".tsv", ".log", ".json", ".xml", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
        ".env", ".html", ".htm", ".css", ".js", ".ts", ".cs", ".razor", ".py", ".sh", ".ps1", ".bat", ".sql", ".java", ".go",
        ".rs", ".c", ".h", ".cpp", ".hpp", ".php", ".rb", ".csproj", ".props", ".targets", ".svg", ".gitignore", ".editorconfig",
    };

    public static bool IsText(string name) => TextExtensions.Contains(Path.GetExtension(name)) || name.StartsWith('.') && !name[1..].Contains('.');

    public static string IconFor(DavEntry item)
    {
        if (item.IsFolder) return "folder";
        var ext = Path.GetExtension(item.Name).ToLowerInvariant();
        return ext switch
        {
            ".png" or ".jpg" or ".jpeg" or ".gif" or ".webp" or ".svg" or ".heic" or ".bmp" or ".tif" or ".tiff" or ".avif" => "image",
            ".mp4" or ".mov" or ".mkv" or ".webm" or ".avi" or ".m4v" => "film",
            ".mp3" or ".flac" or ".wav" or ".ogg" or ".m4a" or ".aac" or ".opus" => "music",
            ".zip" or ".7z" or ".rar" or ".gz" or ".tar" or ".tgz" or ".bz2" or ".xz" => "archive",
            ".pdf" or ".doc" or ".docx" or ".odt" or ".rtf" or ".xls" or ".xlsx" or ".ods" or ".ppt" or ".pptx" or ".odp" => "file-text",
            _ when IsText(item.Name) => "file-code",
            _ => "file",
        };
    }
}
