// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebDav.Storage;

/// <summary>
/// Path validation. Every name that arrives in a URL is checked segment by segment before it touches the file
/// system, and every resolved path is checked to still lie inside its storage root.
/// </summary>
public static class PathSafety
{
    /// <summary>Uploads are written to a temporary file next to the target, then renamed over it.</summary>
    public const string TempPrefix = ".nullify-upload-";

    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static readonly HashSet<string> WindowsDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
    };

    /// <summary>True when a single path segment (file or folder name) is safe to use on this platform.</summary>
    public static bool IsSafeSegment(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 255 || name is "." or "..") return false;
        if (name.StartsWith(TempPrefix, StringComparison.OrdinalIgnoreCase)) return false;
        foreach (var ch in name)
        {
            if (ch < 0x20 || ch == 0x7F || ch == '/' || ch == '\\') return false;
            // ':' would address NTFS alternate data streams; the others are invalid in Windows names.
            if (OperatingSystem.IsWindows() && ch is ':' or '*' or '?' or '"' or '<' or '>' or '|') return false;
        }
        if (OperatingSystem.IsWindows())
        {
            // Windows silently strips trailing dots and spaces, so "a." and "a" would be the same file.
            if (name[^1] is '.' or ' ') return false;
            var stem = name.Split('.')[0].TrimEnd(' ');
            if (WindowsDeviceNames.Contains(stem)) return false;
        }
        return true;
    }

    /// <summary>Validates a configured relative path, which may contain {user}.</summary>
    public static bool IsValidTemplate(string? template)
    {
        if (string.IsNullOrEmpty(template)) return true;
        if (Path.IsPathRooted(template)) return false;
        var probe = template.Replace("{user}", "user", StringComparison.Ordinal);
        if (probe.Contains('{') || probe.Contains('}')) return false;
        return SplitRelative(probe) != null;
    }

    /// <summary>Splits a configured relative path into validated segments; null if any segment is unsafe.</summary>
    public static string[]? SplitRelative(string? path)
    {
        if (string.IsNullOrEmpty(path)) return [];
        var parts = path.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
        return parts.All(IsSafeSegment) ? parts : null;
    }

    /// <summary>Combines a root with validated segments; null if the result is not inside the root.</summary>
    public static string? Combine(string root, IEnumerable<string> segments)
    {
        var list = segments.ToList();
        if (!list.All(IsSafeSegment)) return null;
        var full = Path.GetFullPath(list.Count == 0 ? root : Path.Combine([root, .. list]));
        return IsWithinOrSame(root, full) ? full : null;
    }

    public static string NormalizeRoot(string root) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));

    public static bool IsWithinOrSame(string root, string path)
    {
        root = NormalizeRoot(root);
        path = Path.TrimEndingDirectorySeparator(path);
        return string.Equals(root, path, PathComparison) || IsDescendant(root, path);
    }

    /// <summary>True when <paramref name="path"/> lies strictly below <paramref name="parent"/>.</summary>
    public static bool IsDescendant(string parent, string path)
    {
        parent = Path.TrimEndingDirectorySeparator(parent);
        path = Path.TrimEndingDirectorySeparator(path);
        if (path.Length <= parent.Length || !path.StartsWith(parent, PathComparison)) return false;
        return Path.EndsInDirectorySeparator(parent) || path[parent.Length] == Path.DirectorySeparatorChar || path[parent.Length] == Path.AltDirectorySeparatorChar;
    }

    public static bool SamePath(string a, string b) =>
        string.Equals(Path.TrimEndingDirectorySeparator(a), Path.TrimEndingDirectorySeparator(b), PathComparison);

    /// <summary>
    /// True when any existing component below <paramref name="root"/> on the way to <paramref name="path"/> is a
    /// symbolic link, junction or other reparse point.
    /// </summary>
    public static bool CrossesLink(string root, string path)
    {
        root = NormalizeRoot(root);
        path = Path.TrimEndingDirectorySeparator(path);
        var current = path;
        while (current.Length > root.Length && IsDescendant(root, current))
        {
            try
            {
                var attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0) return true;
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
            {
                // Not created yet: nothing to follow.
            }
            current = Path.GetDirectoryName(current) ?? root;
        }
        return false;
    }

    public static bool IsLink(FileSystemInfo info) => (info.Attributes & FileAttributes.ReparsePoint) != 0;
}
