// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nullify.WebDav.Configuration;

/// <summary>
/// Owns the JSON configuration file: loads and validates it, writes changes atomically and reloads it when it is
/// edited by hand. An invalid file at start-up stops the server; an invalid edit later is logged and ignored.
/// </summary>
public sealed class ConfigStore : IDisposable
{
    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly ILogger<ConfigStore> _log;
    private readonly SemaphoreSlim _write = new(1, 1);
    private readonly FileSystemWatcher? _watcher;
    private Timer? _reloadTimer;
    private string _lastHash = "";

    public string FilePath { get; }
    public ServerConfig Current { get; private set; }

    /// <summary>Raised after a new configuration became current (UI save or file edit).</summary>
    public event Action? Changed;

    public ConfigStore(string path, Func<ServerConfig> seed, ILogger<ConfigStore> log)
    {
        _log = log;
        FilePath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);

        if (File.Exists(FilePath))
        {
            var text = File.ReadAllText(FilePath);
            var config = Parse(text, out var parseError) ?? throw new InvalidOperationException($"{FilePath}: {parseError}");
            var errors = ConfigValidator.Validate(config);
            if (errors.Count > 0)
                throw new InvalidOperationException($"{FilePath} is invalid:{Environment.NewLine}  " + string.Join(Environment.NewLine + "  ", errors));
            Current = config;
            _lastHash = Hash(text);
        }
        else
        {
            Current = seed();
            WriteFile(Current);
            log.LogInformation("Created configuration file {Path}", FilePath);
        }

        try
        {
            _watcher = new FileSystemWatcher(Path.GetDirectoryName(FilePath)!, Path.GetFileName(FilePath))
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
            };
            _watcher.Changed += (_, _) => ScheduleReload();
            _watcher.Created += (_, _) => ScheduleReload();
            _watcher.Renamed += (_, _) => ScheduleReload();
            _watcher.EnableRaisingEvents = true;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or PlatformNotSupportedException)
        {
            log.LogWarning("Configuration file changes will not be detected: {Message}", ex.Message);
        }
    }

    public static ServerConfig? Parse(string json, out string? error)
    {
        try
        {
            error = null;
            return JsonSerializer.Deserialize<ServerConfig>(json, Json) ?? new ServerConfig();
        }
        catch (JsonException ex)
        {
            error = "Invalid JSON: " + ex.Message;
            return null;
        }
    }

    public static string Serialize(ServerConfig config) => JsonSerializer.Serialize(config, Json);

    public ServerConfig Clone() => JsonSerializer.Deserialize<ServerConfig>(Serialize(Current), Json)!;

    /// <summary>Applies a change to a copy of the configuration; saves it when it validates. Returns the validation errors.</summary>
    public Task<IReadOnlyList<string>> UpdateAsync(Action<ServerConfig> change) => UpdateAsync(c =>
    {
        change(c);
        return null;
    });

    /// <summary>As above; the change may return an error message to abandon the update.</summary>
    public async Task<IReadOnlyList<string>> UpdateAsync(Func<ServerConfig, string?> change)
    {
        await _write.WaitAsync();
        try
        {
            var copy = Clone();
            if (change(copy) is { } veto) return [veto];
            return Commit(copy);
        }
        finally
        {
            _write.Release();
        }
    }

    /// <summary>Replaces the whole configuration (raw JSON editor).</summary>
    public async Task<IReadOnlyList<string>> ReplaceAsync(ServerConfig config)
    {
        await _write.WaitAsync();
        try
        {
            return Commit(config);
        }
        finally
        {
            _write.Release();
        }
    }

    private IReadOnlyList<string> Commit(ServerConfig config)
    {
        var errors = ConfigValidator.Validate(config);
        if (errors.Count > 0) return errors;
        WriteFile(config);
        Current = config;
        RaiseChanged();
        return [];
    }

    private void WriteFile(ServerConfig config)
    {
        var text = Serialize(config);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, text, new UTF8Encoding(false));
        // The file holds password hashes: keep it private to the service account.
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        _lastHash = Hash(text);
        File.Move(temp, FilePath, overwrite: true);
    }

    private void ScheduleReload()
    {
        // Editors save in several steps; wait for the writes to settle.
        _reloadTimer?.Dispose();
        _reloadTimer = new Timer(_ => _ = ReloadFromDiskAsync(), null, TimeSpan.FromMilliseconds(500), Timeout.InfiniteTimeSpan);
    }

    private async Task ReloadFromDiskAsync()
    {
        await _write.WaitAsync();
        try
        {
            string text;
            try { text = await File.ReadAllTextAsync(FilePath); }
            catch (IOException) { return; }
            if (Hash(text) == _lastHash) return;

            var config = Parse(text, out var parseError);
            var errors = config == null ? [parseError!] : ConfigValidator.Validate(config);
            if (errors.Count > 0)
            {
                _log.LogError("Ignoring edited configuration file {Path}; the previous configuration stays active:{NewLine}  {Errors}",
                    FilePath, Environment.NewLine, string.Join(Environment.NewLine + "  ", errors));
                _lastHash = Hash(text);
                return;
            }
            _lastHash = Hash(text);
            Current = config!;
            _log.LogInformation("Reloaded configuration from {Path}", FilePath);
            RaiseChanged();
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Reloading configuration failed");
        }
        finally
        {
            _write.Release();
        }
    }

    private void RaiseChanged()
    {
        try { Changed?.Invoke(); }
        catch (Exception ex) { _log.LogError(ex, "Configuration change handler failed"); }
    }

    private static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    public void Dispose()
    {
        _watcher?.Dispose();
        _reloadTimer?.Dispose();
    }
}
