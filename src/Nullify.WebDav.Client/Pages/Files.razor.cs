// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Routing;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;
using Nullify.WebDav.Client.Services;
using Nullify.WebDav.Shared;

namespace Nullify.WebDav.Client.Pages;

/// <summary>
/// The file manager. The URL is the folder's own WebDAV URL (/dav/mount/path/), so every view can be bookmarked and the
/// same address works in a WebDAV client. Files are read and changed through WebDAV; uploads run in files.js.
/// </summary>
public sealed partial class Files
{
    [Parameter] public string? Path { get; set; }

    [Inject] private NavigationManager Nav { get; set; } = default!;
    [Inject] private DavClient Dav { get; set; } = default!;
    [Inject] private ApiClient Api { get; set; } = default!;
    [Inject] private AppState State { get; set; } = default!;
    [Inject] private IJSRuntime JS { get; set; } = default!;

    private enum View { Loading, Root, Folder, SharedByMe }
    private enum Creating { None, Folder, File }

    private sealed class UploadState
    {
        public int Id { get; init; }
        public string Target { get; init; } = "";
        public string Name { get; set; } = "";
        public int Index { get; set; }
        public int Count { get; set; }
        public long Sent { get; set; }
        public long Total { get; set; }
        public int Percent => Total <= 0 ? 0 : (int)Math.Min(100, Sent * 100 / Total);
    }

    private SessionInfo? session;
    private string? fatal;
    private List<ShareInfo> myShares = [];
    private DotNetObjectReference<Files>? selfRef;
    private bool firstVisit = true;

    private View view = View.Loading;
    private string mountSegment = "";
    private string[] segments = [];
    private string? unavailable;
    private DavFolder? listing;
    private bool loading;
    private string? error;
    private int loadToken;

    private string sort = "name";
    private bool descending;
    private readonly HashSet<string> selected = new(StringComparer.Ordinal);
    private string? anchor;

    private List<DavEntry> clipboard = [];
    private bool clipboardCut;
    private List<DavEntry> dragged = [];

    private Creating creating;
    private string? renaming;
    private string nameValue = "";
    private ElementReference nameInput;
    private bool focusName;
    private ElementReference shellRef;
    private bool focusShell;
    private bool preventKey;

    private (double X, double Y)? menuAt;
    private List<DavEntry> menuItems = [];

    private UploadState? upload;
    private bool uploading => upload != null;

    private DavEntry? editing;
    private (string Mount, string Path, string Name, bool CanWrite, List<ShareInfo> Existing)? sharing;
    private bool sidebarOpen;

    // ------------------------------------------------------------------ derived state

    private MountInfo? CurrentMount => session?.Mounts.FirstOrDefault(m => Names.Eq(m.Name, mountSegment));
    private SharedFolderInfo? CurrentShare => session?.SharedWithMe.FirstOrDefault(s => Names.Eq(s.Segment, mountSegment));
    private bool CanWrite => view == View.Folder && (CurrentMount?.CanWrite ?? CurrentShare?.CanWrite ?? false);
    private bool CanShare => view == View.Folder && session?.SharingEnabled == true && CurrentMount?.CanShare == true;
    private string MountTitle => CurrentShare?.Name ?? mountSegment;
    private string FolderUrl => UrlFor(segments, true);

    private string Title => view switch
    {
        View.Folder => (segments.Length > 0 ? segments[^1] : MountTitle) + " · Files",
        View.SharedByMe => "Shared by me · Files",
        _ => "Files · Nullify.WebDav",
    };

    private static string MountUrl(string mount) => "dav/" + Uri.EscapeDataString(mount) + "/";

    private string UrlFor(IEnumerable<string> segs, bool folder)
    {
        var url = MountUrl(mountSegment) + string.Join('/', segs.Select(Uri.EscapeDataString));
        return folder && !url.EndsWith('/') ? url + "/" : url;
    }

    private string AbsoluteUrl(string relative) => new Uri(new Uri(Nav.BaseUri), relative).AbsoluteUri;

    // ------------------------------------------------------------------ lifecycle

    protected override async Task OnInitializedAsync()
    {
        State.Changed += OnStateChanged;
        Dav.SignedOut += OnSignedOut;
        try
        {
            session = await Api.SessionAsync();
            if (session.SharingEnabled) myShares = await Api.SharesAsync();
        }
        catch (ApiClient.ApiException ex) when (ex.Status == HttpStatusCode.Unauthorized)
        {
            OnSignedOut();
        }
        catch (Exception ex)
        {
            fatal = ex.Message;
        }
    }

    protected override async Task OnParametersSetAsync()
    {
        if (session == null) return;
        var relative = Nav.ToBaseRelativePath(Nav.Uri);
        var query = "";
        var q = relative.IndexOfAny(['?', '#']);
        if (q >= 0) { query = relative[q..]; relative = relative[..q]; }
        var parts = relative.Split('/', StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(Uri.UnescapeDataString).ToArray();

        if (parts.Length > 0 && parts[0] == "~")
        {
            if (session.DefaultMount is { } def)
            {
                Nav.NavigateTo(UrlForMount(def, parts[1..]), replace: true);
                return;
            }
            parts = [];
        }
        if (parts.Length == 0 && firstVisit && query.Length == 0 && session.DefaultMount is { } home)
        {
            // Signing in lands on the user's own folder; "All folders" stays one click away.
            firstVisit = false;
            Nav.NavigateTo(MountUrl(home), replace: true);
            return;
        }
        firstVisit = false;

        CloseMenu();
        creating = Creating.None;
        renaming = null;
        if (parts.Length == 0)
        {
            view = query.Contains("view=shared") ? View.SharedByMe : View.Root;
            mountSegment = "";
            segments = [];
            listing = null;
            selected.Clear();
            if (view == View.SharedByMe) await LoadSharesAsync();
            return;
        }

        var sameFolder = view == View.Folder && Names.Eq(mountSegment, parts[0]) && segments.SequenceEqual(parts[1..]);
        view = View.Folder;
        mountSegment = parts[0];
        segments = parts[1..];
        if (!sameFolder)
        {
            selected.Clear();
            anchor = null;
            listing = null;
        }
        unavailable = CurrentMount?.Unavailable;
        if (unavailable == null) await LoadAsync();
    }

    private static string UrlForMount(string mount, IEnumerable<string> segs)
    {
        var rest = string.Join('/', segs.Select(Uri.EscapeDataString));
        return MountUrl(mount) + (rest.Length > 0 ? rest + "/" : "");
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (session != null && selfRef == null)
        {
            selfRef = DotNetObjectReference.Create(this);
            await JS.InvokeVoidAsync("nullifyFiles.init", selfRef);
        }
        if (focusName)
        {
            focusName = false;
            try { await JS.InvokeVoidAsync("nullifyFiles.focusName", nameInput, renaming != null || creating == Creating.File); }
            catch (JSException) { }
        }
        else if (focusShell)
        {
            focusShell = false;
            try { await JS.InvokeVoidAsync("nullifyFiles.focus", shellRef); }
            catch (JSException) { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        State.Changed -= OnStateChanged;
        Dav.SignedOut -= OnSignedOut;
        if (upload != null)
        {
            try { await JS.InvokeVoidAsync("nullifyFiles.cancelUpload", upload.Id); } catch (JSException) { }
        }
        selfRef?.Dispose();
    }

    private void OnStateChanged() => InvokeAsync(StateHasChanged);

    private void OnSignedOut()
    {
        var back = Uri.EscapeDataString("/" + Nav.ToBaseRelativePath(Nav.Uri));
        Nav.NavigateTo("account/login?ReturnUrl=" + back, forceLoad: true);
    }

    // ------------------------------------------------------------------ loading

    private async Task LoadAsync()
    {
        var token = ++loadToken;
        loading = true;
        error = null;
        var url = FolderUrl;
        try
        {
            var result = await Dav.ListAsync(url);
            if (token != loadToken) return;
            listing = result;
            selected.IntersectWith(result.Items.Select(i => i.Url));
        }
        catch (DavException ex)
        {
            if (token != loadToken) return;
            listing = null;
            error = ex.Status == HttpStatusCode.NotFound ? "It does not exist, or you no longer have access to it." : ex.Message;
        }
        catch (HttpRequestException)
        {
            if (token != loadToken) return;
            error = "The server could not be reached.";
        }
        finally
        {
            if (token == loadToken) loading = false;
        }
    }

    private async Task Refresh()
    {
        if (view == View.SharedByMe) { await LoadSharesAsync(); return; }
        try { session = await Api.SessionAsync(); } catch (ApiClient.ApiException) { }
        if (view == View.Folder && unavailable == null) await LoadAsync();
    }

    private async Task LoadSharesAsync()
    {
        if (session?.SharingEnabled != true) return;
        try { myShares = await Api.SharesAsync(); }
        catch (ApiClient.ApiException ex) { State.ShowToast(ex.Message, true); }
    }

    // ------------------------------------------------------------------ sorting and selection

    private IEnumerable<DavEntry> Sorted()
    {
        var items = listing?.Items ?? [];
        IOrderedEnumerable<DavEntry> ordered = items.OrderBy(i => i.IsFolder ? 0 : 1);
        ordered = sort switch
        {
            "modified" => descending ? ordered.ThenByDescending(i => i.Modified) : ordered.ThenBy(i => i.Modified),
            "size" => descending ? ordered.ThenByDescending(i => i.Size ?? 0) : ordered.ThenBy(i => i.Size ?? 0),
            _ => descending ? ordered.ThenByDescending(i => i.Name, StringComparer.CurrentCultureIgnoreCase)
                            : ordered.ThenBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase),
        };
        return ordered;
    }

    private void SortBy(string column)
    {
        if (sort == column) descending = !descending;
        else (sort, descending) = (column, column != "name");
    }

    private MarkupString SortMark(string column) =>
        (MarkupString)(sort == column ? $"<span class=\"sort-mark\">{(descending ? "↓" : "↑")}</span>" : "");

    private List<DavEntry> Selection() => Sorted().Where(i => selected.Contains(i.Url)).ToList();

    private string RowClass(DavEntry e, bool isSelected) =>
        string.Join(' ', new[]
        {
            isSelected ? "selected" : null,
            clipboardCut && clipboard.Any(c => c.Url == e.Url) ? "cut" : null,
            menuAt != null && menuItems.Any(m => m.Url == e.Url) ? "context" : null,
        }.Where(c => c != null));

    private void RowClick(MouseEventArgs e, DavEntry item)
    {
        if (e.ShiftKey && anchor != null)
        {
            var order = Sorted().ToList();
            var a = order.FindIndex(i => i.Url == anchor);
            var b = order.FindIndex(i => i.Url == item.Url);
            if (a >= 0 && b >= 0)
            {
                if (!e.CtrlKey && !e.MetaKey) selected.Clear();
                foreach (var i in order.Skip(Math.Min(a, b)).Take(Math.Abs(a - b) + 1)) selected.Add(i.Url);
                return;
            }
        }
        if (e.CtrlKey || e.MetaKey) Toggle(item);
        else
        {
            selected.Clear();
            selected.Add(item.Url);
        }
        anchor = item.Url;
        focusShell = true;
    }

    private void Toggle(DavEntry item)
    {
        if (!selected.Remove(item.Url)) selected.Add(item.Url);
        anchor = item.Url;
    }

    private void ToggleAll(ChangeEventArgs e)
    {
        if (e.Value is true) SelectAll();
        else selected.Clear();
    }

    private void SelectAll()
    {
        foreach (var i in listing?.Items ?? []) selected.Add(i.Url);
    }

    private void ClearSelection() => selected.Clear();

    private void BackgroundClick()
    {
        selected.Clear();
        focusShell = true;
    }

    // ------------------------------------------------------------------ opening

    private async Task Open(DavEntry item)
    {
        if (item.IsFolder)
        {
            Nav.NavigateTo(item.Url);
            return;
        }
        if (Format.IsText(item.Name))
        {
            editing = item;
            return;
        }
        await JS.InvokeVoidAsync("open", item.Url, "_blank", "noopener");
    }

    private void EditorClosed(bool changed)
    {
        editing = null;
        focusShell = true;
        if (changed) _ = LoadAsync();
    }

    private async Task DownloadSelection()
    {
        var files = Selection().Where(i => !i.IsFolder).Select(i => i.Url).ToArray();
        if (files.Length == 0 && menuItems.Count > 0) files = menuItems.Where(i => !i.IsFolder).Select(i => i.Url).ToArray();
        if (files.Length > 0) await JS.InvokeVoidAsync("nullifyFiles.downloadAll", (object)files);
    }

    private async Task CopyLink(DavEntry? item)
    {
        var url = AbsoluteUrl(item?.Url ?? FolderUrl);
        if (await JS.InvokeAsync<bool>("nullifyFiles.copyText", url)) State.ShowToast("WebDAV address copied");
        else State.ShowToast(url);
    }

    // ------------------------------------------------------------------ context menu

    private void OpenMenu(MouseEventArgs e, DavEntry? item)
    {
        if (view != View.Folder || listing == null) return;
        if (item == null)
        {
            selected.Clear();
            menuItems = [];
        }
        else
        {
            if (!selected.Contains(item.Url))
            {
                selected.Clear();
                selected.Add(item.Url);
                anchor = item.Url;
            }
            menuItems = Selection();
        }
        menuAt = (e.ClientX, e.ClientY);
    }

    private void OpenMenuFromButton(MouseEventArgs e, DavEntry item)
    {
        selected.Clear();
        selected.Add(item.Url);
        menuItems = [item];
        menuAt = (e.ClientX, e.ClientY);
    }

    private void CloseMenu()
    {
        menuAt = null;
        menuItems = [];
    }

    private async Task FromMenu(Func<Task> action)
    {
        CloseMenu();
        await action();
    }

    private Task FromMenu(Action action)
    {
        CloseMenu();
        action();
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------ keyboard

    private async Task OnKey(KeyboardEventArgs e)
    {
        preventKey = false;
        if (creating != Creating.None || renaming != null || editing != null || sharing != null || view != View.Folder || listing == null) return;
        var ctrl = e.CtrlKey || e.MetaKey;
        switch (e.Key)
        {
            case "Delete" when CanWrite && selected.Count > 0:
                await DeleteSelection();
                break;
            case "F2" when CanWrite && selected.Count == 1:
                preventKey = true;
                StartRename(Selection()[0]);
                break;
            case "Enter" when selected.Count == 1:
                await Open(Selection()[0]);
                break;
            case "Escape":
                selected.Clear();
                break;
            case "Backspace" when segments.Length > 0:
            case "ArrowUp" when e.AltKey && segments.Length > 0:
                Nav.NavigateTo(UrlFor(segments[..^1], true));
                break;
            case "a" or "A" when ctrl:
                preventKey = true;
                SelectAll();
                break;
            case "c" or "C" when ctrl && selected.Count > 0:
                ToClipboard(false);
                break;
            case "x" or "X" when ctrl && selected.Count > 0 && CanWrite:
                ToClipboard(true);
                break;
            case "v" or "V" when ctrl && clipboard.Count > 0 && CanWrite:
                await Paste();
                break;
            case "F5":
                preventKey = true;
                await Refresh();
                break;
            case "ArrowDown" or "ArrowUp":
                preventKey = true;
                MoveCursor(e.Key == "ArrowDown" ? 1 : -1, e.ShiftKey);
                break;
        }
    }

    private void MoveCursor(int step, bool extend)
    {
        var order = Sorted().ToList();
        if (order.Count == 0) return;
        var i = anchor == null ? -1 : order.FindIndex(x => x.Url == anchor);
        var next = Math.Clamp(i < 0 ? (step > 0 ? 0 : order.Count - 1) : i + step, 0, order.Count - 1);
        if (!extend) selected.Clear();
        selected.Add(order[next].Url);
        anchor = order[next].Url;
        _ = JS.InvokeVoidAsync("nullifyFiles.scrollIntoView", $".docs-table tr[data-drag-url=\"{order[next].Url.Replace("\"", "\\\"")}\"]");
    }

    // ------------------------------------------------------------------ create, rename, delete

    private void StartCreate(Creating what)
    {
        renaming = null;
        creating = what;
        nameValue = what == Creating.File ? UniqueName("New text file.txt") : UniqueName("New folder");
        focusName = true;
    }

    private void CancelEdit()
    {
        creating = Creating.None;
        renaming = null;
        focusShell = true;
    }

    private async Task CreateKey(KeyboardEventArgs e)
    {
        if (e.Key == "Enter") await Create();
        else if (e.Key == "Escape") CancelEdit();
    }

    private async Task Create()
    {
        var name = nameValue.Trim();
        if (!ValidName(name)) return;
        var url = DavClient.Child(FolderUrl, name, creating == Creating.Folder);
        var what = creating;
        try
        {
            if (what == Creating.Folder) await Dav.CreateFolderAsync(url);
            else await Dav.CreateFileAsync(url, "");
            creating = Creating.None;
            await LoadAsync();
            selected.Clear();
            selected.Add(url);
            anchor = url;
            if (what == Creating.File && listing?.Items.FirstOrDefault(i => i.Url == url) is { } created) editing = created;
            else focusShell = true;
        }
        catch (Exception ex) when (ex is DavException or HttpRequestException)
        {
            State.ShowToast(ex.Message, true);
        }
    }

    private void StartRename(DavEntry item)
    {
        creating = Creating.None;
        renaming = item.Url;
        nameValue = item.Name;
        focusName = true;
    }

    private async Task RenameKey(KeyboardEventArgs e, DavEntry item)
    {
        if (e.Key == "Enter") await Rename(item);
        else if (e.Key == "Escape") CancelEdit();
    }

    private async Task Rename(DavEntry item)
    {
        var name = nameValue.Trim();
        if (name == item.Name) { CancelEdit(); return; }
        if (!ValidName(name)) return;
        var target = DavClient.Child(FolderUrl, name, item.IsFolder);
        try
        {
            // A different spelling of the same name is a rename too, so only refuse real clashes.
            var clash = listing?.Items.Any(i => i.Url != item.Url && string.Equals(i.Name, name, StringComparison.OrdinalIgnoreCase)) == true;
            if (clash) throw new DavException(HttpStatusCode.PreconditionFailed, $"\"{name}\" already exists here.");
            await Dav.MoveAsync(item.Url, target, overwrite: string.Equals(name, item.Name, StringComparison.OrdinalIgnoreCase));
            renaming = null;
            await LoadAsync();
            if (item.IsFolder) await LoadSharesAsync();
            selected.Clear();
            selected.Add(target);
            anchor = target;
            focusShell = true;
        }
        catch (Exception ex) when (ex is DavException or HttpRequestException)
        {
            State.ShowToast(ex.Message, true);
        }
    }

    private async Task DeleteSelection()
    {
        var items = menuItems.Count > 0 ? menuItems : Selection();
        if (items.Count == 0) return;
        var what = items.Count == 1
            ? (items[0].IsFolder ? $"the folder \"{items[0].Name}\" and everything in it" : $"\"{items[0].Name}\"")
            : $"{items.Count} items";
        if (!await JS.InvokeAsync<bool>("nullifyFiles.confirm", $"Delete {what}? This can't be undone.")) return;
        var failed = 0;
        foreach (var item in items)
        {
            try { await Dav.DeleteAsync(item.Url); }
            catch (Exception ex) when (ex is DavException or HttpRequestException)
            {
                failed++;
                State.ShowToast($"{item.Name}: {ex.Message}", true);
            }
        }
        if (failed < items.Count) State.ShowToast(items.Count == 1 ? $"Deleted \"{items[0].Name}\"" : $"Deleted {items.Count - failed} items");
        selected.Clear();
        await LoadAsync();
        if (items.Any(i => i.IsFolder)) await LoadSharesAsync();
    }

    private bool ValidName(string name)
    {
        string? problem = name.Length == 0 ? "Enter a name."
            : name is "." or ".." || name.IndexOfAny(['/', '\\']) >= 0 ? "Names cannot contain / or \\."
            : name.IndexOfAny([':', '*', '?', '"', '<', '>', '|']) >= 0 ? "Names cannot contain : * ? \" < > or |."
            : name.EndsWith('.') || name.EndsWith(' ') ? "Names cannot end with a dot or a space."
            : null;
        if (problem != null) State.ShowToast(problem, true);
        return problem == null;
    }

    private string UniqueName(string name)
    {
        var existing = (listing?.Items ?? []).Select(i => i.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!existing.Contains(name)) return name;
        var ext = System.IO.Path.GetExtension(name);
        var stem = name[..^ext.Length];
        for (var i = 2; ; i++)
        {
            var candidate = $"{stem} ({i}){ext}";
            if (!existing.Contains(candidate)) return candidate;
        }
    }

    // ------------------------------------------------------------------ clipboard, drag and drop

    private void ToClipboard(bool cut)
    {
        var items = menuItems.Count > 0 ? menuItems : Selection();
        if (items.Count == 0) return;
        clipboard = items;
        clipboardCut = cut && CanWrite;
        State.ShowToast($"{(clipboardCut ? "Cut" : "Copied")} {(items.Count == 1 ? $"\"{items[0].Name}\"" : $"{items.Count} items")}. Open a folder and paste.");
    }

    private Task Paste() => PasteInto(FolderUrl);

    private async Task PasteInto(string folderUrl)
    {
        if (clipboard.Count == 0) return;
        var moved = await TransferAsync(clipboard, folderUrl, copy: !clipboardCut);
        if (moved && clipboardCut) clipboard = [];
    }

    [JSInvokable]
    public void DragStarted(string url)
    {
        if (listing == null) return;
        dragged = selected.Contains(url) ? Selection() : listing.Items.Where(i => i.Url == url).ToList();
    }

    [JSInvokable]
    public async Task DropItems(string targetUrl, bool copy)
    {
        var items = dragged;
        dragged = [];
        if (items.Count == 0) return;
        await TransferAsync(items, targetUrl, copy || !CanWrite);
        StateHasChanged();
    }

    /// <summary>Moves or copies items into a folder, asking once before replacing anything.</summary>
    private async Task<bool> TransferAsync(List<DavEntry> items, string folderUrl, bool copy)
    {
        var sameFolder = items.All(i => ParentOf(i.Url) == folderUrl);
        if (sameFolder && !copy) return false;
        var work = items.Select(i =>
        {
            var name = i.Name;
            // Copying into the same folder makes "name (2)" rather than replacing the original.
            if (ParentOf(i.Url) == folderUrl) name = UniqueName(i.Name);
            return (Item: i, Target: DavClient.Child(folderUrl, name, i.IsFolder));
        }).Where(w => w.Target != w.Item.Url).ToList();
        if (work.Any(w => folderUrl.StartsWith(w.Item.Url, StringComparison.Ordinal) && w.Item.IsFolder))
        {
            State.ShowToast("A folder cannot be moved or copied into itself.", true);
            return false;
        }

        var conflicts = new List<(DavEntry Item, string Target)>();
        var done = 0;
        foreach (var w in work)
        {
            try
            {
                if (copy) await Dav.CopyAsync(w.Item.Url, w.Target, overwrite: false);
                else await Dav.MoveAsync(w.Item.Url, w.Target, overwrite: false);
                done++;
            }
            catch (DavException ex) when (ex.Status == HttpStatusCode.PreconditionFailed)
            {
                conflicts.Add(w);
            }
            catch (Exception ex) when (ex is DavException or HttpRequestException)
            {
                State.ShowToast($"{w.Item.Name}: {ex.Message}", true);
            }
        }
        if (conflicts.Count > 0)
        {
            var list = string.Join(", ", conflicts.Take(3).Select(c => c.Item.Name)) + (conflicts.Count > 3 ? $" and {conflicts.Count - 3} more" : "");
            if (await JS.InvokeAsync<bool>("nullifyFiles.confirm", $"{list} already exist{(conflicts.Count == 1 ? "s" : "")} there. Replace?"))
            {
                foreach (var w in conflicts)
                {
                    try
                    {
                        if (copy) await Dav.CopyAsync(w.Item.Url, w.Target, overwrite: true);
                        else await Dav.MoveAsync(w.Item.Url, w.Target, overwrite: true);
                        done++;
                    }
                    catch (Exception ex) when (ex is DavException or HttpRequestException)
                    {
                        State.ShowToast($"{w.Item.Name}: {ex.Message}", true);
                    }
                }
            }
        }
        if (done > 0)
        {
            var where = Uri.UnescapeDataString(folderUrl.TrimEnd('/')[(folderUrl.TrimEnd('/').LastIndexOf('/') + 1)..]);
            State.ShowToast($"{(copy ? "Copied" : "Moved")} {(done == 1 ? $"\"{work[0].Item.Name}\"" : $"{done} items")} to {where}");
            selected.Clear();
            await LoadAsync();
            if (!copy && items.Any(i => i.IsFolder)) await LoadSharesAsync();
        }
        return done > 0;
    }

    private static string ParentOf(string url)
    {
        var trimmed = url.TrimEnd('/');
        return trimmed[..(trimmed.LastIndexOf('/') + 1)];
    }

    // ------------------------------------------------------------------ uploads (files.js does the transfer)

    private async Task PickUpload(bool folders)
    {
        if (!CanWrite || uploading) return;
        await JS.InvokeVoidAsync("nullifyFiles.pick", FolderUrl, folders);
    }

    [JSInvokable]
    public async Task UploadChosen(int id, string target, string[] names, bool[] folders, int count, long total)
    {
        if (upload != null)
        {
            State.ShowToast("Please wait for the current upload to finish.", true);
            await JS.InvokeVoidAsync("nullifyFiles.discardUpload", id);
            return;
        }
        var overwrite = false;
        if (target == FolderUrl && listing != null)
        {
            var existing = listing.Items.Where(i => !i.IsFolder).Select(i => i.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var clashes = names.Where((n, i) => !folders[i] && existing.Contains(n)).ToList();
            if (clashes.Count > 0)
            {
                var list = string.Join(", ", clashes.Take(3)) + (clashes.Count > 3 ? $" and {clashes.Count - 3} more" : "");
                overwrite = await JS.InvokeAsync<bool>("nullifyFiles.confirm",
                    $"{list} already exist{(clashes.Count == 1 ? "s" : "")} here. Replace? (Cancel keeps the existing files and uploads the rest.)");
            }
        }
        upload = new UploadState { Id = id, Target = target, Count = count, Total = total };
        StateHasChanged();
        await JS.InvokeVoidAsync("nullifyFiles.startUpload", id, overwrite);
    }

    [JSInvokable]
    public void UploadProgress(int id, int index, int count, string name, long sent, long total)
    {
        if (upload?.Id != id) return;
        upload.Index = index;
        upload.Count = count;
        if (name.Length > 0) upload.Name = name;
        upload.Sent = sent;
        upload.Total = total;
        StateHasChanged();
    }

    [JSInvokable]
    public async Task UploadDone(int id, int ok, string[] failedNames, int[] failedStatus, string[] failedMessages, bool cancelled)
    {
        if (upload?.Id != id) return;
        var target = upload.Target;
        upload = null;
        var skipped = failedStatus.Count(s => s == 412);
        var failed = failedNames.Length - skipped;
        if (cancelled) State.ShowToast(ok > 0 ? $"Upload cancelled after {ok} file{(ok == 1 ? "" : "s")}" : "Upload cancelled");
        else if (ok > 0) State.ShowToast(ok == 1 && failedNames.Length == 0 ? "Uploaded 1 file" : $"Uploaded {ok} file{(ok == 1 ? "" : "s")}" +
                                                                                   (skipped > 0 ? $", skipped {skipped} that already existed" : ""));
        else if (skipped > 0 && failed == 0) State.ShowToast($"Nothing uploaded: {skipped} file{(skipped == 1 ? "" : "s")} already existed");
        for (var i = 0; i < failedNames.Length; i++)
        {
            if (failedStatus[i] == 412) continue;
            var message = failedMessages[i].Length > 0 ? failedMessages[i]
                : failedStatus[i] == 0 ? "the connection failed" : DavClient.Describe((HttpStatusCode)failedStatus[i]);
            State.ShowToast($"{failedNames[i]}: {message}", true);
        }
        if (view == View.Folder && (target == FolderUrl || target.StartsWith(FolderUrl, StringComparison.Ordinal))) await LoadAsync();
        StateHasChanged();
    }

    [JSInvokable]
    public void UploadFailedToRead(string message)
    {
        State.ShowToast("The dropped files could not be read: " + message, true);
    }

    private async Task CancelUpload()
    {
        if (upload != null) await JS.InvokeVoidAsync("nullifyFiles.cancelUpload", upload.Id);
    }

    // ------------------------------------------------------------------ sharing

    private string CurrentRelative(DavEntry? child) =>
        string.Join('/', child == null ? segments : segments.Append(child.Name));

    private bool IsShared(DavEntry folder)
    {
        var path = CurrentRelative(folder);
        return myShares.Any(s => Names.Eq(s.Mount, mountSegment) && string.Equals(s.Path, path, StringComparison.OrdinalIgnoreCase));
    }

    private void OpenShare(DavEntry? folder)
    {
        var path = CurrentRelative(folder);
        var existing = myShares.Where(s => Names.Eq(s.Mount, mountSegment) && string.Equals(s.Path, path, StringComparison.OrdinalIgnoreCase)).ToList();
        sharing = (mountSegment, path, folder?.Name ?? (segments.Length > 0 ? segments[^1] : mountSegment), CanWrite, existing);
    }

    private void EditShare(ShareInfo share)
    {
        var mount = session?.Mounts.FirstOrDefault(m => Names.Eq(m.Name, share.Mount));
        var name = share.Path.Length > 0 ? share.Path[(share.Path.LastIndexOf('/') + 1)..] : share.Mount;
        sharing = (share.Mount, share.Path, name, mount?.CanWrite ?? false, [share]);
    }

    private async Task ShareClosed(bool changed)
    {
        sharing = null;
        if (changed) await LoadSharesAsync();
        focusShell = true;
    }

    private async Task StopSharing(ShareInfo share)
    {
        if (!await JS.InvokeAsync<bool>("nullifyFiles.confirm", $"Stop sharing \"{share.Name}\" with {Recipients(share)}?")) return;
        try
        {
            await Api.DeleteShareAsync(share.Id);
            State.ShowToast($"Stopped sharing \"{share.Name}\"");
            await LoadSharesAsync();
        }
        catch (ApiClient.ApiException ex)
        {
            State.ShowToast(ex.Message, true);
        }
    }

    private static string Recipients(ShareInfo s) =>
        string.Join(", ", s.Users.Concat(s.Groups.Select(g => g + " (group)")));

    private static string SharedFolderUrl(ShareInfo s) =>
        UrlForMount(s.Mount, s.Path.Split('/', StringSplitOptions.RemoveEmptyEntries));

    // ------------------------------------------------------------------ chrome

    private void CloseSidebar() => sidebarOpen = false;

    private async Task ToggleRail() => await JS.InvokeVoidAsync("nullifyFiles.toggleRail");

    private async Task ToggleTheme() => await JS.InvokeVoidAsync("nullifyFiles.toggleTheme");

    private async Task SignOut()
    {
        try { await Api.LogoutAsync(); } catch (HttpRequestException) { }
        Nav.NavigateTo("account/login", forceLoad: true);
    }

    private static string Initials(string name)
    {
        var parts = name.Split([' ', '.', '_', '-', '@'], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length switch
        {
            0 => "?",
            1 => parts[0][..Math.Min(2, parts[0].Length)].ToUpperInvariant(),
            _ => string.Concat(char.ToUpperInvariant(parts[0][0]), char.ToUpperInvariant(parts[^1][0])),
        };
    }

    private static int Hue(string name) => (int)((uint)name.ToLowerInvariant().Aggregate(17, (h, c) => h * 31 + c) % 360);
}
