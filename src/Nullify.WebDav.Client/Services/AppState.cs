// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebDav.Client.Services;

/// <summary>Toasts shown at the bottom of the window.</summary>
public sealed class AppState
{
    public sealed record Toast(int Id, string Message, bool IsError);

    private int _next;
    public List<Toast> Toasts { get; } = [];
    public event Action? Changed;

    public void ShowToast(string message, bool isError = false)
    {
        var toast = new Toast(++_next, message, isError);
        Toasts.Add(toast);
        if (Toasts.Count > 4) Toasts.RemoveAt(0);
        Changed?.Invoke();
        _ = Task.Delay(isError ? 8000 : 4000).ContinueWith(_ => DismissToast(toast.Id));
    }

    public void DismissToast(int id)
    {
        if (Toasts.RemoveAll(t => t.Id == id) > 0) Changed?.Invoke();
    }
}
