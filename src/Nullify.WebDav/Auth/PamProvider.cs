// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Runtime.InteropServices;
using System.Text;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Auth;

/// <summary>
/// Verifies Linux accounts through PAM (<c>pam_authenticate</c> + <c>pam_acct_mgmt</c>) and reads the account's
/// Unix groups. The service account must be allowed to check other users' passwords: run as root, or (with
/// pam_unix) be a member of the <c>shadow</c> group.
/// </summary>
public sealed partial class PamProvider(ILogger<PamProvider> log) : ICredentialProvider
{
    private const int PamSuccess = 0;
    private const int PamConvErr = 19;
    private const int PamPromptEchoOff = 1;
    private const int PamPromptEchoOn = 2;
    private const int PamSilent = 0x8000;
    private const int PamDisallowNullAuthtok = 0x0001;

    // PAM modules are not all thread safe, and getpwnam/getgrgid use static buffers.
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public ProviderType Type => ProviderType.Pam;
    public bool IsSupported => OperatingSystem.IsLinux();

    public async Task<ProviderResult> AuthenticateAsync(AuthProviderConfig config, string login, string password, CancellationToken ct)
    {
        if (!OperatingSystem.IsLinux()) return ProviderResult.Unavailable;
        if (login.Contains('\0') || password.Contains('\0')) return ProviderResult.Invalid;
        await Gate.WaitAsync(ct);
        try
        {
            return await Task.Run(() => Authenticate(config, login, password), CancellationToken.None);
        }
        catch (DllNotFoundException ex)
        {
            log.LogError("PAM is not available ({Message}). Install libpam0g / pam.", ex.Message);
            return ProviderResult.Unavailable;
        }
        finally
        {
            Gate.Release();
        }
    }

    private sealed class ConversationState(string login, string password)
    {
        public readonly string Login = login;
        public readonly string Password = password;
    }

    private unsafe ProviderResult Authenticate(AuthProviderConfig config, string login, string password)
    {
        var state = GCHandle.Alloc(new ConversationState(login, password));
        IntPtr handle = IntPtr.Zero;
        try
        {
            var conv = new PamConv { Conv = (IntPtr)(delegate* unmanaged<int, IntPtr*, IntPtr*, IntPtr, int>)&Conversation, AppData = GCHandle.ToIntPtr(state) };
            var rc = pam_start(config.Service, login, &conv, out handle);
            if (rc != PamSuccess)
            {
                log.LogWarning("pam_start for service {Service} failed with {Code}", config.Service, rc);
                return ProviderResult.Unavailable;
            }
            rc = pam_authenticate(handle, PamSilent | PamDisallowNullAuthtok);
            if (rc == PamSuccess) rc = pam_acct_mgmt(handle, PamSilent | PamDisallowNullAuthtok);
            pam_end(handle, rc);
            handle = IntPtr.Zero;
            if (rc != PamSuccess) return ProviderResult.Invalid;
            return new ProviderResult(ProviderOutcome.Success, login, config.UseOsGroups ? GroupsOf(login) : []);
        }
        finally
        {
            if (handle != IntPtr.Zero) pam_end(handle, PamConvErr);
            state.Free();
        }
    }

    [UnmanagedCallersOnly]
    private static unsafe int Conversation(int count, IntPtr* messages, IntPtr* responses, IntPtr appData)
    {
        if (count is <= 0 or > 32) return PamConvErr;
        var state = (ConversationState)GCHandle.FromIntPtr(appData).Target!;
        // PAM frees the array and each answer with free(), so they come from the C heap.
        var answers = (PamResponse*)NativeMemory.AllocZeroed((nuint)count, (nuint)sizeof(PamResponse));
        for (var i = 0; i < count; i++)
        {
            var message = (PamMessage*)messages[i];
            answers[i].Resp = message->Style switch
            {
                PamPromptEchoOff => CString(state.Password),
                PamPromptEchoOn => CString(state.Login),
                _ => IntPtr.Zero,
            };
        }
        *responses = (IntPtr)answers;
        return PamSuccess;
    }

    private static unsafe IntPtr CString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var p = (byte*)NativeMemory.Alloc((nuint)bytes.Length + 1);
        bytes.CopyTo(new Span<byte>(p, bytes.Length));
        p[bytes.Length] = 0;
        return (IntPtr)p;
    }

    private static unsafe List<string> GroupsOf(string login)
    {
        var groups = new List<string>();
        var pw = getpwnam(login);
        if (pw == null) return groups;
        var count = 64;
        while (true)
        {
            var ids = new uint[count];
            int n = count;
            fixed (uint* p = ids)
            {
                if (getgrouplist(login, pw->Gid, p, &n) >= 0)
                {
                    for (var i = 0; i < n; i++)
                    {
                        var gr = getgrgid(ids[i]);
                        if (gr != null && gr->Name != IntPtr.Zero) groups.Add(Marshal.PtrToStringUTF8(gr->Name)!);
                    }
                    return groups;
                }
            }
            if (n <= count || count > 65536) return groups;
            count = n;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PamConv
    {
        public IntPtr Conv;
        public IntPtr AppData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PamMessage
    {
        public int Style;
        public IntPtr Msg;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PamResponse
    {
        public IntPtr Resp;
        public int RetCode;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Passwd
    {
        public IntPtr Name;
        public IntPtr Password;
        public uint Uid;
        public uint Gid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Group
    {
        public IntPtr Name;
    }

    [LibraryImport("libpam.so.0", StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int pam_start(string service, string user, PamConv* conv, out IntPtr handle);

    [LibraryImport("libpam.so.0")]
    private static partial int pam_authenticate(IntPtr handle, int flags);

    [LibraryImport("libpam.so.0")]
    private static partial int pam_acct_mgmt(IntPtr handle, int flags);

    [LibraryImport("libpam.so.0")]
    private static partial int pam_end(IntPtr handle, int status);

    [LibraryImport("libc", StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial Passwd* getpwnam(string name);

    [LibraryImport("libc", StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int getgrouplist(string user, uint group, uint* groups, int* count);

    [LibraryImport("libc")]
    private static unsafe partial Group* getgrgid(uint gid);
}
