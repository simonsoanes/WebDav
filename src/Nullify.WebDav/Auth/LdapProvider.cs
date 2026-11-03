// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Nullify.WebDav.Configuration;

namespace Nullify.WebDav.Auth;

/// <summary>
/// Verifies passwords with an LDAP v3 simple bind (RFC 4511/4513) over LDAPS or StartTLS. Works with Active
/// Directory (bind as "{user}@domain" or "DOMAIN\{user}"), OpenLDAP, FreeIPA, Samba and others
/// ("uid={user},ou=people,dc=example,dc=com"). Only the bind is performed; groups are not read from the directory.
/// </summary>
public sealed class LdapProvider(ILogger<LdapProvider> log) : ICredentialProvider
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);
    private const string StartTlsOid = "1.3.6.1.4.1.1466.20037";

    public ProviderType Type => ProviderType.Ldap;
    public bool IsSupported => true;

    public async Task<ProviderResult> AuthenticateAsync(AuthProviderConfig config, string login, string password, CancellationToken ct)
    {
        // An empty password is an "unauthenticated bind", which servers accept for any DN.
        if (password.Length == 0) return ProviderResult.Invalid;
        var dn = ProviderRegistry.ApplyTemplate(config.LoginTemplate, login);
        if (dn == null) return ProviderResult.Invalid;

        var port = config.Port > 0 ? config.Port : ProviderRegistry.DefaultPort(ProviderType.Ldap, config.Security);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        try
        {
            using var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(config.Host, port, cts.Token);
            Stream stream = tcp.GetStream();
            if (config.Security == TransportSecurity.Tls) stream = await UpgradeAsync(stream, config, cts.Token);
            if (config.Security == TransportSecurity.StartTls)
            {
                await stream.WriteAsync(Message(1, Ber.Element(0x77, Ber.Element(0x80, Encoding.ASCII.GetBytes(StartTlsOid)))), cts.Token);
                var (tag, code) = await ReadResultAsync(stream, cts.Token);
                if (tag != 0x78 || code != 0)
                {
                    log.LogWarning("LDAP server {Host} refused StartTLS (result {Code})", config.Host, code);
                    return ProviderResult.Unavailable;
                }
                stream = await UpgradeAsync(stream, config, cts.Token);
            }

            var bind = Ber.Element(0x60,
                Ber.Integer(3),
                Ber.Element(0x04, Encoding.UTF8.GetBytes(dn)),
                Ber.Element(0x80, Encoding.UTF8.GetBytes(password)));
            await stream.WriteAsync(Message(2, bind), cts.Token);
            var (bindTag, result) = await ReadResultAsync(stream, cts.Token);
            try { await stream.WriteAsync(Message(3, Ber.Element(0x42, [])), cts.Token); } catch (IOException) { }
            await stream.DisposeAsync();

            if (bindTag != 0x61) throw new InvalidDataException("Unexpected LDAP response");
            return result switch
            {
                0 => new ProviderResult(ProviderOutcome.Success, login),
                49 or 50 or 53 => ProviderResult.Invalid, // invalidCredentials, insufficientAccessRights, unwillingToPerform
                _ => LogUnavailable(config, $"bind result {result}"),
            };
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or OperationCanceledException or InvalidDataException)
        {
            return LogUnavailable(config, ex.Message);
        }
    }

    private ProviderResult LogUnavailable(AuthProviderConfig config, string message)
    {
        log.LogWarning("LDAP authentication against {Host} failed: {Message}", config.Host, message);
        return ProviderResult.Unavailable;
    }

    private static async Task<Stream> UpgradeAsync(Stream inner, AuthProviderConfig config, CancellationToken ct)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false,
            (_, _, _, errors) => errors == SslPolicyErrors.None || config.AllowInvalidCertificates);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = config.Host }, ct);
        return ssl;
    }

    private static byte[] Message(int id, byte[] operation) => Ber.Element(0x30, Ber.Integer(id), operation);

    /// <summary>Reads one LDAPMessage and returns the protocol operation tag and its resultCode.</summary>
    private static async Task<(int Tag, int Result)> ReadResultAsync(Stream stream, CancellationToken ct)
    {
        var message = await Ber.ReadElementAsync(stream, 0x30, ct);
        var reader = new Ber.Reader(message);
        reader.Read(0x02); // messageID
        var (tag, op) = reader.ReadAny();
        var code = new Ber.Reader(op).Read(0x0A); // resultCode ENUMERATED
        return (tag, code.Length is 0 or > 4 ? -1 : code.Aggregate(0, (acc, b) => acc << 8 | b));
    }

    /// <summary>The handful of BER/DER encodings LDAP needs.</summary>
    internal static class Ber
    {
        public static byte[] Element(byte tag, params byte[][] content)
        {
            var length = content.Sum(c => c.Length);
            var result = new List<byte>(length + 6) { tag };
            result.AddRange(Length(length));
            foreach (var c in content) result.AddRange(c);
            return result.ToArray();
        }

        public static byte[] Integer(int value)
        {
            var bytes = new List<byte>();
            do
            {
                bytes.Insert(0, (byte)(value & 0xFF));
                value >>= 8;
            } while (value > 0);
            if ((bytes[0] & 0x80) != 0) bytes.Insert(0, 0);
            return Element(0x02, bytes.ToArray());
        }

        private static byte[] Length(int length)
        {
            if (length < 0x80) return [(byte)length];
            var bytes = new List<byte>();
            while (length > 0)
            {
                bytes.Insert(0, (byte)(length & 0xFF));
                length >>= 8;
            }
            bytes.Insert(0, (byte)(0x80 | bytes.Count));
            return bytes.ToArray();
        }

        public static async Task<byte[]> ReadElementAsync(Stream stream, byte expectedTag, CancellationToken ct)
        {
            var tag = await ReadByteAsync(stream, ct);
            if (tag != expectedTag) throw new InvalidDataException($"Unexpected BER tag 0x{tag:X2}");
            int length = await ReadByteAsync(stream, ct);
            if ((length & 0x80) != 0)
            {
                var n = length & 0x7F;
                if (n is 0 or > 3) throw new InvalidDataException("Unsupported BER length");
                length = 0;
                for (var i = 0; i < n; i++) length = length << 8 | await ReadByteAsync(stream, ct);
            }
            if (length > 1_000_000) throw new InvalidDataException("LDAP response too large");
            var buffer = new byte[length];
            await stream.ReadExactlyAsync(buffer, ct);
            return buffer;
        }

        private static async Task<byte> ReadByteAsync(Stream stream, CancellationToken ct)
        {
            var one = new byte[1];
            await stream.ReadExactlyAsync(one, ct);
            return one[0];
        }

        public sealed class Reader(byte[] data)
        {
            private int _pos;

            public (byte Tag, byte[] Content) ReadAny()
            {
                if (_pos + 2 > data.Length) throw new InvalidDataException("Truncated BER element");
                var tag = data[_pos++];
                int length = data[_pos++];
                if ((length & 0x80) != 0)
                {
                    var n = length & 0x7F;
                    if (n is 0 or > 3 || _pos + n > data.Length) throw new InvalidDataException("Unsupported BER length");
                    length = 0;
                    for (var i = 0; i < n; i++) length = length << 8 | data[_pos++];
                }
                if (_pos + length > data.Length) throw new InvalidDataException("Truncated BER element");
                var content = data[_pos..(_pos + length)];
                _pos += length;
                return (tag, content);
            }

            public byte[] Read(byte expectedTag)
            {
                var (tag, content) = ReadAny();
                if (tag != expectedTag) throw new InvalidDataException($"Expected BER tag 0x{expectedTag:X2}, got 0x{tag:X2}");
                return content;
            }
        }
    }
}
