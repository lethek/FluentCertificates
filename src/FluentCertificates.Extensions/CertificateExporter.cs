using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace FluentCertificates;

/// <summary>Export format discriminator — internal implementation detail.</summary>
internal enum ExportFormat
{
    Pkcs12,
    Pem,
    Pkcs7,
    Cert
}


/// <summary>
/// Provides output methods for a certificate export operation configured via <see cref="CertificateExportBuilder"/>.
/// Instances are obtained by calling a format-selection method such as
/// <see cref="CertificateExportBuilder.AsPkcs12"/>, <see cref="CertificateExportBuilder.AsPkcs7"/>,
/// or <see cref="CertificateExportBuilder.AsCert"/>.
/// For PEM output, use <see cref="CertificateExportBuilder.AsPem"/> which returns a
/// <see cref="PemCertificateExporter"/> with an additional <see cref="PemCertificateExporter.ToPemString"/> method.
/// </summary>
public class CertificateExporter
{
    private readonly IReadOnlyList<X509Certificate2> _certs;
    private readonly ExportFormat _format;
    private readonly string? _password;
    private readonly SecureString? _securePassword;
    private readonly ExportKeys _keys;


    /// <summary>
    /// Initializes a new <see cref="CertificateExporter"/>.
    /// </summary>
    /// <param name="certs">Certificates to export. Must be non-empty. When they form a single issuer
    /// chain they are reordered root-first, whatever order they arrived in.</param>
    /// <param name="format">The binary format to produce.</param>
    /// <param name="password">Plain-text password (ignored when <paramref name="securePassword"/> is non-null).</param>
    /// <param name="securePassword">SecureString password; takes precedence over <paramref name="password"/>.</param>
    /// <param name="keys">Which private keys to include.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="certs"/> is empty.</exception>
    internal CertificateExporter(ImmutableList<X509Certificate2> certs, ExportFormat format, string? password, SecureString? securePassword, ExportKeys keys)
    {
        if (certs.Count == 0) {
            throw new ArgumentException("No certificates to export.", nameof(certs));
        }
        _certs = OrderRootFirst(certs);
        _format = format;
        _password = password;
        _securePassword = securePassword;
        _keys = keys;
    }


    /// <summary>
    /// Writes the exported bytes to <paramref name="path"/> and returns this instance to allow chaining
    /// multiple <see cref="ToFile"/> calls.
    /// </summary>
    /// <param name="path">Destination file path. The directory must already exist.</param>
    /// <returns>This <see cref="CertificateExporter"/> instance.</returns>
    public CertificateExporter ToFile(string path)
    {
        File.WriteAllBytes(path, ToByteArray());
        return this;
    }

    /// <summary>
    /// Writes the exported bytes to <paramref name="stream"/> and returns this instance.
    /// </summary>
    /// <param name="stream">The destination stream. Must be writable.</param>
    /// <returns>This <see cref="CertificateExporter"/> instance.</returns>
    public CertificateExporter ToStream(Stream stream)
    {
        var bytes = ToByteArray();
        stream.Write(bytes, 0, bytes.Length);
        return this;
    }

    /// <summary>
    /// Produces the exported certificate data as a byte array.
    /// </summary>
    /// <returns>The exported bytes in the format selected on the builder.</returns>
    public virtual byte[] ToByteArray()
        => _format switch {
            ExportFormat.Pkcs12 =>
                ExportPkcs12(),

            ExportFormat.Pem =>
                Encoding.UTF8.GetBytes(ExportPem()),

            ExportFormat.Pkcs7 =>
                _certs.ToCollection().Export(X509ContentType.Pkcs7)
                ?? throw new InvalidOperationException("PKCS#7 export returned null."),

            ExportFormat.Cert =>
                _certs[0].RawData,

            _ => throw new InvalidOperationException($"Unsupported export format: {_format}.")
        };


    /// <summary>
    /// Produces the PKCS#12 representation of the configured certificates and keys.
    /// </summary>
    private byte[] ExportPkcs12()
    {
        //Stripping a private key creates a certificate that only this method can see, so only this
        //method can release it. The ones passed through belong to the caller and are left alone.
        var stripped = new List<X509Certificate2>();
        try {
            return _certs.FilterPrivateKeys(_keys, stripped).ToCollection()
                .Export(X509ContentType.Pkcs12, GetPasswordString())
                ?? throw new InvalidOperationException("PKCS#12 export returned null.");
        } finally {
            foreach (var cert in stripped) {
                cert.Dispose();
            }
        }
    }


    /// <summary>
    /// Produces the PEM-encoded representation of the configured certificates and keys:
    /// private key blocks first, then CERTIFICATE blocks in leaf-first order. The source
    /// list is treated as root-first, so the last certificate in it is the leaf.
    /// </summary>
    internal string ExportPem()
    {
        var stripped = new List<X509Certificate2>();
        try {
            var list = _certs.FilterPrivateKeys(_keys, stripped).Reverse().ToList();
            if (list.Count == 0) {
                return string.Empty;
            }

            using var sw = new StringWriter();
            if (_keys != ExportKeys.None) {
                char[]? buffer = null;
                try {
                    var password = GetPasswordChars(out buffer);
                    foreach (var cert in list.Where(x => x.HasPrivateKey)) {
                        using var key = cert.GetPrivateKey();
                        key.WritePrivateKeyPem(sw, password.Span);
                        sw.Write('\n');
                    }
                } finally {
                    if (buffer != null) {
                        Array.Clear(buffer);
                    }
                }
            }
            sw.Write(PemEncoding.Write("CERTIFICATE", list[0].RawData));
            foreach (var cert in list.Skip(1)) {
                sw.Write('\n');
                sw.Write(PemEncoding.Write("CERTIFICATE", cert.RawData));
            }
            return sw.ToString();

        } finally {
            foreach (var cert in stripped) {
                cert.Dispose();
            }
        }
    }


    /// <summary>
    /// Returns <paramref name="certs"/> ordered root-first, leaf last, when they form a single unambiguous
    /// issuer chain. Every other input, including an unrelated bag of certificates or one holding two
    /// candidates for the same position, is returned untouched.
    /// </summary>
    /// <remarks>
    /// Both the leaf-first PEM block order and <see cref="ExportKeys.Leaf"/> read the leaf off the end of
    /// this list, so a caller who reaches the same chain by a different route (say a leaf seeded by
    /// <c>cert.Export()</c> then topped up with <see cref="CertificateExportBuilder.WithChain(X509Chain)"/>)
    /// must not get a different export.
    /// </remarks>
    private static IReadOnlyList<X509Certificate2> OrderRootFirst(IReadOnlyList<X509Certificate2> certs)
    {
        if (certs.Count < 2) {
            return certs;
        }

        //The root is the one certificate nothing else in the list issued. Self-issued doesn't count:
        //a self-signed root is its own issuer and would otherwise disqualify itself.
        var rootIndex = -1;
        for (var i = 0; i < certs.Count; i++) {
            var cert = certs[i];
            if (certs.Any(issuer => !ReferenceEquals(issuer, cert) && cert.IsIssuedBy(issuer))) {
                continue;
            }
            if (rootIndex >= 0) {
                //More than one certificate without an issuer here, so this isn't a single chain.
                return certs;
            }
            rootIndex = i;
        }
        if (rootIndex < 0) {
            return certs;
        }

        var placed = new bool[certs.Count];
        placed[rootIndex] = true;

        var ordered = new List<X509Certificate2>(certs.Count) { certs[rootIndex] };
        while (ordered.Count < certs.Count) {
            var issuer = ordered[^1];
            var next = -1;
            for (var i = 0; i < certs.Count; i++) {
                if (placed[i] || !certs[i].IsIssuedBy(issuer)) {
                    continue;
                }
                if (next >= 0) {
                    //Two candidates for the same rung: the ordering isn't ours to decide.
                    return certs;
                }
                next = i;
            }
            if (next < 0) {
                //A gap or a disjoint certificate, so this isn't a single chain.
                return certs;
            }
            ordered.Add(certs[next]);
            placed[next] = true;
        }
        return ordered;
    }


    /// <summary>
    /// Returns the effective export password as characters: <see cref="_securePassword"/> decrypted into
    /// <paramref name="buffer"/> when non-null, otherwise <see cref="_password"/>.
    /// </summary>
    /// <param name="buffer">Receives the buffer holding a decrypted <see cref="SecureString"/>, which the
    /// caller must zero once finished with the returned characters. Null when there was nothing to decrypt,
    /// since a plain-text password is already an unerasable managed string.</param>
    private ReadOnlyMemory<char> GetPasswordChars(out char[]? buffer)
    {
        if (_securePassword is null) {
            buffer = null;
            return (_password ?? String.Empty).AsMemory();
        }

        buffer = new char[_securePassword.Length];
        var ptr = Marshal.SecureStringToGlobalAllocUnicode(_securePassword);
        try {
            Marshal.Copy(ptr, buffer, 0, buffer.Length);
        } finally {
            Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
        return buffer.AsMemory();
    }


    /// <summary>
    /// Returns the effective export password: <see cref="_securePassword"/> converted to string when non-null,
    /// otherwise <see cref="_password"/>.
    /// </summary>
    /// <remarks>
    /// Only for the formats whose platform API takes a <see cref="string"/>. It defeats the point of a
    /// <see cref="SecureString"/>, since the result cannot be zeroed, so prefer
    /// <see cref="GetPasswordChars"/> wherever a span-taking overload exists.
    /// </remarks>
    private string? GetPasswordString()
    {
        if (_securePassword is null) {
            return _password;
        }

        var ptr = Marshal.SecureStringToGlobalAllocUnicode(_securePassword);
        try {
            return Marshal.PtrToStringUni(ptr);
        } finally {
            Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
    }
}
