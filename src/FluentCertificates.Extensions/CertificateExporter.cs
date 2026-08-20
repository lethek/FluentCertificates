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
    private readonly X509Certificate2? _primary;
    private readonly ExportFormat _format;
    private readonly string? _password;
    private readonly SecureString? _securePassword;
    private readonly ExportKeys _keys;


    /// <summary>
    /// Initializes a new <see cref="CertificateExporter"/>.
    /// </summary>
    /// <param name="certs">Certificates to export. Must be non-empty. When they form a single issuer
    /// chain they are reordered leaf-first, whatever order they arrived in.</param>
    /// <param name="anchor">The certificate the caller anchored on, or null. See
    /// <see cref="CertificateExportBuilder.Anchor"/>.</param>
    /// <param name="format">The binary format to produce.</param>
    /// <param name="password">Plain-text password (ignored when <paramref name="securePassword"/> is non-null).</param>
    /// <param name="securePassword">SecureString password; takes precedence over <paramref name="password"/>.</param>
    /// <param name="keys">Which private keys to include.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="certs"/> is empty.</exception>
    internal CertificateExporter(ImmutableList<X509Certificate2> certs, X509Certificate2? anchor, ExportFormat format, string? password, SecureString? securePassword, ExportKeys keys)
    {
        if (certs.Count == 0) {
            throw new ArgumentException("No certificates to export.", nameof(certs));
        }
        if (anchor != null && !certs.Any(x => String.Equals(x.Thumbprint, anchor.Thumbprint, StringComparison.OrdinalIgnoreCase))) {
            throw new ArgumentException(
                "The anchor certificate is not among the certificates being exported. An export cannot "
                + "target a certificate it does not contain.", nameof(anchor));
        }

        _certs = OrderLeafFirst(certs, out var sorted);

        //An anchor is the caller's own statement of which certificate the export is about, so it
        //outranks anything inferred from the list. Only without one does the sorted chain's leaf stand in.
        _primary = anchor ?? (sorted ? _certs[0] : null);
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
                ExportCert(),

            _ => throw new InvalidOperationException($"Unsupported export format: {_format}.")
        };


    /// <summary>
    /// Produces the DER bytes of the primary certificate: the anchor, or the sorted chain's leaf.
    /// </summary>
    private byte[] ExportCert()
        => RequirePrimary("AsCert()").RawData;


    /// <summary>
    /// Produces the PKCS#12 representation of the configured certificates and keys.
    /// </summary>
    private byte[] ExportPkcs12()
    {
        //Stripping a private key creates a certificate that only this method can see, so only this
        //method can release it. The ones passed through belong to the caller and are left alone.
        var stripped = new List<X509Certificate2>();
        try {
            return FilterKeys(stripped).ToCollection()
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
    /// private key blocks first, then CERTIFICATE blocks in list order, which is leaf-first.
    /// </summary>
    internal string ExportPem()
    {
        var stripped = new List<X509Certificate2>();
        try {
            var list = FilterKeys(stripped).ToList();
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
    /// Returns <paramref name="certs"/> ordered leaf-first, root last, when they form a single unambiguous
    /// issuer chain. Every other input, including an unrelated bag of certificates or one holding two
    /// candidates for the same position, is returned untouched.
    /// </summary>
    /// <param name="certs">The certificates to order.</param>
    /// <param name="leafIsKnown">Receives false when the input could not be resolved to a single chain, so
    /// the certificate at index 0 is whatever the caller happened to supply first rather than a leaf this
    /// method identified. A single certificate is always its own leaf, so it sets this true.</param>
    /// <remarks>
    /// The PEM block order, and the fallback <see cref="ExportKeys.Primary"/> and
    /// <see cref="CertificateExportBuilder.AsCert"/> use when there is no anchor, all read off the front of this list, so a
    /// caller who reaches the same chain by a different route (say a leaf seeded by
    /// <c>cert.Export()</c> then topped up with <see cref="CertificateExportBuilder.WithChain(X509Chain)"/>)
    /// must not get a different export.
    /// </remarks>
    private static IReadOnlyList<X509Certificate2> OrderLeafFirst(IReadOnlyList<X509Certificate2> certs, out bool leafIsKnown)
    {
        if (certs.Count < 2) {
            leafIsKnown = true;
            return certs;
        }

        leafIsKnown = false;

        //The leaf is the one certificate that issued nothing else in the list. Self-issued doesn't count:
        //a self-signed root is its own issuer and would otherwise disqualify itself.
        var leafIndex = -1;
        for (var i = 0; i < certs.Count; i++) {
            var cert = certs[i];
            if (certs.Any(subject => !ReferenceEquals(subject, cert) && subject.IsIssuedBy(cert))) {
                continue;
            }
            if (leafIndex >= 0) {
                //More than one certificate that issued nothing here, so this isn't a single chain.
                return certs;
            }
            leafIndex = i;
        }
        if (leafIndex < 0) {
            return certs;
        }

        var placed = new bool[certs.Count];
        placed[leafIndex] = true;

        var ordered = new List<X509Certificate2>(certs.Count) { certs[leafIndex] };
        while (ordered.Count < certs.Count) {
            var subject = ordered[^1];
            var next = -1;
            for (var i = 0; i < certs.Count; i++) {
                if (placed[i] || !subject.IsIssuedBy(certs[i])) {
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

        leafIsKnown = true;
        return ordered;
    }


    /// <summary>
    /// Applies <see cref="_keys"/> to the certificate list. <see cref="ExportKeys.Primary"/> resolves the
    /// primary certificate first, so it throws rather than guessing when nothing designates one.
    /// </summary>
    /// <param name="stripped">Receives the keyless certificates this call creates, for the caller to dispose.</param>
    private IEnumerable<X509Certificate2> FilterKeys(ICollection<X509Certificate2> stripped)
        => _keys == ExportKeys.Primary
            ? _certs.FilterPrivateKeys(_keys, RequirePrimary("ExportKeys.Primary"), stripped)
            : _certs.FilterPrivateKeys(_keys, stripped);


    /// <summary>
    /// Returns the primary certificate, throwing when there is no anchor and <see cref="OrderLeafFirst"/>
    /// could not work out a leaf to stand in for one.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when the certificates are not a single issuer chain
    /// and no anchor names the primary certificate.</exception>
    private X509Certificate2 RequirePrimary(string operation)
        => _primary ?? throw new InvalidOperationException(
            $"{operation} needs to identify the primary certificate, but the {_certs.Count} certificates "
            + "supplied are not a single unambiguous issuer chain and none was anchored as the primary one. "
            + "Export them with ExportKeys.All or ExportKeys.None, seed the export from the certificate you "
            + "mean with cert.Export(), or narrow the set to one chain.");


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
