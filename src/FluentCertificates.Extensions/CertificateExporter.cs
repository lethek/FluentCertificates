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
    Pkcs7Pem,
    Cert
}


/// <summary>
/// Provides output methods for a certificate export operation configured via <see cref="CertificateExportBuilder"/>.
/// Instances are obtained by calling a format-selection method such as
/// <see cref="CertificateExportBuilder.AsPkcs12"/>, <see cref="CertificateExportBuilder.AsPkcs7"/>,
/// or <see cref="CertificateExportBuilder.AsCert"/>.
/// For certificate and key PEM output, use <see cref="CertificateExportBuilder.AsPem"/> which returns a
/// <see cref="PemCertificateExporter"/> with an additional <see cref="PemCertificateExporter.ToPemString"/> method.
/// <see cref="CertificateExportBuilder.AsPkcs7"/> also writes PEM when asked for
/// <see cref="Pkcs7Encoding.Pem"/>, but as bytes only, since its other encoding is binary.
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
    /// <param name="certs">Certificates to export. Must be non-empty. They are written in exactly this
    /// order: ordering is decided when they are added to the builder, not here.</param>
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

        //The list is written as given. A chain was sorted when AddChain declared it one; a collection
        //keeps the caller's order. Nothing here re-reads the certificates to second-guess either.
        _certs = certs;

        //An anchor designates a certificate; so does being the only one there, since that involves no
        //guessing. Position never does: index 0 of a larger bundle is just whatever came first.
        _primary = anchor ?? (certs.Count == 1 ? certs[0] : null);
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
        stream.Write(ToByteArray());
        return this;
    }

    /// <summary>
    /// Produces the exported certificate data as a byte array.
    /// </summary>
    /// <returns>The exported bytes in the format selected on the builder.</returns>
    public byte[] ToByteArray()
        => _format switch {
            ExportFormat.Pkcs12 =>
                ExportPkcs12(),

            ExportFormat.Pem =>
                Encoding.UTF8.GetBytes(ExportPem()),

            ExportFormat.Pkcs7 =>
                ExportPkcs7(),

            ExportFormat.Pkcs7Pem =>
                Encoding.UTF8.GetBytes(PemEncoding.WriteString("PKCS7", ExportPkcs7())),

            ExportFormat.Cert =>
                ExportCert(),

            _ => throw new InvalidOperationException($"Unsupported export format: {_format}.")
        };


    /// <summary>
    /// Produces the DER bytes of the PKCS#7 bundle, which the PEM form then wraps.
    /// </summary>
    private byte[] ExportPkcs7()
        => _certs.ToCollection().Export(X509ContentType.Pkcs7)
        ?? throw new InvalidOperationException("PKCS#7 export returned null.");


    /// <summary>
    /// Produces the DER bytes of the primary certificate, which is the anchor.
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
            //Never empty: the constructor rejects an empty set and key filtering maps one-for-one
            var list = FilterKeys(stripped).ToList();

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
    /// Applies <see cref="_keys"/> to the certificate list. <see cref="ExportKeys.Primary"/> resolves the
    /// primary certificate first, so it throws rather than guessing when nothing designates one.
    /// </summary>
    /// <param name="stripped">Receives the keyless certificates this call creates, for the caller to dispose.</param>
    private IEnumerable<X509Certificate2> FilterKeys(ICollection<X509Certificate2> stripped)
        => _certs.FilterPrivateKeys(
            _keys,
            stripped,
            _keys == ExportKeys.Primary ? RequirePrimary("ExportKeys.Primary") : null
        );


    /// <summary>
    /// Returns the primary certificate, throwing when nothing anchored one.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when no anchor names the primary certificate.</exception>
    private X509Certificate2 RequirePrimary(string operation)
        => _primary ?? throw new InvalidOperationException(
            $"{operation} needs to identify the primary certificate, but this export is a bundle of "
            + $"{_certs.Count} certificates with none anchored as the primary one. A bundle has no leaf to "
            + "infer, and arriving first is not evidence of being one. Export it with ExportKeys.All or "
            + "ExportKeys.None, or seed the export from the certificate you mean with cert.Export() or "
            + "chain.Export().");


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
