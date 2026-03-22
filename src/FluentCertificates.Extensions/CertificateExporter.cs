using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using FluentCertificates.Internals;


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
    private readonly ImmutableList<X509Certificate2> _certs;
    private readonly ExportFormat _format;
    private readonly string? _password;
    private readonly SecureString? _securePassword;
    private readonly ExportKeys _keys;


    /// <summary>
    /// Initializes a new <see cref="CertificateExporter"/>.
    /// </summary>
    /// <param name="certs">Certificates to export. Must be non-empty.</param>
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
        _certs = certs;
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
                _certs.FilterPrivateKeys(_keys).ToCollection()
                    .Export(X509ContentType.Pkcs12, GetPasswordString())
                ?? throw new InvalidOperationException("PKCS#12 export returned null."),

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
    /// Produces the PEM-encoded representation of the configured certificates and keys.
    /// The output order matches <see cref="X509Certificate2EnumerableExtensions.ToPemString"/>:
    /// private key blocks first, then CERTIFICATE blocks in leaf-first order.
    /// </summary>
    internal string ExportPem()
    {
        var list = _certs.FilterPrivateKeys(_keys).Reverse().ToList();
        if (list.Count == 0) {
            return string.Empty;
        }

        using var sw = new StringWriter();
        if (_keys != ExportKeys.None) {
            foreach (var cert in list.Where(x => x.HasPrivateKey)) {
                cert.GetPrivateKey().ExportAsPrivateKeyPem(sw, GetPasswordString());
                sw.Write('\n');
            }
        }
        sw.Write(PemEncoding.Write("CERTIFICATE", list[0].RawData));
        foreach (var cert in list.Skip(1)) {
            sw.Write('\n');
            sw.Write(PemEncoding.Write("CERTIFICATE", cert.RawData));
        }
        return sw.ToString();
    }


    /// <summary>
    /// Returns the effective export password: <see cref="_securePassword"/> converted to string when non-null,
    /// otherwise <see cref="_password"/>.
    /// </summary>
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
