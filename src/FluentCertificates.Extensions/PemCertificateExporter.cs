using System.Collections.Immutable;
using System.Security;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// A <see cref="CertificateExporter"/> for a format that can be written as text.
/// Obtained by calling <see cref="CertificateExportBuilder.AsPem"/> or
/// <see cref="CertificateExportBuilder.AsPkcs7"/>.
/// Adds <see cref="ToPemString"/> for convenient string output in addition to the
/// binary output methods inherited from <see cref="CertificateExporter"/>.
/// </summary>
/// <remarks>
/// <see cref="Pkcs7Encoding.Der"/> is not supported for string output. The chosen format is validated
/// when the string is rendered rather than when the export is configured, so that
/// <see cref="CertificateExportBuilder.AsPkcs7"/> can offer <see cref="ToPemString"/> for the encoding
/// that does produce text.
/// </remarks>
public sealed class PemCertificateExporter : CertificateExporter
{
    /// <summary>
    /// Initializes a new <see cref="PemCertificateExporter"/>.
    /// </summary>
    /// <param name="certs">Certificates to export. Must be non-empty.</param>
    /// <param name="anchor">The certificate the caller anchored on, or null. See
    /// <see cref="CertificateExportBuilder.Anchor"/>.</param>
    /// <param name="format">The format to produce, which decides what <see cref="ToPemString"/> writes.</param>
    /// <param name="password">Optional password for encrypted private-key blocks (ignored when <paramref name="securePassword"/> is non-null).</param>
    /// <param name="securePassword">SecureString password; takes precedence over <paramref name="password"/>.</param>
    /// <param name="keys">Which private keys to include.</param>
    internal PemCertificateExporter(ImmutableList<X509Certificate2> certs, X509Certificate2? anchor, ExportFormat format, string? password, SecureString? securePassword, ExportKeys keys)
        : base(certs, anchor, format, password, securePassword, keys)
    {
    }

    /// <summary>
    /// Returns the export as PEM text. For <see cref="CertificateExportBuilder.AsPem"/> that is private
    /// key blocks first, then CERTIFICATE blocks in leaf-first order; for
    /// <see cref="CertificateExportBuilder.AsPkcs7"/> it is the one <c>PKCS7</c> block.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the format selected is binary. <see cref="Pkcs7Encoding.Der"/> is not supported for
    /// string output; use <see cref="Pkcs7Encoding.Pem"/>, or read the bytes.
    /// </exception>
    public string ToPemString()
        => Format switch {
            ExportFormat.Pem => ExportPem(),
            ExportFormat.Pkcs7Pem => ExportPkcs7Pem(),
            _ => throw new InvalidOperationException(
                $"This export writes binary {Format} data, not text. Ask AsPkcs7 for "
                + $"{nameof(Pkcs7Encoding)}.{nameof(Pkcs7Encoding.Pem)}, or read the bytes with "
                + "ToByteArray, ToFile or ToStream.")
        };
}
