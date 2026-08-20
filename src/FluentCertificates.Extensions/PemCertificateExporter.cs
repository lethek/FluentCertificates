using System.Collections.Immutable;
using System.Security;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// A <see cref="CertificateExporter"/> specialised for PEM output.
/// Obtained by calling <see cref="CertificateExportBuilder.AsPem"/>.
/// Adds <see cref="ToPemString"/> for convenient string output in addition to the
/// binary output methods inherited from <see cref="CertificateExporter"/>.
/// </summary>
public sealed class PemCertificateExporter : CertificateExporter
{
    /// <summary>
    /// Initializes a new <see cref="PemCertificateExporter"/>.
    /// </summary>
    /// <param name="certs">Certificates to export. Must be non-empty.</param>
    /// <param name="password">Optional password for encrypted private-key blocks (ignored when <paramref name="securePassword"/> is non-null).</param>
    /// <param name="securePassword">SecureString password; takes precedence over <paramref name="password"/>.</param>
    /// <param name="keys">Which private keys to include.</param>
    internal PemCertificateExporter(ImmutableList<X509Certificate2> certs, string? password, SecureString? securePassword, ExportKeys keys)
        : base(certs, ExportFormat.Pem, password, securePassword, keys)
    {
    }

    /// <summary>
    /// Returns the PEM-encoded representation of the configured certificates and keys as a string.
    /// Private key blocks appear first, followed by CERTIFICATE blocks in leaf-first order.
    /// </summary>
    public string ToPemString()
        => ExportPem();
}
