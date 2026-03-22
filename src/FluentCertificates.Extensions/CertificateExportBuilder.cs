using System.Collections.Immutable;
using System.Security;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// An immutable fluent builder for configuring certificate export operations.
/// Obtain an instance by calling <c>cert.Export()</c>, <c>chain.Export()</c>, or <c>collection.Export()</c>.
/// Chain configuration methods (e.g. <see cref="WithPrivateKey"/>, <see cref="WithChain(IEnumerable{X509Certificate2})"/>,
/// <see cref="WithPassword(string)"/>) then select a format with <see cref="AsPkcs12"/>, <see cref="AsPem"/>,
/// <see cref="AsPkcs7"/>, or <see cref="AsCert"/>.
/// </summary>
public record CertificateExportBuilder
{
    /// <summary>
    /// The certificates to be exported, in the order they were added.
    /// </summary>
    public ImmutableList<X509Certificate2> Certificates { get; init; } = ImmutableList<X509Certificate2>.Empty;

    /// <summary>
    /// Controls which private keys are included in the export.
    /// Defaults to <see cref="ExportKeys.All"/>.
    /// </summary>
    public ExportKeys Keys { get; init; } = ExportKeys.All;

    /// <summary>
    /// Plain-text password used to protect private keys (e.g. in PKCS#12 output).
    /// If <see cref="SecurePassword"/> is also set, <see cref="SecurePassword"/> takes precedence.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// SecureString password used to protect private keys (e.g. in PKCS#12 output).
    /// Takes precedence over <see cref="Password"/> when non-null.
    /// Disposal of the <see cref="SecureString"/> after export is the caller's responsibility.
    /// </summary>
    public SecureString? SecurePassword { get; init; }


    /// <summary>
    /// Initializes a new <see cref="CertificateExportBuilder"/> with the given certificates.
    /// </summary>
    /// <param name="certs">The initial set of certificates to export.</param>
    internal CertificateExportBuilder(IEnumerable<X509Certificate2> certs)
        => Certificates = certs.ToImmutableList();


    /// <summary>
    /// Returns a new builder with the key-export behaviour set to <paramref name="keys"/>.
    /// </summary>
    /// <param name="keys">Which private keys to include in the export.</param>
    public CertificateExportBuilder WithKeys(ExportKeys keys)
        => this with { Keys = keys };

    /// <summary>
    /// Returns a new builder that will include only the leaf certificate's private key in the export
    /// (i.e. <see cref="ExportKeys.Leaf"/>).
    /// </summary>
    public CertificateExportBuilder WithPrivateKey()
        => this with { Keys = ExportKeys.Leaf };

    /// <summary>
    /// Returns a new builder that will include all private keys in the export
    /// (i.e. <see cref="ExportKeys.All"/>).
    /// </summary>
    public CertificateExportBuilder WithPrivateKeys()
        => this with { Keys = ExportKeys.All };

    /// <summary>
    /// Returns a new builder that will strip all private keys from the export
    /// (i.e. <see cref="ExportKeys.None"/>).
    /// </summary>
    public CertificateExportBuilder WithoutPrivateKeys()
        => this with { Keys = ExportKeys.None };

    /// <summary>
    /// Returns a new builder that appends the certificates from <paramref name="chain"/> to the
    /// builder's certificate list, deduplicating by thumbprint (certificates already present are skipped).
    /// </summary>
    /// <param name="chain">An X.509 chain whose elements are appended.</param>
    public CertificateExportBuilder WithChain(X509Chain chain)
        => WithChain(chain.ToEnumerable());

    /// <summary>
    /// Returns a new builder that appends <paramref name="certs"/> to the builder's certificate list,
    /// deduplicating by thumbprint (certificates already present are skipped).
    /// </summary>
    /// <param name="certs">Additional certificates to include.</param>
    public CertificateExportBuilder WithChain(IEnumerable<X509Certificate2> certs)
    {
        var existing = Certificates.Select(c => c.Thumbprint).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var toAdd = certs.Where(c => existing.Add(c.Thumbprint));
        return this with { Certificates = Certificates.AddRange(toAdd) };
    }

    /// <summary>
    /// Returns a new builder with a plain-text export password.
    /// If <see cref="SecurePassword"/> is also set on the resulting builder, it takes precedence.
    /// </summary>
    /// <param name="password">The plain-text password, or <c>null</c> to clear it.</param>
    public CertificateExportBuilder WithPassword(string? password)
        => this with { Password = password };

    /// <summary>
    /// Returns a new builder with a <see cref="SecureString"/> export password.
    /// This value takes precedence over <see cref="Password"/> when non-null.
    /// Disposal of the <see cref="SecureString"/> after export is the caller's responsibility.
    /// </summary>
    /// <param name="password">The secure password.</param>
    public CertificateExportBuilder WithPassword(SecureString password)
        => this with { SecurePassword = password };


    /// <summary>
    /// Selects PKCS#12 (PFX) as the export format.
    /// Returns a <see cref="CertificateExporter"/> whose output methods write the binary PKCS#12 data.
    /// </summary>
    public CertificateExporter AsPkcs12()
        => new(Certificates, ExportFormat.Pkcs12, Password, SecurePassword, Keys);

    /// <summary>
    /// Selects PEM as the export format.
    /// Returns a <see cref="PemCertificateExporter"/> whose <see cref="PemCertificateExporter.ToPemString"/>
    /// method produces a PEM-encoded string, and whose output methods write the UTF-8 bytes of that string.
    /// </summary>
    public PemCertificateExporter AsPem()
        => new(Certificates, Password, Keys);

    /// <summary>
    /// Selects PKCS#7 (P7B) as the export format. Private keys are never included in PKCS#7 output.
    /// Returns a <see cref="CertificateExporter"/> whose output methods write the binary PKCS#7 data.
    /// </summary>
    public CertificateExporter AsPkcs7()
        => new(Certificates, ExportFormat.Pkcs7, null, null, ExportKeys.None);

    /// <summary>
    /// Selects DER-encoded certificate (CER/CRT) as the export format.
    /// Only the first certificate in the builder's list is exported — for chains,
    /// this is typically the root certificate; for single-certificate builders it is the leaf.
    /// Returns a <see cref="CertificateExporter"/> whose output methods write the raw DER bytes.
    /// </summary>
    public CertificateExporter AsCert()
        => new(Certificates, ExportFormat.Cert, null, null, ExportKeys.None);
}
