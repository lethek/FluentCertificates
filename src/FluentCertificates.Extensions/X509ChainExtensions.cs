using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public static class X509ChainExtensions
{
    public static IEnumerable<X509Certificate2> ToEnumerable(this X509Chain chain)
        => chain
            .ChainElements
            .Reverse()
            .Select(x => x.Certificate);


    public static X509Certificate2Collection ToCollection(this X509Chain chain, ExportKeys include = ExportKeys.All)
        => chain.ToEnumerable().FilterPrivateKeys(include).ToCollection();


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this chain.
    /// Certificates are added in root-first order (same as <see cref="ToEnumerable"/>).
    /// Use <see cref="CertificateExportBuilder.AsCert"/> to export the first certificate (the root);
    /// use <see cref="CertificateExportBuilder.AsPkcs12"/> etc. to export all chain certificates.
    /// </summary>
    /// <param name="chain">The certificate chain to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing the chain's certificates.</returns>
    public static CertificateExportBuilder Export(this X509Chain chain)
        => new(chain.ToEnumerable());
}