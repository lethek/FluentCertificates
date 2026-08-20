using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Provides extension methods for <see cref="X509Chain"/>.
/// </summary>
public static class X509ChainExtensions
{
    /// <summary>
    /// Returns the chain's certificates in leaf-first order, which is the order
    /// <see cref="X509Chain.ChainElements"/> already uses. The root certificate is therefore last.
    /// </summary>
    /// <param name="chain">The chain whose certificates are returned.</param>
    /// <returns>The chain's certificates, leaf first and root last.</returns>
    public static IEnumerable<X509Certificate2> ToEnumerable(this X509Chain chain)
        => chain
            .ChainElements
            .Select(x => x.Certificate);


    /// <summary>
    /// Returns the chain's certificates as a collection in leaf-first order, with private keys kept
    /// or stripped according to <paramref name="include"/>.
    /// </summary>
    /// <param name="chain">The chain whose certificates are returned.</param>
    /// <param name="include">Which private keys to retain. <see cref="ExportKeys.Primary"/> keeps only
    /// the first certificate's key, the leaf being first in this ordering.</param>
    /// <returns>The chain's certificates, leaf first and root last.</returns>
    /// <remarks>
    /// Any <paramref name="include"/> value other than <see cref="ExportKeys.All"/> replaces the keyed
    /// certificates with new keyless ones and passes the rest through, so the collection mixes certificates
    /// created here with the chain's own. Do not dispose its elements; dispose the <paramref name="chain"/>.
    /// </remarks>
    public static X509Certificate2Collection ToCollection(this X509Chain chain, ExportKeys include = ExportKeys.All)
        => chain.ToEnumerable().FilterPrivateKeys(include).ToCollection();


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this chain.
    /// Certificates are added in leaf-first order (same as <see cref="ToEnumerable"/>), and the chain's
    /// end certificate becomes the builder's <see cref="CertificateExportBuilder.Anchor"/>.
    /// Use <see cref="CertificateExportBuilder.AsCert"/> to export that leaf;
    /// use <see cref="CertificateExportBuilder.AsPkcs12"/> etc. to export all chain certificates.
    /// </summary>
    /// <param name="chain">The certificate chain to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing the chain's certificates.</returns>
    public static CertificateExportBuilder Export(this X509Chain chain)
    {
        var certs = chain.ToEnumerable().ToList();
        return new CertificateExportBuilder(certs, certs.Count > 0 ? certs[0] : null);
    }
}