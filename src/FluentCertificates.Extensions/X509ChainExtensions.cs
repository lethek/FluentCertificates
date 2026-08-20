using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Provides extension methods for <see cref="X509Chain"/>.
/// </summary>
public static class X509ChainExtensions
{
    /// <summary>
    /// Returns the chain's certificates in root-first order, which is the reverse of
    /// <see cref="X509Chain.ChainElements"/>. The leaf certificate is therefore last.
    /// </summary>
    /// <param name="chain">The chain whose certificates are returned.</param>
    /// <returns>The chain's certificates, root first and leaf last.</returns>
    public static IEnumerable<X509Certificate2> ToEnumerable(this X509Chain chain)
        => chain
            .ChainElements
            .Reverse()
            .Select(x => x.Certificate);


    /// <summary>
    /// Returns the chain's certificates as a collection in root-first order, with private keys kept
    /// or stripped according to <paramref name="include"/>.
    /// </summary>
    /// <param name="chain">The chain whose certificates are returned.</param>
    /// <param name="include">Which private keys to retain. <see cref="ExportKeys.Leaf"/> keeps only
    /// the last certificate's key, the leaf being last in this ordering.</param>
    /// <returns>The chain's certificates, root first and leaf last.</returns>
    /// <remarks>
    /// Any <paramref name="include"/> value other than <see cref="ExportKeys.All"/> replaces the keyed
    /// certificates with new keyless ones and passes the rest through, so the collection mixes certificates
    /// created here with the chain's own. Do not dispose its elements; dispose the <paramref name="chain"/>.
    /// </remarks>
    public static X509Certificate2Collection ToCollection(this X509Chain chain, ExportKeys include = ExportKeys.All)
        => chain.ToEnumerable().FilterPrivateKeys(include).ToCollection();


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this chain.
    /// Certificates are added in root-first order (same as <see cref="ToEnumerable"/>).
    /// Use <see cref="CertificateExportBuilder.AsCert"/> to export the last certificate (the leaf);
    /// use <see cref="CertificateExportBuilder.AsPkcs12"/> etc. to export all chain certificates.
    /// </summary>
    /// <param name="chain">The certificate chain to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing the chain's certificates.</returns>
    public static CertificateExportBuilder Export(this X509Chain chain)
        => new(chain.ToEnumerable());
}