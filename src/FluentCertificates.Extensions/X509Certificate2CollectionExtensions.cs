using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public static class X509Certificate2CollectionExtensions
{
    public static IEnumerable<X509Certificate2> ToEnumerable(this X509Certificate2Collection collection)
        => collection;


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this collection.
    /// </summary>
    /// <param name="collection">The certificate collection to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing all certificates in the collection.</returns>
    public static CertificateExportBuilder Export(this X509Certificate2Collection collection)
        => new(collection.Cast<X509Certificate2>());
}
