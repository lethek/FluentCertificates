using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Provides extension methods for <see cref="X509Certificate2Collection"/>.
/// </summary>
public static class X509Certificate2CollectionExtensions
{
    /// <summary>
    /// Exposes the collection as an <see cref="IEnumerable{T}"/>, so LINQ operators and the
    /// <see cref="IEnumerable{T}"/> extension methods in this library can be used against it.
    /// </summary>
    /// <param name="collection">The collection to expose.</param>
    /// <returns>The same certificates, as a sequence.</returns>
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
