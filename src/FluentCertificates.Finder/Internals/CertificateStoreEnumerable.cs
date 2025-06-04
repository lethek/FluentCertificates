using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

/// <summary>
/// Enumerates certificates from a specified <see cref="CertificateStore"/>.
/// Provides multiple constructors for different store representations and yields <see cref="CertificateFinderResult"/> for each certificate found.
/// </summary>
internal sealed class CertificateStoreEnumerable(CertificateStore certStore) : IEnumerable<CertificateFinderResult>
{
    /// <summary>
    /// Initializes a new instance of <see cref="CertificateStoreEnumerable"/> using an <see cref="X509Store"/>.
    /// </summary>
    /// <param name="store">The X509Store to enumerate certificates from.</param>
    public CertificateStoreEnumerable(X509Store store)
        : this(new CertificateStore(store)) { }

    
    /// <summary>
    /// Initializes a new instance of <see cref="CertificateStoreEnumerable"/> using a store name and location.
    /// </summary>
    /// <param name="name">The name of the certificate store.</param>
    /// <param name="location">The location of the certificate store.</param>
    public CertificateStoreEnumerable(string name, StoreLocation location)
        : this(new CertificateStore(name, location)) { }

    
    /// <summary>
    /// Initializes a new instance of <see cref="CertificateStoreEnumerable"/> using a <see cref="StoreName"/> and location.
    /// </summary>
    /// <param name="name">The store name as <see cref="StoreName"/>.</param>
    /// <param name="location">The store location.</param>
    public CertificateStoreEnumerable(StoreName name, StoreLocation location)
        : this(new CertificateStore(name, location)) { }

    
    /// <summary>
    /// Returns an enumerator that iterates through the certificates in the store.
    /// </summary>
    /// <returns>An enumerator of <see cref="CertificateFinderResult"/>.</returns>
    public IEnumerator<CertificateFinderResult> GetEnumerator()
        => GetCertificatesFromStore(certStore).GetEnumerator();

    
    /// <summary>
    /// Returns a non-generic enumerator that iterates through the certificates in the store.
    /// </summary>
    /// <returns>An enumerator object.</returns>
    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();

    
    /// <summary>
    /// Retrieves certificates from the specified <see cref="CertificateStore"/>.
    /// Handles exceptions if the store does not exist, returning an empty result in such cases.
    /// </summary>
    /// <param name="certStore">The certificate store to enumerate.</param>
    /// <returns>An IEnumerable of <see cref="CertificateFinderResult"/>.</returns>
    private static IEnumerable<CertificateFinderResult> GetCertificatesFromStore(CertificateStore certStore) {
        try {
            using var store = certStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            return store.Certificates.Select(x => new CertificateFinderResult { Store = certStore, Certificate = x });
        } catch (CryptographicException) {
            //Thrown if store doesn't exist: we don't want to create a new store or error-out, just return empty results for it
            return [];
        }
    }
}
