using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

internal sealed class CertificateStoreEnumerable(CertificateStore certStore) : IEnumerable<CertificateFinderResult>
{
    public CertificateStoreEnumerable(X509Store store)
        : this(new CertificateStore(store)) { }

    public CertificateStoreEnumerable(string name, StoreLocation location)
        : this(new CertificateStore(name, location)) { }

    public CertificateStoreEnumerable(StoreName name, StoreLocation location)
        : this(new CertificateStore(name, location)) { }

    public IEnumerator<CertificateFinderResult> GetEnumerator()
        => GetCertificatesFromStore(certStore).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();

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
