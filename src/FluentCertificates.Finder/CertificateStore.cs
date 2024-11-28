using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public record CertificateStore(string Name, StoreLocation Location) : AbstractCertificateSource {
    public CertificateStore(X509Store store)
        : this(store.Name!, store.Location) { }

    
    public CertificateStore(StoreName name, StoreLocation location)
        : this(GetProperStoreName(name), location) { }

    
    public X509Store Open(OpenFlags flags) {
#if NETSTANDARD2_0
        var store = new X509Store(Name, Location);
        store.Open(flags);
#else
        var store = new X509Store(Name, Location, flags);
#endif
        return store;
    }

    
    private static string GetProperStoreName(StoreName name)
        => name switch {
            StoreName.AddressBook => "AddressBook",
            StoreName.AuthRoot => "AuthRoot",
            StoreName.CertificateAuthority => "CA",
            StoreName.Disallowed => "Disallowed",
            StoreName.My => "My",
            StoreName.Root => "Root",
            StoreName.TrustedPeople => "TrustedPeople",
            StoreName.TrustedPublisher => "TrustedPublisher",
            _ => throw new ArgumentException($"Unsupported StoreName value: {name}", nameof(name))
        };
}
