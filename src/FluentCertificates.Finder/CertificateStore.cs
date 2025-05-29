using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Represents a certificate store source with a specific name and location.
/// Provides methods to open the store and convert <see cref="StoreName"/> to string.
/// </summary>
/// <param name="Name">The name of the certificate store.</param>
/// <param name="Location">The location of the certificate store.</param>
public record CertificateStore(string Name, StoreLocation Location) : AbstractCertificateSource
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateStore"/> class from an <see cref="X509Store"/>.
    /// </summary>
    /// <param name="store">The X509Store instance.</param>
    public CertificateStore(X509Store store)
        : this(store.Name!, store.Location) { }

    
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateStore"/> class from a <see cref="StoreName"/> and <see cref="StoreLocation"/>.
    /// </summary>
    /// <param name="name">The store name as <see cref="StoreName"/>.</param>
    /// <param name="location">The store location.</param>    
    public CertificateStore(StoreName name, StoreLocation location)
        : this(GetProperStoreName(name), location) { }

    
    /// <summary>
    /// Opens the certificate store with the specified <see cref="OpenFlags"/>.
    /// </summary>
    /// <param name="flags">The flags to use when opening the store.</param>
    /// <returns>An <see cref="X509Store"/> instance.</returns>    
    public X509Store Open(OpenFlags flags)
        => new(Name, Location, flags);


    /// <summary>
    /// Converts a <see cref="StoreName"/> to its corresponding string representation.
    /// </summary>
    /// <param name="name">The store name.</param>
    /// <returns>The string representation of the store name.</returns>
    /// <exception cref="ArgumentException">Thrown if the <see cref="StoreName"/> value is unsupported.</exception>
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
