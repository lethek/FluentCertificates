using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>A certificate source reading an X.509 store, identified by name and location.</summary>
/// <remarks>
/// Opened read-only and existing-only, so searching never creates a store and a missing one yields no
/// results rather than throwing. Two instances naming the same store compare equal, so it is read once
/// however many times it was added.
/// </remarks>
/// <param name="Name">The name of the certificate store.</param>
/// <param name="Location">The location of the certificate store.</param>
public sealed record CertificateStoreSource(string Name, StoreLocation Location) : AbstractCertificateSource
{
    /// <summary>Initializes a new instance from an <see cref="X509Store"/>.</summary>
    /// <param name="store">The X509Store instance.</param>
    public CertificateStoreSource(X509Store store)
        : this(store.Name!, store.Location) { }


    /// <summary>Initializes a new instance from a <see cref="StoreName"/> and <see cref="StoreLocation"/>.</summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    public CertificateStoreSource(StoreName name, StoreLocation location)
        : this(GetProperStoreName(name), location) { }


    /// <inheritdoc/>
    public override string Kind => "Store";


    /// <summary>Opens the certificate store with the specified <see cref="OpenFlags"/>.</summary>
    /// <param name="flags">The flags to use when opening the store.</param>
    /// <returns>An <see cref="X509Store"/> instance.</returns>
    public X509Store Open(OpenFlags flags)
        => new(Name, Location, flags);


    /// <summary>Reads every certificate in the store. Nothing can be filtered natively, since the platform
    /// exposes no way to query a store.</summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>One batch holding every certificate in the store.</returns>
    protected override IEnumerable<CertificateBatch> Enumerate(CertificateFilter filter)
        => [Located(OpenCertificates())];


    /// <summary>Identical to <see cref="Enumerate"/>: one batch, so there is no order of batches to reverse.</summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>One batch holding every certificate in the store.</returns>
    protected override IEnumerable<CertificateBatch> EnumerateDescending(CertificateFilter filter)
        => [Located(OpenCertificates())];


    private CertificateBatch Located(IEnumerable<X509Certificate2> certificates)
        => new(certificates, $@"{Location}\{Name}");


    private X509Certificate2Collection OpenCertificates()
    {
        try {
            using var store = Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            return store.Certificates;
        } catch (CryptographicException) {
            //Thrown when the store doesn't exist
            return [];
        }
    }


    /// <summary>Converts a <see cref="StoreName"/> to its string representation.</summary>
    /// <param name="name">The store name.</param>
    /// <returns>The string representation of the store name.</returns>
    /// <exception cref="ArgumentException">The <see cref="StoreName"/> value is unsupported.</exception>
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
