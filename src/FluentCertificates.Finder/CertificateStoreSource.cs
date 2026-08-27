using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// A certificate source reading an X.509 store, identified by name and location.
/// </summary>
/// <remarks>
/// A record, so two instances naming the same store compare equal and <see cref="CertificateFinder"/>
/// reads that store once however many times it was added.
/// <para>
/// The store is opened read-only and existing-only, so searching one never creates it. A store that does
/// not exist yields no results rather than throwing.
/// </para>
/// </remarks>
/// <param name="Name">The name of the certificate store.</param>
/// <param name="Location">The location of the certificate store.</param>
public sealed record CertificateStoreSource(string Name, StoreLocation Location) : AbstractCertificateSource
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateStoreSource"/> class from an <see cref="X509Store"/>.
    /// </summary>
    /// <param name="store">The X509Store instance.</param>
    public CertificateStoreSource(X509Store store)
        : this(store.Name!, store.Location) { }


    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateStoreSource"/> class from a <see cref="StoreName"/> and <see cref="StoreLocation"/>.
    /// </summary>
    /// <param name="name">The store name as <see cref="StoreName"/>.</param>
    /// <param name="location">The store location.</param>
    public CertificateStoreSource(StoreName name, StoreLocation location)
        : this(GetProperStoreName(name), location) { }


    /// <inheritdoc/>
    public override string Kind => "Store";


    /// <summary>
    /// Opens the certificate store with the specified <see cref="OpenFlags"/>.
    /// </summary>
    /// <param name="flags">The flags to use when opening the store.</param>
    /// <returns>An <see cref="X509Store"/> instance.</returns>
    public X509Store Open(OpenFlags flags)
        => new(Name, Location, flags);


    /// <summary>
    /// Reads every certificate in the store. Nothing here can be filtered natively: the platform exposes
    /// no way to query a store, so <see cref="X509Store.Certificates"/> materialises all of them before
    /// any predicate could apply.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>Every certificate in the store.</returns>
    protected override IEnumerable<CertificateFinderResult> Enumerate(CertificateFilter filter)
        //Opened in a helper because a method containing `yield return` cannot also contain a catch clause
        => Located(OpenCertificates());


    /// <summary>
    /// Free, since <see cref="X509Store.Certificates"/> is already a materialised collection: reading it
    /// backwards costs no more than reading it forwards.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>Every certificate in the store, last first.</returns>
    protected override IEnumerable<CertificateFinderResult> EnumerateDescending(CertificateFilter filter)
        => Located(OpenCertificates().Reverse());


    private IEnumerable<CertificateFinderResult> Located(IEnumerable<X509Certificate2> certificates)
    {
        //Built once rather than per certificate: every result from this source shares the one location
        var location = $@"{Location}\{Name}";
        return Results(certificates, _ => location);
    }


    private X509Certificate2Collection OpenCertificates()
    {
        try {
            using var store = Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            return store.Certificates;
        } catch (CryptographicException) {
            //Thrown if the store doesn't exist: yield nothing rather than creating one or erroring out
            return [];
        }
    }


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
