using System.Collections;
using System.Collections.Immutable;
using System.Linq.Expressions;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace FluentCertificates;

public record CertificateFinder : IQueryable<X509Certificate2>
{
    public ImmutableList<(string Name, StoreLocation Location)> Stores { get; init; } = ImmutableList<(string, StoreLocation)>.Empty;

    public virtual Type ElementType => Queryable.ElementType;
    public virtual Expression Expression => Queryable.Expression;
    public virtual IQueryProvider Provider => Queryable.Provider;


    public static CertificateFinder Create()
        => new();


    public CertificateFinder ClearStores()
        => this with { Stores = ImmutableList<(string, StoreLocation)>.Empty };


    public CertificateFinder SetStores(params X509Store[] stores)
        => this with { Stores = stores.Select(x => (x.Name, x.Location)).ToImmutableList() };

    public CertificateFinder SetStores(IEnumerable<X509Store> stores)
        => this with { Stores = stores.Select(x => (x.Name, x.Location)).ToImmutableList() };

    public CertificateFinder SetStores(params (string Name, StoreLocation Location)[] stores)
        => this with { Stores = stores.Select(x => (x.Name, x.Location)).ToImmutableList() };

    public CertificateFinder SetStores(IEnumerable<(string Name, StoreLocation Location)> stores)
        => this with { Stores = stores.Select(x => (x.Name, x.Location)).ToImmutableList() };

    public CertificateFinder SetStores(params (StoreName Name, StoreLocation Location)[] stores)
        => this with { Stores = stores.Select(x => (GetProperStoreName(x.Name), x.Location)).ToImmutableList() };

    public CertificateFinder SetStores(IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => this with { Stores = stores.Select(x => (GetProperStoreName(x.Name), x.Location)).ToImmutableList() };


    public CertificateFinder AddStores(params X509Store[] stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => (x.Name, x.Location))) };

    public CertificateFinder AddStores(IEnumerable<X509Store> stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => (x.Name, x.Location))) };

    public CertificateFinder AddStores(params (string Name, StoreLocation Location)[] stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => (x.Name, x.Location))) };

    public CertificateFinder AddStores(IEnumerable<(string Name, StoreLocation Location)> stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => (x.Name, x.Location))) };

    public CertificateFinder AddStores(params (StoreName Name, StoreLocation Location)[] stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => (GetProperStoreName(x.Name), x.Location))) };

    public CertificateFinder AddStores(IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => (GetProperStoreName(x.Name), x.Location))) };


    public CertificateFinder AddStore(X509Store store)
        => this with { Stores = Stores.Add((store.Name, store.Location)) };

    public CertificateFinder AddStore(string name, StoreLocation location)
        => this with { Stores = Stores.Add((name, location)) };

    public CertificateFinder AddStore(StoreName name, StoreLocation location)
        => this with { Stores = Stores.Add((GetProperStoreName(name), location)) };


    public CertificateFinder AddCommonStores()
        => this with {
            Stores = Stores.AddRange(CommonStores)
        };


    public virtual IEnumerator<X509Certificate2> GetEnumerator()
        => Provider.Execute<IEnumerable<X509Certificate2>>(Expression).GetEnumerator();


    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();


    protected IQueryable<X509Certificate2> Queryable
        => Stores
            .Distinct()
            .SelectMany(x => {
                try {
                    using var store = new X509Store(x.Name, x.Location, OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    return store.Certificates.Cast<X509Certificate2>();
                } catch (CryptographicException) {
                    //Thrown if store doesn't exist: we don't want to create a new store or error-out, just return empty results for it
                    return Enumerable.Empty<X509Certificate2>();
                }
            })
            .AsQueryable();


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
            _ => throw new ArgumentException(nameof(name))
        };


    private static readonly ImmutableList<(string Name, StoreLocation)> CommonStores = new[] {
        ("My", StoreLocation.CurrentUser),
        ("CA", StoreLocation.CurrentUser),
        ("Root", StoreLocation.CurrentUser),
        ("My", StoreLocation.LocalMachine),
        ("CA", StoreLocation.LocalMachine),
        ("Root", StoreLocation.LocalMachine),
        ("WebHosting", StoreLocation.LocalMachine)
    }.ToImmutableList();
}
