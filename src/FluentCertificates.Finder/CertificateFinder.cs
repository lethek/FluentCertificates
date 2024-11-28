using System.Collections;
using System.Collections.Immutable;
using System.Linq.Expressions;
using System.Security.Cryptography.X509Certificates;
using FluentCertificates.Internals;

namespace FluentCertificates;

public record CertificateFinder : IQueryable<CertificateFinderResult> {
    public virtual Type ElementType => Queryable.ElementType;
    public virtual Expression Expression => Queryable.Expression;
    public virtual IQueryProvider Provider => Queryable.Provider;


    public CertificateFinder ClearStores()
        => this with { Stores = Stores.Clear() };


    public CertificateFinder SetStores(params X509Store[] stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x)).ToImmutableList() };

    public CertificateFinder SetStores(IEnumerable<X509Store> stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x)).ToImmutableList() };

    public CertificateFinder SetStores(params (string Name, StoreLocation Location)[] stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x.Name, x.Location)).ToImmutableList() };

    public CertificateFinder SetStores(IEnumerable<(string Name, StoreLocation Location)> stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x.Name, x.Location)).ToImmutableList() };

    public CertificateFinder SetStores(params (StoreName Name, StoreLocation Location)[] stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x.Name, x.Location)).ToImmutableList() };

    public CertificateFinder SetStores(IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x.Name, x.Location)).ToImmutableList() };


    public CertificateFinder AddStores(params X509Store[] stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x))) };

    public CertificateFinder AddStores(IEnumerable<X509Store> stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x))) };

    public CertificateFinder AddStores(params (string Name, StoreLocation Location)[] stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };

    public CertificateFinder AddStores(IEnumerable<(string Name, StoreLocation Location)> stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };

    public CertificateFinder AddStores(params (StoreName Name, StoreLocation Location)[] stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };

    public CertificateFinder AddStores(IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };


    public CertificateFinder AddStore(X509Store store)
        => this with { Stores = Stores.Add(new CertificateStoreEnumerable(store)) };

    public CertificateFinder AddStore(string name, StoreLocation location)
        => this with { Stores = Stores.Add(new CertificateStoreEnumerable(name, location)) };

    public CertificateFinder AddStore(StoreName name, StoreLocation location)
        => this with { Stores = Stores.Add(new CertificateStoreEnumerable(name, location)) };


    public CertificateFinder AddCommonStores()
        => this with {
            Stores = Stores.AddRange(CommonStores)
        };


    public CertificateFinder AddDirectory(string dir)
        => this with { Stores = Stores.Add(new CertificateDirectoryEnumerable(dir)) };

    public CertificateFinder AddDirectories(params string[] dirs)
        => this with { Stores = Stores.AddRange(dirs.Select(dir => new CertificateDirectoryEnumerable(dir))) };

    public CertificateFinder AddDirectories(IEnumerable<string> dirs)
        => this with { Stores = Stores.AddRange(dirs.Select(dir => new CertificateDirectoryEnumerable(dir))) };


    public virtual IEnumerator<CertificateFinderResult> GetEnumerator()
        => Provider.Execute<IEnumerable<CertificateFinderResult>>(Expression).GetEnumerator();


    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();


    protected IQueryable<CertificateFinderResult> Queryable
        => Stores
            .Distinct()
            .SelectMany(x => x)
            .AsQueryable();

    
    private ImmutableList<IEnumerable<CertificateFinderResult>> Stores { get; init; } = ImmutableList<IEnumerable<CertificateFinderResult>>.Empty;
    

    private static readonly ImmutableList<CertificateStoreEnumerable> CommonStores = new CertificateStoreEnumerable[] {
        new("My", StoreLocation.CurrentUser),
        new("CA", StoreLocation.CurrentUser),
        new("Root", StoreLocation.CurrentUser),
        new("My", StoreLocation.LocalMachine),
        new("CA", StoreLocation.LocalMachine),
        new("Root", StoreLocation.LocalMachine),
        new("WebHosting", StoreLocation.LocalMachine)
    }.ToImmutableList();
}
