using System.Collections;
using System.Collections.Immutable;
using System.Linq.Expressions;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

/// <summary>
/// Provides a fluent API for building and executing queries to find X.509 certificates
/// from various sources such as certificate stores and directories.
/// Implements <see cref="IQueryable{CertificateFinderResult}"/> for LINQ support.
/// </summary>
public record CertificateFinder : IQueryable<CertificateFinderResult>
{
    /// <inheritdoc/>    
    public virtual Type ElementType => Queryable.ElementType;

    /// <inheritdoc/>    
    public virtual Expression Expression => Queryable.Expression;

    /// <inheritdoc/>    
    public virtual IQueryProvider Provider => Queryable.Provider;


    /// <summary>
    /// Removes all currently configured certificate stores.
    /// </summary>
    /// <returns>A new <see cref="CertificateFinder"/> instance with no stores.</returns>    
    public CertificateFinder ClearStores()
        => this with { Stores = Stores.Clear() };


    /// <summary>
    /// Sets the certificate stores to the specified <see cref="X509Store"/> instances.
    /// </summary>
    /// <param name="stores">The stores to set.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the specified stores.</returns>
    public CertificateFinder SetStores(params X509Store[] stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x)).ToImmutableList() };

    /// <summary>
    /// Sets the certificate stores to the specified <see cref="X509Store"/> instances.
    /// </summary>
    /// <param name="stores">The stores to set.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the specified stores.</returns>
    public CertificateFinder SetStores(IEnumerable<X509Store> stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x)).ToImmutableList() };

    /// <summary>
    /// Sets the certificate stores by name and location.
    /// </summary>
    /// <param name="stores">The store names and locations.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the specified stores.</returns>
    public CertificateFinder SetStores(params (string Name, StoreLocation Location)[] stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x.Name, x.Location)).ToImmutableList() };

    /// <summary>
    /// Sets the certificate stores by name and location.
    /// </summary>
    /// <param name="stores">The store names and locations.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the specified stores.</returns>
    public CertificateFinder SetStores(IEnumerable<(string Name, StoreLocation Location)> stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x.Name, x.Location)).ToImmutableList() };

    /// <summary>
    /// Sets the certificate stores by <see cref="StoreName"/> and location.
    /// </summary>
    /// <param name="stores">The store names and locations.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the specified stores.</returns>
    public CertificateFinder SetStores(params (StoreName Name, StoreLocation Location)[] stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x.Name, x.Location)).ToImmutableList() };

    /// <summary>
    /// Sets the certificate stores by <see cref="StoreName"/> and location.
    /// </summary>
    /// <param name="stores">The store names and locations.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the specified stores.</returns>
    public CertificateFinder SetStores(IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => this with { Stores = stores.Select(x => (IEnumerable<CertificateFinderResult>)new CertificateStoreEnumerable(x.Name, x.Location)).ToImmutableList() };


    /// <summary>
    /// Adds the specified <see cref="X509Store"/> instances to the current stores.
    /// </summary>
    /// <param name="stores">The stores to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params X509Store[] stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x))) };

    /// <summary>
    /// Adds the specified <see cref="X509Store"/> instances to the current stores.
    /// </summary>
    /// <param name="stores">The stores to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(IEnumerable<X509Store> stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x))) };

    /// <summary>
    /// Adds stores by name and location to the current stores.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params (string Name, StoreLocation Location)[] stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };

    /// <summary>
    /// Adds stores by name and location to the current stores.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(IEnumerable<(string Name, StoreLocation Location)> stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };

    /// <summary>
    /// Adds stores by <see cref="StoreName"/> and location to the current stores.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params (StoreName Name, StoreLocation Location)[] stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };

    /// <summary>
    /// Adds stores by <see cref="StoreName"/> and location to the current stores.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => this with { Stores = Stores.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };


    /// <summary>
    /// Adds a single <see cref="X509Store"/> to the current stores.
    /// </summary>
    /// <param name="store">The store to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(X509Store store)
        => this with { Stores = Stores.Add(new CertificateStoreEnumerable(store)) };

    /// <summary>
    /// Adds a store by name and location to the current stores.
    /// </summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(string name, StoreLocation location)
        => this with { Stores = Stores.Add(new CertificateStoreEnumerable(name, location)) };

    /// <summary>
    /// Adds a store by <see cref="StoreName"/> and location to the current stores.
    /// </summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(StoreName name, StoreLocation location)
        => this with { Stores = Stores.Add(new CertificateStoreEnumerable(name, location)) };
    
    
    /// <summary>
    /// Adds a set of common certificate stores (My, CA, Root, WebHosting) for both CurrentUser and LocalMachine.
    /// </summary>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the common stores added.</returns>
    public CertificateFinder AddCommonStores()
        => this with {
            Stores = Stores.AddRange(CommonStores)
        };


    /// <summary>
    /// Adds a directory as a certificate source.
    /// </summary>
    /// <param name="dir">The directory path.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directory added.</returns>
    public CertificateFinder AddDirectory(string dir)
        => this with { Stores = Stores.Add(new CertificateDirectoryEnumerable(dir)) };

    /// <summary>
    /// Adds multiple directories as certificate sources.
    /// </summary>
    /// <param name="dirs">The directory paths.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directories added.</returns>
    public CertificateFinder AddDirectories(params string[] dirs)
        => this with { Stores = Stores.AddRange(dirs.Select(dir => new CertificateDirectoryEnumerable(dir))) };

    /// <summary>
    /// Adds multiple directories as certificate sources.
    /// </summary>
    /// <param name="dirs">The directory paths.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directories added.</returns>
    public CertificateFinder AddDirectories(IEnumerable<string> dirs)
        => this with { Stores = Stores.AddRange(dirs.Select(dir => new CertificateDirectoryEnumerable(dir))) };


    /// <summary>
    /// Returns an enumerator that iterates through the found certificates.
    /// </summary>
    /// <returns>An enumerator for <see cref="CertificateFinderResult"/>.</returns>
    public virtual IEnumerator<CertificateFinderResult> GetEnumerator()
        => Provider.Execute<IEnumerable<CertificateFinderResult>>(Expression).GetEnumerator();


    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();


    /// <summary>
    /// Gets the underlying LINQ queryable for the current set of stores.
    /// </summary>
    protected IQueryable<CertificateFinderResult> Queryable
        => Stores
            .Distinct()
            .SelectMany(x => x)
            .AsQueryable();

    
    /// <summary>
    /// Gets the list of certificate sources (stores or directories).
    /// </summary>
    private ImmutableList<IEnumerable<CertificateFinderResult>> Stores { get; init; } = ImmutableList<IEnumerable<CertificateFinderResult>>.Empty;
    

    /// <summary>
    /// Gets a list of common certificate stores used by <see cref="AddCommonStores"/>.
    /// </summary>
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
