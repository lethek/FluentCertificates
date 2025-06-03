using System.Collections;
using System.Collections.Immutable;
using System.IO.Abstractions;
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
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateFinder"/> class.
    /// </summary>
    /// <param name="fileSystem">
    /// An optional <see cref="IFileSystem"/> implementation to use for directory operations.
    /// If <see langword="null"/>, a default <see cref="FileSystem"/> is used.
    /// </param>
    public CertificateFinder(IFileSystem? fileSystem = null)
        => _fileSystem = fileSystem ?? new FileSystem();


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
    public CertificateFinder ClearSources()
        => this with { Sources = Sources.Clear() };


    /// <summary>
    /// Adds the specified <see cref="X509Store"/> instances to the current stores.
    /// </summary>
    /// <param name="stores">The stores to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params X509Store[] stores)
        => this with { Sources = Sources.AddRange(stores.Select(x => new CertificateStoreEnumerable(x))) };

    
    /// <summary>
    /// Adds the specified <see cref="X509Store"/> instances to the current stores.
    /// </summary>
    /// <param name="stores">The stores to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(IEnumerable<X509Store> stores)
        => this with { Sources = Sources.AddRange(stores.Select(x => new CertificateStoreEnumerable(x))) };

    
    /// <summary>
    /// Adds stores by name and location to the current stores.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params (string Name, StoreLocation Location)[] stores)
        => this with { Sources = Sources.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };

    
    /// <summary>
    /// Adds stores by name and location to the current stores.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(IEnumerable<(string Name, StoreLocation Location)> stores)
        => this with { Sources = Sources.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };

    
    /// <summary>
    /// Adds stores by <see cref="StoreName"/> and location to the current stores.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params (StoreName Name, StoreLocation Location)[] stores)
        => this with { Sources = Sources.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };

    
    /// <summary>
    /// Adds stores by <see cref="StoreName"/> and location to the current stores.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => this with { Sources = Sources.AddRange(stores.Select(x => new CertificateStoreEnumerable(x.Name, x.Location))) };


    /// <summary>
    /// Adds a single <see cref="X509Store"/> to the current stores.
    /// </summary>
    /// <param name="store">The store to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(X509Store store)
        => this with { Sources = Sources.Add(new CertificateStoreEnumerable(store)) };

    
    /// <summary>
    /// Adds a store by name and location to the current stores.
    /// </summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(string name, StoreLocation location)
        => this with { Sources = Sources.Add(new CertificateStoreEnumerable(name, location)) };

    
    /// <summary>
    /// Adds a store by <see cref="StoreName"/> and location to the current stores.
    /// </summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(StoreName name, StoreLocation location)
        => this with { Sources = Sources.Add(new CertificateStoreEnumerable(name, location)) };
    
    
    /// <summary>
    /// Adds a set of common certificate stores (My, CA, Root, WebHosting) for both CurrentUser and LocalMachine.
    /// </summary>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the common stores added.</returns>
    public CertificateFinder AddCommonStores()
        => this with {
            Sources = Sources.AddRange(CommonStores)
        };


    /// <summary>
    /// Adds a directory as a certificate source. Subdirectories are not searched by default.
    /// </summary>
    /// <param name="dir">The directory path.</param>
    /// <param name="recurse">Indicates whether to search subdirectories.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directory added.</returns>
    public CertificateFinder AddDirectory(string dir, bool recurse = false)
        => this with { Sources = Sources.Add(new CertificateDirectoryEnumerable(_fileSystem, dir, recurse)) };

    
    /// <summary>
    /// Adds multiple directories as certificate sources. Subdirectories are not searched by default.
    /// </summary>
    /// <remarks>
    /// If a directory needs its subdirectories searched too, use the other
    /// <see cref="AddDirectories(System.Collections.Generic.IEnumerable{string},bool)"/> overload
    /// or use <see cref="AddDirectory"/>.
    /// </remarks>
    /// <param name="dirs">The directory paths.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directories added.</returns>
    public CertificateFinder AddDirectories(params string[] dirs)
        => this with { Sources = Sources.AddRange(dirs.Select(dir => new CertificateDirectoryEnumerable(_fileSystem, dir, false))) };

    
    /// <summary>
    /// Adds multiple directories as certificate sources. Subdirectories are not searched by default.
    /// </summary>
    /// <param name="dirs">The directory paths.</param>
    /// <param name="recurse">Indicates whether to search subdirectories.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directories added.</returns>
    public CertificateFinder AddDirectories(IEnumerable<string> dirs, bool recurse = false)
        => this with { Sources = Sources.AddRange(dirs.Select(dir => new CertificateDirectoryEnumerable(_fileSystem, dir, recurse))) };


    /// <summary>
    /// Adds a custom certificate source to the current set of sources.
    /// </summary>
    /// <param name="customSource">An <see cref="IEnumerable{CertificateFinderResult}"/> representing a custom source of certificates.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the custom source added.</returns>
    public CertificateFinder AddCustomSource(IEnumerable<CertificateFinderResult> customSource)
        => this with { Sources = Sources.Add(customSource) };


    /// <summary>
    /// Adds multiple custom certificate sources to the current set of sources.
    /// </summary>
    /// <param name="customSources">An <see cref="IEnumerable"/> of <see cref="IEnumerable{CertificateFinderResult}"/> representing multiple custom sources of certificates.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the custom sources added.</returns>
    public CertificateFinder AddCustomSources(IEnumerable<IEnumerable<CertificateFinderResult>> customSources)
        => this with { Sources = Sources.AddRange(customSources) };


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
        => Sources
            .Distinct()
            .SelectMany(x => x)
            .AsQueryable();


    /// <summary>
    /// Gets the list of certificate sources (stores or directories).
    /// </summary>
    internal protected ImmutableList<IEnumerable<CertificateFinderResult>> Sources { get; init; } = ImmutableList<IEnumerable<CertificateFinderResult>>.Empty;


    private readonly IFileSystem _fileSystem; 


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
