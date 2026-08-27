using System.Collections;
using System.Collections.Immutable;
using System.IO.Abstractions;
using System.Linq.Expressions;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// An immutable fluent API for finding X.509 certificates across stores, directories and custom sources.
/// Configure with the <c>Add*</c> methods, narrow with <see cref="Where"/>, then enumerate.
/// </summary>
/// <remarks>
/// Each source is responsible for locating, materialising and filtering its own certificates: the finder
/// composes sources, hands each one the <see cref="Filter"/>, and collates what comes back. It applies no
/// predicates of its own.
/// <para>
/// <see cref="Where"/> is an instance method taking an expression tree, which is what lets ordinary LINQ
/// reach the sources: <c>finder.Where(x =&gt; ...)</c> and <c>from x in finder where ... select x</c> both
/// bind to it in preference to <see cref="Enumerable.Where{T}(IEnumerable{T}, Func{T,bool})"/>. The
/// predicate-taking terminals (<see cref="Any"/>, <see cref="First"/>, <see cref="FirstOrDefault"/>,
/// <see cref="Last"/>, <see cref="LastOrDefault"/>, <see cref="Single"/>, <see cref="SingleOrDefault"/>
/// and <see cref="Count"/>) shadow their counterparts the same way. Every other LINQ operator runs after
/// collation, which is correct but does no filtering
/// at the source; so does a predicate held as a <see cref="Func{T,TResult}"/> rather than written inline,
/// since only a lambda converts to an expression tree.
/// </para>
/// </remarks>
public record CertificateFinder : IEnumerable<CertificateFinderResult>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateFinder"/> class.
    /// </summary>
    /// <param name="fileSystem">
    /// An optional <see cref="IFileSystem"/> for directory sources this finder creates.
    /// If <see langword="null"/>, a default <see cref="FileSystem"/> is used.
    /// </param>
    public CertificateFinder(IFileSystem? fileSystem = null)
        => _fileSystem = fileSystem ?? new FileSystem();


    /// <summary>The sources this finder searches, in the order they were added.</summary>
    public ImmutableList<AbstractCertificateSource> Sources { get; init; } = ImmutableList<AbstractCertificateSource>.Empty;


    /// <summary>The predicates handed to every source. See <see cref="Where"/>.</summary>
    public CertificateFilter Filter { get; init; } = CertificateFilter.Empty;


    /// <summary>
    /// Narrows the search. The predicate is handed to every source, which is responsible for returning
    /// only what matches it. Calling this more than once combines the predicates with AND.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>A new <see cref="CertificateFinder"/> with the predicate added.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is null.</exception>
    public CertificateFinder Where(Expression<Func<CertificateFinderResult, bool>> predicate)
        => this with { Filter = Filter.Add(predicate) };


    /// <summary>
    /// Whether any certificate matches <paramref name="predicate"/>.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns><see langword="true"/> if at least one matches.</returns>
    /// <remarks>
    /// Shadows <see cref="Enumerable.Any{T}(IEnumerable{T},Func{T,bool})"/> so the predicate reaches the
    /// sources. See <see cref="Where"/>.
    /// </remarks>
    public bool Any(Expression<Func<CertificateFinderResult, bool>> predicate)
        => Where(predicate).Any();


    /// <summary>
    /// The first certificate matching <paramref name="predicate"/>.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The first matching result.</returns>
    /// <exception cref="InvalidOperationException">Nothing matched.</exception>
    /// <remarks>
    /// Shadows <see cref="Enumerable.First{T}(IEnumerable{T},Func{T,bool})"/> so the predicate reaches the
    /// sources. See <see cref="Where"/>.
    /// </remarks>
    public CertificateFinderResult First(Expression<Func<CertificateFinderResult, bool>> predicate)
        => Where(predicate).First();


    /// <summary>
    /// The first certificate matching <paramref name="predicate"/>, or <see langword="null"/> if none does.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The first matching result, or <see langword="null"/>.</returns>
    /// <remarks>
    /// Shadows <see cref="Enumerable.FirstOrDefault{T}(IEnumerable{T},Func{T,bool})"/> so the predicate
    /// reaches the sources. See <see cref="Where"/>.
    /// </remarks>
    public CertificateFinderResult? FirstOrDefault(Expression<Func<CertificateFinderResult, bool>> predicate)
        => Where(predicate).FirstOrDefault();


    /// <summary>
    /// The last certificate matching <paramref name="predicate"/>.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The last matching result.</returns>
    /// <exception cref="InvalidOperationException">Nothing matched.</exception>
    /// <remarks>
    /// Shadows <see cref="Enumerable.Last{T}(IEnumerable{T},Func{T,bool})"/> so the predicate reaches the
    /// sources. See <see cref="Where"/>. Sources are searched newest-added first and the search stops at
    /// the first one holding a match, so a source reporting
    /// <see cref="AbstractCertificateSource.CanEnumerateDescending"/> never reads past its own last match.
    /// Which result is "last" still depends on the order each source yields, and that is unspecified:
    /// neither a directory listing nor a store enumeration promises one.
    /// </remarks>
    public CertificateFinderResult Last(Expression<Func<CertificateFinderResult, bool>> predicate)
        => LastOrDefault(predicate)
            ?? throw new InvalidOperationException("Sequence contains no matching element");


    /// <summary>
    /// The last certificate matching <paramref name="predicate"/>, or <see langword="null"/> if none does.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The last matching result, or <see langword="null"/>.</returns>
    /// <remarks>
    /// Shadows <see cref="Enumerable.LastOrDefault{T}(IEnumerable{T},Func{T,bool})"/> so the predicate
    /// reaches the sources. See <see cref="Last"/> on what "last" means here.
    /// </remarks>
    public CertificateFinderResult? LastOrDefault(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        var filter = Filter.Add(predicate);

        foreach (var source in Sources.Distinct().Reverse()) {
            var found = LastFrom(source, filter);
            if (found is not null) {
                return found;
            }
        }
        return null;
    }


    private static CertificateFinderResult? LastFrom(AbstractCertificateSource source, CertificateFilter filter)
    {
        if (source.CanEnumerateDescending) {
            return source.FindDescending(filter).FirstOrDefault();
        }

        //Read forwards instead, releasing each match as the next supersedes it: only the final one is
        //ever returned, so the rest are unreachable the moment they are replaced
        CertificateFinderResult? last = null;
        foreach (var result in source.Find(filter)) {
            if (last is not null && source.OwnsCertificates) {
                last.Certificate.Dispose();
            }
            last = result;
        }
        return last;
    }


    /// <summary>
    /// The only certificate matching <paramref name="predicate"/>.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The single matching result.</returns>
    /// <exception cref="InvalidOperationException">Nothing matched, or more than one did.</exception>
    /// <remarks>
    /// Shadows <see cref="Enumerable.Single{T}(IEnumerable{T},Func{T,bool})"/> so the predicate reaches the
    /// sources. See <see cref="Where"/>.
    /// </remarks>
    public CertificateFinderResult Single(Expression<Func<CertificateFinderResult, bool>> predicate)
        => Where(predicate).Single();


    /// <summary>
    /// The only certificate matching <paramref name="predicate"/>, or <see langword="null"/> if none does.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The single matching result, or <see langword="null"/>.</returns>
    /// <exception cref="InvalidOperationException">More than one matched.</exception>
    /// <remarks>
    /// Shadows <see cref="Enumerable.SingleOrDefault{T}(IEnumerable{T},Func{T,bool})"/> so the predicate
    /// reaches the sources. See <see cref="Where"/>.
    /// </remarks>
    public CertificateFinderResult? SingleOrDefault(Expression<Func<CertificateFinderResult, bool>> predicate)
        => Where(predicate).SingleOrDefault();


    /// <summary>
    /// How many certificates match <paramref name="predicate"/>.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The number of matching results.</returns>
    /// <remarks>
    /// Shadows <see cref="Enumerable.Count{T}(IEnumerable{T},Func{T,bool})"/> so the predicate reaches the
    /// sources. See <see cref="Where"/>.
    /// </remarks>
    public int Count(Expression<Func<CertificateFinderResult, bool>> predicate)
        => Where(predicate).Count();


    /// <summary>
    /// Removes all currently configured sources.
    /// </summary>
    /// <returns>A new <see cref="CertificateFinder"/> instance with no sources.</returns>
    public CertificateFinder ClearSources()
        => this with { Sources = Sources.Clear() };


    /// <summary>
    /// Adds a certificate source.
    /// </summary>
    /// <param name="source">The source to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional source.</returns>
    public CertificateFinder AddSource(AbstractCertificateSource source)
        => this with { Sources = Sources.Add(source) };


    /// <summary>
    /// Adds certificate sources.
    /// </summary>
    /// <param name="sources">The sources to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional sources.</returns>
    public CertificateFinder AddSources(params IEnumerable<AbstractCertificateSource> sources)
        => this with { Sources = Sources.AddRange(sources) };


    /// <summary>
    /// Adds the specified <see cref="X509Store"/> instances to the current sources.
    /// </summary>
    /// <param name="stores">The stores to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params IEnumerable<X509Store> stores)
        => this with { Sources = Sources.AddRange(stores.Select(x => new CertificateStore(x))) };


    /// <summary>
    /// Adds stores by name and location to the current sources.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params IEnumerable<(string Name, StoreLocation Location)> stores)
        => this with { Sources = Sources.AddRange(stores.Select(x => new CertificateStore(x.Name, x.Location))) };


    /// <summary>
    /// Adds stores by <see cref="StoreName"/> and location to the current sources.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => this with { Sources = Sources.AddRange(stores.Select(x => new CertificateStore(x.Name, x.Location))) };


    /// <summary>
    /// Adds a single <see cref="X509Store"/> to the current sources.
    /// </summary>
    /// <param name="store">The store to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(X509Store store)
        => AddSource(new CertificateStore(store));


    /// <summary>
    /// Adds a store by name and location to the current sources.
    /// </summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(string name, StoreLocation location)
        => AddSource(new CertificateStore(name, location));


    /// <summary>
    /// Adds a store by <see cref="StoreName"/> and location to the current sources.
    /// </summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(StoreName name, StoreLocation location)
        => AddSource(new CertificateStore(name, location));


    /// <summary>
    /// Adds a set of common certificate stores (My, CA, Root, WebHosting) for CurrentUser and LocalMachine.
    /// </summary>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the common stores added.</returns>
    public CertificateFinder AddCommonStores()
        => this with { Sources = Sources.AddRange(CommonStores) };


    /// <summary>
    /// Adds a directory as a certificate source. Subdirectories are not searched by default.
    /// </summary>
    /// <param name="dir">The directory path.</param>
    /// <param name="recurse">Whether to search subdirectories.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directory added.</returns>
    public CertificateFinder AddDirectory(string dir, bool recurse = false)
        => AddSource(new CertificateDirectory(dir, recurse, _fileSystem));


    /// <summary>
    /// Adds multiple directories as certificate sources.
    /// </summary>
    /// <param name="dirs">The directory paths.</param>
    /// <param name="recurse">Whether to search subdirectories.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directories added.</returns>
    public CertificateFinder AddDirectories(IEnumerable<string> dirs, bool recurse = false)
        => this with { Sources = Sources.AddRange(dirs.Select(dir => new CertificateDirectory(dir, recurse, _fileSystem))) };


    /// <summary>
    /// Adds multiple directories as certificate sources. Subdirectories are not searched; use
    /// <see cref="AddDirectories(IEnumerable{string},bool)"/> or <see cref="AddDirectory"/> for that.
    /// </summary>
    /// <param name="dirs">The directory paths.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directories added.</returns>
    public CertificateFinder AddDirectories(params string[] dirs)
        => AddDirectories(dirs, false);


    /// <summary>
    /// Adds certificates the caller already holds as a source. They are never disposed by the finder.
    /// </summary>
    /// <param name="certificates">The certificates to search.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the certificates added.</returns>
    public CertificateFinder AddCustomSource(params IEnumerable<X509Certificate2> certificates)
        => AddSource(new CustomCertificateSource(certificates));


    /// <summary>
    /// Returns an enumerator over every matching certificate, source by source, in the order the sources
    /// were added.
    /// </summary>
    /// <remarks>
    /// Sources are deduplicated by value, so a store or directory added twice is read once. Results are
    /// not deduplicated: a certificate two sources both reach is reported by each of them, since where a
    /// certificate was found is part of the answer. To collapse those, add
    /// <c>.DistinctBy(r =&gt; (r.Certificate.Thumbprint, r.Source.Kind, r.Location))</c>.
    /// </remarks>
    /// <returns>An enumerator for <see cref="CertificateFinderResult"/>.</returns>
    public IEnumerator<CertificateFinderResult> GetEnumerator()
        => Sources.Distinct().SelectMany(source => source.Find(Filter)).GetEnumerator();


    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();


    private readonly IFileSystem _fileSystem;


    /// <summary>
    /// Gets a list of common certificate stores used by <see cref="AddCommonStores"/>.
    /// </summary>
    private static readonly ImmutableList<CertificateStore> CommonStores = [
        new("My", StoreLocation.CurrentUser),
        new("CA", StoreLocation.CurrentUser),
        new("Root", StoreLocation.CurrentUser),
        new("My", StoreLocation.LocalMachine),
        new("CA", StoreLocation.LocalMachine),
        new("Root", StoreLocation.LocalMachine),
        new("WebHosting", StoreLocation.LocalMachine)
    ];
}
