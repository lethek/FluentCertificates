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
/// <see cref="Where"/> is an instance method, and an instance method beats an extension method in overload
/// resolution, so <c>finder.Where(x =&gt; ...)</c> and <c>from x in finder where ... select x</c> reach the
/// sources rather than <see cref="Enumerable.Where{T}(IEnumerable{T}, Func{T,bool})"/>. The
/// predicate-taking terminals (<see cref="Any"/>, <see cref="All"/>, <see cref="First"/>, <see cref="FirstOrDefault"/>,
/// <see cref="Last"/>, <see cref="LastOrDefault"/>, <see cref="Single"/>, <see cref="SingleOrDefault"/>
/// and <see cref="Count"/>) shadow their counterparts the same way. Every other LINQ operator runs after
/// collation, which is correct but does no filtering at the source.
/// </para>
/// <para>
/// The parameter is an <see cref="Expression{TDelegate}"/> rather than a delegate so that a source able to
/// translate a predicate into a native query can read it. That is also why a predicate held in a
/// <see cref="Func{T,TResult}"/> variable does not reach the sources: only a lambda written inline converts
/// to an expression tree, so anything else binds to the extension method instead.
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
    /// sources. See <see cref="Where"/>. The match is released rather than returned, since the answer is
    /// only whether one exists.
    /// </remarks>
    public bool Any(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        foreach (var result in Where(predicate)) {
            result.Source.Release(result);
            return true;
        }
        return false;
    }


    /// <summary>
    /// Whether every certificate found matches <paramref name="predicate"/>. True if none were found.
    /// </summary>
    /// <param name="predicate">The predicate every result must satisfy.</param>
    /// <returns><see langword="true"/> if they all match, or if there are none.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is null.</exception>
    /// <remarks>
    /// Shadows <see cref="Enumerable.All{T}(IEnumerable{T},Func{T,bool})"/> so the predicate reaches the
    /// sources. See <see cref="Where"/>. What the sources are given is the negation, since a source can
    /// answer "is anything not a match?" natively and stop at the first one it finds.
    /// </remarks>
    public bool All(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        return !Any(Expression.Lambda<Func<CertificateFinderResult, bool>>(
            Expression.Not(predicate.Body),
            predicate.Parameters
        ));
    }


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
    /// the first one holding a match, so a source implementing
    /// <c>EnumerateDescending</c> never reads past its own last match. Which result is "last" still depends
    /// on the order each source yields, and that is unspecified: neither a directory listing nor a store
    /// enumeration promises one.
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

        //How a source finds its own last match, and what it releases getting there, is the source's business
        return Sources.Distinct()
            .Reverse()
            .Select(source => source.FindLast(filter))
            .FirstOrDefault(found => found is not null);
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
        => SingleOrDefault(predicate)
            ?? throw new InvalidOperationException("Sequence contains no matching element");


    /// <summary>
    /// The only certificate matching <paramref name="predicate"/>, or <see langword="null"/> if none does.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The single matching result, or <see langword="null"/>.</returns>
    /// <exception cref="InvalidOperationException">More than one matched.</exception>
    /// <remarks>
    /// Shadows <see cref="Enumerable.SingleOrDefault{T}(IEnumerable{T},Func{T,bool})"/> so the predicate
    /// reaches the sources. See <see cref="Where"/>. A second match ends the search, and both it and the
    /// first are released, since throwing returns neither to the caller.
    /// </remarks>
    public CertificateFinderResult? SingleOrDefault(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        CertificateFinderResult? found = null;
        foreach (var result in Where(predicate)) {
            if (found is not null) {
                found.Source.Release(found);
                result.Source.Release(result);
                throw new InvalidOperationException("Sequence contains more than one matching element");
            }
            found = result;
        }
        return found;
    }


    /// <summary>
    /// How many certificates match <paramref name="predicate"/>.
    /// </summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The number of matching results.</returns>
    /// <remarks>
    /// Shadows <see cref="Enumerable.Count{T}(IEnumerable{T},Func{T,bool})"/> so the predicate reaches the
    /// sources. See <see cref="Where"/>. Every match is released as it is counted, since the answer is a
    /// number and no certificate reaches the caller.
    /// </remarks>
    public int Count(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        var count = 0;
        foreach (var result in Where(predicate)) {
            result.Source.Release(result);
            count++;
        }
        return count;
    }


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
    /// Removes a source. Every source equal to <paramref name="source"/> goes, since a duplicate is
    /// searched no differently from the original.
    /// </summary>
    /// <param name="source">The source to remove.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance without that source.</returns>
    /// <remarks>
    /// Sources are records with value equality, so a source equal to one that was added removes it: a
    /// directory is dropped by <c>RemoveSource(new CertificateDirectorySource(path))</c> without holding
    /// on to the instance that was added.
    /// </remarks>
    public CertificateFinder RemoveSource(AbstractCertificateSource source)
        => this with { Sources = Sources.RemoveAll(x => x == source) };


    /// <summary>
    /// Removes several sources. See <see cref="RemoveSource"/>.
    /// </summary>
    /// <param name="sources">The sources to remove.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance without those sources.</returns>
    public CertificateFinder RemoveSources(params IEnumerable<AbstractCertificateSource> sources)
    {
        var unwanted = sources.ToHashSet();
        return this with { Sources = Sources.RemoveAll(unwanted.Contains) };
    }


    /// <summary>
    /// Removes every source matching <paramref name="match"/>.
    /// </summary>
    /// <param name="match">Chooses which sources to remove.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance without those sources.</returns>
    /// <remarks>
    /// Narrows a configured finder without naming each source, for example dropping every directory with
    /// <c>RemoveSources(x =&gt; x.Kind == "Directory")</c>.
    /// </remarks>
    public CertificateFinder RemoveSources(Func<AbstractCertificateSource, bool> match)
        => this with { Sources = Sources.RemoveAll(x => match(x)) };


    /// <summary>
    /// Adds the specified <see cref="X509Store"/> instances to the current sources.
    /// </summary>
    /// <param name="stores">The stores to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params IEnumerable<X509Store> stores)
        => AddSources(stores.Select(x => new CertificateStoreSource(x)));


    /// <summary>
    /// Adds stores by name and location to the current sources.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params IEnumerable<(string Name, StoreLocation Location)> stores)
        => AddSources(stores.Select(x => new CertificateStoreSource(x.Name, x.Location)));


    /// <summary>
    /// Adds stores by <see cref="StoreName"/> and location to the current sources.
    /// </summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => AddSources(stores.Select(x => new CertificateStoreSource(x.Name, x.Location)));


    /// <summary>
    /// Adds a single <see cref="X509Store"/> to the current sources.
    /// </summary>
    /// <param name="store">The store to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(X509Store store)
        => AddSource(new CertificateStoreSource(store));


    /// <summary>
    /// Adds a store by name and location to the current sources.
    /// </summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(string name, StoreLocation location)
        => AddSource(new CertificateStoreSource(name, location));


    /// <summary>
    /// Adds a store by <see cref="StoreName"/> and location to the current sources.
    /// </summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(StoreName name, StoreLocation location)
        => AddSource(new CertificateStoreSource(name, location));


    /// <summary>
    /// Adds a set of common certificate stores (My, CA, Root, WebHosting) for CurrentUser and LocalMachine.
    /// </summary>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the common stores added.</returns>
    public CertificateFinder AddCommonStores()
        => AddSources(CommonStores);


    /// <summary>
    /// Adds a directory as a certificate source. Subdirectories are not searched by default.
    /// </summary>
    /// <param name="dir">The directory path.</param>
    /// <param name="recurse">Whether to search subdirectories.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directory added.</returns>
    public CertificateFinder AddDirectory(string dir, bool recurse = false)
        => AddSource(new CertificateDirectorySource(dir, recurse, _fileSystem));


    /// <summary>
    /// Adds multiple directories as certificate sources.
    /// </summary>
    /// <param name="dirs">The directory paths.</param>
    /// <param name="recurse">Whether to search subdirectories.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directories added.</returns>
    public CertificateFinder AddDirectories(IEnumerable<string> dirs, bool recurse = false)
        => AddSources(dirs.Select(dir => new CertificateDirectorySource(dir, recurse, _fileSystem)));


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
    public CertificateFinder AddCertificates(params IEnumerable<X509Certificate2> certificates)
        => AddSource(new CertificateCollectionSource(certificates));


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
    private static readonly ImmutableList<CertificateStoreSource> CommonStores = [
        new("My", StoreLocation.CurrentUser),
        new("CA", StoreLocation.CurrentUser),
        new("Root", StoreLocation.CurrentUser),
        new("My", StoreLocation.LocalMachine),
        new("CA", StoreLocation.LocalMachine),
        new("Root", StoreLocation.LocalMachine),
        new("WebHosting", StoreLocation.LocalMachine)
    ];
}
