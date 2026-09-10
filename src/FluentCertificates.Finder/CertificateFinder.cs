using System.Collections;
using System.Collections.Immutable;
using System.IO.Abstractions;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// An immutable fluent API for finding X.509 certificates across stores, directories and custom sources.
/// </summary>
/// <remarks>
/// <see cref="Where"/> and the predicate-taking terminals are instance methods shadowing their LINQ
/// counterparts, so the predicate reaches the sources; only an inline lambda converts to the
/// <see cref="Expression{TDelegate}"/> they take, so a predicate held in a <see cref="Func{T,TResult}"/>
/// variable binds to the extension method instead and never reaches a source. A terminal that discards the
/// certificates it matched releases them, which async LINQ over <see cref="AsAsyncEnumerable"/> does not.
/// </remarks>
public record CertificateFinder : IEnumerable<CertificateFinderResult>
{
    /// <summary>Initializes a new instance of the <see cref="CertificateFinder"/> class.</summary>
    /// <param name="fileSystem">An <see cref="IFileSystem"/> for directory sources this finder creates, or null for the default.</param>
    public CertificateFinder(IFileSystem? fileSystem = null)
        => _fileSystem = fileSystem ?? new FileSystem();


    /// <summary>The sources this finder searches, in the order they were added.</summary>
    public ImmutableList<AbstractCertificateSource> Sources { get; init; } = ImmutableList<AbstractCertificateSource>.Empty;


    /// <summary>The predicates handed to every source. See <see cref="Where"/>.</summary>
    public CertificateFilter Filter { get; init; } = CertificateFilter.Empty;


    /// <summary>Narrows the search. Calling this more than once combines the predicates with AND.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>A new <see cref="CertificateFinder"/> with the predicate added.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is null.</exception>
    public CertificateFinder Where(Expression<Func<CertificateFinderResult, bool>> predicate)
        => this with { Filter = Filter.Add(predicate) };


    /// <summary>Narrows the search to certificates whose subject is the same name as <paramref name="name"/>.
    /// Combines with other predicates by AND, like <see cref="Where"/>.</summary>
    /// <param name="name">The name a result's subject must match.</param>
    /// <param name="comparer">How to compare the two names, or null for <see cref="X500NameComparer.Values"/>,
    /// which disregards how the characters were encoded and answers the same on every runtime.</param>
    /// <returns>A new <see cref="CertificateFinder"/> with the predicate added.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="name"/> is null.</exception>
    public CertificateFinder WhereSubjectMatches(
        X500DistinguishedName name,
        IEqualityComparer<X500DistinguishedName>? comparer = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        var matches = comparer ?? X500NameComparer.Values;
        return Where(r => matches.Equals(name, r.Certificate.SubjectName));
    }


    /// <summary>Narrows the search to certificates whose issuer is the same name as <paramref name="name"/>.
    /// Combines with other predicates by AND, like <see cref="Where"/>.</summary>
    /// <param name="name">The name a result's issuer must match.</param>
    /// <param name="comparer">How to compare the two names, or null for <see cref="X500NameComparer.Values"/>,
    /// which disregards how the characters were encoded and answers the same on every runtime.</param>
    /// <returns>A new <see cref="CertificateFinder"/> with the predicate added.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="name"/> is null.</exception>
    public CertificateFinder WhereIssuerMatches(
        X500DistinguishedName name,
        IEqualityComparer<X500DistinguishedName>? comparer = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        var matches = comparer ?? X500NameComparer.Values;
        return Where(r => matches.Equals(name, r.Certificate.IssuerName));
    }


    /// <summary>Whether any certificate matches <paramref name="predicate"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns><see langword="true"/> if at least one matches.</returns>
    public bool Any(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        foreach (var result in Where(predicate)) {
            result.Source.Release(result);
            return true;
        }
        return false;
    }


    /// <summary>Whether every certificate found matches <paramref name="predicate"/>. True if none were found.</summary>
    /// <param name="predicate">The predicate every result must satisfy.</param>
    /// <returns><see langword="true"/> if they all match, or if there are none.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is null.</exception>
    public bool All(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        return !Any(Negate(predicate));
    }


    /// <summary>The first certificate matching <paramref name="predicate"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The first matching result.</returns>
    /// <exception cref="InvalidOperationException">Nothing matched.</exception>
    public CertificateFinderResult First(Expression<Func<CertificateFinderResult, bool>> predicate)
        => Where(predicate).First();


    /// <summary>The first certificate matching <paramref name="predicate"/>, or <see langword="null"/> if none does.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The first matching result, or <see langword="null"/>.</returns>
    public CertificateFinderResult? FirstOrDefault(Expression<Func<CertificateFinderResult, bool>> predicate)
        => Where(predicate).FirstOrDefault();


    /// <summary>The last certificate matching <paramref name="predicate"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The last matching result.</returns>
    /// <exception cref="InvalidOperationException">Nothing matched.</exception>
    /// <remarks>
    /// Sources are searched newest-added first, but which result within a source is "last" is unspecified:
    /// neither a directory listing nor a store enumeration promises an order.
    /// </remarks>
    public CertificateFinderResult Last(Expression<Func<CertificateFinderResult, bool>> predicate)
        => LastOrDefault(predicate)
            ?? throw new InvalidOperationException("Sequence contains no matching element");


    /// <summary>The last certificate matching <paramref name="predicate"/>, or <see langword="null"/> if none does.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The last matching result, or <see langword="null"/>.</returns>
    public CertificateFinderResult? LastOrDefault(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        var filter = Filter.Add(predicate);

        return Sources.Distinct()
            .Reverse()
            .Select(source => source.FindLast(filter))
            .FirstOrDefault(found => found is not null);
    }


    /// <summary>The only certificate matching <paramref name="predicate"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The single matching result.</returns>
    /// <exception cref="InvalidOperationException">Nothing matched, or more than one did.</exception>
    public CertificateFinderResult Single(Expression<Func<CertificateFinderResult, bool>> predicate)
        => SingleOrDefault(predicate)
            ?? throw new InvalidOperationException("Sequence contains no matching element");


    /// <summary>The only certificate matching <paramref name="predicate"/>, or <see langword="null"/> if none does.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The single matching result, or <see langword="null"/>.</returns>
    /// <exception cref="InvalidOperationException">More than one matched.</exception>
    public CertificateFinderResult? SingleOrDefault(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        CertificateFinderResult? found = null;
        try {
            foreach (var result in Where(predicate)) {
                if (found is not null) {
                    //Cleared first, so the handler below cannot release it a second time
                    var first = found;
                    found = null;
                    first.Source.Release(first);
                    result.Source.Release(result);
                    throw new InvalidOperationException("Sequence contains more than one matching element");
                }
                found = result;
            }
        } catch {
            if (found is not null) {
                found.Source.Release(found);
            }
            throw;
        }
        return found;
    }


    /// <summary>How many certificates match <paramref name="predicate"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <returns>The number of matching results.</returns>
    public int Count(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        var count = 0;
        foreach (var result in Where(predicate)) {
            result.Source.Release(result);
            count++;
        }
        return count;
    }


    /// <summary>Whether any certificate matches <paramref name="predicate"/>. Asynchronous <see cref="Any"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns><see langword="true"/> if at least one matches.</returns>
    public async ValueTask<bool> AnyAsync(
        Expression<Func<CertificateFinderResult, bool>> predicate,
        CancellationToken cancellationToken = default)
    {
        await foreach (var result in Where(predicate).AsAsyncEnumerable(cancellationToken).ConfigureAwait(false)) {
            result.Source.Release(result);
            return true;
        }
        return false;
    }


    /// <summary>Whether every certificate found matches <paramref name="predicate"/>. Asynchronous <see cref="All"/>.</summary>
    /// <param name="predicate">The predicate every result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns><see langword="true"/> if they all match, or if there are none.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is null.</exception>
    public async ValueTask<bool> AllAsync(
        Expression<Func<CertificateFinderResult, bool>> predicate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        return !await AnyAsync(Negate(predicate), cancellationToken).ConfigureAwait(false);
    }


    /// <summary>The first certificate matching <paramref name="predicate"/>. Asynchronous <see cref="First"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>The first matching result.</returns>
    /// <exception cref="InvalidOperationException">Nothing matched.</exception>
    public async ValueTask<CertificateFinderResult> FirstAsync(
        Expression<Func<CertificateFinderResult, bool>> predicate,
        CancellationToken cancellationToken = default)
        => await FirstOrDefaultAsync(predicate, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Sequence contains no matching element");


    /// <summary>The first match, or <see langword="null"/> if none does. Asynchronous <see cref="FirstOrDefault"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>The first matching result, or <see langword="null"/>.</returns>
    public async ValueTask<CertificateFinderResult?> FirstOrDefaultAsync(
        Expression<Func<CertificateFinderResult, bool>> predicate,
        CancellationToken cancellationToken = default)
    {
        await foreach (var result in Where(predicate).AsAsyncEnumerable(cancellationToken).ConfigureAwait(false)) {
            return result;
        }
        return null;
    }


    /// <summary>The last certificate matching <paramref name="predicate"/>. Asynchronous <see cref="Last"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>The last matching result.</returns>
    /// <exception cref="InvalidOperationException">Nothing matched.</exception>
    public async ValueTask<CertificateFinderResult> LastAsync(
        Expression<Func<CertificateFinderResult, bool>> predicate,
        CancellationToken cancellationToken = default)
        => await LastOrDefaultAsync(predicate, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Sequence contains no matching element");


    /// <summary>The last match, or <see langword="null"/> if none does. Asynchronous <see cref="LastOrDefault"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>The last matching result, or <see langword="null"/>.</returns>
    public async ValueTask<CertificateFinderResult?> LastOrDefaultAsync(
        Expression<Func<CertificateFinderResult, bool>> predicate,
        CancellationToken cancellationToken = default)
    {
        var filter = Filter.Add(predicate);

        foreach (var source in Sources.Distinct().Reverse()) {
            var found = await source.FindLastAsync(filter, cancellationToken).ConfigureAwait(false);
            if (found is not null) {
                return found;
            }
        }
        return null;
    }


    /// <summary>The only certificate matching <paramref name="predicate"/>. Asynchronous <see cref="Single"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>The single matching result.</returns>
    /// <exception cref="InvalidOperationException">Nothing matched, or more than one did.</exception>
    public async ValueTask<CertificateFinderResult> SingleAsync(
        Expression<Func<CertificateFinderResult, bool>> predicate,
        CancellationToken cancellationToken = default)
        => await SingleOrDefaultAsync(predicate, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Sequence contains no matching element");


    /// <summary>The only match, or <see langword="null"/> if none does. Asynchronous <see cref="SingleOrDefault"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>The single matching result, or <see langword="null"/>.</returns>
    /// <exception cref="InvalidOperationException">More than one matched.</exception>
    public async ValueTask<CertificateFinderResult?> SingleOrDefaultAsync(
        Expression<Func<CertificateFinderResult, bool>> predicate,
        CancellationToken cancellationToken = default)
    {
        CertificateFinderResult? found = null;
        try {
            await foreach (var result in Where(predicate).AsAsyncEnumerable(cancellationToken).ConfigureAwait(false)) {
                if (found is not null) {
                    //Cleared first, so the handler below cannot release it a second time
                    var first = found;
                    found = null;
                    first.Source.Release(first);
                    result.Source.Release(result);
                    throw new InvalidOperationException("Sequence contains more than one matching element");
                }
                found = result;
            }
        } catch {
            if (found is not null) {
                found.Source.Release(found);
            }
            throw;
        }
        return found;
    }


    /// <summary>How many certificates match <paramref name="predicate"/>. Asynchronous <see cref="Count"/>.</summary>
    /// <param name="predicate">The predicate a result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>The number of matching results.</returns>
    public async ValueTask<int> CountAsync(
        Expression<Func<CertificateFinderResult, bool>> predicate,
        CancellationToken cancellationToken = default)
    {
        var count = 0;
        await foreach (var result in Where(predicate).AsAsyncEnumerable(cancellationToken).ConfigureAwait(false)) {
            result.Source.Release(result);
            count++;
        }
        return count;
    }


    /// <summary>Removes all currently configured sources.</summary>
    /// <returns>A new <see cref="CertificateFinder"/> instance with no sources.</returns>
    public CertificateFinder ClearSources()
        => this with { Sources = Sources.Clear() };


    /// <summary>Adds a certificate source.</summary>
    /// <param name="source">The source to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional source.</returns>
    public CertificateFinder AddSource(AbstractCertificateSource source)
        => this with { Sources = Sources.Add(source) };


    /// <summary>Adds certificate sources.</summary>
    /// <param name="sources">The sources to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional sources.</returns>
    public CertificateFinder AddSources(params IEnumerable<AbstractCertificateSource> sources)
        => this with { Sources = Sources.AddRange(sources) };


    /// <summary>Removes every source equal to <paramref name="source"/>.</summary>
    /// <param name="source">The source to remove.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance without that source.</returns>
    public CertificateFinder RemoveSource(AbstractCertificateSource source)
        => this with { Sources = Sources.RemoveAll(x => x == source) };


    /// <summary>Removes several sources. See <see cref="RemoveSource"/>.</summary>
    /// <param name="sources">The sources to remove.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance without those sources.</returns>
    public CertificateFinder RemoveSources(params IEnumerable<AbstractCertificateSource> sources)
    {
        var unwanted = sources.ToHashSet();
        return this with { Sources = Sources.RemoveAll(unwanted.Contains) };
    }


    /// <summary>Removes every source matching <paramref name="match"/>.</summary>
    /// <param name="match">Chooses which sources to remove.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance without those sources.</returns>
    public CertificateFinder RemoveSources(Func<AbstractCertificateSource, bool> match)
        => this with { Sources = Sources.RemoveAll(x => match(x)) };


    /// <summary>Adds the specified <see cref="X509Store"/> instances to the current sources.</summary>
    /// <param name="stores">The stores to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params IEnumerable<X509Store> stores)
        => AddSources(stores.Select(x => new CertificateStoreSource(x)));


    /// <summary>Adds stores by name and location to the current sources.</summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params IEnumerable<(string Name, StoreLocation Location)> stores)
        => AddSources(stores.Select(x => new CertificateStoreSource(x.Name, x.Location)));


    /// <summary>Adds stores by <see cref="StoreName"/> and location to the current sources.</summary>
    /// <param name="stores">The store names and locations to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional stores.</returns>
    public CertificateFinder AddStores(params IEnumerable<(StoreName Name, StoreLocation Location)> stores)
        => AddSources(stores.Select(x => new CertificateStoreSource(x.Name, x.Location)));


    /// <summary>Adds a single <see cref="X509Store"/> to the current sources.</summary>
    /// <param name="store">The store to add.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(X509Store store)
        => AddSource(new CertificateStoreSource(store));


    /// <summary>Adds a store by name and location to the current sources.</summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(string name, StoreLocation location)
        => AddSource(new CertificateStoreSource(name, location));


    /// <summary>Adds a store by <see cref="StoreName"/> and location to the current sources.</summary>
    /// <param name="name">The store name.</param>
    /// <param name="location">The store location.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the additional store.</returns>
    public CertificateFinder AddStore(StoreName name, StoreLocation location)
        => AddSource(new CertificateStoreSource(name, location));


    /// <summary>Adds the common stores (My, CA, Root, WebHosting) for CurrentUser and LocalMachine.</summary>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the common stores added.</returns>
    public CertificateFinder AddCommonStores()
        => AddSources(CommonStores);


    /// <summary>Adds a directory as a certificate source. Subdirectories are not searched by default.</summary>
    /// <param name="dir">The directory path.</param>
    /// <param name="recurse">Whether to search subdirectories.</param>
    /// <param name="searchPattern">Which file names to read. See <see cref="CertificateDirectorySource.SearchPattern"/>.</param>
    /// <param name="password">The password protecting the PKCS#12 files. See <see cref="CertificateDirectorySource.Password"/>.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directory added.</returns>
    public CertificateFinder AddDirectory(string dir, bool recurse = false, string searchPattern = "*", string? password = null)
        => AddSource(new CertificateDirectorySource(dir, recurse, _fileSystem) {
            SearchPattern = searchPattern,
            Password = password
        });


    /// <summary>Adds multiple directories as certificate sources.</summary>
    /// <param name="dirs">The directory paths.</param>
    /// <param name="recurse">Whether to search subdirectories.</param>
    /// <param name="searchPattern">Which file names to read in every one of these directories.</param>
    /// <param name="password">The password protecting the PKCS#12 files in every one of these directories.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directories added.</returns>
    public CertificateFinder AddDirectories(IEnumerable<string> dirs, bool recurse = false, string searchPattern = "*", string? password = null)
        => AddSources(dirs.Select(dir => new CertificateDirectorySource(dir, recurse, _fileSystem) {
            SearchPattern = searchPattern,
            Password = password
        }));


    /// <summary>
    /// Adds multiple directories as certificate sources. Subdirectories are not searched; use
    /// <see cref="AddDirectories(IEnumerable{string},bool,string,string)"/> for that.
    /// </summary>
    /// <param name="dirs">The directory paths.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the directories added.</returns>
    public CertificateFinder AddDirectories(params string[] dirs)
        => AddDirectories(dirs, false);


    /// <summary>Adds certificates the caller already holds. They are never disposed by the finder.</summary>
    /// <param name="certificates">The certificates to search.</param>
    /// <returns>A new <see cref="CertificateFinder"/> instance with the certificates added.</returns>
    public CertificateFinder AddCertificates(params IEnumerable<X509Certificate2> certificates)
        => AddSource(new CertificateCollectionSource(certificates));


    /// <summary>Enumerates every matching certificate, source by source, in the order the sources were added.</summary>
    /// <remarks>
    /// Sources are deduplicated by value, so a store or directory added twice is read once. Results are not:
    /// a certificate two sources both reach is reported by each of them.
    /// </remarks>
    /// <returns>An enumerator for <see cref="CertificateFinderResult"/>.</returns>
    public IEnumerator<CertificateFinderResult> GetEnumerator()
        => Sources.Distinct().SelectMany(source => source.Find(Filter)).GetEnumerator();


    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();


    /// <summary>The same results as <see cref="GetEnumerator"/>, in the same order, enumerated asynchronously.</summary>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The matching results.</returns>
    /// <remarks>
    /// A method rather than <see cref="IAsyncEnumerable{T}"/> on the finder itself, which would make every
    /// LINQ operator ambiguous on .NET 10. Named <c>As</c> rather than <c>To</c> because
    /// <c>ToAsyncEnumerable</c> is an extension on <see cref="IEnumerable{T}"/> that wraps the synchronous
    /// enumeration instead.
    /// </remarks>
    public async IAsyncEnumerable<CertificateFinderResult> AsAsyncEnumerable(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var source in Sources.Distinct()) {
            await foreach (var result in source.FindAsync(Filter, cancellationToken).ConfigureAwait(false)) {
                yield return result;
            }
        }
    }


    /// <summary>Rewrites a predicate as its negation, so <see cref="All"/> can ask the sources for a counter-example.</summary>
    private static Expression<Func<CertificateFinderResult, bool>> Negate(
        Expression<Func<CertificateFinderResult, bool>> predicate)
        => Expression.Lambda<Func<CertificateFinderResult, bool>>(
            Expression.Not(predicate.Body),
            predicate.Parameters
        );


    private readonly IFileSystem _fileSystem;


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
