using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Base type for the sources a <see cref="CertificateFinder"/> can search. A source locates certificates,
/// materialises them, and honours the <see cref="CertificateFilter"/> it is given. The finder does no
/// filtering of its own.
/// </summary>
/// <remarks>
/// Override <see cref="Enumerate"/> to produce candidates, applying as much of the filter natively as the
/// source can. <see cref="Find"/> then applies the filter in full, so a source that can push nothing down
/// is still correct, and one that pushes everything down pays only a cheap second pass over a set that
/// already matches. Overriding <see cref="Enumerate"/> therefore cannot break the contract.
/// <para>
/// Every member has an asynchronous counterpart, and the asynchronous ones wrap the synchronous ones by
/// default. A source overrides <see cref="EnumerateAsync"/> only where it has real asynchronous work,
/// such as reading files; one with nothing to await implements <see cref="Enumerate"/> alone and is
/// still enumerable and cancellable through <see cref="FindAsync"/>.
/// </para>
/// </remarks>
public abstract record AbstractCertificateSource
{
    /// <summary>
    /// Identifies the kind of source, for example <c>"Store"</c> or <c>"Directory"</c>. The library does
    /// not read it; it is there so a caller can group results, or collapse a certificate two overlapping
    /// sources of the same kind both reach, with
    /// <c>DistinctBy(r =&gt; (r.Certificate.Thumbprint, r.Source.Kind, r.Location))</c>.
    /// </summary>
    public abstract string Kind { get; }


    /// <summary>
    /// Produces candidate results, applying as much of <paramref name="filter"/> as this source can do
    /// natively. Returning a superset is always correct; returning less than the matching set is not.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <returns>Candidate results.</returns>
    protected abstract IEnumerable<CertificateFinderResult> Enumerate(CertificateFilter filter);


    /// <summary>
    /// Produces candidate results in the reverse of <see cref="Enumerate"/>'s order, or
    /// <see langword="null"/> if this source cannot go backwards. Returning <see langword="null"/> is the
    /// default, so a source opts in rather than out.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <returns>Candidate results last first, or <see langword="null"/>.</returns>
    /// <remarks>
    /// What is returned must be the true reverse of what <see cref="Enumerate"/> would yield, or
    /// <see cref="CertificateFinder.Last"/> will disagree with enumerating the finder. Implement it only
    /// when going backwards costs about what going forwards does: a source that would have to buffer its
    /// whole output should return <see langword="null"/> and let <see cref="FindLast"/> read it forwards,
    /// which is cheaper than buffering.
    /// </remarks>
    protected virtual IEnumerable<CertificateFinderResult>? EnumerateDescending(CertificateFilter filter)
        => null;


    /// <summary>
    /// The asynchronous counterpart of <see cref="Enumerate"/>. Wraps <see cref="Enumerate"/> by default,
    /// checking <paramref name="cancellationToken"/> between results, so a source that overrides nothing
    /// is still cancellable.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>Candidate results.</returns>
    /// <remarks>
    /// Override this only where the source has genuinely asynchronous work to do, such as reading files.
    /// The default costs a state machine and nothing else, and a source with no asynchronous IO gains
    /// nothing by overriding it. Whatever is overridden here must agree with <see cref="Enumerate"/>: the
    /// two produce the same results, so a caller cannot be made to choose between them for correctness.
    /// </remarks>
    protected virtual IAsyncEnumerable<CertificateFinderResult> EnumerateAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken)
        => ToAsyncEnumerable(Enumerate(filter), cancellationToken);


    /// <summary>
    /// The asynchronous counterpart of <see cref="EnumerateDescending"/>, or <see langword="null"/> if
    /// this source cannot go backwards. Wraps <see cref="EnumerateDescending"/> by default, so a source
    /// opts into backwards enumeration once rather than once per form.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>Candidate results last first, or <see langword="null"/>.</returns>
    protected virtual IAsyncEnumerable<CertificateFinderResult>? EnumerateDescendingAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken)
    {
        var candidates = EnumerateDescending(filter);
        return candidates is null ? null : ToAsyncEnumerable(candidates, cancellationToken);
    }


    /// <summary>
    /// Releases a result this source produced that is being discarded rather than returned to the caller.
    /// That happens when the filter rejects it, when <see cref="FindLast"/> passes over it, and when a
    /// terminal such as <see cref="CertificateFinder.Count"/> counts a match without returning it. Disposes
    /// the certificate by default.
    /// </summary>
    /// <param name="result">The result being discarded. The caller can never reach it.</param>
    /// <remarks>
    /// Override to a no-op in a source that passes through certificates the caller supplied, since those
    /// are not its to release. A source backed by a cache or pool can return the certificate here instead.
    /// Call it only for a result nothing else holds.
    /// </remarks>
    public virtual void Release(CertificateFinderResult result)
        => result.Certificate.Dispose();


    /// <summary>
    /// Returns every certificate this source holds that matches <paramref name="filter"/>, and nothing else.
    /// </summary>
    /// <param name="filter">The predicates the results must satisfy.</param>
    /// <returns>The matching results.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    public IEnumerable<CertificateFinderResult> Find(CertificateFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return Iterate(Enumerate(filter), filter);
    }


    /// <summary>
    /// Returns every certificate this source holds that matches <paramref name="filter"/>, in the reverse
    /// of the order <see cref="Find"/> yields them, or <see langword="null"/> if this source cannot go
    /// backwards.
    /// </summary>
    /// <param name="filter">The predicates the results must satisfy.</param>
    /// <returns>The matching results last first, or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    public IEnumerable<CertificateFinderResult>? FindDescending(CertificateFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var candidates = EnumerateDescending(filter);
        return candidates is null ? null : Iterate(candidates, filter);
    }


    /// <summary>
    /// Returns the last certificate this source holds that matches <paramref name="filter"/>, or
    /// <see langword="null"/> if none does.
    /// </summary>
    /// <param name="filter">The predicates the result must satisfy.</param>
    /// <returns>The last matching result, or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    /// <remarks>
    /// Uses <see cref="EnumerateDescending"/> where the source implements it, stopping at the first match.
    /// Otherwise it reads forwards and keeps the last match, releasing each one the next supersedes, since
    /// only the final one is ever returned.
    /// </remarks>
    public CertificateFinderResult? FindLast(CertificateFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);

        var descending = FindDescending(filter);
        if (descending is not null) {
            return descending.FirstOrDefault();
        }

        CertificateFinderResult? last = null;
        try {
            foreach (var result in Find(filter)) {
                if (last is not null) {
                    Release(last);
                }
                last = result;
            }
        } catch {
            //The match being held never reaches the caller now, so this is the last chance to release it
            if (last is not null) {
                Release(last);
            }
            throw;
        }
        return last;
    }


    /// <summary>
    /// The asynchronous counterpart of <see cref="Find"/>.
    /// </summary>
    /// <param name="filter">The predicates the results must satisfy.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The matching results.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    public IAsyncEnumerable<CertificateFinderResult> FindAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return IterateAsync(EnumerateAsync(filter, cancellationToken), filter, cancellationToken);
    }


    /// <summary>
    /// The asynchronous counterpart of <see cref="FindDescending"/>.
    /// </summary>
    /// <param name="filter">The predicates the results must satisfy.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The matching results last first, or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    public IAsyncEnumerable<CertificateFinderResult>? FindDescendingAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var candidates = EnumerateDescendingAsync(filter, cancellationToken);
        return candidates is null ? null : IterateAsync(candidates, filter, cancellationToken);
    }


    /// <summary>
    /// The asynchronous counterpart of <see cref="FindLast"/>.
    /// </summary>
    /// <param name="filter">The predicates the result must satisfy.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>The last matching result, or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    public async ValueTask<CertificateFinderResult?> FindLastAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);

        var descending = FindDescendingAsync(filter, cancellationToken);
        if (descending is not null) {
            await foreach (var result in descending.ConfigureAwait(false)) {
                return result;
            }
            return null;
        }

        CertificateFinderResult? last = null;
        try {
            await foreach (var result in FindAsync(filter, cancellationToken).ConfigureAwait(false)) {
                if (last is not null) {
                    Release(last);
                }
                last = result;
            }
        } catch {
            //The match being held never reaches the caller now, so this is the last chance to release it.
            //Cancelling is the ordinary way to get here
            if (last is not null) {
                Release(last);
            }
            throw;
        }
        return last;
    }


    /// <summary>
    /// Projects certificates into results carrying this source and a location.
    /// </summary>
    /// <param name="certificates">The certificates found.</param>
    /// <param name="location">Identifies a certificate within this source. See <see cref="CertificateFinderResult.Location"/>.</param>
    /// <returns>The results.</returns>
    protected IEnumerable<CertificateFinderResult> SelectResults(
        IEnumerable<X509Certificate2> certificates,
        Func<X509Certificate2, string> location)
        => certificates.Select(cert => new CertificateFinderResult {
            Source = this,
            Location = location(cert),
            Certificate = cert
        });


    private IEnumerable<CertificateFinderResult> Iterate(IEnumerable<CertificateFinderResult> candidates, CertificateFilter filter)
    {
        foreach (var result in candidates) {
            if (filter.Matches(result)) {
                yield return result;
            } else {
                //This source created it and is discarding it, so it must release it: nothing else can
                Release(result);
            }
        }
    }


    private async IAsyncEnumerable<CertificateFinderResult> IterateAsync(
        IAsyncEnumerable<CertificateFinderResult> candidates,
        CertificateFilter filter,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var result in candidates.WithCancellation(cancellationToken).ConfigureAwait(false)) {
            if (filter.Matches(result)) {
                yield return result;
            } else {
                //This source created it and is discarding it, so it must release it: nothing else can
                Release(result);
            }
        }
    }


#pragma warning disable CS1998 //Bridging a synchronous source: there is nothing here to await
    private static async IAsyncEnumerable<CertificateFinderResult> ToAsyncEnumerable(
        IEnumerable<CertificateFinderResult> results,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var result in results) {
            cancellationToken.ThrowIfCancellationRequested();
            yield return result;
        }
    }
#pragma warning restore CS1998
}
