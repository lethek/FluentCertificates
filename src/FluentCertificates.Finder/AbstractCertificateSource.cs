using System.Runtime.CompilerServices;

namespace FluentCertificates;

/// <summary>
/// Base type for the sources a <see cref="CertificateFinder"/> can search. A source locates certificates,
/// materialises them in batches, and honours the <see cref="CertificateFilter"/> it is given. The finder
/// does no filtering of its own.
/// </summary>
/// <remarks>
/// <see cref="Find"/> applies the filter in full, so <see cref="Enumerate"/> may push down as much or as
/// little of it as the source can. Every certificate in a yielded batch reaches either the caller or
/// <see cref="Release"/>, so a source holding nothing of its own between batches cannot leak.
/// </remarks>
public abstract record AbstractCertificateSource
{
    /// <summary>
    /// Identifies the kind of source, for example <c>"Store"</c> or <c>"Directory"</c>. The library never
    /// reads it; it is there for a caller to group results by.
    /// </summary>
    public abstract string Kind { get; }


    /// <summary>
    /// Produces batches of candidate certificates, applying as much of <paramref name="filter"/> as this
    /// source can do natively. Returning a superset is correct; returning less than the matching set is not.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <returns>The batches, pulled only as far as the caller reads.</returns>
    protected abstract IEnumerable<CertificateBatch> Enumerate(CertificateFilter filter);


    /// <summary>
    /// Produces the same batches in the reverse of <see cref="Enumerate"/>'s order, or
    /// <see langword="null"/> if this source cannot go backwards.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <returns>The batches last first, or <see langword="null"/>.</returns>
    /// <remarks>Reverse the order the batches arrive in only: each batch is reversed for you.</remarks>
    protected virtual IEnumerable<CertificateBatch>? EnumerateDescending(CertificateFilter filter)
        => null;


    /// <summary>The asynchronous counterpart of <see cref="Enumerate"/>, which it wraps by default.</summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The batches.</returns>
    /// <remarks>
    /// An override must agree with <see cref="Enumerate"/>, and need not check
    /// <paramref name="cancellationToken"/>: the token is checked once per certificate as the results are
    /// handed out, whatever produced them.
    /// </remarks>
    protected virtual IAsyncEnumerable<CertificateBatch> EnumerateAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken)
        => ToAsyncEnumerable(Enumerate(filter));


    /// <summary>The asynchronous counterpart of <see cref="EnumerateDescending"/>, which it wraps.</summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The batches last first, or <see langword="null"/>.</returns>
    protected virtual IAsyncEnumerable<CertificateBatch>? EnumerateDescendingAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken)
    {
        var candidates = EnumerateDescending(filter);
        return candidates is null ? null : ToAsyncEnumerable(candidates);
    }


    /// <summary>
    /// Releases a certificate this source produced that is being discarded rather than returned to the
    /// caller, disposing it by default.
    /// </summary>
    /// <param name="result">The result being discarded; the caller can never reach it.</param>
    /// <remarks>Override to a no-op in a source passing through certificates the caller supplied.</remarks>
    public virtual void Release(CertificateFinderResult result)
        => result.Certificate.Dispose();


    /// <summary>Returns every certificate this source holds that matches <paramref name="filter"/>.</summary>
    /// <param name="filter">The predicates the results must satisfy.</param>
    /// <returns>The matching results.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    public IEnumerable<CertificateFinderResult> Find(CertificateFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return Iterate(Enumerate(filter), filter, descending: false);
    }


    /// <summary>Returns what <see cref="Find"/> would, in reverse, or <see langword="null"/>.</summary>
    /// <param name="filter">The predicates the results must satisfy.</param>
    /// <returns>The matching results last first, or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    public IEnumerable<CertificateFinderResult>? FindDescending(CertificateFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var candidates = EnumerateDescending(filter);
        return candidates is null ? null : Iterate(candidates, filter, descending: true);
    }


    /// <summary>The last certificate this source holds that matches <paramref name="filter"/>.</summary>
    /// <param name="filter">The predicates the result must satisfy.</param>
    /// <returns>The last matching result, or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
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


    /// <summary>The asynchronous counterpart of <see cref="Find"/>.</summary>
    /// <param name="filter">The predicates the results must satisfy.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The matching results.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    public IAsyncEnumerable<CertificateFinderResult> FindAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        return IterateAsync(EnumerateAsync(filter, cancellationToken), filter, false, cancellationToken);
    }


    /// <summary>The asynchronous counterpart of <see cref="FindDescending"/>.</summary>
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
        return candidates is null ? null : IterateAsync(candidates, filter, true, cancellationToken);
    }


    /// <summary>The asynchronous counterpart of <see cref="FindLast"/>.</summary>
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
            //Cancelling is the ordinary way to get here
            if (last is not null) {
                Release(last);
            }
            throw;
        }
        return last;
    }


    /// <summary>
    /// Hands out the certificates in each batch that match the filter, releases every other one, and reads
    /// each batch back to front when <paramref name="descending"/>.
    /// </summary>
    private IEnumerable<CertificateFinderResult> Iterate(
        IEnumerable<CertificateBatch> batches,
        CertificateFilter filter,
        bool descending)
    {
        foreach (var batch in batches) {
            var next = 0;
            var handedOver = false;
            try {
                for (; next < batch.Certificates.Count; next++) {
                    var result = Project(batch, next, descending);
                    if (!filter.Matches(result)) {
                        Release(result);
                        continue;
                    }
                    handedOver = true;
                    yield return result;
                    handedOver = false;
                }
            } finally {
                ReleaseRemainder(batch, next, handedOver, descending);
            }
        }
    }


    /// <summary>The asynchronous counterpart of <see cref="Iterate"/>.</summary>
    private async IAsyncEnumerable<CertificateFinderResult> IterateAsync(
        IAsyncEnumerable<CertificateBatch> batches,
        CertificateFilter filter,
        bool descending,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var batch in batches.WithCancellation(cancellationToken).ConfigureAwait(false)) {
            var next = 0;
            var handedOver = false;
            try {
                for (; next < batch.Certificates.Count; next++) {
                    //Per certificate, so cancelling stops part way through a large batch
                    cancellationToken.ThrowIfCancellationRequested();
                    var result = Project(batch, next, descending);
                    if (!filter.Matches(result)) {
                        Release(result);
                        continue;
                    }
                    handedOver = true;
                    yield return result;
                    handedOver = false;
                }
            } finally {
                ReleaseRemainder(batch, next, handedOver, descending);
            }
        }
    }


    /// <summary>
    /// Releases the part of a batch the caller will never see, whether it stopped reading, cancelled, or
    /// the filter threw. <paramref name="handedOver"/> means the one it stopped on is already the
    /// caller's, so releasing starts after it.
    /// </summary>
    private void ReleaseRemainder(CertificateBatch batch, int next, bool handedOver, bool descending)
    {
        for (var i = handedOver ? next + 1 : next; i < batch.Certificates.Count; i++) {
            Release(Project(batch, i, descending));
        }
    }


    /// <summary>
    /// Projects the certificate <paramref name="position"/> places into the batch, counting from the end
    /// when <paramref name="descending"/>.
    /// </summary>
    private CertificateFinderResult Project(CertificateBatch batch, int position, bool descending)
        => new() {
            Source = this,
            Location = batch.Location,
            Certificate = batch.Certificates[descending ? batch.Certificates.Count - 1 - position : position]
        };


    /// <summary>Bridges a synchronous source to the asynchronous path.</summary>
    /// <remarks>
    /// Takes no <see cref="CancellationToken"/> on purpose: <see cref="IterateAsync"/> is on every
    /// asynchronous path and already checks the token per certificate, so a check here would cover less
    /// and no test could tell whether it was still present.
    /// </remarks>
#pragma warning disable CS1998 //Bridging a synchronous source: there is nothing here to await
    // ReSharper disable once AsyncMethodWithoutAwait
    private static async IAsyncEnumerable<CertificateBatch> ToAsyncEnumerable(IEnumerable<CertificateBatch> batches)
    {
        foreach (var batch in batches) {
            yield return batch;
        }
    }
#pragma warning restore CS1998
}
