using System.Runtime.CompilerServices;

namespace FluentCertificates;

/// <summary>
/// Base type for the sources a <see cref="CertificateFinder"/> can search. A source locates certificates,
/// materialises them in batches, and honours the <see cref="CertificateFilter"/> it is given. The finder
/// does no filtering of its own.
/// </summary>
/// <remarks>
/// Override <see cref="Enumerate"/> to produce batches, applying as much of the filter natively as the
/// source can. <see cref="Find"/> then applies the filter in full, so a source that can push nothing down
/// is still correct, and one that pushes everything down pays only a cheap second pass over a set that
/// already matches. Overriding <see cref="Enumerate"/> therefore cannot break the contract.
/// <para>
/// A <see cref="CertificateBatch"/> is one group of certificates the source materialised at once, such as
/// a file or a store. Yielding it hands those certificates over: whatever the caller does not take is
/// released here, so a source holding nothing of its own between batches cannot leak.
/// </para>
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
    /// Produces batches of candidate certificates, applying as much of <paramref name="filter"/> as this
    /// source can do natively. Returning a superset is always correct; returning less than the matching
    /// set is not.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <returns>The batches, pulled one at a time and only as far as the caller reads.</returns>
    protected abstract IEnumerable<CertificateBatch> Enumerate(CertificateFilter filter);


    /// <summary>
    /// Produces the same batches in the reverse of <see cref="Enumerate"/>'s order, or
    /// <see langword="null"/> if this source cannot go backwards. Returning <see langword="null"/> is the
    /// default, so a source opts in rather than out.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <returns>The batches last first, or <see langword="null"/>.</returns>
    /// <remarks>
    /// Reverse the order the batches come in and nothing else: each one is read back to front for you, so
    /// a source cannot disagree with itself about what its last certificate is. Implement this only when
    /// going backwards costs about what going forwards does: a source that would have to buffer its whole
    /// output should return <see langword="null"/> and let <see cref="FindLast"/> read it forwards, which
    /// is cheaper than buffering.
    /// </remarks>
    protected virtual IEnumerable<CertificateBatch>? EnumerateDescending(CertificateFilter filter)
        => null;


    /// <summary>
    /// The asynchronous counterpart of <see cref="Enumerate"/>. Wraps <see cref="Enumerate"/> by default,
    /// so a source that overrides nothing is still usable and cancellable asynchronously.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The batches.</returns>
    /// <remarks>
    /// Override this only where the source has genuinely asynchronous work to do, such as reading files.
    /// The default costs a state machine and nothing else, and a source with no asynchronous IO gains
    /// nothing by overriding it. Whatever is overridden here must agree with <see cref="Enumerate"/>: the
    /// two produce the same results, so a caller cannot be made to choose between them for correctness.
    /// <para>
    /// An override need not check <paramref name="cancellationToken"/> to be cancellable: the token is
    /// checked once per certificate as the results are handed out, whatever produced them.
    /// </para>
    /// </remarks>
    protected virtual IAsyncEnumerable<CertificateBatch> EnumerateAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken)
        => ToAsyncEnumerable(Enumerate(filter));


    /// <summary>
    /// The asynchronous counterpart of <see cref="EnumerateDescending"/>, or <see langword="null"/> if
    /// this source cannot go backwards. Wraps <see cref="EnumerateDescending"/> by default, so a source
    /// opts into backwards enumeration once rather than once per form.
    /// </summary>
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
    /// caller. That happens when the filter rejects it, when the caller stops reading before reaching it,
    /// when <see cref="FindLast"/> passes over it, and when a terminal such as
    /// <see cref="CertificateFinder.Count"/> counts a match without returning it. Disposes the certificate
    /// by default.
    /// </summary>
    /// <param name="result">The result being discarded. The caller can never reach it.</param>
    /// <remarks>
    /// Override to a no-op in a source that passes through certificates the caller supplied, since those
    /// are not its to release. A source backed by a cache or pool can return the certificate here instead.
    /// Every certificate in a batch reaches either the caller or this method, exactly once.
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
        return Iterate(Enumerate(filter), filter, descending: false);
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
        return candidates is null ? null : Iterate(candidates, filter, descending: true);
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
        return IterateAsync(EnumerateAsync(filter, cancellationToken), filter, false, cancellationToken);
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
        return candidates is null ? null : IterateAsync(candidates, filter, true, cancellationToken);
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
    /// Hands out the certificates in each batch that match the filter, and releases every other one: the
    /// ones the filter rejects, and the ones past where the caller stopped reading. Reads each batch back
    /// to front when <paramref name="descending"/>, which is what makes a batch of several certificates
    /// reverse properly rather than only the order the batches arrive in.
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
                        //This source created it and is discarding it, so it must release it: nothing else can
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
                    //Checked per certificate, so cancelling stops part way through a large batch
                    cancellationToken.ThrowIfCancellationRequested();
                    var result = Project(batch, next, descending);
                    if (!filter.Matches(result)) {
                        //This source created it and is discarding it, so it must release it: nothing else can
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
    /// the filter threw. Those certificates are already materialised and nothing else can reach them.
    /// </summary>
    /// <param name="batch">The batch being abandoned.</param>
    /// <param name="next">How far into the batch the loop had read when it left.</param>
    /// <param name="handedOver">
    /// Whether the one it stopped on was handed to the caller, in which case it is theirs and releasing
    /// starts after it.
    /// </param>
    /// <param name="descending">Whether the batch was being read back to front.</param>
    private void ReleaseRemainder(CertificateBatch batch, int next, bool handedOver, bool descending)
    {
        for (var i = handedOver ? next + 1 : next; i < batch.Certificates.Count; i++) {
            Release(Project(batch, i, descending));
        }
    }


    /// <summary>
    /// Projects the certificate <paramref name="position"/> places into the batch, counting from the end
    /// of it when <paramref name="descending"/>.
    /// </summary>
    private CertificateFinderResult Project(CertificateBatch batch, int position, bool descending)
        => new() {
            Source = this,
            Location = batch.Location,
            Certificate = batch.Certificates[descending ? batch.Certificates.Count - 1 - position : position]
        };


    /// <summary>
    /// Bridges a synchronous source to the asynchronous path.
    /// </summary>
    /// <remarks>
    /// Takes no <see cref="CancellationToken"/> on purpose, and neither call site passes one. This bridge
    /// runs only for a source that does not override <see cref="EnumerateAsync"/>, whereas
    /// <see cref="IterateAsync"/> is on every asynchronous path and checks the token per certificate there.
    /// A check here would be a second one covering less, and no test could tell whether it was still
    /// present. Cancellation is pinned by <c>AsAsyncEnumerable_WhenCancelled_Throws</c>.
    /// </remarks>
#pragma warning disable CS1998 //Bridging a synchronous source: there is nothing here to await
    private static async IAsyncEnumerable<CertificateBatch> ToAsyncEnumerable(IEnumerable<CertificateBatch> batches)
    {
        foreach (var batch in batches) {
            yield return batch;
        }
    }
#pragma warning restore CS1998
}
