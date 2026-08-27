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
        foreach (var result in Find(filter)) {
            if (last is not null) {
                Release(last);
            }
            last = result;
        }
        return last;
    }


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
    /// Releases a result this source produced and then discarded, which happens when the filter rejects it
    /// or when <see cref="FindLast"/> passes over it. Disposes the certificate by default.
    /// </summary>
    /// <param name="result">The result being discarded. The caller can never reach it.</param>
    /// <remarks>
    /// Override to a no-op in a source that passes through certificates the caller supplied, since those
    /// are not its to release. A source backed by a cache or pool can return the certificate here instead.
    /// </remarks>
    protected virtual void Release(CertificateFinderResult result)
        => result.Certificate.Dispose();


    /// <summary>
    /// Projects certificates into results carrying this source and a location.
    /// </summary>
    /// <param name="certificates">The certificates found.</param>
    /// <param name="location">Identifies a certificate within this source. See <see cref="CertificateFinderResult.Location"/>.</param>
    /// <returns>The results.</returns>
    protected IEnumerable<CertificateFinderResult> Results(
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
}
