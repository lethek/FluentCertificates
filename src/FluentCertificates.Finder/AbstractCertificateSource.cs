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
    /// Identifies the kind of source, for example <c>"Store"</c> or <c>"Directory"</c>. Together with a
    /// result's <see cref="CertificateFinderResult.Location"/> and thumbprint this forms the identity
    /// <see cref="CertificateFinder"/> deduplicates on, so two sources whose reach overlaps report the
    /// same certificate once.
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
    /// of the order <see cref="Find"/> yields them.
    /// </summary>
    /// <param name="filter">The predicates the results must satisfy.</param>
    /// <returns>The matching results, last first.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    /// <exception cref="NotSupportedException"><see cref="CanEnumerateDescending"/> is false.</exception>
    public IEnumerable<CertificateFinderResult> FindDescending(CertificateFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        if (!CanEnumerateDescending) {
            throw new NotSupportedException($"{GetType().Name} cannot enumerate in descending order.");
        }
        return Iterate(EnumerateDescending(filter), filter);
    }


    /// <summary>
    /// Produces candidate results, applying as much of <paramref name="filter"/> as this source can do
    /// natively. Returning a superset is always correct; returning less than the matching set is not.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <returns>Candidate results.</returns>
    protected abstract IEnumerable<CertificateFinderResult> Enumerate(CertificateFilter filter);


    /// <summary>
    /// Whether this source can enumerate backwards, which lets <see cref="CertificateFinder.Last"/> stop
    /// at the first match instead of reading everything. Override alongside
    /// <see cref="EnumerateDescending"/>.
    /// </summary>
    /// <remarks>
    /// Only worth claiming when going backwards costs about what going forwards does. A source that would
    /// have to buffer its whole output to reverse it should leave this <see langword="false"/>: the finder
    /// then reads it forwards and keeps the last match, which is cheaper than buffering.
    /// </remarks>
    public virtual bool CanEnumerateDescending => false;


    /// <summary>
    /// Produces candidate results in the reverse of <see cref="Enumerate"/>'s order. It must be the true
    /// reverse of what that call would yield, or <see cref="CertificateFinder.Last"/> and
    /// <see cref="Enumerable.Last{T}(IEnumerable{T})"/> will disagree.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for.</param>
    /// <returns>Candidate results, last first.</returns>
    /// <exception cref="NotSupportedException">This source does not support it; see <see cref="CanEnumerateDescending"/>.</exception>
    protected virtual IEnumerable<CertificateFinderResult> EnumerateDescending(CertificateFilter filter)
        => throw new NotSupportedException($"{GetType().Name} cannot enumerate in descending order.");


    /// <summary>
    /// Whether this source creates the certificates it yields, and so may dispose the ones that are
    /// discarded. A source passing through certificates the caller supplied must return
    /// <see langword="false"/>, since those are not its to release.
    /// </summary>
    /// <remarks>
    /// Read by <see cref="Find"/> for the results a filter rejects, and by <see cref="CertificateFinder"/>
    /// for the ones deduplication drops.
    /// </remarks>
    public virtual bool OwnsCertificates => true;


    private IEnumerable<CertificateFinderResult> Iterate(IEnumerable<CertificateFinderResult> candidates, CertificateFilter filter)
    {
        foreach (var result in candidates) {
            if (filter.Matches(result)) {
                yield return result;
            } else if (OwnsCertificates) {
                //This source created it and is discarding it, so it must release it: nothing else can
                result.Certificate.Dispose();
            }
        }
    }
}
