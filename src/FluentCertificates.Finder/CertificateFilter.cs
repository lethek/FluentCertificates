using System.Collections.Immutable;
using System.Linq.Expressions;

namespace FluentCertificates;

/// <summary>
/// An immutable set of predicates a <see cref="CertificateFinder"/> passes to its sources. A result must
/// satisfy every one of them.
/// </summary>
/// <remarks>
/// A predicate is compiled once, when it is added, rather than once per enumeration or once per source.
/// </remarks>
public sealed class CertificateFilter
{
    /// <summary>A filter with no predicates, matching every certificate.</summary>
    public static CertificateFilter Empty { get; } = new(ImmutableList<CertificatePredicate>.Empty);


    /// <summary>
    /// The predicates, in the order they were added. A source reads these to apply what it can natively.
    /// </summary>
    public IReadOnlyList<CertificatePredicate> Predicates => _predicates;


    /// <summary>Whether this filter has no predicates, and so matches everything.</summary>
    public bool IsEmpty => _predicates.IsEmpty;


    /// <summary>
    /// Returns a new filter with <paramref name="predicate"/> added, compiling it once.
    /// </summary>
    /// <param name="predicate">The predicate to add.</param>
    /// <returns>A new filter.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is null.</exception>
    public CertificateFilter Add(Expression<Func<CertificateFinderResult, bool>> predicate)
        => Add(new CertificatePredicate(predicate));


    /// <summary>
    /// Returns a new filter with <paramref name="predicate"/> added.
    /// </summary>
    /// <param name="predicate">The predicate to add.</param>
    /// <returns>A new filter.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is null.</exception>
    public CertificateFilter Add(CertificatePredicate predicate)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        return new CertificateFilter(_predicates.Add(predicate));
    }


    /// <summary>
    /// Whether <paramref name="result"/> satisfies every predicate.
    /// </summary>
    /// <param name="result">The result to test.</param>
    /// <returns><see langword="true"/> if it matches all of them, or if there are none.</returns>
    public bool Matches(CertificateFinderResult result)
    {
        foreach (var predicate in _predicates) {
            if (!predicate.Compiled(result)) {
                return false;
            }
        }
        return true;
    }


    private CertificateFilter(ImmutableList<CertificatePredicate> predicates)
        => _predicates = predicates;


    private readonly ImmutableList<CertificatePredicate> _predicates;
}
