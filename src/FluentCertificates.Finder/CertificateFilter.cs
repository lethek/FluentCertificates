using System.Collections.Immutable;
using System.Linq.Expressions;

namespace FluentCertificates;

/// <summary>
/// An immutable set of predicates a <see cref="CertificateFinder"/> passes to its sources. Each predicate
/// is kept both as an expression tree, for a source able to translate it into a native query, and as a
/// compiled delegate, for one that can only apply it in memory.
/// </summary>
/// <remarks>
/// A predicate is compiled once, when it is added, rather than once per enumeration or once per source.
/// </remarks>
public sealed class CertificateFilter
{
    /// <summary>A filter with no predicates, matching every certificate.</summary>
    public static CertificateFilter Empty { get; } = new(
        ImmutableList<Expression<Func<CertificateFinderResult, bool>>>.Empty,
        ImmutableList<Func<CertificateFinderResult, bool>>.Empty
    );


    /// <summary>
    /// The predicates as expression trees, in the order they were added. A source that can translate a
    /// predicate into a native query reads it from here.
    /// </summary>
    public IReadOnlyList<Expression<Func<CertificateFinderResult, bool>>> Expressions => _expressions;


    /// <summary>Whether this filter has no predicates, and so matches everything.</summary>
    public bool IsEmpty => _expressions.IsEmpty;


    /// <summary>
    /// Returns a new filter with <paramref name="predicate"/> added. Predicates combine with AND.
    /// </summary>
    /// <param name="predicate">The predicate to add.</param>
    /// <returns>A new filter.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is null.</exception>
    public CertificateFilter Add(Expression<Func<CertificateFinderResult, bool>> predicate)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        return new CertificateFilter(_expressions.Add(predicate), _compiled.Add(predicate.Compile()));
    }


    /// <summary>
    /// Whether <paramref name="result"/> satisfies every predicate.
    /// </summary>
    /// <param name="result">The result to test.</param>
    /// <returns><see langword="true"/> if it matches all of them, or if there are none.</returns>
    public bool Matches(CertificateFinderResult result)
    {
        foreach (var predicate in _compiled) {
            if (!predicate(result)) {
                return false;
            }
        }
        return true;
    }


    private CertificateFilter(
        ImmutableList<Expression<Func<CertificateFinderResult, bool>>> expressions,
        ImmutableList<Func<CertificateFinderResult, bool>> compiled)
    {
        _expressions = expressions;
        _compiled = compiled;
    }


    private readonly ImmutableList<Expression<Func<CertificateFinderResult, bool>>> _expressions;
    private readonly ImmutableList<Func<CertificateFinderResult, bool>> _compiled;
}
