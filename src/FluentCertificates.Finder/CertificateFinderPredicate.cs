using System.Linq.Expressions;

namespace FluentCertificates;

/// <summary>
/// One predicate from a <see cref="CertificateFilter"/>, in both of the forms a source might need: an
/// expression tree to translate into a native query, and a compiled delegate to apply in memory.
/// </summary>
/// <remarks>
/// A source that translates some predicates but not others applies the remainder through
/// <see cref="Compiled"/>, rather than compiling <see cref="Expression"/> itself once per enumeration.
/// </remarks>
public sealed class CertificateFinderPredicate
{
    /// <summary>
    /// Creates a predicate, compiling <paramref name="expression"/> once.
    /// </summary>
    /// <param name="expression">The predicate a result must satisfy.</param>
    /// <exception cref="ArgumentNullException"><paramref name="expression"/> is null.</exception>
    public CertificateFinderPredicate(Expression<Func<CertificateFinderResult, bool>> expression)
    {
        ArgumentNullException.ThrowIfNull(expression);
        Expression = expression;
        Compiled = expression.Compile();
    }


    /// <summary>The predicate as an expression tree, for a source that can translate it.</summary>
    public Expression<Func<CertificateFinderResult, bool>> Expression { get; }


    /// <summary>The predicate compiled, for a source that can only apply it in memory.</summary>
    public Func<CertificateFinderResult, bool> Compiled { get; }
}
