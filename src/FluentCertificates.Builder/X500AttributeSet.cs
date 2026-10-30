using System.Collections;
using System.Collections.Immutable;

namespace FluentCertificates;


/// <summary>
/// The attributes of one relative distinguished name, which together form one level of a distinguished name.
/// </summary>
/// <remarks>
/// More than one attribute makes the name multi-valued, as in <c>CN=Example+OU=Sales</c>. The attributes
/// are held in the order given, but they form a set, so two sets with the same attributes in any order are equal.
/// </remarks>
public sealed class X500AttributeSet : IReadOnlyList<X500Attribute>, IEquatable<X500AttributeSet>
{
    /// <summary>
    /// Initializes a set holding the specified attributes.
    /// </summary>
    /// <param name="attributes">The attributes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="attributes"/> or an attribute in it is null.</exception>
    public X500AttributeSet(IEnumerable<X500Attribute> attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        _attributes = [.. attributes];
        if (_attributes.Any(x => x is null)) {
            throw new ArgumentNullException(nameof(attributes), "An attribute is null.");
        }
    }


    /// <summary>
    /// Gets the number of attributes.
    /// </summary>
    public int Count => _attributes.Count;


    /// <summary>
    /// Gets the attribute at the specified index.
    /// </summary>
    /// <param name="index">The zero-based index.</param>
    public X500Attribute this[int index] => _attributes[index];


    /// <inheritdoc/>
    public IEnumerator<X500Attribute> GetEnumerator()
        => _attributes.GetEnumerator();


    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();


    /// <summary>
    /// Determines whether another set holds the same attributes, in any order.
    /// </summary>
    /// <param name="other">The set to compare.</param>
    public bool Equals(X500AttributeSet? other)
        => other is not null && GetSortedAttributes().SequenceEqual(other.GetSortedAttributes());


    /// <inheritdoc/>
    public override bool Equals(object? obj)
        => Equals(obj as X500AttributeSet);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var attribute in GetSortedAttributes()) {
            hash.Add(attribute);
        }
        return hash.ToHashCode();
    }


    internal X500AttributeSet WithoutOid(string? oid)
        => new(_attributes.Where(x => x.OID.Value != oid));


    private List<X500Attribute> GetSortedAttributes()
    {
        var sorted = new List<X500Attribute>(_attributes);
        sorted.Sort(X500Attribute.Compare);
        return sorted;
    }


    private readonly ImmutableList<X500Attribute> _attributes;
}
