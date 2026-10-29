using System.Collections.Immutable;

namespace FluentCertificates;


/// <summary>
/// A relative distinguished name: one or more attributes that together form one level of a distinguished name.
/// </summary>
/// <param name="Attributes">The attributes. More than one makes the name multi-valued, as in <c>CN=Example+OU=Sales</c>.</param>
public sealed record X500RelativeDistinguishedName(ImmutableList<X500Attribute> Attributes)
{
    /// <summary>
    /// Determines whether another relative distinguished name holds the same attributes, in any order.
    /// </summary>
    /// <param name="other">The relative distinguished name to compare.</param>
    /// <remarks>The attributes of one relative distinguished name form a set, so their order carries no meaning.</remarks>
    public bool Equals(X500RelativeDistinguishedName? other)
        => other is not null && GetSortedAttributes().SequenceEqual(other.GetSortedAttributes());


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var attribute in GetSortedAttributes()) {
            hash.Add(attribute);
        }
        return hash.ToHashCode();
    }


    internal X500RelativeDistinguishedName WithoutOid(string? oid)
        => new([.. Attributes.Where(x => x.OID.Value != oid)]);


    private List<X500Attribute> GetSortedAttributes()
    {
        var sorted = new List<X500Attribute>(Attributes);
        sorted.Sort(X500Attribute.Compare);
        return sorted;
    }
}
