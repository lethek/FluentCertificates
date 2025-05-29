using System.Formats.Asn1;

namespace FluentCertificates;

/// <summary>
/// Represents an abstract X.509 GeneralName, which is used in various certificate extensions
/// (such as Subject Alternative Name and Name Constraints) to encode different types of names.
/// </summary>
public abstract record GeneralName
{
    /// <summary>
    /// Gets the ASN.1 tag that identifies the specific GeneralName type.
    /// </summary>    
    public abstract Asn1Tag Tag { get; }

    
    /// <summary>
    /// Writes the encoded representation of this GeneralName to the specified <see cref="AsnWriter"/>.
    /// </summary>
    /// <param name="writer">The ASN.1 writer to which the GeneralName will be written.</param>
    public void WriteTo(AsnWriter writer)
        => EncodeCore(writer);

    
    /// <summary>
    /// When implemented in a derived class, encodes the GeneralName to the specified <see cref="AsnWriter"/>.
    /// </summary>
    /// <param name="writer">The ASN.1 writer to which the GeneralName will be encoded.</param>
    protected abstract void EncodeCore(AsnWriter writer);
}