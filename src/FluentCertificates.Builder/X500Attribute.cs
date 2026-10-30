using System.Formats.Asn1;
using System.Security.Cryptography;

namespace FluentCertificates;


/// <summary>
/// One attribute of a relative distinguished name: an attribute type and its value.
/// </summary>
/// <remarks>
/// A value is either a character string, held as text with the ASN.1 string type it is encoded as, or
/// any other value, held as its raw DER encoding.
/// </remarks>
public sealed record X500Attribute
{
    /// <summary>
    /// Initializes a character-string attribute.
    /// </summary>
    /// <param name="oid">The attribute type.</param>
    /// <param name="valueEncoding">The ASN.1 string type the value is encoded as.</param>
    /// <param name="value">The value.</param>
    /// <exception cref="ArgumentNullException"><paramref name="oid"/> or <paramref name="value"/> is null.</exception>
    public X500Attribute(Oid oid, UniversalTagNumber valueEncoding, string value)
    {
        ArgumentNullException.ThrowIfNull(oid);
        ArgumentNullException.ThrowIfNull(value);
        OID = oid;
        ValueEncoding = valueEncoding;
        Value = value;
    }


    private X500Attribute(Oid oid, UniversalTagNumber valueEncoding, byte[] derValue)
    {
        OID = oid;
        ValueEncoding = valueEncoding;
        DerValue = derValue;
    }


    /// <summary>
    /// Gets the attribute type.
    /// </summary>
    public Oid OID { get; }


    /// <summary>
    /// Gets the ASN.1 string type of a character-string value. For a raw value it is the universal type of
    /// the DER encoding, or <see cref="UniversalTagNumber.EndOfContents"/> when that encoding is not universal.
    /// </summary>
    public UniversalTagNumber ValueEncoding { get; }


    /// <summary>
    /// Gets the value of a character-string attribute, or null when the value is held as raw DER.
    /// </summary>
    public string? Value { get; }


    /// <summary>
    /// Gets the complete DER encoding of a raw value, or an empty value for a character string.
    /// </summary>
    public ReadOnlyMemory<byte> DerValue { get; }


    /// <summary>
    /// Creates an attribute from the DER encoding of its value.
    /// </summary>
    /// <param name="oid">The attribute type.</param>
    /// <param name="derValue">One complete DER encoding of the value.</param>
    /// <returns>A character-string attribute when the value is a well-formed character string, otherwise a raw one.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="oid"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="derValue"/> is not exactly one DER value.</exception>
    public static X500Attribute CreateFromDer(Oid oid, ReadOnlySpan<byte> derValue)
    {
        ArgumentNullException.ThrowIfNull(oid);

        Asn1Tag tag;
        int consumed;
        try {
            tag = Asn1Tag.Decode(derValue, out _);
            AsnDecoder.ReadEncodedValue(derValue, AsnEncodingRules.DER, out _, out _, out consumed);
        } catch (AsnContentException ex) {
            throw new ArgumentException("The value must be one complete DER encoding.", nameof(derValue), ex);
        }
        if (consumed != derValue.Length) {
            throw new ArgumentException("The value must be one complete DER encoding.", nameof(derValue));
        }

        var universal = tag.TagClass == TagClass.Universal ? (UniversalTagNumber)tag.TagValue : UniversalTagNumber.EndOfContents;
        if (!tag.IsConstructed && IsCharacterString(universal)) {
            try {
                return new X500Attribute(oid, universal, AsnDecoder.ReadCharacterString(derValue, AsnEncodingRules.DER, universal, out _));
            } catch (AsnContentException) {
                //Text that does not decode, such as invalid UTF-8, stays as the bytes it came in
            }
        }
        return new X500Attribute(oid, universal, derValue.ToArray());
    }


    /// <summary>
    /// Determines whether another attribute has the same type, value encoding and value.
    /// </summary>
    /// <param name="other">The attribute to compare.</param>
    public bool Equals(X500Attribute? other)
        => other is not null
           && OID.Value == other.OID.Value
           && ValueEncoding == other.ValueEncoding
           && String.Equals(Value, other.Value, StringComparison.Ordinal)
           && DerValue.Span.SequenceEqual(other.DerValue.Span);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(OID.Value);
        hash.Add(ValueEncoding);
        hash.Add(Value, StringComparer.Ordinal);
        hash.AddBytes(DerValue.Span);
        return hash.ToHashCode();
    }


    internal static int Compare(X500Attribute x, X500Attribute y)
    {
        var result = String.CompareOrdinal(x.OID.Value, y.OID.Value);
        if (result == 0) {
            result = x.ValueEncoding.CompareTo(y.ValueEncoding);
        }
        if (result == 0) {
            result = String.CompareOrdinal(x.Value, y.Value);
        }
        return result != 0 ? result : x.DerValue.Span.SequenceCompareTo(y.DerValue.Span);
    }


    internal void Encode(AsnWriter writer)
    {
        using (writer.PushSequence()) {
            writer.WriteObjectIdentifier(OID.Value!);
            if (Value is null) {
                writer.WriteEncodedValue(DerValue.Span);
            } else {
                writer.WriteCharacterString(ValueEncoding, Value);
            }
        }
    }


    //T61String is left out because .NET reads its bytes as Latin-1 and writes them back as UTF-8, so the
    //value would not survive a round trip
    private static bool IsCharacterString(UniversalTagNumber tag)
        => tag is UniversalTagNumber.UTF8String
            or UniversalTagNumber.NumericString
            or UniversalTagNumber.PrintableString
            or UniversalTagNumber.IA5String
            or UniversalTagNumber.VisibleString
            or UniversalTagNumber.BMPString;
}
