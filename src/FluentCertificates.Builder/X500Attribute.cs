using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;

using FluentCertificates.Internals;

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
    /// <exception cref="ArgumentException"><paramref name="valueEncoding"/> is not a character string type, or
    /// <paramref name="value"/> has a character that type cannot hold.</exception>
    public X500Attribute(Oid oid, UniversalTagNumber valueEncoding, string value)
    {
        ArgumentNullException.ThrowIfNull(oid);
        ArgumentNullException.ThrowIfNull(value);
        ThrowIfNotEncodable(valueEncoding, value);
        OID = CheckOid(oid);
        ValueEncoding = valueEncoding;
        Value = value;
    }


    private X500Attribute(Oid oid, UniversalTagNumber valueEncoding, byte[] derValue)
    {
        OID = CheckOid(oid);
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
    /// <exception cref="ArgumentException"><paramref name="derValue"/> is not exactly one DER value, or is a
    /// UTF8String or BMPString whose bytes are not valid text.</exception>
    /// <remarks>The value is checked against the DER rules of ITU-T X.690 for its structure and for the universal
    /// types that have content rules. A value outside the character set of its string type, such as a wildcard in a
    /// PrintableString, is kept as raw DER. The content of a primitive with an application, context-specific or
    /// private tag cannot be checked, since what it was implicitly tagged from is not known.</remarks>
    public static X500Attribute CreateFromDer(Oid oid, ReadOnlySpan<byte> derValue)
    {
        ArgumentNullException.ThrowIfNull(oid);

        Asn1Tag tag;
        try {
            DerValidator.Validate(derValue);
            tag = Asn1Tag.Decode(derValue, out _);
        } catch (AsnContentException ex) {
            throw new ArgumentException(ex.Message, nameof(derValue), ex);
        }

        var universal = tag.TagClass == TagClass.Universal ? (UniversalTagNumber)tag.TagValue : UniversalTagNumber.EndOfContents;
        if (!tag.IsConstructed && (IsCharacterString(universal) || universal == UniversalTagNumber.T61String)) {
            try {
                var text = AsnDecoder.ReadCharacterString(derValue, AsnEncodingRules.DER, universal, out _);
                //T61String is only read as text when it is ASCII, since .NET reads any other byte as Latin-1 and
                //writes it back as UTF-8, which would change the value
                if (universal != UniversalTagNumber.T61String || text.All(Char.IsAscii)) {
                    return new X500Attribute(oid, universal, text);
                }
            } catch (AsnContentException ex) when (universal is UniversalTagNumber.UTF8String or UniversalTagNumber.BMPString) {
                //These two types hold any text, so bytes that decode to none are not a value of the type
                throw new ArgumentException($"The {universal} value is not valid text.", nameof(derValue), ex);
            } catch (Exception ex) when (ex is AsnContentException or ArgumentException) {
                //A value outside the character set of its type, such as a * in a PrintableString, stays as the bytes it came in
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


    //An Oid with no value could not be encoded
    private static Oid CheckOid(Oid oid)
        => String.IsNullOrEmpty(oid.Value)
            ? throw new ArgumentException("The OID has no value.", nameof(oid))
            : oid;


    private static void ThrowIfNotEncodable(UniversalTagNumber encoding, string value)
    {
        //The character sets are spelt out rather than left to the writer, because an older System.Formats.Asn1
        //does not check them all, and the same value must be refused on every target framework
        var allowed = encoding switch {
            UniversalTagNumber.PrintableString => value.All(x => Char.IsAsciiLetterOrDigit(x) || " '()+,-./:=?".Contains(x)),
            UniversalTagNumber.NumericString => value.All(x => Char.IsAsciiDigit(x) || x == ' '),
            UniversalTagNumber.IA5String or UniversalTagNumber.T61String => value.All(Char.IsAscii),
            UniversalTagNumber.VisibleString => value.All(x => x is >= ' ' and <= '~'),
            _ => true
        };
        if (!allowed) {
            throw new ArgumentException($"The value has a character that a {encoding} cannot hold.", nameof(value));
        }

        try {
            new AsnWriter(AsnEncodingRules.DER).WriteCharacterString(encoding, value);
        } catch (EncoderFallbackException ex) {
            throw new ArgumentException($"The value has a character that a {encoding} cannot hold.", nameof(value), ex);
        } catch (ArgumentException ex) {
            throw new ArgumentException($"{encoding} is not a character string type.", nameof(encoding), ex);
        }
    }


    private static bool IsCharacterString(UniversalTagNumber tag)
        => tag is UniversalTagNumber.UTF8String
            or UniversalTagNumber.NumericString
            or UniversalTagNumber.PrintableString
            or UniversalTagNumber.IA5String
            or UniversalTagNumber.VisibleString
            or UniversalTagNumber.BMPString;
}
