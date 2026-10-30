using System.Formats.Asn1;

namespace FluentCertificates.Internals;

/// <summary>
/// Rewrites one BER encoded value as DER, for the BER that RFC 4514 allows in a <c>#</c> hex value.
/// </summary>
/// <remarks>
/// Covers what BER permits and DER does not at the level of structure: indefinite and non-minimal lengths,
/// constructed strings, the order of a SET's members, and a BOOLEAN's true value. A constructed BIT STRING is
/// refused rather than guessed at. The result is not checked here: <see cref="DerValidator"/> refuses what is
/// still not DER, such as a BIT STRING with non-zero padding or a malformed time.
/// </remarks>
internal static class BerToDer
{
    public static byte[] Normalize(ReadOnlySpan<byte> ber)
    {
        var der = Normalize(ber, 0, out var consumed);
        if (consumed != ber.Length) {
            throw new AsnContentException("The value has bytes after its encoding.");
        }
        return der;
    }


    private static byte[] Normalize(ReadOnlySpan<byte> source, int depth, out int consumed)
    {
        if (depth > MaxDepth) {
            throw new AsnContentException("The value is nested too deeply.");
        }

        var tag = Asn1Tag.Decode(source, out _);
        AsnDecoder.ReadEncodedValue(source, AsnEncodingRules.BER, out var contentOffset, out var contentLength, out consumed);
        var content = source.Slice(contentOffset, contentLength);

        if (!tag.IsConstructed) {
            if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.Boolean) {
                if (content.Length != 1) {
                    throw new AsnContentException("A BOOLEAN has exactly one content byte.");
                }
                return Write(tag, [content[0] == 0 ? (byte)0x00 : (byte)0xFF]);
            }
            return Write(tag, content);
        }

        if (tag.TagClass == TagClass.Universal && IsString((UniversalTagNumber)tag.TagValue)) {
            //A constructed string is the concatenation of its OCTET STRING segments
            var bytes = new List<byte>();
            AppendSegments(content, bytes, depth + 1);
            return Write(new Asn1Tag(tag.TagClass, tag.TagValue, isConstructed: false), bytes.ToArray());
        }

        if (tag.TagClass == TagClass.Universal && (UniversalTagNumber)tag.TagValue == UniversalTagNumber.BitString) {
            throw new AsnContentException("A constructed BIT STRING is not supported.");
        }

        var children = new List<byte[]>();
        for (var offset = 0; offset < content.Length;) {
            children.Add(Normalize(content[offset..], depth + 1, out var childLength));
            offset += childLength;
        }
        if (tag.TagClass == TagClass.Universal && (UniversalTagNumber)tag.TagValue == UniversalTagNumber.SetOf) {
            children.Sort((x, y) => x.AsSpan().SequenceCompareTo(y));
        }
        return Write(tag, children.SelectMany(x => x).ToArray());
    }


    private static void AppendSegments(ReadOnlySpan<byte> content, List<byte> bytes, int depth)
    {
        if (depth > MaxDepth) {
            throw new AsnContentException("The value is nested too deeply.");
        }

        for (var offset = 0; offset < content.Length;) {
            var segment = content[offset..];
            var tag = Asn1Tag.Decode(segment, out _);
            if (tag.TagClass != TagClass.Universal || tag.TagValue != (int)UniversalTagNumber.OctetString) {
                throw new AsnContentException("A constructed string is made of OCTET STRING segments.");
            }
            AsnDecoder.ReadEncodedValue(segment, AsnEncodingRules.BER, out var contentOffset, out var contentLength, out var consumed);
            if (tag.IsConstructed) {
                AppendSegments(segment.Slice(contentOffset, contentLength), bytes, depth + 1);
            } else {
                bytes.AddRange(segment.Slice(contentOffset, contentLength).ToArray());
            }
            offset += consumed;
        }
    }


    private static byte[] Write(Asn1Tag tag, ReadOnlySpan<byte> content)
    {
        var tagBytes = new byte[tag.CalculateEncodedSize()];
        tag.Encode(tagBytes);

        byte[] lengthBytes;
        if (content.Length < 0x80) {
            lengthBytes = [(byte)content.Length];
        } else {
            var length = content.Length;
            var significant = new List<byte>();
            for (; length > 0; length >>= 8) {
                significant.Insert(0, (byte)length);
            }
            lengthBytes = [(byte)(0x80 | significant.Count), .. significant];
        }

        return [.. tagBytes, .. lengthBytes, .. content];
    }


    private static bool IsString(UniversalTagNumber tag)
        => tag is UniversalTagNumber.OctetString
            or UniversalTagNumber.UTF8String
            or UniversalTagNumber.NumericString
            or UniversalTagNumber.PrintableString
            or UniversalTagNumber.T61String
            or UniversalTagNumber.VideotexString
            or UniversalTagNumber.IA5String
            or UniversalTagNumber.VisibleString
            or UniversalTagNumber.GraphicString
            or UniversalTagNumber.GeneralString
            or UniversalTagNumber.UniversalString
            or UniversalTagNumber.BMPString;


    private const int MaxDepth = 32;
}
