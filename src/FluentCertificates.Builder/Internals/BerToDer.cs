using System.Formats.Asn1;

namespace FluentCertificates.Internals;

/// <summary>
/// Rewrites one BER encoded value as DER, for the BER that RFC 4514 allows in a <c>#</c> hex value and the BER
/// that names in the wild are sometimes encoded with.
/// </summary>
/// <remarks>
/// Covers what BER permits and DER does not at the level of structure: indefinite and non-minimal lengths,
/// constructed strings, the order of a SET's members, and a BOOLEAN's true value. A constructed BIT STRING is
/// refused rather than guessed at. The result is not checked here: <see cref="DerValidator"/> refuses what is
/// still not DER, such as a BIT STRING with non-zero padding or a malformed time.
/// A value that is already DER is returned as it is. Any other value is sized in one pass and then written in a
/// second, into a single buffer.
/// </remarks>
internal static class BerToDer
{
    public static byte[] Normalize(ReadOnlySpan<byte> ber)
    {
        try {
            DerValidator.Validate(ber);
            return ber.ToArray();
        } catch (AsnContentException) {
            //Not DER, so it is rewritten below
        }

        var sizes = new List<int>();
        var size = Measure(ber, 0, sizes, out var consumed);
        if (consumed != ber.Length) {
            throw new AsnContentException("The value has bytes after its encoding.");
        }

        var der = new byte[size];
        var index = 0;
        Write(ber, sizes, ref index, der);
        return der;
    }


    /// <summary>
    /// Works out the size of a value once it is DER, and records the size of each value's content, parents
    /// before their children, for <see cref="Write"/> to read back in the same order.
    /// </summary>
    private static int Measure(ReadOnlySpan<byte> source, int depth, List<int> sizes, out int consumed)
    {
        CheckDepth(depth);

        var tag = Asn1Tag.Decode(source, out _);
        AsnDecoder.ReadEncodedValue(source, AsnEncodingRules.BER, out var contentOffset, out var contentLength, out consumed);
        var content = source.Slice(contentOffset, contentLength);

        var slot = sizes.Count;
        sizes.Add(0);

        int contentSize;
        if (!tag.IsConstructed) {
            if (IsUniversal(tag, UniversalTagNumber.Boolean) && content.Length != 1) {
                throw new AsnContentException("A BOOLEAN has exactly one content byte.");
            }
            contentSize = content.Length;
        } else if (IsConstructedString(tag)) {
            //A constructed string is the concatenation of its OCTET STRING segments
            contentSize = MeasureSegments(content, depth + 1);
        } else if (IsUniversal(tag, UniversalTagNumber.BitString)) {
            throw new AsnContentException("A constructed BIT STRING is not supported.");
        } else {
            contentSize = 0;
            for (var offset = 0; offset < content.Length;) {
                contentSize += Measure(content[offset..], depth + 1, sizes, out var childLength);
                offset += childLength;
            }
        }

        sizes[slot] = contentSize;
        return tag.CalculateEncodedSize() + GetLengthSize(contentSize) + contentSize;
    }


    private static int MeasureSegments(ReadOnlySpan<byte> content, int depth)
    {
        CheckDepth(depth);

        var size = 0;
        for (var offset = 0; offset < content.Length;) {
            var segment = content[offset..];
            var tag = GetSegmentTag(segment);
            AsnDecoder.ReadEncodedValue(segment, AsnEncodingRules.BER, out var contentOffset, out var contentLength, out var consumed);
            size += tag.IsConstructed
                ? MeasureSegments(segment.Slice(contentOffset, contentLength), depth + 1)
                : contentLength;
            offset += consumed;
        }
        return size;
    }


    /// <summary>
    /// Writes a value as DER into the start of <paramref name="destination"/>, which <see cref="Measure"/> has sized.
    /// </summary>
    /// <returns>The number of bytes written.</returns>
    private static int Write(ReadOnlySpan<byte> source, List<int> sizes, ref int index, Span<byte> destination)
    {
        var tag = Asn1Tag.Decode(source, out _);
        AsnDecoder.ReadEncodedValue(source, AsnEncodingRules.BER, out var contentOffset, out var contentLength, out _);
        var content = source.Slice(contentOffset, contentLength);
        var contentSize = sizes[index++];

        var isString = IsConstructedString(tag);
        var written = (isString ? new Asn1Tag(tag.TagClass, tag.TagValue, isConstructed: false) : tag).Encode(destination);
        written += WriteLength(contentSize, destination[written..]);
        var body = destination.Slice(written, contentSize);

        if (!tag.IsConstructed) {
            if (IsUniversal(tag, UniversalTagNumber.Boolean)) {
                body[0] = content[0] == 0 ? (byte)0x00 : (byte)0xFF;
            } else {
                content.CopyTo(body);
            }
        } else if (isString) {
            CopySegments(content, body);
        } else {
            WriteChildren(content, IsUniversal(tag, UniversalTagNumber.SetOf), sizes, ref index, body);
        }
        return written + contentSize;
    }


    private static void WriteChildren(ReadOnlySpan<byte> content, bool sort, List<int> sizes, ref int index, Span<byte> body)
    {
        var children = sort ? new List<(int Start, int Length)>() : null;
        var position = 0;
        for (var offset = 0; offset < content.Length;) {
            var child = content[offset..];
            AsnDecoder.ReadEncodedValue(child, AsnEncodingRules.BER, out _, out _, out var consumed);
            var length = Write(child, sizes, ref index, body[position..]);
            children?.Add((position, length));
            position += length;
            offset += consumed;
        }

        //DER orders the members of a SET OF by their encodings, so they are put back in that order from a copy
        if (children is { Count: > 1 }) {
            var written = body.ToArray();
            children.Sort((x, y) => written.AsSpan(x.Start, x.Length).SequenceCompareTo(written.AsSpan(y.Start, y.Length)));
            position = 0;
            foreach (var (start, length) in children) {
                written.AsSpan(start, length).CopyTo(body[position..]);
                position += length;
            }
        }
    }


    private static int CopySegments(ReadOnlySpan<byte> content, Span<byte> destination)
    {
        var copied = 0;
        for (var offset = 0; offset < content.Length;) {
            var segment = content[offset..];
            var tag = GetSegmentTag(segment);
            AsnDecoder.ReadEncodedValue(segment, AsnEncodingRules.BER, out var contentOffset, out var contentLength, out var consumed);
            var segmentContent = segment.Slice(contentOffset, contentLength);
            if (tag.IsConstructed) {
                copied += CopySegments(segmentContent, destination[copied..]);
            } else {
                segmentContent.CopyTo(destination[copied..]);
                copied += contentLength;
            }
            offset += consumed;
        }
        return copied;
    }


    private static Asn1Tag GetSegmentTag(ReadOnlySpan<byte> segment)
    {
        var tag = Asn1Tag.Decode(segment, out _);
        return IsUniversal(tag, UniversalTagNumber.OctetString)
            ? tag
            : throw new AsnContentException("A constructed string is made of OCTET STRING segments.");
    }


    private static int WriteLength(int length, Span<byte> destination)
    {
        if (length < 0x80) {
            destination[0] = (byte)length;
            return 1;
        }

        var count = GetLengthSize(length) - 1;
        destination[0] = (byte)(0x80 | count);
        for (var i = count; i > 0; i--) {
            destination[i] = (byte)length;
            length >>= 8;
        }
        return count + 1;
    }


    private static int GetLengthSize(int length)
    {
        if (length < 0x80) {
            return 1;
        }

        var size = 1;
        for (; length > 0; length >>= 8) {
            size++;
        }
        return size;
    }


    private static void CheckDepth(int depth)
    {
        if (depth > MaxDepth) {
            throw new AsnContentException("The value is nested too deeply.");
        }
    }


    private static bool IsUniversal(Asn1Tag tag, UniversalTagNumber number)
        => tag.TagClass == TagClass.Universal && tag.TagValue == (int)number;


    private static bool IsConstructedString(Asn1Tag tag)
        => tag.IsConstructed && tag.TagClass == TagClass.Universal && IsString((UniversalTagNumber)tag.TagValue);


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
