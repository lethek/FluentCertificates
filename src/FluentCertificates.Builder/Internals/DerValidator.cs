using System.Formats.Asn1;

namespace FluentCertificates.Internals;

/// <summary>
/// Checks that a value is one complete DER encoding, by the rules of ITU-T X.690 sections 8, 10 and 11.
/// </summary>
/// <remarks>
/// Written out by hand, rather than left to <c>AsnReader</c>, so that every target framework applies the
/// same rules. It checks the structure and the content rules of the universal types that have them. It does
/// not check the character set of a string type, which belongs to the type and not to DER. A primitive
/// with a context-specific, application or private tag is opaque without the ASN.1 schema that says what
/// it was implicitly tagged from, so its content is not checked.
/// </remarks>
internal static class DerValidator
{
    public static void Validate(ReadOnlySpan<byte> value)
    {
        var consumed = ValidateElement(value, 0);
        if (consumed != value.Length) {
            throw CreateError("The value has bytes after its encoding.");
        }
    }


    private static int ValidateElement(ReadOnlySpan<byte> source, int depth)
    {
        if (depth > MaxDepth) {
            throw CreateError("The value is nested too deeply.");
        }

        var offset = ReadTag(source, out var tagClass, out var constructed, out var number);
        var length = ReadLength(source, ref offset);
        var content = source.Slice(offset, length);

        if (tagClass == UniversalClass) {
            ValidateUniversal(number, constructed, content, depth);
        } else if (constructed) {
            ValidateChildren(content, depth, null);
        }
        return offset + length;
    }


    private static void ValidateUniversal(int number, bool constructed, ReadOnlySpan<byte> content, int depth)
    {
        switch (number) {
            case Sequence:
                RequireConstructed(constructed);
                ValidateChildren(content, depth, null);
                return;
            case Set:
                RequireConstructed(constructed);
                var children = new List<(int Start, int Length, int Class, int Number)>();
                ValidateChildren(content, depth, children);
                ValidateSetOrder(content, children);
                return;
            case External or EmbeddedPdv or CharacterString:
                //Constructed by definition, with a structure that is not checked further here
                RequireConstructed(constructed);
                ValidateChildren(content, depth, null);
                return;
        }

        //Everything else is primitive in DER, including every string type
        if (constructed) {
            throw CreateError("A constructed form is not allowed for this type in DER.");
        }

        switch (number) {
            case Boolean:
                if (content.Length != 1 || content[0] is not (0x00 or 0xFF)) {
                    throw CreateError("A BOOLEAN is one byte, 00 or FF.");
                }
                break;
            case Integer or Enumerated:
                ValidateInteger(content);
                break;
            case BitString:
                ValidateBitString(content);
                break;
            case Null:
                if (content.Length != 0) {
                    throw CreateError("A NULL has no content.");
                }
                break;
            case ObjectIdentifier:
                ValidateObjectIdentifier(content);
                break;
            case UtcTime:
                ValidateTime(content, generalized: false);
                break;
            case GeneralizedTime:
                ValidateTime(content, generalized: true);
                break;
        }
    }


    private static void ValidateInteger(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0) {
            throw CreateError("An INTEGER has at least one content byte.");
        }
        if (content.Length > 1 && ((content[0] == 0x00 && content[1] < 0x80) || (content[0] == 0xFF && content[1] >= 0x80))) {
            throw CreateError("An INTEGER is encoded in as few bytes as possible.");
        }
    }


    private static void ValidateBitString(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0) {
            throw CreateError("A BIT STRING has a byte counting its unused bits.");
        }
        var unused = content[0];
        if (unused > 7 || (content.Length == 1 && unused != 0)) {
            throw CreateError("A BIT STRING has 0 to 7 unused bits, and none when it has no content.");
        }
        if (unused > 0 && (content[^1] & ((1 << unused) - 1)) != 0) {
            throw CreateError("The unused bits of a BIT STRING are zero.");
        }
    }


    private static void ValidateObjectIdentifier(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0) {
            throw CreateError("An OBJECT IDENTIFIER has at least one content byte.");
        }
        var startsSubidentifier = true;
        foreach (var b in content) {
            if (startsSubidentifier && b == 0x80) {
                throw CreateError("An OBJECT IDENTIFIER arc is encoded in as few bytes as possible.");
            }
            startsSubidentifier = (b & 0x80) == 0;
        }
        if (!startsSubidentifier) {
            throw CreateError("An OBJECT IDENTIFIER ends in the middle of an arc.");
        }
    }


    private static void ValidateTime(ReadOnlySpan<byte> content, bool generalized)
    {
        //UTCTime is YYMMDDHHMMSSZ. GeneralizedTime is YYYYMMDDHHMMSS, then an optional fraction with no trailing
        //zero, then Z. Both are UTC, with the seconds always present.
        var yearDigits = generalized ? 4 : 2;
        var fixedLength = yearDigits + 10;
        if (content.Length < fixedLength + 1 || content[^1] != (byte)'Z') {
            throw CreateError("The time is not in the DER form, which is in UTC and ends in Z.");
        }
        for (var i = 0; i < fixedLength; i++) {
            if (!Char.IsAsciiDigit((char)content[i])) {
                throw CreateError("The time has a character that is not a digit.");
            }
        }

        if (content.Length > fixedLength + 1) {
            if (!generalized || content[fixedLength] != (byte)'.' || content.Length < fixedLength + 3) {
                throw CreateError("The time has an unexpected fraction.");
            }
            for (var i = fixedLength + 1; i < content.Length - 1; i++) {
                if (!Char.IsAsciiDigit((char)content[i])) {
                    throw CreateError("The time has a character that is not a digit.");
                }
            }
            if (content[^2] == (byte)'0') {
                throw CreateError("The fraction of a time has no trailing zero.");
            }
        }

        var year = ReadDigits(content, 0, yearDigits);
        if (!generalized) {
            year += year >= 50 ? 1900 : 2000;
        }
        var month = ReadDigits(content, yearDigits, 2);
        var day = ReadDigits(content, yearDigits + 2, 2);
        var hour = ReadDigits(content, yearDigits + 4, 2);
        var minute = ReadDigits(content, yearDigits + 6, 2);
        var second = ReadDigits(content, yearDigits + 8, 2);
        if (month is < 1 or > 12
            || day < 1 || day > DateTime.DaysInMonth(year == 0 ? 2000 : year, month)
            || hour > 23 || minute > 59 || second > 59) {
            throw CreateError("The time is not a valid date and time.");
        }
    }


    private static int ReadDigits(ReadOnlySpan<byte> content, int start, int count)
    {
        var result = 0;
        for (var i = start; i < start + count; i++) {
            result = result * 10 + (content[i] - '0');
        }
        return result;
    }


    private static void ValidateSetOrder(ReadOnlySpan<byte> content, List<(int Start, int Length, int Class, int Number)> children)
    {
        //A SET OF is sorted by encoding. A SET of distinct types is sorted by tag, which is the same thing
        //for the usual tags but not for every one, so either order is accepted.
        var byEncoding = true;
        var byTag = true;
        for (var i = 1; i < children.Count; i++) {
            var previous = children[i - 1];
            var current = children[i];
            if (content.Slice(previous.Start, previous.Length).SequenceCompareTo(content.Slice(current.Start, current.Length)) > 0) {
                byEncoding = false;
            }
            if (previous.Class > current.Class || (previous.Class == current.Class && previous.Number >= current.Number)) {
                byTag = false;
            }
        }
        if (!byEncoding && !byTag) {
            throw CreateError("The members of a SET are not in the order DER requires.");
        }
    }


    private static void ValidateChildren(ReadOnlySpan<byte> content, int depth, List<(int Start, int Length, int Class, int Number)>? children)
    {
        for (var offset = 0; offset < content.Length;) {
            var child = content[offset..];
            ReadTag(child, out var tagClass, out _, out var number);
            var consumed = ValidateElement(child, depth + 1);
            children?.Add((offset, consumed, tagClass, number));
            offset += consumed;
        }
    }


    private static int ReadTag(ReadOnlySpan<byte> source, out int tagClass, out bool constructed, out int number)
    {
        if (source.IsEmpty) {
            throw CreateError("The value is empty or cut short.");
        }

        var first = source[0];
        tagClass = first >> 6;
        constructed = (first & 0x20) != 0;
        number = first & 0x1F;
        var offset = 1;
        if (number != 0x1F) {
            return offset;
        }

        //High tag number form: the number follows in base 128 and could not have been written in the low form
        number = 0;
        for (var count = 1; ; count++) {
            if (offset >= source.Length) {
                throw CreateError("The tag is cut short.");
            }
            var b = source[offset++];
            if (count == 1 && b == 0x80) {
                throw CreateError("The tag number is not encoded in as few bytes as possible.");
            }
            if (count > 4) {
                throw CreateError("The tag number is too large.");
            }
            number = (number << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                break;
            }
        }
        if (number < 0x1F) {
            throw CreateError("The tag number is not encoded in as few bytes as possible.");
        }
        return offset;
    }


    private static int ReadLength(ReadOnlySpan<byte> source, ref int offset)
    {
        if (offset >= source.Length) {
            throw CreateError("The length is missing.");
        }

        var first = source[offset++];
        long length = first;
        if (first >= 0x80) {
            var count = first & 0x7F;
            if (first == 0x80) {
                throw CreateError("DER does not allow the indefinite length form.");
            }
            if (count > 4 || offset + count > source.Length) {
                throw CreateError("The length is too large or cut short.");
            }
            if (source[offset] == 0x00) {
                throw CreateError("The length is not encoded in as few bytes as possible.");
            }
            length = 0;
            for (var i = 0; i < count; i++) {
                length = (length << 8) | source[offset++];
            }
            if (length < 0x80) {
                throw CreateError("The length is not encoded in as few bytes as possible.");
            }
        }

        if (length > source.Length - offset) {
            throw CreateError("The content is shorter than its length says.");
        }
        return (int)length;
    }


    private static void RequireConstructed(bool constructed)
    {
        if (!constructed) {
            throw CreateError("This type is constructed.");
        }
    }


    private static AsnContentException CreateError(string message)
        => new($"The value is not DER: {message}");


    private const int MaxDepth = 32;
    private const int UniversalClass = 0;

    private const int Boolean = 1;
    private const int Integer = 2;
    private const int BitString = 3;
    private const int Null = 5;
    private const int ObjectIdentifier = 6;
    private const int External = 8;
    private const int Enumerated = 10;
    private const int EmbeddedPdv = 11;
    private const int Sequence = 16;
    private const int Set = 17;
    private const int UtcTime = 23;
    private const int GeneralizedTime = 24;
    private const int CharacterString = 29;
}
