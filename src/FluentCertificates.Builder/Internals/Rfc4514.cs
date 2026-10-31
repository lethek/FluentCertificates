using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace FluentCertificates.Internals;

/// <summary>
/// Reads and writes the string form of a distinguished name defined by RFC 4514.
/// </summary>
/// <remarks>
/// Parsing is strict: no spaces around separators, no quoted values and no semicolon separator. Only the
/// attribute keywords RFC 4514 names are understood, and any other attribute type is a dotted OID.
/// The string lists the relative names most specific first, the reverse of how they are encoded, and so does
/// the list this class reads and writes.
/// </remarks>
internal static class Rfc4514
{
    public static ImmutableList<X500AttributeSet> Parse(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        var relativeNames = ImmutableList.CreateBuilder<X500AttributeSet>();
        var pos = 0;
        if (name.Length > 0) {
            while (true) {
                var attributes = ImmutableList.CreateBuilder<X500Attribute>();
                while (true) {
                    attributes.Add(ParseAttribute(name, ref pos));
                    if (pos < name.Length && name[pos] == '+') {
                        pos++;
                        continue;
                    }
                    break;
                }
                relativeNames.Add(new X500AttributeSet(attributes.ToImmutable()));

                if (pos == name.Length) {
                    break;
                }
                //ParseAttribute only stops at a separator or the end, so this is a comma
                pos++;
            }
        }
        return relativeNames.ToImmutable();
    }


    public static string Format(IEnumerable<X500AttributeSet> relativeNames)
        => String.Join(
            ',',
            relativeNames.Select(x => String.Join('+', x.Select(FormatAttribute)))
        );


    private static X500Attribute ParseAttribute(string name, ref int pos)
    {
        var oid = ParseAttributeType(name, ref pos);

        if (pos >= name.Length || name[pos] != '=') {
            throw CreateError(name, pos, "expected '=' after the attribute type");
        }
        pos++;

        if (pos < name.Length && name[pos] == '#') {
            pos++;
            return ParseHexValue(name, ref pos, oid);
        }

        var start = pos;
        var value = ParseStringValue(name, ref pos);
        try {
            return new X500Attribute(oid, AttributeEncodings.GetValueEncoding(oid.Value), value);
        } catch (ArgumentException ex) {
            throw CreateError(name, start, ex.Message, ex);
        }
    }


    private static Oid ParseAttributeType(string name, ref int pos)
    {
        var start = pos;
        while (pos < name.Length && (Char.IsAsciiLetterOrDigit(name[pos]) || name[pos] is '-' or '.')) {
            pos++;
        }
        if (pos == start) {
            throw CreateError(name, pos, "expected an attribute type");
        }

        var type = name.AsSpan(start, pos - start);
        if (Char.IsAsciiDigit(type[0])) {
            return ParseNumericOid(name, start, type);
        }

        if (type.Contains('.') || !Keywords.TryGetValue(type.ToString(), out var oid)) {
            throw CreateError(name, start, $"'{type}' is not a keyword RFC 4514 defines, so write the attribute type as an OID");
        }
        return new Oid(oid);
    }


    private static Oid ParseNumericOid(string name, int start, ReadOnlySpan<char> type)
    {
        //numericoid = number 1*( DOT number ), where a number has no leading zero
        var arcs = type.ToString().Split('.');
        if (arcs.Length < 2 || arcs.Any(x => x.Length == 0 || !x.All(Char.IsAsciiDigit) || (x.Length > 1 && x[0] == '0'))) {
            throw CreateError(name, start, $"'{type}' is not a numeric OID");
        }

        //The first arc is 0, 1 or 2, and under 0 and 1 the second is at most 39. Older versions of the writer
        //do not check this, so it is not left to them.
        if (arcs[0].Length > 1 || arcs[0][0] > '2' || (arcs[0][0] < '2' && (arcs[1].Length > 2 || (arcs[1].Length == 2 && arcs[1][0] > '3')))) {
            throw CreateError(name, start, $"'{type}' is not a valid OID");
        }

        //The writer is the authority on the rest, such as an arc too large to encode
        try {
            new AsnWriter(AsnEncodingRules.DER).WriteObjectIdentifier(type);
        } catch (ArgumentException) {
            throw CreateError(name, start, $"'{type}' is not a valid OID");
        }
        return new Oid(type.ToString());
    }


    private static X500Attribute ParseHexValue(string name, ref int pos, Oid oid)
    {
        var start = pos;
        while (pos < name.Length && name[pos] is not (',' or '+')) {
            pos++;
        }
        var hex = name.AsSpan(start, pos - start);
        if (hex.IsEmpty || hex.Length % 2 != 0 || hex.IndexOfAnyExcept("0123456789abcdefABCDEF") >= 0) {
            throw CreateError(name, start, "expected one or more pairs of hex digits after '#'");
        }

        //RFC 4514 defines the hex as a BER encoding, so it is rewritten as the DER a Name needs
        try {
            return X500Attribute.CreateFromDer(oid, BerToDer.Normalize(Convert.FromHexString(hex)));
        } catch (Exception ex) when (ex is ArgumentException or AsnContentException) {
            throw CreateError(name, start, "the hex digits are not one complete BER value", ex);
        }
    }


    private static string ParseStringValue(string name, ref int pos)
    {
        var start = pos;
        var endsInSpace = false;

        //A character takes at most 3 bytes of UTF-8, and an escape takes more characters than the byte it stands for
        var buffer = ArrayPool<byte>.Shared.Rent((name.Length - pos) * 3);
        var count = 0;
        try {
            while (pos < name.Length && name[pos] is not (',' or '+')) {
                var c = name[pos];
                endsInSpace = false;

                if (c == '\\') {
                    if (pos + 1 >= name.Length) {
                        throw CreateError(name, pos, "a backslash needs a character to escape");
                    }
                    var next = name[pos + 1];
                    if (next is '"' or '+' or ',' or ';' or '<' or '>' or '\\' or ' ' or '#' or '=') {
                        buffer[count++] = (byte)next;
                        pos += 2;
                    } else if (pos + 2 < name.Length && Char.IsAsciiHexDigit(next) && Char.IsAsciiHexDigit(name[pos + 2])) {
                        buffer[count++] = Byte.Parse(name.AsSpan(pos + 1, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
                        pos += 3;
                    } else {
                        throw CreateError(name, pos, "a backslash must be followed by a special character or two hex digits");
                    }
                    continue;
                }

                if (c is '"' or ';' or '<' or '>' or '\0') {
                    throw CreateError(name, pos, $"'{c}' must be escaped");
                }
                if (pos == start && c == ' ') {
                    throw CreateError(name, pos, "a leading space must be escaped");
                }

                var length = Char.IsHighSurrogate(c) && pos + 1 < name.Length && Char.IsLowSurrogate(name[pos + 1]) ? 2 : 1;
                try {
                    count += StrictUtf8.GetBytes(name.AsSpan(pos, length), buffer.AsSpan(count));
                } catch (EncoderFallbackException) {
                    throw CreateError(name, pos, "the text is not valid Unicode");
                }
                endsInSpace = c == ' ';
                pos += length;
            }

            if (endsInSpace) {
                throw CreateError(name, pos - 1, "a trailing space must be escaped");
            }

            try {
                return StrictUtf8.GetString(buffer, 0, count);
            } catch (DecoderFallbackException ex) {
                throw CreateError(name, start, "the escaped bytes are not valid UTF-8", ex);
            }
        } finally {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }


    private static string FormatAttribute(X500Attribute attribute)
    {
        var type = attribute.OID.Value!;
        var builder = new StringBuilder(KeywordsByOid.GetValueOrDefault(type) ?? type).Append('=');

        if (attribute.Value is null) {
            return builder.Append('#').Append(Convert.ToHexString(attribute.DerValue.Span)).ToString();
        }

        var value = attribute.Value;
        for (var i = 0; i < value.Length; i++) {
            var c = value[i];
            if (c == '\0') {
                builder.Append("\\00");
            } else if (c is '"' or '+' or ',' or ';' or '<' or '>' or '\\'
                      || (c is ' ' or '#' && i == 0)
                      || (c == ' ' && i == value.Length - 1)) {
                builder.Append('\\').Append(c);
            } else {
                builder.Append(c);
            }
        }
        return builder.ToString();
    }


    private static FormatException CreateError(string name, int pos, string reason, Exception? inner = null)
        => new($"'{name}' is not an RFC 4514 distinguished name: {reason} (at position {pos}).", inner);


    private static readonly UTF8Encoding StrictUtf8 = new(false, true);


    private static readonly FrozenDictionary<string, string> Keywords = new Dictionary<string, string> {
        ["CN"] = Oids.CommonName,
        ["L"] = Oids.LocalityName,
        ["ST"] = Oids.StateOrProvinceName,
        ["O"] = Oids.Organization,
        ["OU"] = Oids.OrganizationalUnit,
        ["C"] = Oids.CountryOrRegionName,
        ["STREET"] = Oids.StreetAddress,
        ["DC"] = Oids.DomainComponent,
        ["UID"] = Oids.UserId,
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);


    private static readonly FrozenDictionary<string, string> KeywordsByOid
        = Keywords.ToFrozenDictionary(x => x.Value, x => x.Key, StringComparer.Ordinal);
}
