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
    public static ImmutableList<X500RelativeDistinguishedName> Parse(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        var relativeNames = ImmutableList.CreateBuilder<X500RelativeDistinguishedName>();
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
                relativeNames.Add(new X500RelativeDistinguishedName(attributes.ToImmutable()));

                if (pos == name.Length) {
                    break;
                }
                //ParseAttribute only stops at a separator or the end, so this is a comma
                pos++;
            }
        }
        return relativeNames.ToImmutable();
    }


    public static string Format(IEnumerable<X500RelativeDistinguishedName> relativeNames)
        => String.Join(
            ',',
            relativeNames.Select(x => String.Join('+', x.Attributes.Select(FormatAttribute)))
        );


    private static X500Attribute ParseAttribute(string name, ref int pos)
    {
        var oid = ParseAttributeType(name, ref pos);

        if (pos >= name.Length || name[pos] != '=') {
            throw Error(name, pos, "expected '=' after the attribute type");
        }
        pos++;

        if (pos < name.Length && name[pos] == '#') {
            pos++;
            return ParseHexValue(name, ref pos, oid);
        }

        var value = ParseStringValue(name, ref pos);
        var encoding = oid.Value == Oids.CountryOrRegionName ? UniversalTagNumber.PrintableString : UniversalTagNumber.UTF8String;
        return new X500Attribute(oid, encoding, value);
    }


    private static Oid ParseAttributeType(string name, ref int pos)
    {
        var start = pos;
        while (pos < name.Length && (Char.IsAsciiLetterOrDigit(name[pos]) || name[pos] is '-' or '.')) {
            pos++;
        }
        if (pos == start) {
            throw Error(name, pos, "expected an attribute type");
        }

        var type = name.AsSpan(start, pos - start);
        if (Char.IsAsciiDigit(type[0])) {
            return ParseNumericOid(name, start, type);
        }

        if (type.Contains('.') || !Keywords.TryGetValue(type.ToString(), out var oid)) {
            throw Error(name, start, $"'{type}' is not a keyword RFC 4514 defines, so write the attribute type as an OID");
        }
        return new Oid(oid);
    }


    private static Oid ParseNumericOid(string name, int start, ReadOnlySpan<char> type)
    {
        //numericoid = number 1*( DOT number ), where a number has no leading zero
        var arcs = type.ToString().Split('.');
        if (arcs.Length < 2 || arcs.Any(x => x.Length == 0 || !x.All(Char.IsAsciiDigit) || (x.Length > 1 && x[0] == '0'))) {
            throw Error(name, start, $"'{type}' is not a numeric OID");
        }

        //The writer is the authority on which arc combinations are valid
        try {
            new AsnWriter(AsnEncodingRules.DER).WriteObjectIdentifier(type);
        } catch (ArgumentException) {
            throw Error(name, start, $"'{type}' is not a valid OID");
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
            throw Error(name, start, "expected one or more pairs of hex digits after '#'");
        }

        try {
            return X500Attribute.CreateFromDer(oid, Convert.FromHexString(hex));
        } catch (ArgumentException ex) {
            throw Error(name, start, "the hex digits are not one complete DER value", ex);
        }
    }


    private static string ParseStringValue(string name, ref int pos)
    {
        var bytes = new List<byte>();
        var start = pos;
        var endsInSpace = false;

        while (pos < name.Length && name[pos] is not (',' or '+')) {
            var c = name[pos];
            endsInSpace = false;

            if (c == '\\') {
                if (pos + 1 >= name.Length) {
                    throw Error(name, pos, "a backslash needs a character to escape");
                }
                var next = name[pos + 1];
                if (next is '"' or '+' or ',' or ';' or '<' or '>' or '\\' or ' ' or '#' or '=') {
                    bytes.Add((byte)next);
                    pos += 2;
                } else if (pos + 2 < name.Length && Char.IsAsciiHexDigit(next) && Char.IsAsciiHexDigit(name[pos + 2])) {
                    bytes.Add(Byte.Parse(name.AsSpan(pos + 1, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture));
                    pos += 3;
                } else {
                    throw Error(name, pos, "a backslash must be followed by a special character or two hex digits");
                }
                continue;
            }

            if (c is '"' or ';' or '<' or '>' or '\0') {
                throw Error(name, pos, $"'{c}' must be escaped");
            }
            if (pos == start && c == ' ') {
                throw Error(name, pos, "a leading space must be escaped");
            }

            var length = Char.IsHighSurrogate(c) && pos + 1 < name.Length && Char.IsLowSurrogate(name[pos + 1]) ? 2 : 1;
            try {
                bytes.AddRange(StrictUtf8.GetBytes(name.AsSpan(pos, length).ToString()));
            } catch (EncoderFallbackException) {
                throw Error(name, pos, "the text is not valid Unicode");
            }
            endsInSpace = c == ' ';
            pos += length;
        }

        if (endsInSpace) {
            throw Error(name, pos - 1, "a trailing space must be escaped");
        }

        try {
            return StrictUtf8.GetString(bytes.ToArray());
        } catch (DecoderFallbackException ex) {
            throw Error(name, start, "the escaped bytes are not valid UTF-8", ex);
        }
    }


    private static string FormatAttribute(X500Attribute attribute)
    {
        var type = attribute.OID.Value!;
        var keyword = Keywords.FirstOrDefault(x => x.Value == type).Key;
        var builder = new StringBuilder(keyword ?? type).Append('=');

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


    private static FormatException Error(string name, int pos, string reason, Exception? inner = null)
        => new($"'{name}' is not an RFC 4514 distinguished name: {reason} (at position {pos}).", inner);


    private static readonly UTF8Encoding StrictUtf8 = new(false, true);


    private static readonly Dictionary<string, string> Keywords = new(StringComparer.OrdinalIgnoreCase) {
        ["CN"] = Oids.CommonName,
        ["L"] = Oids.LocalityName,
        ["ST"] = Oids.StateOrProvinceName,
        ["O"] = Oids.Organization,
        ["OU"] = Oids.OrganizationalUnit,
        ["C"] = Oids.CountryOrRegionName,
        ["STREET"] = Oids.StreetAddress,
        ["DC"] = Oids.DomainComponent,
        ["UID"] = Oids.UserId,
    };
}
