using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FluentCertificates;

/// <summary>
/// Compares two X.500 distinguished names under a chosen rule, hashing them consistently with it, so a name
/// can key a dictionary or narrow a search.
/// </summary>
/// <remarks>
/// <para>
/// The members differ along two axes: how an attribute's value is compared, and whether the order of the
/// relative distinguished names matters. Order <em>within</em> one relative distinguished name never
/// matters, because that is an ASN.1 SET and RFC 5280 s7.1 matches it as one.
/// </para>
/// <para>
/// Order between relative distinguished names is significant in X.500: s7.1 matches two names only when the
/// matching parts appear in the same sequence, and the subtree rule that directoryName name constraints are
/// built on drops trailing parts. The <c>AnyOrder</c> members deliberately depart from that, and suit a
/// lookup rather than a decision about trust.
/// </para>
/// <para>
/// A name whose bytes do not decode is compared by those bytes under every member, so it still equals
/// itself.
/// </para>
/// </remarks>
public abstract class X500NameComparer : IEqualityComparer<X500DistinguishedName>
{
    /// <summary>Initializes a new instance of a derived comparer.</summary>
    protected X500NameComparer()
    { }


    /// <summary>
    /// Compares the encoded bytes, so any difference in encoding is a difference in name.
    /// </summary>
    /// <remarks>
    /// The strictest member, and the only one that never decodes. It reports two spellings of one name as
    /// different names, which RFC 5280 s4.1.2.4 makes reachable by permitting a conforming authority either
    /// PrintableString or UTF8String.
    /// </remarks>
    public static X500NameComparer Exact { get; } = new EncodedX500NameComparer();


    /// <summary>
    /// Compares decoded attribute values character by character, with the order of the relative
    /// distinguished names significant.
    /// </summary>
    /// <remarks>
    /// Independent of how the characters were encoded, and independent of the runtime's globalization mode,
    /// which makes it the predictable choice for a dictionary key. Case, whitespace and Unicode spelling all
    /// still count; see <see cref="Folded"/> to disregard those.
    /// </remarks>
    public static X500NameComparer Values { get; } = new DecodedX500NameComparer(fold: false, anyOrder: false);


    /// <summary>
    /// Compares decoded attribute values character by character, disregarding the order of the relative
    /// distinguished names.
    /// </summary>
    /// <remarks>See <see cref="Values"/>, which this loosens. Ignoring that order departs from RFC 5280
    /// s7.1, so prefer <see cref="Values"/> wherever the answer decides whether something is trusted.</remarks>
    public static X500NameComparer ValuesAnyOrder { get; } = new DecodedX500NameComparer(fold: false, anyOrder: true);


    /// <summary>
    /// Compares decoded attribute values with case, whitespace runs and Unicode spelling folded away, with
    /// the order of the relative distinguished names significant.
    /// </summary>
    /// <remarks>
    /// Approximates how RFC 5280 s7.1 asks a relying party to compare names, and deliberately errs towards
    /// matching. It is not the s7.1 algorithm: that mandates the RFC 4518 StringPrep profile, where this
    /// composes ICU's collator with the fold Java's <c>X500Principal</c> performs. Its answers depend on the
    /// runtime's globalization support, so check <see cref="CanFold"/> before relying on it.
    /// </remarks>
    public static X500NameComparer Folded { get; } = new DecodedX500NameComparer(fold: true, anyOrder: false);


    /// <summary>
    /// Compares decoded attribute values with case, whitespace runs and Unicode spelling folded away,
    /// disregarding the order of the relative distinguished names.
    /// </summary>
    /// <remarks>The loosest member, being <see cref="Folded"/> with the order requirement dropped as
    /// <see cref="ValuesAnyOrder"/> drops it. Suits a lookup, not a decision about trust.</remarks>
    public static X500NameComparer FoldedAnyOrder { get; } = new DecodedX500NameComparer(fold: true, anyOrder: true);


    /// <summary>
    /// Whether this runtime can perform the folding <see cref="Folded"/> and <see cref="FoldedAnyOrder"/>
    /// rely on.
    /// </summary>
    /// <remarks>
    /// Probed rather than asked for, because both halves fail open in globalization-invariant mode: the
    /// comparison still answers there, it simply stops folding and matches fewer names. Nothing throws, so
    /// this is the only way to tell.
    /// </remarks>
    public static bool CanFold { get; } =
        CultureInfo.InvariantCulture.CompareInfo.Compare("ß", "ss", CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace) == 0
        && !String.Equals("ﬁ".Normalize(NormalizationForm.FormKD), "ﬁ", StringComparison.Ordinal);


    /// <summary>Whether two names are the same name under this comparer's rule.</summary>
    /// <param name="x">The first name, which may be null.</param>
    /// <param name="y">The second name, which may be null.</param>
    /// <returns><see langword="true"/> if both are null, or both are non-null and match.</returns>
    public bool Equals(X500DistinguishedName? x, X500DistinguishedName? y)
        => ReferenceEquals(x, y) || (x is not null && y is not null && EqualsName(x, y));


    /// <summary>Returns a hash code agreeing with this comparer's <see cref="Equals(X500DistinguishedName,X500DistinguishedName)"/>.</summary>
    /// <param name="obj">The name to hash.</param>
    /// <returns>A hash code equal for any two names this comparer reports as the same.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="obj"/> is null.</exception>
    public int GetHashCode(X500DistinguishedName obj)
    {
        ArgumentNullException.ThrowIfNull(obj);
        return GetHashCodeOfName(obj);
    }


    /// <summary>Whether two non-null names are the same name under this comparer's rule.</summary>
    /// <param name="x">The first name, never null.</param>
    /// <param name="y">The second name, never null and not the same instance as <paramref name="x"/>.</param>
    /// <returns><see langword="true"/> if they match.</returns>
    protected abstract bool EqualsName(X500DistinguishedName x, X500DistinguishedName y);


    /// <summary>Returns a hash code for a non-null name, agreeing with <see cref="EqualsName"/>.</summary>
    /// <param name="name">The name to hash, never null.</param>
    /// <returns>A hash code equal for any two names <see cref="EqualsName"/> reports as the same.</returns>
    protected abstract int GetHashCodeOfName(X500DistinguishedName name);


    private sealed class EncodedX500NameComparer : X500NameComparer
    {
        protected override bool EqualsName(X500DistinguishedName x, X500DistinguishedName y)
            => x.RawData.AsSpan().SequenceEqual(y.RawData);


        protected override int GetHashCodeOfName(X500DistinguishedName name)
            => GetHashCodeOfBytes(name.RawData);
    }


    private sealed class DecodedX500NameComparer(bool fold, bool anyOrder) : X500NameComparer
    {
        protected override bool EqualsName(X500DistinguishedName x, X500DistinguishedName y)
        {
            var left = ReadName(x);
            var right = ReadName(y);

            //Bytes rather than nothing when a name will not decode: a name has to equal itself, which a
            //comparison that always fails cannot deliver
            if (left is null || right is null) {
                return x.RawData.AsSpan().SequenceEqual(y.RawData);
            }

            if (left.Count != right.Count) {
                return false;
            }

            if (anyOrder) {
                return MatchesAsMultiset(left, right, MatchesRelativeName);
            }

            for (var i = 0; i < left.Count; i++) {
                if (!MatchesRelativeName(left[i], right[i])) {
                    return false;
                }
            }
            return true;
        }


        protected override int GetHashCodeOfName(X500DistinguishedName name)
        {
            var parsed = ReadName(name);
            if (parsed is null) {
                return GetHashCodeOfBytes(name.RawData);
            }

            //Summed rather than combined in sequence wherever order does not count, so that two names this
            //comparer reports as the same cannot hash differently for having listed their parts in another
            //order
            var relative = parsed.Select(rdn => Sum(rdn.Select(GetHashCodeOfAttribute)));
            if (anyOrder) {
                return Sum(relative);
            }

            var hash = new HashCode();
            foreach (var value in relative) {
                hash.Add(value);
            }
            return hash.ToHashCode();
        }


        private bool MatchesRelativeName(List<X500Attribute> x, List<X500Attribute> y)
            //Always a multiset: a relative distinguished name is an ASN.1 SET, which carries no order
            => x.Count == y.Count && MatchesAsMultiset(x, y, MatchesAttribute);


        private bool MatchesAttribute(X500Attribute x, X500Attribute y)
        {
            if (!String.Equals(x.Oid, y.Oid, StringComparison.Ordinal)) {
                return false;
            }

            //Text and bytes are separate fields rather than two spellings of one, so a value that did not
            //decode cannot be impersonated by text that reads like its encoding
            if (x.Text is null || y.Text is null) {
                return x.Text is null && y.Text is null && x.Raw.AsSpan().SequenceEqual(y.Raw);
            }

            return fold
                ? CultureInfo.InvariantCulture.CompareInfo.Compare(x.Text, y.Text, FoldedComparison) == 0
                : String.Equals(x.Text, y.Text, StringComparison.Ordinal);
        }


        private int GetHashCodeOfAttribute(X500Attribute attribute)
        {
            var value = attribute.Text is null
                ? GetHashCodeOfBytes(attribute.Raw)
                : fold
                    ? CultureInfo.InvariantCulture.CompareInfo.GetHashCode(attribute.Text, FoldedComparison)
                    : attribute.Text.GetHashCode(StringComparison.Ordinal);

            return HashCode.Combine(attribute.Oid.GetHashCode(StringComparison.Ordinal), value);
        }


        private List<List<X500Attribute>>? ReadName(X500DistinguishedName name)
        {
            try {
                var relativeNames = new List<List<X500Attribute>>();
                var outer = new AsnReader(name.RawData, AsnEncodingRules.DER);
                var rdns = outer.ReadSequence();

                //Nothing may trail the name, or the attribute it ends with. Bytes the comparison never
                //reads are bytes anyone is free to choose, and this comparer would then call two names the
                //same where Exact calls them different.
                outer.ThrowIfNotEmpty();

                while (rdns.HasData) {
                    var attributes = rdns.ReadSetOf();
                    var read = new List<X500Attribute>();
                    while (attributes.HasData) {
                        var attribute = attributes.ReadSequence();
                        var oid = attribute.ReadObjectIdentifier();
                        read.Add(ReadAttribute(oid, attribute, fold));
                        attribute.ThrowIfNotEmpty();
                    }
                    relativeNames.Add(read);
                }
                return relativeNames;
            } catch (Exception ex) when (ex is AsnContentException or ArgumentException) {
                return null;
            }
        }
    }


    /// <summary>One attribute of a name, carrying either its decoded text or the bytes it would not decode from.</summary>
    private readonly record struct X500Attribute(string Oid, string? Text, byte[] Raw);


    private static X500Attribute ReadAttribute(string oid, AsnReader attribute, bool fold)
    {
        var tag = attribute.PeekTag();
        var encoded = attribute.ReadEncodedValue();
        var text = ReadText(tag, encoded);

        return text is null
            ? new X500Attribute(oid, null, encoded.ToArray())
            : new X500Attribute(oid, fold ? Fold(text) : text, []);
    }


    /// <summary>The characters <paramref name="encoded"/> spells, or <see langword="null"/> when it carries
    /// none this comparer reads.</summary>
    /// <remarks>A value that will not decode returns null so the caller compares its bytes, rather than a
    /// guess at its characters: two values that decode to nothing are not thereby the same value.</remarks>
    private static string? ReadText(Asn1Tag tag, ReadOnlyMemory<byte> encoded)
    {
        //A constructed string is not DER, and its content octets are nested tags rather than characters
        if (tag.TagClass != TagClass.Universal || tag.IsConstructed) {
            return null;
        }

        try {
            return (UniversalTagNumber)tag.TagValue switch {
                //System.Formats.Asn1 reads UCS-4 under no typed method, so it is taken apart by hand. Without
                //this arm a UniversalString name could never match the UTF8String spelling of that same name.
                UniversalTagNumber.UniversalString => Ucs4.GetString(GetContentOctets(encoded.Span)),
                var known when Array.IndexOf(TextValueTags, known) >= 0
                    => new AsnReader(encoded, AsnEncodingRules.DER).ReadCharacterString(known),
                _ => null
            };
        } catch (Exception ex) when (ex is AsnContentException or ArgumentException) {
            //Only this value is unreadable, so only this value falls back to its bytes; the rest of the
            //name still compares as text. DecoderFallbackException arrives here as an ArgumentException.
            return null;
        }
    }


    private static ReadOnlySpan<byte> GetContentOctets(ReadOnlySpan<byte> encoded)
    {
        AsnDecoder.ReadEncodedValue(encoded, AsnEncodingRules.DER, out int contentOffset, out int contentLength, out _);
        return encoded.Slice(contentOffset, contentLength);
    }


    /// <summary>Folds a value to the form <see cref="Folded"/> compares, leaving case to the comparison itself.</summary>
    private static string Fold(string text)
    {
        //Compatibility normalisation, then whitespace, then the case round trip Java's X500Principal
        //performs: upper-then-lower is not the same as lowercasing once, and is what carries a dotless i
        //onto an i
        var collapsed = String.Join(" ", Normalize(text).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return Normalize(collapsed.ToUpper(EnUs).ToLower(EnUs));
    }


    private static string Normalize(string text)
    {
        try {
            return text.Normalize(NormalizationForm.FormKD);
        } catch (ArgumentException) {
            return text;
        }
    }


    /// <summary>Whether every member of <paramref name="x"/> can be paired off against a member of
    /// <paramref name="y"/>, no member of <paramref name="y"/> serving twice.</summary>
    /// <remarks>First fit, which decides this correctly only where <paramref name="matches"/> is transitive:
    /// otherwise taking one partner can strand a later member that had no other, and the answer turns on the
    /// order the two lists arrived in. Ordinal equality is transitive; the folding comparison is believed to
    /// be and is not proven to be.</remarks>
    private static bool MatchesAsMultiset<T>(List<T> x, List<T> y, Func<T, T, bool> matches)
    {
        var taken = new bool[y.Count];
        foreach (var left in x) {
            var found = false;
            for (var i = 0; i < y.Count && !found; i++) {
                if (!taken[i] && matches(left, y[i])) {
                    taken[i] = true;
                    found = true;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }


    private static int Sum(IEnumerable<int> hashes)
    {
        var sum = 0;
        foreach (var hash in hashes) {
            unchecked {
                sum += hash;
            }
        }
        return sum;
    }


    private static int GetHashCodeOfBytes(ReadOnlySpan<byte> bytes)
    {
        var hash = new HashCode();
        hash.AddBytes(bytes);
        return hash.ToHashCode();
    }


    /// <summary>The collation <see cref="Folded"/> compares under, once both values carry Java's fold.</summary>
    private const CompareOptions FoldedComparison = CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace;


    private static readonly CultureInfo EnUs = GetEnUsOrInvariant();


    private static CultureInfo GetEnUsOrInvariant()
    {
        try {
            return CultureInfo.GetCultureInfo("en-US");
        } catch (CultureNotFoundException) {
            return CultureInfo.InvariantCulture;
        }
    }


    /// <summary>The string types an attribute value carries text in, as far as a typed reader will read one.</summary>
    /// <remarks>Wider than RFC 5280's DirectoryString, which is the choice most attributes are declared as:
    /// an emailAddress is an IA5String and an x121Address a NumericString, and both hold characters that
    /// have to compare as characters. UniversalString is absent because no typed reader accepts it; it is
    /// read by hand in <see cref="ReadText"/>.</remarks>
    private static readonly UniversalTagNumber[] TextValueTags = [
        UniversalTagNumber.UTF8String, UniversalTagNumber.NumericString, UniversalTagNumber.PrintableString,
        UniversalTagNumber.T61String, UniversalTagNumber.IA5String, UniversalTagNumber.VisibleString,
        UniversalTagNumber.BMPString
    ];

    //Strict, so bytes that are not UCS-4 fall back to a byte comparison instead of decoding to a run of
    //replacement characters that any other undecodable value would also decode to
    private static readonly UTF32Encoding Ucs4 = new(bigEndian: true, byteOrderMark: false, throwOnInvalidCharacters: true);
}
