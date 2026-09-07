using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FluentCertificates.Internals;

/// <summary>
/// Decides whether two X.500 distinguished names are the same name to a relying party.
/// </summary>
/// <remarks>
/// RFC 5280 s7.1 has relying parties compare names in a canonical form, and OpenSSL's X509_NAME_cmp and
/// Java's X500Principal both do: they fold case, collapse whitespace and disregard which ASN.1 string
/// type carried the characters. Whoever writes a name chooses all three, so comparing encoded bytes would
/// wave through every re-encoding of one name. Names are therefore read apart into a canonical string
/// first. The display form is no good for that, because it escapes a leading or trailing space with a
/// backslash that survives whitespace folding.
/// Two names alike enough to match here are treated as the same even where a validator might tell them
/// apart, which is the safe direction for the caller relying on this.
/// </remarks>
internal static class X500NameComparer
{
    /// <summary>
    /// Whether this build can fold the characters the comparison relies on. Both halves fail open in
    /// globalization-invariant mode, where Compare degrades rather than throwing and Normalize returns its
    /// input, so the capability is tested for the equivalence it exists to catch rather than asked for.
    /// </summary>
    public static bool CanFold { get; } =
        CultureInfo.InvariantCulture.CompareInfo.Compare("ß", "ss", CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace) == 0
        && !String.Equals("ﬁ".Normalize(NormalizationForm.FormKD), "ﬁ", StringComparison.Ordinal);


    /// <summary>
    /// A name read into the form <see cref="IsSameName"/> compares, and whether folding turned one of its
    /// attribute values into something a relying party would read as more than one attribute.
    /// </summary>
    public readonly record struct CanonicalName(string Value, bool FoldsIntoSeparator);


    /// <summary>
    /// Reads a name into its canonical form, or returns <see langword="null"/> when it is not valid DER.
    /// </summary>
    public static CanonicalName? Read(X500DistinguishedName name)
    {
        try {
            var canonical = new StringBuilder();
            var foldsIntoSeparator = false;
            var rdns = new AsnReader(name.RawData, AsnEncodingRules.DER).ReadSequence();
            while (rdns.HasData) {
                var attributes = rdns.ReadSetOf();
                while (attributes.HasData) {
                    var attribute = attributes.ReadSequence();
                    //Escaped so that no attribute's own text can pass itself off as this structure
                    Append(canonical, attribute.ReadObjectIdentifier());
                    canonical.Append('=');
                    var value = AttributeValue(attribute);
                    var folded = Fold(value);
                    foldsIntoSeparator |= CountSeparators(folded) > CountSeparators(value);
                    Append(canonical, folded);
                    canonical.Append(',');
                }
                canonical.Append(';');
            }
            return new CanonicalName(canonical.ToString(), foldsIntoSeparator);
        } catch (Exception ex) when (ex is AsnContentException or ArgumentException) {
            //Null rather than the encoded bytes: a name reduced to its bytes matches nothing, which would
            //exempt it from the comparison instead of failing it
            return null;
        }
    }


    /// <summary>
    /// Counts the characters a canonical name is punctuated with. Folding turning a value's character into
    /// one of these makes the name parse as a different shape than its DER says.
    /// </summary>
    /// <remarks>
    /// The escaping in <see cref="Read"/> keeps a value's own text out of the structure, but a relying party
    /// need not be so careful. Java's X500Principal escapes an attribute value and only then normalises it,
    /// so a character that folds into a separator arrives unescaped: a single common name of
    /// <c>Issuing CA[U+FF0C]OU=PKI</c> canonicalises there to the same string as the two-attribute name
    /// <c>CN=Issuing CA,OU=PKI</c>, and X500Principal.equals reports the two as one name. No legitimate name
    /// needs a character that only becomes punctuation once folded, so the ambiguity is refused rather than
    /// settled one validator's way.
    /// </remarks>
    private static int CountSeparators(string text)
    {
        var count = 0;
        foreach (var c in text) {
            if (Separators.Contains(c)) {
                count++;
            }
        }
        return count;
    }


    private const string Separators = ",+=;<>\"\\";


    /// <summary>
    /// Whether two canonical names are the same name to a relying party.
    /// </summary>
    /// <remarks>
    /// Asked three ways because the validators disagree and neither covers the other. ICU's collator
    /// equates "gross" with "groß", which no case mapping does; Java equates a dotless i with an i and a
    /// combining ypogegrammeni with an iota, which the collator weighs apart. A name needing both at once
    /// satisfies neither alone, so the third question runs the collator over Java's fold, composing them
    /// rather than choosing. That also settles the order the two normalise in: the canonical form
    /// normalises before case mapping and Java after, which reorders combining marks differently.
    /// </remarks>
    public static bool IsSameName(string subject, string issuer)
        => CultureInfo.InvariantCulture.CompareInfo.Compare(subject, issuer, CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace) == 0
        || String.Equals(FoldAsJavaDoes(subject), FoldAsJavaDoes(issuer), StringComparison.Ordinal)
        || CultureInfo.InvariantCulture.CompareInfo.Compare(FoldAsJavaDoes(subject), FoldAsJavaDoes(issuer), CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace) == 0;


    private static string FoldAsJavaDoes(string name)
    {
        //Java's X500Principal uppercases and then lowercases, which differs from lowercasing once: the
        //round trip is what carries a dotless i onto an i. It does this under Locale.US, and so does this,
        //because invariant casing deliberately leaves a dotless i alone.
        var folded = name.ToUpper(EnUs).ToLower(EnUs);

        //Normalising again after the case round trip mirrors Java's order. The values were already
        //normalised into the canonical form and NFKD is idempotent here, so this is for agreement by
        //construction.
        try {
            return folded.Normalize(NormalizationForm.FormKD);
        } catch (ArgumentException) {
            return folded;
        }
    }


    private static void Append(StringBuilder canonical, string value)
    {
        foreach (var c in value) {
            if (c is '\\' or ',' or ';' or '=') {
                canonical.Append('\\');
            }
            canonical.Append(c);
        }
    }


    /// <summary>
    /// The attribute's text as encoded, before folding, so that <see cref="Read"/> can tell what folding
    /// changes about it.
    /// </summary>
    private static string AttributeValue(AsnReader attribute)
    {
        var tag = attribute.PeekTag();

        var text = tag.TagClass != TagClass.Universal
            ? null
            : (UniversalTagNumber)tag.TagValue switch {
                //System.Formats.Asn1 will not read UCS-4 under any typed method, so this one is taken
                //apart by hand. Without this arm it falls to the hex path below, where a UniversalString
                //issuer name could never match the UTF8String subject spelling that same name.
                UniversalTagNumber.UniversalString => Ucs4.GetString(ContentOctets(attribute.ReadEncodedValue().Span)),
                var known when Array.IndexOf(DirectoryStringTags, known) >= 0 => attribute.ReadCharacterString(known),
                _ => null
            };

        //Not text, so there is nothing to fold and the encoding is the value
        return text ?? Convert.ToHexString(attribute.ReadEncodedValue().Span);
    }


    private static ReadOnlySpan<byte> ContentOctets(ReadOnlySpan<byte> encoded)
    {
        AsnDecoder.ReadEncodedValue(encoded, AsnEncodingRules.DER, out int contentOffset, out int contentLength, out _);
        return encoded.Slice(contentOffset, contentLength);
    }


    private static string Fold(string text)
    {
        //Compatibility normalisation first, so a ligature, a fullwidth letter and the Kelvin sign each
        //reduce to the letters they stand for, as Java's canonical form does. Then whitespace, which every
        //validator collapses. Case is left to the comparison itself.
        string normalized;
        try {
            normalized = text.Normalize(NormalizationForm.FormKD);
        } catch (ArgumentException) {
            //Text that is not valid Unicode has no normal form; compare what is there
            normalized = text;
        }
        return String.Join(" ", normalized.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }


    /// <summary>The culture Java canonicalises names under, or the invariant one on a build restricted to
    /// predefined cultures, which has no such object to hand out.</summary>
    private static readonly CultureInfo EnUs = GetEnUsOrInvariant();


    private static CultureInfo GetEnUsOrInvariant()
    {
        try {
            return CultureInfo.GetCultureInfo("en-US");
        } catch (CultureNotFoundException) {
            return CultureInfo.InvariantCulture;
        }
    }


    /// <summary>The DirectoryString choices a typed reader will accept. UniversalString is deliberately
    /// absent; <see cref="AttributeValue"/> reads it by hand.</summary>
    private static readonly UniversalTagNumber[] DirectoryStringTags = [
        UniversalTagNumber.UTF8String, UniversalTagNumber.NumericString, UniversalTagNumber.PrintableString,
        UniversalTagNumber.T61String, UniversalTagNumber.IA5String, UniversalTagNumber.VisibleString,
        UniversalTagNumber.BMPString
    ];

    private static readonly UTF32Encoding Ucs4 = new(bigEndian: true, byteOrderMark: false);
}
