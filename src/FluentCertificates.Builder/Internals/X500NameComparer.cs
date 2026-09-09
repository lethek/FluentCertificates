using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FluentCertificates.Internals;

/// <summary>Decides whether two X.500 distinguished names are the same name to a relying party.</summary>
/// <remarks>
/// RFC 5280 s7.1 compares names in a canonical form that folds case, collapses whitespace and disregards
/// the ASN.1 string type, so comparing encoded bytes would wave through every re-encoding of one name.
/// The display form cannot serve as that canonical form, because it escapes a leading or trailing space
/// with a backslash that survives whitespace folding.
/// </remarks>
internal static class X500NameComparer
{
    /// <summary>Whether this build can fold the characters the comparison relies on. Probed rather than
    /// asked for, because both halves fail open in globalization-invariant mode.</summary>
    public static bool CanFold { get; } =
        CultureInfo.InvariantCulture.CompareInfo.Compare("ß", "ss", CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace) == 0
        && !String.Equals("ﬁ".Normalize(NormalizationForm.FormKD), "ﬁ", StringComparison.Ordinal);


    /// <summary>A name read into the form <see cref="IsSameName"/> compares, and whether folding turned one
    /// of its attribute values into something readable as more than one attribute.</summary>
    public readonly record struct CanonicalName(string Value, bool FoldsIntoSeparator);


    /// <summary>Reads a name into its canonical form, or <see langword="null"/> when it is not valid DER.</summary>
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
            //Null rather than the encoded bytes: bytes would match nothing, exempting the name from the
            //comparison instead of failing it
            return null;
        }
    }


    /// <summary>Counts the characters a canonical name is punctuated with. Folding a value's character into
    /// one of these makes the name parse as a different shape than its DER says.</summary>
    /// <remarks>
    /// Java's X500Principal escapes an attribute value before normalising it, so a character that folds into
    /// a separator arrives unescaped and a single common name of <c>Issuing CA[U+FF0C]OU=PKI</c>
    /// canonicalises there to the two-attribute <c>CN=Issuing CA,OU=PKI</c>. The ambiguity is refused rather
    /// than settled one validator's way.
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


    /// <summary>
    /// The characters a folded value must not turn into, since each separates one part of a name from
    /// another.
    /// </summary>
    /// <remarks>'#' is here because Java renders an unprintable attribute value as '#' plus the hex of its
    /// encoding, so a character folding into a leading '#' lets a value spell out another name's
    /// encoding.</remarks>
    private const string Separators = ",+=;<>\"\\#";


    /// <summary>Whether two canonical names are the same name to a relying party.</summary>
    /// <remarks>
    /// Asked three ways because the validators disagree and neither covers the other: ICU's collator equates
    /// "gross" with "groß", Java equates a dotless i with an i, and a name needing both satisfies neither
    /// alone. The third comparison composes them by running the collator over Java's fold.
    /// </remarks>
    public static bool IsSameName(string subject, string issuer)
        => CultureInfo.InvariantCulture.CompareInfo.Compare(subject, issuer, CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace) == 0
        || String.Equals(FoldAsJavaDoes(subject), FoldAsJavaDoes(issuer), StringComparison.Ordinal)
        || CultureInfo.InvariantCulture.CompareInfo.Compare(FoldAsJavaDoes(subject), FoldAsJavaDoes(issuer), CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace) == 0;


    private static string FoldAsJavaDoes(string name)
    {
        //The upper-then-lower round trip is not the same as lowercasing once: it is what carries a dotless i
        //onto an i. Under en-US like Java, because invariant casing leaves a dotless i alone.
        var folded = name.ToUpper(EnUs).ToLower(EnUs);

        //Normalising after the case round trip mirrors Java's order
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


    /// <summary>The attribute's text as encoded, before folding.</summary>
    private static string AttributeValue(AsnReader attribute)
    {
        var tag = attribute.PeekTag();

        var text = tag.TagClass != TagClass.Universal
            ? null
            : (UniversalTagNumber)tag.TagValue switch {
                //System.Formats.Asn1 reads UCS-4 under no typed method, so it is taken apart by hand. Without
                //this arm a UniversalString name could never match the UTF8String spelling of that same name.
                UniversalTagNumber.UniversalString => Ucs4.GetString(ContentOctets(attribute.ReadEncodedValue().Span)),
                var known when Array.IndexOf(DirectoryStringTags, known) >= 0 => attribute.ReadCharacterString(known),
                _ => null
            };

        return text ?? Convert.ToHexString(attribute.ReadEncodedValue().Span);
    }


    private static ReadOnlySpan<byte> ContentOctets(ReadOnlySpan<byte> encoded)
    {
        AsnDecoder.ReadEncodedValue(encoded, AsnEncodingRules.DER, out int contentOffset, out int contentLength, out _);
        return encoded.Slice(contentOffset, contentLength);
    }


    private static string Fold(string text)
    {
        //Compatibility normalisation first, as Java's canonical form does, then whitespace. Case is left to
        //the comparison itself.
        string normalized;
        try {
            normalized = text.Normalize(NormalizationForm.FormKD);
        } catch (ArgumentException) {
            normalized = text;
        }
        return String.Join(" ", normalized.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }


    private static readonly CultureInfo EnUs = GetEnUsOrInvariant();


    private static CultureInfo GetEnUsOrInvariant()
    {
        try {
            return CultureInfo.GetCultureInfo("en-US");
        } catch (CultureNotFoundException) {
            return CultureInfo.InvariantCulture;
        }
    }


    /// <summary>The DirectoryString choices a typed reader will accept.</summary>
    private static readonly UniversalTagNumber[] DirectoryStringTags = [
        UniversalTagNumber.UTF8String, UniversalTagNumber.NumericString, UniversalTagNumber.PrintableString,
        UniversalTagNumber.T61String, UniversalTagNumber.IA5String, UniversalTagNumber.VisibleString,
        UniversalTagNumber.BMPString
    ];

    private static readonly UTF32Encoding Ucs4 = new(bigEndian: true, byteOrderMark: false);
}
