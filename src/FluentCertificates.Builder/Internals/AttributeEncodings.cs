using System.Collections.Frozen;
using System.Formats.Asn1;

namespace FluentCertificates.Internals;

/// <summary>
/// The ASN.1 string type an attribute is written as when the caller does not choose one.
/// </summary>
/// <remarks>
/// Both the <see cref="X500NameBuilder"/> methods and the RFC 4514 parser read this, so a name comes out as the
/// same bytes whichever way it was put together.
/// </remarks>
internal static class AttributeEncodings
{
    public static UniversalTagNumber GetValueEncoding(string? oid)
        => oid is not null && FixedEncodings.TryGetValue(oid, out var encoding) ? encoding : UniversalTagNumber.UTF8String;


    //RFC 5280 Appendix A.1 declares the first five outright, so no other string type is a value of them. The
    //rest follow RFC 4519 and RFC 4517, which give telephone number and destination indicator as a
    //PrintableString and X.121 address and ISDN number as a NumericString. Any other attribute is written as
    //UTF8String, which holds any text and is valid for a DirectoryString. The three letter and three digit
    //country codes (2.5.4.98 and 2.5.4.99) are not listed because their X.520 syntax has not been checked.
    private static readonly FrozenDictionary<string, UniversalTagNumber> FixedEncodings = new Dictionary<string, UniversalTagNumber> {
        [Oids.CountryOrRegionName] = UniversalTagNumber.PrintableString,
        [Oids.SerialNumber] = UniversalTagNumber.PrintableString,
        [Oids.DnQualifier] = UniversalTagNumber.PrintableString,
        [Oids.DomainComponent] = UniversalTagNumber.IA5String,
        [Oids.EmailAddress] = UniversalTagNumber.IA5String,
        [Oids.TelephoneNumber] = UniversalTagNumber.PrintableString,
        [Oids.DestinationIndicator] = UniversalTagNumber.PrintableString,
        [Oids.X121Address] = UniversalTagNumber.NumericString,
        [Oids.InternationalISDNNumber] = UniversalTagNumber.NumericString
    }.ToFrozenDictionary(StringComparer.Ordinal);
}
