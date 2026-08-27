using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using SideData;


namespace FluentCertificates;

/// <summary>
/// Provides extension methods for <see cref="X500RelativeDistinguishedName"/>.
/// </summary>
public static class X500RelativeDistinguishedNameExtensions
{
    /// <summary>
    /// Gets the ASN.1 string encoding used by this RDN's value, for example
    /// <see cref="UniversalTagNumber.UTF8String"/> or <see cref="UniversalTagNumber.PrintableString"/>.
    /// The encoding is read from the RDN's DER and cached against the instance.
    /// </summary>
    /// <param name="self">The relative distinguished name to inspect.</param>
    /// <returns>The <see cref="UniversalTagNumber"/> of the value's encoding.</returns>
    /// <exception cref="CryptographicException">Thrown if the RDN's encoded data cannot be parsed.</exception>
    public static UniversalTagNumber GetSingleElementValueEncoding(this X500RelativeDistinguishedName self)
        => self.SideDataBag().GetOrAdd("SingleElementValueEncoding", () => ParseValueEncoding(self));


    private static UniversalTagNumber ParseValueEncoding(X500RelativeDistinguishedName self)
    {
        var rawDataSpan = self.RawData.Span;

        var outer = new AsnValueReader(rawDataSpan, AsnEncodingRules.DER);

        //Windows does not enforce the sort order on multi-value RDNs.
        var rdn = outer.ReadSetOf(skipSortOrderValidation: true);
        var typeAndValue = rdn.ReadSequence();

        //Only the value's encoding is wanted, so the attribute type is read past rather than decoded
        typeAndValue.ReadEncodedValue();
        var firstValue = typeAndValue.ReadEncodedValue();
        typeAndValue.ThrowIfNotEmpty();

        //firstValue is a slice of rawDataSpan, so it always overlaps and the offset is always found
        rawDataSpan.Overlaps(firstValue, out int offset);
        var singleElementValue = rawDataSpan.Slice(offset, firstValue.Length);

        try {
            var reader = new AsnValueReader(singleElementValue, AsnEncodingRules.DER);
            var tag = reader.PeekTag();
            return (UniversalTagNumber)tag.TagValue;

        } catch (AsnContentException e) {
            throw new CryptographicException("ASN1 corrupted data.", e);
        }
    }
}
