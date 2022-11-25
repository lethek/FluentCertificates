using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using SideData.LowLevel;


namespace FluentCertificates;

public static class X500RelativeDistinguishedNameExtensions
{
    public static UniversalTagNumber GetSingleElementValueEncoding(this X500RelativeDistinguishedName self)
        => self.TypedSideData().GetOrAdd(ParseValueEncoding);


    private static UniversalTagNumber ParseValueEncoding(X500RelativeDistinguishedName self)
    {
        var rawDataSpan = self.RawData.Span;

        var outer = new AsnValueReader(rawDataSpan, AsnEncodingRules.DER);

        //Windows does not enforce the sort order on multi-value RDNs.
        var rdn = outer.ReadSetOf(skipSortOrderValidation: true);
        var typeAndValue = rdn.ReadSequence();

        var firstType = Oids.GetSharedOrNewOid(ref typeAndValue);
        var firstValue = typeAndValue.ReadEncodedValue();
        typeAndValue.ThrowIfNotEmpty();

        var overlaps = rawDataSpan.Overlaps(firstValue, out int offset);
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
