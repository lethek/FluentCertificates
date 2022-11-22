#if !NET7_0_OR_GREATER
using System.Diagnostics;
using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;


namespace FluentCertificates.System.Security.Cryptography.X509Certificates;

public static class X500DistinguishedNameExtensions
{
    public static IEnumerable<X500RelativeDistinguishedName> EnumerateRelativeDistinguishedNames(this X500DistinguishedName dn, bool reversed = true)
    {
        if (!ParsedAttributesTable.TryGetValue(dn, out var attributes)) {
            attributes = ParseAttributes(dn.RawData);
            ParsedAttributesTable.AddOrUpdate(dn, attributes);
        }
        return EnumerateRelativeDistinguishedNames(attributes, reversed);
    }


    private static IEnumerable<X500RelativeDistinguishedName> EnumerateRelativeDistinguishedNames(List<X500RelativeDistinguishedName> parsedAttributes, bool reversed)
    {
        if (reversed) {
            for (int i = parsedAttributes.Count - 1; i >= 0; i--) {
                yield return parsedAttributes[i];
            }
        } else {
            for (int i = 0; i < parsedAttributes.Count; i++) {
                yield return parsedAttributes[i];
            }
        }
    }


    private static List<X500RelativeDistinguishedName> ParseAttributes(byte[] rawData)
    {
        List<X500RelativeDistinguishedName>? parsedAttributes = null;
        ReadOnlyMemory<byte> rawDataMemory = rawData;
        ReadOnlySpan<byte> rawDataSpan = rawData;

        try {
            AsnValueReader outer = new AsnValueReader(rawDataSpan, AsnEncodingRules.DER);
            AsnValueReader sequence = outer.ReadSequence();
            outer.ThrowIfNotEmpty();

            while (sequence.HasData) {
                ReadOnlySpan<byte> encodedValue = sequence.PeekEncodedValue();

                if (!rawDataSpan.Overlaps(encodedValue, out int offset)) {
                    Debug.Fail("AsnValueReader produced a span outside of the original bounds");
                    throw new UnreachableException();
                }

                var rdn = new X500RelativeDistinguishedName(rawDataMemory.Slice(offset, encodedValue.Length));
                sequence.ReadEncodedValue();
                (parsedAttributes ??= new List<X500RelativeDistinguishedName>()).Add(rdn);
            }
        } catch (AsnContentException e) {
            throw new CryptographicException("ASN1 corrupted data.", e);
        }

        return parsedAttributes ?? new List<X500RelativeDistinguishedName>();
    }


    private static readonly ConditionalWeakTable<X500DistinguishedName, List<X500RelativeDistinguishedName>> ParsedAttributesTable = new();
}
#endif
