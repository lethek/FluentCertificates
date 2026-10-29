using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

internal static class X500NameDer
{
    /// <summary>
    /// Reads the relative distinguished names out of an encoded Name. A Name is encoded least specific first,
    /// so the result is reversed into the most-specific-first order of the string form.
    /// </summary>
    public static ImmutableList<X500RelativeDistinguishedName> Read(ReadOnlyMemory<byte> rawData)
    {
        //BER rules, because names in the wild are not always sorted or minimally encoded and still have to be read
        var relativeNames = ImmutableList.CreateBuilder<X500RelativeDistinguishedName>();
        try {
            var outer = new AsnReader(rawData, AsnEncodingRules.BER);
            var sequence = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            while (sequence.HasData) {
                var set = sequence.ReadSetOf(skipSortOrderValidation: true);
                var attributes = ImmutableList.CreateBuilder<X500Attribute>();
                while (set.HasData) {
                    var pair = set.ReadSequence();
                    var oid = new Oid(pair.ReadObjectIdentifier());
                    var value = pair.ReadEncodedValue();
                    pair.ThrowIfNotEmpty();
                    attributes.Add(X500Attribute.CreateFromDer(oid, value.Span));
                }
                relativeNames.Add(new X500RelativeDistinguishedName(attributes.ToImmutable()));
            }
        } catch (AsnContentException ex) {
            throw new CryptographicException("The distinguished name is not a valid ASN.1 Name.", ex);
        }
        relativeNames.Reverse();
        return relativeNames.ToImmutable();
    }


    public static X500DistinguishedName Write(IEnumerable<X500RelativeDistinguishedName> relativeNames)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            foreach (var relativeName in relativeNames.Reverse()) {
                if (relativeName.Attributes.IsEmpty) {
                    throw new InvalidOperationException("A relative distinguished name needs at least one attribute.");
                }
                //DER sorts the members of a SET OF as the writer disposes this scope
                using (writer.PushSetOf()) {
                    foreach (var attribute in relativeName.Attributes) {
                        attribute.Encode(writer);
                    }
                }
            }
        }
        return new X500DistinguishedName(writer.Encode());
    }
}
