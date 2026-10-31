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
    public static ImmutableList<X500AttributeSet> Read(ReadOnlyMemory<byte> rawData)
    {
        //BER rules, because names in the wild are not always sorted or minimally encoded and still have to be read
        var relativeNames = ImmutableList.CreateBuilder<X500AttributeSet>();
        try {
            var outer = new AsnReader(rawData, AsnEncodingRules.BER);
            var sequence = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            while (sequence.HasData) {
                var set = sequence.ReadSetOf(skipSortOrderValidation: true);
                if (!set.HasData) {
                    throw new AsnContentException("A relative distinguished name has at least one attribute.");
                }
                var attributes = ImmutableList.CreateBuilder<X500Attribute>();
                while (set.HasData) {
                    var pair = set.ReadSequence();
                    var oid = new Oid(pair.ReadObjectIdentifier());
                    var value = pair.ReadEncodedValue();
                    pair.ThrowIfNotEmpty();
                    attributes.Add(X500Attribute.CreateFromDer(oid, BerToDer.Normalize(value.Span)));
                }
                relativeNames.Add(new X500AttributeSet(attributes.ToImmutable()));
            }
        } catch (Exception ex) when (ex is AsnContentException or ArgumentException) {
            throw new CryptographicException("The distinguished name is not a valid ASN.1 Name.", ex);
        }
        relativeNames.Reverse();
        return relativeNames.ToImmutable();
    }


    public static X500DistinguishedName Write(IEnumerable<X500AttributeSet> relativeNames)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            foreach (var relativeName in relativeNames.Reverse()) {
                //DER sorts the members of a SET OF as the writer disposes this scope
                using (writer.PushSetOf()) {
                    foreach (var attribute in relativeName) {
                        attribute.Encode(writer);
                    }
                }
            }
        }
        return new X500DistinguishedName(writer.Encode());
    }
}
