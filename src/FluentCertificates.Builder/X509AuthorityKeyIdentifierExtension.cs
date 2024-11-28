using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;

public sealed class X509AuthorityKeyIdentifierExtension(X509Certificate2 certificateAuthority, bool critical)
    : X509Extension(Oids.AuthorityKeyIdentifierOid, EncodeExtension(certificateAuthority), critical)
{
    private static byte[] EncodeExtension(X509Certificate2 ca)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence()) {
            var subjectKeyIdentifier = ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
            if (subjectKeyIdentifier != null) {
                writer.WriteOctetString(subjectKeyIdentifier.RawData.AsSpan().Slice(2), KeyIdTag);
            }
        }

        return writer.Encode();
    }
    
    
    private static readonly Asn1Tag KeyIdTag = new(TagClass.ContextSpecific, 0);
}
