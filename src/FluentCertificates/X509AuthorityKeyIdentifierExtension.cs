using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;


namespace FluentCertificates;

public sealed class X509AuthorityKeyIdentifierExtension : X509Extension
{
    public X509AuthorityKeyIdentifierExtension(X509Certificate2 certificateAuthority, bool critical)
        : base(AuthorityKeyIdentifierOid, EncodeExtension(certificateAuthority), critical) { }


    private static byte[] EncodeExtension(X509Certificate2 ca)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        var subjectKeyIdentifier = ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
        if (subjectKeyIdentifier != null) {
            var keyIdTag = new Asn1Tag(TagClass.ContextSpecific, 0);
            writer.WriteOctetString(subjectKeyIdentifier.RawData.AsSpan().Slice(2), keyIdTag);
        }

        writer.PopSequence();
        return writer.Encode();
    }


    private static readonly Oid AuthorityKeyIdentifierOid = new("2.5.29.35");
}
