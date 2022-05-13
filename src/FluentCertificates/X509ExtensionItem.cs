using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace FluentCertificates;

public record X509ExtensionItem
{
    public DerObjectIdentifier Oid { get; init; }

    public X509Extension Extension { get; init; }

    public X509ExtensionItem(DerObjectIdentifier oid, X509Extension extension)
    {
        Oid = oid;
        Extension = extension;
    }

    public X509ExtensionItem(DerObjectIdentifier oid, bool critical, Asn1Encodable encodable)
    {
        Oid = oid;
        Extension = new X509Extension(critical, new DerOctetString(encodable));
    }

    public X509ExtensionItem(DerObjectIdentifier oid, bool critical, IAsn1Convertible convertible)
    {
        Oid = oid;
        Extension = new X509Extension(critical, new DerOctetString(convertible));
    }
}