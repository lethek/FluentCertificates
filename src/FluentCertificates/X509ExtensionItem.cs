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


    public static IEqualityComparer<X509ExtensionItem> OidEqualityComparer = new EqualityComparer();


    private class EqualityComparer : IEqualityComparer<X509ExtensionItem>
    {
        public bool Equals(X509ExtensionItem? x, X509ExtensionItem? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (ReferenceEquals(x, null)) return false;
            if (ReferenceEquals(y, null)) return false;
            if (x.GetType() != y.GetType()) return false;
            return x.Oid.Equals(y.Oid);
        }

        public int GetHashCode(X509ExtensionItem obj) => HashCode.Combine(obj.Oid);
    }
}