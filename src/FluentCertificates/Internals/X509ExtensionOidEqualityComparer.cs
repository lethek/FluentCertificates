using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

internal class X509ExtensionOidEqualityComparer : IEqualityComparer<X509Extension>
{
    public bool Equals(X509Extension? x, X509Extension? y)
    {
        if (ReferenceEquals(x, y)) return true;
        if (ReferenceEquals(x, null)) return false;
        if (ReferenceEquals(y, null)) return false;
        if (x.GetType() != y.GetType()) return false;
        return x.Oid.Value.Equals(y.Oid.Value);
    }

    public int GetHashCode(X509Extension obj) => HashCode.Combine(obj.Oid.Value);
}
