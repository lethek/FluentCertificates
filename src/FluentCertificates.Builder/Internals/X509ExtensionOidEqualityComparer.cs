using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

internal class X509ExtensionOidEqualityComparer : IEqualityComparer<X509Extension>
{
    public bool Equals(X509Extension? x, X509Extension? y)
    {
        if (ReferenceEquals(x, y)) {
            return true;
        }

        if (x is null || y is null) {
            return false;
        }

        if (x.GetType() != y.GetType()) {
            return false;
        }

        return String.Equals(x.Oid?.Value, y.Oid?.Value);
    }

    
    public int GetHashCode(X509Extension obj) => HashCode.Combine(obj.Oid?.Value);
}
