using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

/// <summary>
/// Treats two extensions as the same when they carry the same OID, whatever their runtime types.
/// </summary>
/// <remarks>
/// A certificate carries at most one extension per OID, so the OID alone is the identity. Runtime type is
/// deliberately not part of it: .NET hands back a concrete subclass for a well-known OID it generates
/// itself, while an extension built by hand is typically the base <see cref="X509Extension"/>, and treating
/// those two as different would let both reach <see cref="System.Security.Cryptography.X509Certificates.CertificateRequest"/>,
/// which throws on a duplicate OID.
/// </remarks>
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

        return String.Equals(x.Oid?.Value, y.Oid?.Value);
    }

    
    public int GetHashCode(X509Extension obj) => HashCode.Combine(obj.Oid?.Value);
}
