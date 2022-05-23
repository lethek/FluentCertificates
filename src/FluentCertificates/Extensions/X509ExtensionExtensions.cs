using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;

using BouncyX509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

namespace FluentCertificates.Extensions;

internal static class X509ExtensionExtensions
{
    public static X509Extension ToDotNet(this BouncyX509Extension ext, string oid)
        => new X509Extension(oid, ext.Value.GetOctets(), ext.IsCritical);

    public static X509Extension ToDotNet(this BouncyX509Extension ext, DerObjectIdentifier oid)
        => new X509Extension(oid.Id, ext.Value.GetOctets(), ext.IsCritical);


    public static BouncyX509Extension ToBouncyCastle(this X509Extension ext)
        => throw new NotImplementedException();
}
