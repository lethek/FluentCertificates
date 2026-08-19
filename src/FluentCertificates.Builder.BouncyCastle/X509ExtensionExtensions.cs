using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;

using X509ExtensionBC = Org.BouncyCastle.Asn1.X509.X509Extension;


namespace FluentCertificates;

public static class X509ExtensionExtensions
{
    public static X509ExtensionBC ConvertToBouncyCastle(this X509Extension ext)
        => new(ext.Critical, new DerOctetString(ext.RawData));
}
