using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

// Both namespaces define X509Extension, so neither short name is usable unqualified here
using X509ExtensionBC = Org.BouncyCastle.Asn1.X509.X509Extension;
using X509ExtensionDotNet = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

/// <summary>
/// Conversions between BouncyCastle and .NET types, used only to build inputs for tests and to pick
/// apart their output. These were once part of a FluentCertificates.Builder.BouncyCastle project, but
/// nothing shipped depends on BouncyCastle any more, so they live here instead.
/// </summary>
internal static class BouncyCastleTestExtensions
{
    public static X500DistinguishedName ConvertToDotNet(this X509Name name)
        => new(name.ToString());


    public static X509ExtensionBC ConvertToBouncyCastle(this X509ExtensionDotNet ext)
        => new(ext.Critical, new DerOctetString(ext.RawData));
}
