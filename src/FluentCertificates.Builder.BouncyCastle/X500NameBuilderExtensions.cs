using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;


namespace FluentCertificates;

public static class X500NameBuilderExtensions
{
    public static X500DistinguishedName ConvertToDotNet(this X509Name name)
        => new(name.ToString());


    public static X500NameBuilder Add(this X500NameBuilder builder, DerObjectIdentifier oid, UniversalTagNumber valueEncoding, params string[] values)
        => builder.Add(new Oid(oid.Id), valueEncoding, values);
}
