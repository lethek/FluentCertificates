using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;


namespace FluentCertificates;

public static class X500NameBuilderExtensions
{
    public static X500DistinguishedName ConvertToDotNet(this X509Name name)
        => new(name.ToString());

    
    public static X509Name ConvertToBouncyCastle(this X500NameBuilder builder)
        => new(
            builder.Attributes.Select(x => new DerObjectIdentifier(x.OID.Value)).ToArray(),
            builder.Attributes.Select(x => x.Value).ToArray()
        );


    public static X500NameBuilder Remove(this X500NameBuilder builder, DerObjectIdentifier oid)
        => builder.Remove(new Oid(oid.Id));


    public static X500NameBuilder Add(this X500NameBuilder builder, DerObjectIdentifier oid, params string[] values)
        => builder.Add(new Oid(oid.Id), values);


    public static X500NameBuilder Set(this X500NameBuilder builder, DerObjectIdentifier oid, params string[] values)
        => builder.Set(new Oid(oid.Id), values);


    public static bool Equivalent(this X500NameBuilder builder, X509Name? other)
        => other != null && builder.ConvertToBouncyCastle().Equivalent(other, true);
}
