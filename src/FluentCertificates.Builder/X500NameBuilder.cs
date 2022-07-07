using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;

namespace FluentCertificates;


public record X500NameBuilder
{
    public X500NameBuilder()
    { }


    public X500NameBuilder(X509Name name) =>
        Attributes = name.GetOidList()
            .Cast<DerObjectIdentifier>()
            .Zip(
                name.GetValueList().Cast<string>(),
                (oid, value) => (new Oid(oid.Id), value)
            )
            .ToImmutableList();


    public X500NameBuilder(X500DistinguishedName name)
        : this(new X509Name(name.Name))
    { }


    public X500NameBuilder(string name)
        : this(new X509Name(name))
    { }


    public ImmutableList<(Oid OID, string Value)> Attributes { get; init; } = ImmutableList<(Oid, string)>.Empty;


    public X500DistinguishedName Create()
        => new(ToX509Name().ToString());

    
    public X500NameBuilder Clear()
        => this with { Attributes = Attributes.Clear() };
    

    public X500NameBuilder Remove(Oid oid)
        => this with {
            Attributes = Attributes.Where(x => x.OID.Value != oid.Value).ToImmutableList()
        };


    public X500NameBuilder Remove(DerObjectIdentifier oid)
        => Remove(new Oid(oid.Id));


    public X500NameBuilder Remove(string oid)
        => Remove(new Oid(oid));


    public X500NameBuilder Add(Oid oid, params string[] values)
        => this with {
            Attributes = Attributes.AddRange(values.Where(x => x != null).Select(x => (oid, x)))
        };


    public X500NameBuilder Add(DerObjectIdentifier oid, params string[] values)
        => Add(new Oid(oid.Id), values);


    public X500NameBuilder Add(string oid, params string[] values)
        => Add(new Oid(oid), values);


    public X500NameBuilder Set(Oid oid, params string[] values)
        => this with {
            Attributes = Attributes
                .Where(x => x.OID.Value != oid.Value)
                .Concat(values.Where(x => x != null).Select(x => (oid, x)))
                .ToImmutableList()
        };


    public X500NameBuilder Set(DerObjectIdentifier oid, params string[] values)
        => Set(new Oid(oid.Id), values);


    public X500NameBuilder Set(string oid, params string[] values)
        => Set(new Oid(oid), values);

    
    public X500NameBuilder SetCommonName(string value)
        => Set(X509Name.CN, value);


    public X500NameBuilder SetOrganization(string value)
        => Set(X509Name.O, value);


    public X500NameBuilder SetCountry(string value)
        => Set(X509Name.C, value);


    public X500NameBuilder SetLocality(string value)
        => Set(X509Name.L, value);


    public X500NameBuilder SetPhoneNumber(string value)
        => Set(X509Name.TelephoneNumber, value);


    public X500NameBuilder SetStreetAddress(string value)
        => Set(X509Name.Street, value);


    public X500NameBuilder SetState(string value)
        => Set(X509Name.ST, value);


    public X500NameBuilder SetPostCode(string value)
        => Set(X509Name.PostalCode, value);


    public X500NameBuilder SetUnstructuredName(string value)
        => Set(X509Name.UnstructuredName, value);


    public X500NameBuilder SetUnstructuredAddress(string value)
        => Set(X509Name.UnstructuredAddress, value);


    public X500NameBuilder SetUserId(string value)
        => Set(X509Name.UID, value);


    public X500NameBuilder SetSerialNumber(string value)
        => Set(X509Name.SerialNumber, value);


    public X500NameBuilder SetGivenName(string value)
        => Set(X509Name.GivenName, value);


    public X500NameBuilder SetSurname(string value)
        => Set(X509Name.Surname, value);


    public X500NameBuilder SetTitle(string value)
        => Set(X509Name.T, value);


    public X500NameBuilder SetDistinguishedNameQualifier(string value)
        => Set(X509Name.DnQualifier, value);


    public X500NameBuilder SetOrganizationalUnits(params string[] values)
        => Set(X509Name.OU, values);


    public X500NameBuilder SetDomainComponents(params string[] values)
        => Set(X509Name.DC, values);


    public X500NameBuilder AddOrganizationalUnit(string value)
        => Add(X509Name.OU, value);


    public X500NameBuilder AddOrganizationalUnits(params string[] values)
        => Add(X509Name.OU, values);


    public X500NameBuilder AddDomainComponent(string value)
        => Add(X509Name.DC, value);


    public X500NameBuilder AddDomainComponents(params string[] values)
        => Add(X509Name.DC, values);


    [Obsolete("Obsolete: use Subject Alternative Name extensions instead. If you're using CertificateBuilder then try its SetEmail method.")]
    public X500NameBuilder SetEmail(string value)
        => Set(X509Name.E, value);


    public X500DistinguishedName ToX500DistinguishedName()
        => new(ToString());


    public X509Name ToX509Name()
        => new(
            Attributes.Select(x => new DerObjectIdentifier(x.OID.Value)).ToArray(),
            Attributes.Select(x => x.Value).ToArray()
        );


    public override string ToString()
        => ToX509Name().ToString();


    public virtual bool Equals(X500DistinguishedName? other)
        => other != null && ToX500DistinguishedName().RawData.SequenceEqual(other.RawData);
    
    public virtual bool Equals(X509Name? other)
        => other != null && ToX509Name().Equivalent(other, true);
    
    public virtual bool Equals(string? other)
        => other != null && ToX500DistinguishedName().RawData.SequenceEqual(new X500DistinguishedName(other).RawData);


    public static bool Equals(X500NameBuilder? left, X500DistinguishedName? right)
        => (left == null && right == null) || (left != null && left.Equals(right));

    public static bool Equals(X500NameBuilder? left, X509Name? right)
        => (left == null && right == null) || (left != null && left.Equals(right));

    public static bool Equals(X500NameBuilder? left, string? right)
        => (left == null && right == null) || (left != null && left.Equals(right));


    public static bool Equals(X500DistinguishedName? left, X500NameBuilder? right)
        => (left == null && right == null) || (right != null && right.Equals(left));

    public static bool Equals(X509Name? left, X500NameBuilder? right)
        => (left == null && right == null) || (right != null && right.Equals(left));

    public static bool Equals(string? left, X500NameBuilder? right)
        => (left == null && right == null) || (right != null && right.Equals(left));


    public static bool operator ==(X500NameBuilder? left, X500DistinguishedName? right) => Equals(left, right);
    public static bool operator ==(X500NameBuilder? left, X509Name? right) => Equals(left, right);
    public static bool operator ==(X500NameBuilder? left, string? right) => Equals(left, right);


    public static bool operator ==(X500DistinguishedName left, X500NameBuilder right) => Equals(left, right);
    public static bool operator ==(X509Name left, X500NameBuilder right) => Equals(left, right);
    public static bool operator ==(string left, X500NameBuilder right) => Equals(left, right);


    public static bool operator !=(X500NameBuilder left, X500DistinguishedName right) => !Equals(left, right);
    public static bool operator !=(X500NameBuilder left, X509Name right) => !Equals(left, right);
    public static bool operator !=(X500NameBuilder left, string right) => !Equals(left, right);


    public static bool operator !=(X500DistinguishedName left, X500NameBuilder right) => !Equals(left, right);
    public static bool operator !=(X509Name left, X500NameBuilder right) => !Equals(left, right);
    public static bool operator !=(string left, X500NameBuilder right) => !Equals(left, right);

    
    public static implicit operator X500DistinguishedName(X500NameBuilder builder) => builder.ToX500DistinguishedName();
    public static implicit operator X509Name(X500NameBuilder builder) => builder.ToX509Name();
    public static implicit operator string(X500NameBuilder builder) => builder.ToString();
}
