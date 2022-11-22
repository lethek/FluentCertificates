using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;


public record X500NameBuilder
{
    public X500NameBuilder()
    { }


    public X500NameBuilder(X500DistinguishedName name)
        => Attributes = name
            .EnumerateRelativeDistinguishedNames()
            .Select(x => (x.GetSingleElementType(), x.GetSingleElementValue()))
            .ToImmutableList();


    public X500NameBuilder(string name)
        : this(new X500DistinguishedName(name))
    { }


    public ImmutableList<(Oid OID, string? Value)> Attributes { get; init; } = ImmutableList<(Oid, string?)>.Empty;


    public X500DistinguishedName Create()
    {
        var builder = new X500DistinguishedNameBuilder();
        foreach (var attribute in Attributes) {
            builder.Add(attribute.OID, attribute.Value);
        }
        return builder.Build();
    }


    public X500NameBuilder Clear()
        => this with { Attributes = Attributes.Clear() };
    

    public X500NameBuilder Remove(Oid oid)
        => this with {
            Attributes = Attributes.Where(x => x.OID.Value != oid.Value).ToImmutableList()
        };


    public X500NameBuilder Remove(string oid)
        => Remove(new Oid(oid));


    public X500NameBuilder Add(Oid oid, params string[] values)
        => this with {
            Attributes = Attributes.AddRange(values.Where(x => x != null).Select(x => (oid, (string?)x)))
        };


    public X500NameBuilder Add(string oid, params string[] values)
        => Add(new Oid(oid), values);


    public X500NameBuilder Set(Oid oid, params string[] values)
        => this with {
            Attributes = Attributes
                .Where(x => x.OID.Value != oid.Value)
                .Concat(values.Where(x => x != null).Select(x => (oid, (string?)x)))
                .ToImmutableList()
        };


    public X500NameBuilder Set(string oid, params string[] values)
        => Set(new Oid(oid), values);

    
    public X500NameBuilder SetCommonName(string value)
        => Set(Oids.CommonNameOid, value);


    public X500NameBuilder SetOrganization(string value)
        => Set(Oids.OrganizationOid, value);


    public X500NameBuilder SetCountry(string value)
        => Set(Oids.CountryOrRegionNameOid, value);


    public X500NameBuilder SetLocality(string value)
        => Set(Oids.LocalityNameOid, value);


    public X500NameBuilder SetPhoneNumber(string value)
        => Set(Oids.TelephoneNumberOid, value);


    public X500NameBuilder SetStreetAddress(string value)
        => Set(Oids.StreetAddressOid, value);


    public X500NameBuilder SetState(string value)
        => Set(Oids.StateOrProvinceNameOid, value);


    public X500NameBuilder SetPostalCode(string value)
        => Set(Oids.PostalCodeOid, value);


    public X500NameBuilder SetUserId(string value)
        => Set(Oids.UserIdOid, value);


    public X500NameBuilder SetSerialNumber(string value)
        => Set(Oids.SerialNumberOid, value);


    public X500NameBuilder SetGivenName(string value)
        => Set(Oids.GivenNameOid, value);


    public X500NameBuilder SetSurname(string value)
        => Set(Oids.SurnameOid, value);


    public X500NameBuilder SetTitle(string value)
        => Set(Oids.TitleOid, value);


    public X500NameBuilder SetDistinguishedNameQualifier(string value)
        => Set(Oids.DnQualifierOid, value);


    public X500NameBuilder SetOrganizationalUnits(params string[] values)
        => Set(Oids.OrganizationalUnitOid, values);


    public X500NameBuilder SetDomainComponents(params string[] values)
        => Set(Oids.DomainComponentOid, values);


    public X500NameBuilder AddOrganizationalUnit(string value)
        => Add(Oids.OrganizationalUnitOid, value);


    public X500NameBuilder AddOrganizationalUnits(params string[] values)
        => Add(Oids.OrganizationalUnitOid, values);


    public X500NameBuilder AddDomainComponent(string value)
        => Add(Oids.DomainComponentOid, value);


    public X500NameBuilder AddDomainComponents(params string[] values)
        => Add(Oids.DomainComponentOid, values);


    [Obsolete("Obsolete: use Subject Alternative Name extensions instead. If you're using CertificateBuilder then try its SetEmail method.")]
    public X500NameBuilder SetEmail(string value)
        => Set(Oids.EmailAddressOid, value);


    public override string ToString()
        => Create().Name;


    public virtual bool Equals(X500DistinguishedName? other)
        => other != null && Create().RawData.SequenceEqual(other.RawData);
    
    public virtual bool Equals(string? other)
        => other != null && Create().RawData.SequenceEqual(new X500DistinguishedName(other).RawData);

    /*
    public static bool Equals(X500NameBuilder? left, X500DistinguishedName? right)
        => (left == null && right == null) || (left != null && left.Equals(right));

    public static bool Equals(X500NameBuilder? left, string? right)
        => (left == null && right == null) || (left != null && left.Equals(right));


    public static bool Equals(X500DistinguishedName? left, X500NameBuilder? right)
        => (left == null && right == null) || (right != null && right.Equals(left));

    public static bool Equals(string? left, X500NameBuilder? right)
        => (left == null && right == null) || (right != null && right.Equals(left));
    */


    public static bool operator ==(X500NameBuilder? left, X500DistinguishedName? right) => Equals(left, right);
    public static bool operator ==(X500NameBuilder? left, string? right) => Equals(left, right);


    public static bool operator ==(X500DistinguishedName left, X500NameBuilder right) => Equals(left, right);
    public static bool operator ==(string left, X500NameBuilder right) => Equals(left, right);


    public static bool operator !=(X500NameBuilder left, X500DistinguishedName right) => !Equals(left, right);
    public static bool operator !=(X500NameBuilder left, string right) => !Equals(left, right);


    public static bool operator !=(X500DistinguishedName left, X500NameBuilder right) => !Equals(left, right);
    public static bool operator !=(string left, X500NameBuilder right) => !Equals(left, right);
    
    public static implicit operator X500DistinguishedName(X500NameBuilder builder) => builder.Create();
    public static explicit operator string(X500NameBuilder builder) => builder.ToString();
}
