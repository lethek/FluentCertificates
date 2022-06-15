using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;

namespace FluentCertificates;


// ReSharper disable WithExpressionModifiesAllMembers
public record X509NameBuilder
{
    public static X509NameBuilder Create(X509NameBuilder? copy = null)
        => new(copy);


    public X509NameBuilder(X509NameBuilder? copy)
        => Attributes = (copy == null)
            ? ImmutableList<(DerObjectIdentifier, string)>.Empty
            : copy.Attributes;


    public X509NameBuilder() : this(null) { }


    public ImmutableList<(DerObjectIdentifier OID, string Value)> Attributes { get; init; }

    
    public X509Name Build()
        => new(
            Attributes.Select(x => x.OID).ToArray(),
            Attributes.Select(x => x.Value).ToArray()
        );


    public X509NameBuilder Clear()
        => this with { Attributes = Attributes.Clear() };


    public X509NameBuilder Remove(DerObjectIdentifier oid)
        => this with {
            Attributes = Attributes.Where(x => !x.OID.Equals(oid)).ToImmutableList()
        };


    public X509NameBuilder Add(DerObjectIdentifier oid, params string[] values)
        => this with {
            Attributes = Attributes.AddRange(values.Where(x => x != null).Select(x => (oid, x)))
        };


    public X509NameBuilder Set(DerObjectIdentifier oid, params string[] values)
        => this with {
            Attributes = Attributes
                .Where(x => x.OID != oid)
                .Concat(values.Where(x => x != null).Select(x => (oid, x)))
                .ToImmutableList()
        };


    public X509NameBuilder SetCommonName(string value)
        => Set(X509Name.CN, value);


    public X509NameBuilder SetOrganization(string value)
        => Set(X509Name.O, value);


    public X509NameBuilder SetCountry(string value)
        => Set(X509Name.C, value);


    public X509NameBuilder SetLocality(string value)
        => Set(X509Name.L, value);


    public X509NameBuilder SetPhoneNumber(string value)
        => Set(X509Name.TelephoneNumber, value);


    public X509NameBuilder SetStreetAddress(string value)
        => Set(X509Name.Street, value);


    public X509NameBuilder SetState(string value)
        => Set(X509Name.ST, value);


    public X509NameBuilder SetPostCode(string value)
        => Set(X509Name.PostalCode, value);


    public X509NameBuilder SetUnstructuredName(string value)
        => Set(X509Name.UnstructuredName, value);


    public X509NameBuilder SetUnstructuredAddress(string value)
        => Set(X509Name.UnstructuredAddress, value);


    public X509NameBuilder SetUserId(string value)
        => Set(X509Name.UID, value);


    public X509NameBuilder SetSerialNumber(string value)
        => Set(X509Name.SerialNumber, value);


    public X509NameBuilder SetGivenName(string value)
        => Set(X509Name.GivenName, value);


    public X509NameBuilder SetSurname(string value)
        => Set(X509Name.Surname, value);


    public X509NameBuilder SetTitle(string value)
        => Set(X509Name.T, value);


    public X509NameBuilder SetDistinguishedNameQualifier(string value)
        => Set(X509Name.DnQualifier, value);


    public X509NameBuilder SetOrganizationalUnits(params string[] values)
        => Set(X509Name.OU, values);


    public X509NameBuilder SetDomainComponents(params string[] values)
        => Set(X509Name.DC, values);


    public X509NameBuilder AddOrganizationalUnit(string value)
        => Add(X509Name.OU, value);


    public X509NameBuilder AddOrganizationalUnits(params string[] values)
        => Add(X509Name.OU, values);


    public X509NameBuilder AddDomainComponent(string value)
        => Add(X509Name.DC, value);


    public X509NameBuilder AddDomainComponents(params string[] values)
        => Add(X509Name.DC, values);


    [Obsolete("Obsolete: use Subject Alternative Name extensions instead. If you're using CertificateBuilder then try its SetEmail method.")]
    public X509NameBuilder SetEmail(string value)
        => Set(X509Name.E, value);


    public override string ToString()
        => Build().ToString();


    public X500DistinguishedName ToX500DistinguishedName()
        => new(ToString());


    public virtual bool Equals(X509Name? other)
        => other != null && Build().Equivalent(other, true);


    public virtual bool Equals(X500DistinguishedName? other)
        => other != null && ToX500DistinguishedName().RawData.SequenceEqual(other.RawData);


    public virtual bool Equals(string? other)
        => other != null && ToX500DistinguishedName().RawData.SequenceEqual(new X500DistinguishedName(other).RawData);


    public static bool Equals(X509NameBuilder? left, X509Name? right)
        => (left == null && right == null) || (left != null && left.Equals(right));


    public static bool Equals(X509NameBuilder? left, X500DistinguishedName? right)
        => (left == null && right == null) || (left != null && left.Equals(right));


    public static bool Equals(X509NameBuilder? left, string? right)
        => (left == null && right == null) || (left != null && left.Equals(right));


    public static bool operator ==(X509NameBuilder? left, X500DistinguishedName? right) => Equals(left, right);
    public static bool operator ==(X509NameBuilder? left, X509Name? right) => Equals(left, right);
    public static bool operator ==(X509NameBuilder? left, string? right) => Equals(left, right);


    public static bool operator ==(X500DistinguishedName left, X509NameBuilder right) => Equals(right, left);
    public static bool operator ==(X509Name left, X509NameBuilder right) => Equals(right, left);
    public static bool operator ==(string left, X509NameBuilder right) => Equals(right, left);


    public static bool operator !=(X509NameBuilder left, X500DistinguishedName right) => !Equals(left, right);
    public static bool operator !=(X509NameBuilder left, X509Name right) => !Equals(left, right);
    public static bool operator !=(X509NameBuilder left, string right) => !Equals(left, right);


    public static bool operator !=(X500DistinguishedName left, X509NameBuilder right) => !Equals(right, left);
    public static bool operator !=(X509Name left, X509NameBuilder right) => !Equals(right, left);
    public static bool operator !=(string left, X509NameBuilder right) => !Equals(right, left);

    
    public static implicit operator X500DistinguishedName(X509NameBuilder builder)
        => builder.ToX500DistinguishedName();


    public static implicit operator X509Name(X509NameBuilder builder)
        => builder.Build();


    public static implicit operator string(X509NameBuilder builder)
        => builder.ToString();
}
