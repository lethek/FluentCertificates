using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;

namespace FluentCertificates;

public record X509NameBuilder
{
    public static X509NameBuilder Create(X509NameBuilder? copy = null)
        => new(copy);

    public X509NameBuilder(X509NameBuilder? copy)
    {
        if (copy != null) {
            _oids = new List<DerObjectIdentifier>(copy._oids);
            _values = new List<string>(copy._values);
        } else {
            _oids = new List<DerObjectIdentifier>();
            _values = new List<string>();
        }
    }

    public X509NameBuilder() : this(null) { }

    public X509Name Build()
        => new(_oids, _values);

    public X509NameBuilder Clear()
    {
        _oids.Clear();
        _values.Clear();
        return this;
    }

    public X509NameBuilder Set(DerObjectIdentifier oid, string? value)
    {
        if (value != null) {
            _oids.Add(oid);
            _values.Add(value);
        } else {
            Unset(oid);
        }
        return this;
    }

    public X509NameBuilder Unset(DerObjectIdentifier oid)
    {
        var index = _oids.IndexOf(oid);
        if (index >= 0) {
            _oids.RemoveAt(index);
            _values.RemoveAt(index);
        }
        return this;
    }

    public X509NameBuilder SetCommonName(string value)
        => Set(X509Name.CN, value);

    public X509NameBuilder SetOrganization(string value)
        => Set(X509Name.O, value);

    public X509NameBuilder SetOrganizationalUnit(string value)
        => Set(X509Name.OU, value);

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

    public X509NameBuilder SetDomainComponent(string value)
        => Set(X509Name.DC, value);

    public X509NameBuilder SetDistinguishedNameQualifier(string value)
        => Set(X509Name.DnQualifier, value);

    [Obsolete("Obsolete: use Subject Alternative Name extensions instead")]
    public X509NameBuilder SetEmail(string value)
        => Set(X509Name.E, value);

    public override string ToString()
        => Build().ToString();

    public static implicit operator X509Name(X509NameBuilder builder)
        => builder.Build();

    private readonly List<DerObjectIdentifier> _oids;
    private readonly List<string> _values;
}