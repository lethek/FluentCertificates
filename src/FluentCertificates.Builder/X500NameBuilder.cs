using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;


public record X500NameBuilder
{
    public X500NameBuilder()
    { }


    public X500NameBuilder(X500DistinguishedName name)
        => RelativeDistinguishedNames = name
            .EnumerateRelativeDistinguishedNames()
            .Select(x => (x.GetSingleElementType(), x.GetSingleElementValueEncoding(), x.GetSingleElementValue()!))
            .ToImmutableList();


    public X500NameBuilder(string name)
        : this(new X500DistinguishedName(name))
    { }


    public ImmutableList<(Oid OID, UniversalTagNumber ValueEncoding, string Value)> RelativeDistinguishedNames { get; init; }
        = ImmutableList<(Oid, UniversalTagNumber, string)>.Empty;


    public X500DistinguishedName Create()
    {
        var builder = new X500DistinguishedNameBuilder();
        foreach (var rdn in RelativeDistinguishedNames) {
            builder.Add(rdn.OID, rdn.Value, rdn.ValueEncoding);
        }
        return builder.Build();
    }


    public X500NameBuilder Clear()
        => this with { RelativeDistinguishedNames = RelativeDistinguishedNames.Clear() };
    

    public X500NameBuilder Remove(Oid oid)
        => this with {
            RelativeDistinguishedNames = RelativeDistinguishedNames.Where(x => x.OID.Value != oid.Value).ToImmutableList()
        };


    public X500NameBuilder Remove(string oid)
        => Remove(new Oid(oid));


    public X500NameBuilder Add(Oid oid, UniversalTagNumber valueEncoding, params string[] values)
        => this with {
            RelativeDistinguishedNames = RelativeDistinguishedNames.AddRange(
                values
                    .Where(x => x != null)
                    .Select(x => (oid, valueEncoding, x))
            )
        };


    public X500NameBuilder Add(Oid oid, params string[] values)
        => Add(oid, UniversalTagNumber.UTF8String, values);


    public X500NameBuilder Add(string oid, UniversalTagNumber valueEncoding, params string[] values)
        => Add(new Oid(oid), valueEncoding, values);


    public X500NameBuilder Add(string oid, params string[] values)
        => Add(new Oid(oid), values);


    public X500NameBuilder Set(Oid oid, UniversalTagNumber valueEncoding = UniversalTagNumber.UTF8String, params string[] values)
        => this with {
            RelativeDistinguishedNames = RelativeDistinguishedNames
                .Where(x => x.OID.Value != oid.Value)
                .Concat(
                    values
                        .Where(x => x != null)
                        .Select(x => (oid, valueEncoding, x))
                )
                .ToImmutableList()
        };


    public X500NameBuilder Set(Oid oid, params string[] values)
        => Set(oid, UniversalTagNumber.UTF8String, values);


    public X500NameBuilder Set(string oid, UniversalTagNumber valueEncoding = UniversalTagNumber.UTF8String, params string[] values)
        => Set(new Oid(oid), valueEncoding, values);

    
    public X500NameBuilder Set(string oid, params string[] values)
        => Set(new Oid(oid), values);


    public X500NameBuilder SetCommonName(string value)
        => Set(Oids.CommonNameOid, UniversalTagNumber.UTF8String, value);


    public X500NameBuilder SetOrganization(string value)
        => Set(Oids.OrganizationOid, UniversalTagNumber.UTF8String, value);


    public X500NameBuilder SetCountry(string value)
        => Set(Oids.CountryOrRegionNameOid, UniversalTagNumber.PrintableString, value);


    public X500NameBuilder SetLocality(string value)
        => Set(Oids.LocalityNameOid, UniversalTagNumber.UTF8String, value);


    public X500NameBuilder SetPhoneNumber(string value)
        => Set(Oids.TelephoneNumberOid, UniversalTagNumber.PrintableString, value);


    public X500NameBuilder SetStreetAddress(string value)
        => Set(Oids.StreetAddressOid, UniversalTagNumber.PrintableString, value);


    public X500NameBuilder SetState(string value)
        => Set(Oids.StateOrProvinceNameOid, UniversalTagNumber.UTF8String, value);


    public X500NameBuilder SetPostalCode(string value)
        => Set(Oids.PostalCodeOid, UniversalTagNumber.PrintableString, value);


    public X500NameBuilder SetUserId(string value)
        => Set(Oids.UserIdOid, value);


    public X500NameBuilder SetSerialNumber(string value)
        => Set(Oids.SerialNumberOid, UniversalTagNumber.PrintableString, value);


    public X500NameBuilder SetGivenName(string value)
        => Set(Oids.GivenNameOid, UniversalTagNumber.PrintableString, value);


    public X500NameBuilder SetSurname(string value)
        => Set(Oids.SurnameOid, UniversalTagNumber.PrintableString, value);


    public X500NameBuilder SetTitle(string value)
        => Set(Oids.TitleOid, UniversalTagNumber.UTF8String, value);


    public X500NameBuilder SetDistinguishedNameQualifier(string value)
        => Set(Oids.DnQualifierOid, UniversalTagNumber.PrintableString, value);


    public X500NameBuilder SetOrganizationalUnits(params string[] values)
        => Set(Oids.OrganizationalUnitOid, UniversalTagNumber.UTF8String, values);


    public X500NameBuilder SetDomainComponents(params string[] values)
        => Set(Oids.DomainComponentOid, UniversalTagNumber.IA5String, values);


    public X500NameBuilder AddOrganizationalUnit(string value)
        => Add(Oids.OrganizationalUnitOid, UniversalTagNumber.UTF8String, value);


    public X500NameBuilder AddOrganizationalUnits(params string[] values)
        => Add(Oids.OrganizationalUnitOid, UniversalTagNumber.UTF8String, values);


    public X500NameBuilder AddDomainComponent(string value)
        => Add(Oids.DomainComponentOid, UniversalTagNumber.IA5String, value);


    public X500NameBuilder AddDomainComponents(params string[] values)
        => Add(Oids.DomainComponentOid, UniversalTagNumber.IA5String, values);


    [Obsolete("Obsolete: use Subject Alternative Name extensions instead. If you're using CertificateBuilder then try its SetEmail method.")]
    public X500NameBuilder SetEmail(string value)
        => Set(Oids.EmailAddressOid, UniversalTagNumber.IA5String, value);


    public override string ToString()
        => Create().Name;


    public virtual bool Equals(X500DistinguishedName? other)
        => other != null && Create().RawData.SequenceEqual(other.RawData);
    
    public virtual bool Equals(string? other)
        => other != null && Create().RawData.SequenceEqual(new X500DistinguishedName(other).RawData);


    public bool Equivalent(X500NameBuilder other, bool orderMatters = false)
        => orderMatters
            ? throw new NotImplementedException()
            : ScrambledEquals(RelativeDistinguishedNames, other.RelativeDistinguishedNames, x => (x.OID.Value, x.Value));


    public bool Equivalent(string other, bool orderMatters = false)
        => Equivalent(new X500NameBuilder(other), orderMatters);


    public bool Equivalent(X500DistinguishedName other, bool orderMatters = false)
        => Equivalent(new X500NameBuilder(other), orderMatters);


    public static implicit operator X500DistinguishedName(X500NameBuilder builder) => builder.Create();
    public static explicit operator string(X500NameBuilder builder) => builder.ToString();


    private static bool ScrambledEquals<T,TK>(IEnumerable<T> list1, IEnumerable<T> list2, Func<T,TK> keySelector)
    {
        var cnt = new Dictionary<TK, int>();
        foreach (T s in list1) {
            var k = keySelector(s);
            if (cnt.ContainsKey(k)) {
                cnt[k]++;
            } else {
                cnt.Add(k, 1);
            }
        }
        foreach (T s in list2) {
            var k = keySelector(s);
            if (cnt.ContainsKey(k)) {
                cnt[k]--;
            } else {
                return false;
            }
        }
        return cnt.Values.All(c => c == 0);
    }
}
