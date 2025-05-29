using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;


/// <summary>
/// Provides a builder for constructing and manipulating X.500 distinguished names,
/// commonly used for X.509 certificate subjects and issuers.
/// </summary>
public record X500NameBuilder
{
    /// <summary>
    /// Initializes a new, empty instance of the <see cref="X500NameBuilder"/> class.
    /// </summary>
    public X500NameBuilder() { }


    /// <summary>
    /// Initializes a new, empty instance of the <see cref="X500NameBuilder"/> class.
    /// </summary>
    public X500NameBuilder(X500DistinguishedName name)
        => RelativeDistinguishedNames = name
            .EnumerateRelativeDistinguishedNames()
            .Select(x => (x.GetSingleElementType(), x.GetSingleElementValueEncoding(), x.GetSingleElementValue()!))
            .ToImmutableList();


    /// <summary>
    /// Initializes a new instance of the <see cref="X500NameBuilder"/> class from a distinguished name string.
    /// </summary>
    /// <param name="name">The distinguished name string.</param>
    public X500NameBuilder(string name)
        : this(new X500DistinguishedName(name))
    { }


    /// <summary>
    /// Gets the list of relative distinguished names (RDNs) as tuples of OID, value encoding, and value.
    /// </summary>
    public ImmutableList<(Oid OID, UniversalTagNumber ValueEncoding, string Value)> RelativeDistinguishedNames { get; init; }
        = ImmutableList<(Oid, UniversalTagNumber, string)>.Empty;


    /// <summary>
    /// Builds and returns an <see cref="X500DistinguishedName"/> from the current RDNs.
    /// </summary>
    /// <returns>The constructed <see cref="X500DistinguishedName"/>.</returns>
    public X500DistinguishedName Create()
    {
        var builder = new X500DistinguishedNameBuilder();
        foreach (var rdn in RelativeDistinguishedNames) {
            builder.Add(rdn.OID, rdn.Value, (UniversalTagNumber?)rdn.ValueEncoding);
        }
        return builder.Build();
    }


    /// <summary>
    /// Returns a new builder with all RDNs removed.
    /// </summary>
    public X500NameBuilder Clear()
        => this with { RelativeDistinguishedNames = RelativeDistinguishedNames.Clear() };


    /// <summary>
    /// Returns a new builder with all RDNs matching the specified OID removed.
    /// </summary>
    /// <param name="oid">The OID to remove.</param>
    public X500NameBuilder Remove(Oid oid)
        => this with {
            RelativeDistinguishedNames = RelativeDistinguishedNames.Where(x => x.OID.Value != oid.Value).ToImmutableList()
        };


    /// <summary>
    /// Returns a new builder with all RDNs matching the specified OID string removed.
    /// </summary>
    /// <param name="oid">The OID string to remove.</param>
    public X500NameBuilder Remove(string oid)
        => Remove(new Oid(oid));


    /// <summary>
    /// Gets the value of the first Common Name (CN) RDN, if present.
    /// </summary>
    public string? GetCommonName()
        => GetFirstMatchingValue(Oids.CommonNameOid);


    /// <summary>
    /// Gets the value of the first Organization (O) RDN, if present.
    /// </summary>
    public string? GetOrganization()
        => GetFirstMatchingValue(Oids.OrganizationOid);


    /// <summary>
    /// Gets the value of the first Country (C) RDN, if present.
    /// </summary>
    public string? GetCountry()
        => GetFirstMatchingValue(Oids.CountryOrRegionNameOid);


    /// <summary>
    /// Gets the value of the first Locality (L) RDN, if present.
    /// </summary>
    public string? GetLocality()
        => GetFirstMatchingValue(Oids.LocalityNameOid);


    /// <summary>
    /// Gets the value of the first Telephone Number RDN, if present.
    /// </summary>
    public string? GetPhoneNumber()
        => GetFirstMatchingValue(Oids.TelephoneNumberOid);


    /// <summary>
    /// Gets the value of the first Street Address RDN, if present.
    /// </summary>
    public string? GetStreetAddress()
        => GetFirstMatchingValue(Oids.StreetAddressOid);


    /// <summary>
    /// Gets the value of the first State or Province (ST) RDN, if present.
    /// </summary>
    public string? GetState()
        => GetFirstMatchingValue(Oids.StateOrProvinceNameOid);


    /// <summary>
    /// Gets the value of the first Postal Code RDN, if present.
    /// </summary>
    public string? GetPostalCode()
        => GetFirstMatchingValue(Oids.PostalCodeOid);


    /// <summary>
    /// Gets the value of the first User ID RDN, if present.
    /// </summary>
    public string? GetUserId()
        => GetFirstMatchingValue(Oids.UserIdOid);


    /// <summary>
    /// Gets the value of the first Serial Number RDN, if present.
    /// </summary>
    public string? GetSerialNumber()
        => GetFirstMatchingValue(Oids.SerialNumberOid);


    /// <summary>
    /// Gets the value of the first Given Name RDN, if present.
    /// </summary>
    public string? GetGivenName()
        => GetFirstMatchingValue(Oids.GivenNameOid);


    /// <summary>
    /// Gets the value of the first Surname RDN, if present.
    /// </summary>
    public string? GetSurname()
        => GetFirstMatchingValue(Oids.SurnameOid);


    /// <summary>
    /// Gets the value of the first Title RDN, if present.
    /// </summary>
    public string? GetTitle()
        => GetFirstMatchingValue(Oids.TitleOid);


    /// <summary>
    /// Gets the value of the first Distinguished Name Qualifier RDN, if present.
    /// </summary>
    public string? GetDistinguishedNameQualifier() 
        => GetFirstMatchingValue(Oids.DnQualifierOid);


    /// <summary>
    /// Gets all values of Organizational Unit (OU) RDNs.
    /// </summary>
    public List<string> GetOrganizationalUnits()
        => GetAllMatchingValues(Oids.OrganizationalUnitOid);


    /// <summary>
    /// Gets all values of Domain Component (DC) RDNs.
    /// </summary>
    public List<string> GetDomainComponents()
        => GetAllMatchingValues(Oids.DomainComponentOid);


    /// <summary>
    /// Gets the value of the first Email Address RDN, if present.
    /// </summary>
    public string? GetEmail()
        => GetFirstMatchingValue(Oids.EmailAddressOid);


    /// <summary>
    /// Gets all values of RDNs matching the specified OID.
    /// </summary>
    /// <param name="oid">The OID to match.</param>
    private List<string> GetAllMatchingValues(Oid oid)
        => RelativeDistinguishedNames
            .Where(x => x.OID.Value == oid.Value)
            .Select(x => x.Value)
            .ToList();


    /// <summary>
    /// Gets the value of the first RDN matching the specified OID, or null if not found.
    /// </summary>
    /// <param name="oid">The OID to match.</param>
    private string? GetFirstMatchingValue(Oid oid)
        => RelativeDistinguishedNames
            .FirstOrDefault(x => x.OID.Value == oid.Value)
            .Value;


    /// <summary>
    /// Returns a new builder with the specified values added as RDNs with the given OID and encoding.
    /// </summary>
    /// <param name="oid">The OID of the RDN.</param>
    /// <param name="valueEncoding">The ASN.1 encoding for the value.</param>
    /// <param name="values">The values to add.</param>
    public X500NameBuilder Add(Oid oid, UniversalTagNumber valueEncoding, params string[] values)
        => this with {
            RelativeDistinguishedNames = RelativeDistinguishedNames.AddRange(
                values
                    .Where(x => x != null)
                    .Select(x => (oid, valueEncoding, x))
            )
        };


    /// <summary>
    /// Returns a new builder with the specified values added as RDNs with the given OID and UTF8 encoding.
    /// </summary>
    /// <param name="oid">The OID of the RDN.</param>
    /// <param name="values">The values to add.</param>
    public X500NameBuilder Add(Oid oid, params string[] values)
        => Add(oid, UniversalTagNumber.UTF8String, values);


    /// <summary>
    /// Returns a new builder with the specified values added as RDNs with the given OID string and encoding.
    /// </summary>
    /// <param name="oid">The OID string of the RDN.</param>
    /// <param name="valueEncoding">The ASN.1 encoding for the value.</param>
    /// <param name="values">The values to add.</param>
    public X500NameBuilder Add(string oid, UniversalTagNumber valueEncoding, params string[] values)
        => Add(new Oid(oid), valueEncoding, values);


    /// <summary>
    /// Returns a new builder with the specified values added as RDNs with the given OID string and UTF8 encoding.
    /// </summary>
    /// <param name="oid">The OID string of the RDN.</param>
    /// <param name="values">The values to add.</param>
    public X500NameBuilder Add(string oid, params string[] values)
        => Add(new Oid(oid), values);


    /// <summary>
    /// Returns a new builder with the specified RDNs set (replacing any existing RDNs with the same OID).
    /// </summary>
    /// <param name="oid">The OID of the RDN.</param>
    /// <param name="valueEncoding">The ASN.1 encoding for the value.</param>
    /// <param name="values">The values to set.</param>
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


    /// <summary>
    /// Returns a new builder with the specified RDNs set (replacing any existing RDNs with the same OID), using UTF8 encoding.
    /// </summary>
    /// <param name="oid">The OID of the RDN.</param>
    /// <param name="values">The values to set.</param>
    public X500NameBuilder Set(Oid oid, params string[] values)
        => Set(oid, UniversalTagNumber.UTF8String, values);


    /// <summary>
    /// Returns a new builder with the specified RDNs set (replacing any existing RDNs with the same OID string and encoding).
    /// </summary>
    /// <param name="oid">The OID string of the RDN.</param>
    /// <param name="valueEncoding">The ASN.1 encoding for the value.</param>
    /// <param name="values">The values to set.</param>
    public X500NameBuilder Set(string oid, UniversalTagNumber valueEncoding = UniversalTagNumber.UTF8String, params string[] values)
        => Set(new Oid(oid), valueEncoding, values);


    /// <summary>
    /// Returns a new builder with the specified RDNs set (replacing any existing RDNs with the same OID string), using UTF8 encoding.
    /// </summary>
    /// <param name="oid">The OID string of the RDN.</param>
    /// <param name="values">The values to set.</param>
    public X500NameBuilder Set(string oid, params string[] values)
        => Set(new Oid(oid), values);


    /// <summary>
    /// Sets the Common Name (CN) RDN to the specified value.
    /// </summary>
    /// <param name="value">The common name value.</param>
    public X500NameBuilder SetCommonName(string value)
        => Set(Oids.CommonNameOid, UniversalTagNumber.UTF8String, value);


    /// <summary>
    /// Sets the Organization (O) RDN to the specified value.
    /// </summary>
    /// <param name="value">The organization value.</param>
    public X500NameBuilder SetOrganization(string value)
        => Set(Oids.OrganizationOid, UniversalTagNumber.UTF8String, value);


    /// <summary>
    /// Sets the Country (C) RDN to the specified value.
    /// </summary>
    /// <param name="value">The country value.</param>
    public X500NameBuilder SetCountry(string value)
        => Set(Oids.CountryOrRegionNameOid, UniversalTagNumber.PrintableString, value);


    /// <summary>
    /// Sets the Locality (L) RDN to the specified value.
    /// </summary>
    /// <param name="value">The locality value.</param>
    public X500NameBuilder SetLocality(string value)
        => Set(Oids.LocalityNameOid, UniversalTagNumber.UTF8String, value);


    /// <summary>
    /// Sets the Telephone Number RDN to the specified value.
    /// </summary>
    /// <param name="value">The phone number value.</param>
    public X500NameBuilder SetPhoneNumber(string value)
        => Set(Oids.TelephoneNumberOid, UniversalTagNumber.PrintableString, value);


    /// <summary>
    /// Sets the Street Address RDN to the specified value.
    /// </summary>
    /// <param name="value">The street address value.</param>
    public X500NameBuilder SetStreetAddress(string value)
        => Set(Oids.StreetAddressOid, UniversalTagNumber.PrintableString, value);


    /// <summary>
    /// Sets the State or Province (ST) RDN to the specified value.
    /// </summary>
    /// <param name="value">The state or province value.</param>
    public X500NameBuilder SetState(string value)
        => Set(Oids.StateOrProvinceNameOid, UniversalTagNumber.UTF8String, value);


    /// <summary>
    /// Sets the Postal Code RDN to the specified value.
    /// </summary>
    /// <param name="value">The postal code value.</param>
    public X500NameBuilder SetPostalCode(string value)
        => Set(Oids.PostalCodeOid, UniversalTagNumber.PrintableString, value);


    /// <summary>
    /// Sets the User ID RDN to the specified value.
    /// </summary>
    /// <param name="value">The user ID value.</param>
    public X500NameBuilder SetUserId(string value)
        => Set(Oids.UserIdOid, value);


    /// <summary>
    /// Sets the Serial Number RDN to the specified value.
    /// </summary>
    /// <param name="value">The serial number value.</param>
    public X500NameBuilder SetSerialNumber(string value)
        => Set(Oids.SerialNumberOid, UniversalTagNumber.PrintableString, value);


    /// <summary>
    /// Sets the Given Name RDN to the specified value.
    /// </summary>
    /// <param name="value">The given name value.</param>
    public X500NameBuilder SetGivenName(string value)
        => Set(Oids.GivenNameOid, UniversalTagNumber.PrintableString, value);


    /// <summary>
    /// Sets the Surname RDN to the specified value.
    /// </summary>
    /// <param name="value">The surname value.</param>
    public X500NameBuilder SetSurname(string value)
        => Set(Oids.SurnameOid, UniversalTagNumber.PrintableString, value);


    /// <summary>
    /// Sets the Title RDN to the specified value.
    /// </summary>
    /// <param name="value">The title value.</param>
    public X500NameBuilder SetTitle(string value)
        => Set(Oids.TitleOid, UniversalTagNumber.UTF8String, value);


    /// <summary>
    /// Sets the Distinguished Name Qualifier RDN to the specified value.
    /// </summary>
    /// <param name="value">The DN qualifier value.</param>
    public X500NameBuilder SetDistinguishedNameQualifier(string value)
        => Set(Oids.DnQualifierOid, UniversalTagNumber.PrintableString, value);


    /// <summary>
    /// Sets the Organizational Unit (OU) RDNs to the specified values.
    /// </summary>
    /// <param name="values">The organizational unit values.</param>
    public X500NameBuilder SetOrganizationalUnits(params string[] values)
        => Set(Oids.OrganizationalUnitOid, UniversalTagNumber.UTF8String, values);


    /// <summary>
    /// Sets the Domain Component (DC) RDNs to the specified values.
    /// </summary>
    /// <param name="values">The domain component values.</param>
    public X500NameBuilder SetDomainComponents(params string[] values)
        => Set(Oids.DomainComponentOid, UniversalTagNumber.IA5String, values);


    /// <summary>
    /// Adds an Organizational Unit (OU) RDN with the specified value.
    /// </summary>
    /// <param name="value">The organizational unit value.</param>
    public X500NameBuilder AddOrganizationalUnit(string value)
        => Add(Oids.OrganizationalUnitOid, UniversalTagNumber.UTF8String, value);


    /// <summary>
    /// Adds Organizational Unit (OU) RDNs with the specified values.
    /// </summary>
    /// <param name="values">The organizational unit values.</param>
    public X500NameBuilder AddOrganizationalUnits(params string[] values)
        => Add(Oids.OrganizationalUnitOid, UniversalTagNumber.UTF8String, values);


    /// <summary>
    /// Adds a Domain Component (DC) RDN with the specified value.
    /// </summary>
    /// <param name="value">The domain component value.</param>
    public X500NameBuilder AddDomainComponent(string value)
        => Add(Oids.DomainComponentOid, UniversalTagNumber.IA5String, value);


    /// <summary>
    /// Adds Domain Component (DC) RDNs with the specified values.
    /// </summary>
    /// <param name="values">The domain component values.</param>
    public X500NameBuilder AddDomainComponents(params string[] values)
        => Add(Oids.DomainComponentOid, UniversalTagNumber.IA5String, values);


    /// <summary>
    /// Sets the Email Address RDN to the specified value.
    /// </summary>
    /// <param name="value">The email address value.</param>
    [Obsolete("Obsolete: use Subject Alternative Name extensions instead. If you're using CertificateBuilder then try its SetEmail method.")]
    public X500NameBuilder SetEmail(string value)
        => Set(Oids.EmailAddressOid, UniversalTagNumber.IA5String, value);


    /// <summary>
    /// Returns the distinguished name as a string.
    /// </summary>
    /// <returns>The distinguished name string.</returns>
    public override string ToString()
        => Create().Name;


    /// <summary>
    /// Determines whether the current builder is equal to the specified <see cref="X500DistinguishedName"/>.
    /// </summary>
    /// <param name="other">The distinguished name to compare.</param>
    /// <returns>True if equal; otherwise, false.</returns>
    public bool Equals(X500DistinguishedName? other)
        => other != null && Create().RawData.SequenceEqual(other.RawData);

    
    /// <summary>
    /// Determines whether the current builder is equal to the specified distinguished name string.
    /// </summary>
    /// <param name="other">The distinguished name string to compare.</param>
    /// <returns>True if equal; otherwise, false.</returns>
    public bool Equals(string? other)
        => other != null && Create().RawData.SequenceEqual(new X500DistinguishedName(other).RawData);


    /// <summary>
    /// Determines whether the current builder is equivalent to another builder, optionally considering order.
    /// </summary>
    /// <param name="other">The other builder to compare.</param>
    /// <param name="orderMatters">Whether order of RDNs matters.</param>
    /// <returns>True if equivalent; otherwise, false.</returns>
    public bool EquivalentTo(X500NameBuilder other, bool orderMatters = false)
        => orderMatters
            ? CheckOrderedEquivalence(RelativeDistinguishedNames, other.RelativeDistinguishedNames, x => (x.OID.Value, x.Value))
            : CheckUnorderedEquivalence(RelativeDistinguishedNames, other.RelativeDistinguishedNames, x => (x.OID.Value, x.Value));


    /// <summary>
    /// Determines whether the current builder is equivalent to the specified distinguished name string, optionally considering order.
    /// </summary>
    /// <param name="other">The distinguished name string to compare.</param>
    /// <param name="orderMatters">Whether order of RDNs matters.</param>
    /// <returns>True if equivalent; otherwise, false.</returns>
    public bool EquivalentTo(string other, bool orderMatters = false)
        => EquivalentTo(new X500NameBuilder(other), orderMatters);


    /// <summary>
    /// Determines whether the current builder is equivalent to the specified <see cref="X500DistinguishedName"/>, optionally considering order.
    /// </summary>
    /// <param name="other">The distinguished name to compare.</param>
    /// <param name="orderMatters">Whether order of RDNs matters.</param>
    /// <returns>True if equivalent; otherwise, false.</returns>
    public bool EquivalentTo(X500DistinguishedName other, bool orderMatters = false)
        => EquivalentTo(new X500NameBuilder(other), orderMatters);


    /// <summary>
    /// Implicitly converts the builder to an <see cref="X500DistinguishedName"/>.
    /// </summary>
    /// <param name="builder">The builder to convert.</param>
    public static implicit operator X500DistinguishedName(X500NameBuilder builder) => builder.Create();
    
    
    /// <summary>
    /// Explicitly converts the builder to a distinguished name string.
    /// </summary>
    /// <param name="builder">The builder to convert.</param>    
    public static explicit operator string(X500NameBuilder builder) => builder.ToString();


    /// <summary>
    /// Checks for ordered equivalence between two lists using a key selector.
    /// </summary>
    /// <typeparam name="T">The element type.</typeparam>
    /// <typeparam name="TK">The key type.</typeparam>
    /// <param name="list1">The first list.</param>
    /// <param name="list2">The second list.</param>
    /// <param name="keySelector">The key selector function.</param>
    /// <returns>True if the lists are equivalent in order; otherwise, false.</returns>
    private static bool CheckOrderedEquivalence<T, TK>(IEnumerable<T> list1, IEnumerable<T> list2, Func<T, TK> keySelector)
        where TK : notnull
    {
        var list1Keys = list1.Select(keySelector);
        var list2Keys = list2.Select(keySelector);
        return list1Keys.SequenceEqual(list2Keys);
    }
    

    /// <summary>
    /// Checks for unordered equivalence between two lists using a key selector.
    /// </summary>
    /// <typeparam name="T">The element type.</typeparam>
    /// <typeparam name="TK">The key type.</typeparam>
    /// <param name="list1">The first list.</param>
    /// <param name="list2">The second list.</param>
    /// <param name="keySelector">The key selector function.</param>
    /// <returns>True if the lists are equivalent regardless of order; otherwise, false.</returns>
    private static bool CheckUnorderedEquivalence<T, TK>(IEnumerable<T> list1, IEnumerable<T> list2, Func<T, TK> keySelector)
        where TK : notnull
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
