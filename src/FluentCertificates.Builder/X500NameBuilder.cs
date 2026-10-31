using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

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
    /// Initializes a new instance of the <see cref="X500NameBuilder"/> class from an existing distinguished name.
    /// </summary>
    /// <param name="name">The distinguished name, whose multi-valued relative names and non-string values are kept as they are.</param>
    /// <exception cref="ArgumentNullException"><paramref name="name"/> is null.</exception>
    /// <exception cref="CryptographicException"><paramref name="name"/> is not an ASN.1 Name.</exception>
    public X500NameBuilder(X500DistinguishedName name)
    {
        ArgumentNullException.ThrowIfNull(name);
        RelativeDistinguishedNames = X500NameDer.Read(name.RawData);
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="X500NameBuilder"/> class from a distinguished name string.
    /// </summary>
    /// <param name="name">The distinguished name in the string form defined by RFC 4514, such as <c>CN=Example+OU=Sales,O=Acme</c>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="name"/> is null.</exception>
    /// <exception cref="FormatException"><paramref name="name"/> does not strictly conform to RFC 4514.</exception>
    /// <remarks>
    /// The same string builds the same name on every platform. No spaces are allowed around the separators. Only the keywords CN, L, ST, O, OU, C, STREET,
    /// DC and UID are recognised; write any other attribute type as a dotted OID. Values are encoded as UTF8String,
    /// except for the attributes whose standard fixes another string type: a country, serial number, DN qualifier and
    /// telephone number are PrintableStrings, and a domain component and email address are IA5Strings. A value written as <c>#</c> and hex digits is a BER
    /// encoding, which is kept as raw DER once rewritten as DER, or as a string when it is one.
    /// </remarks>
    public X500NameBuilder(string name)
    {
        RelativeDistinguishedNames = Rfc4514.Parse(name);
    }


    /// <summary>
    /// Gets the relative distinguished names (RDNs), each holding one or more attributes.
    /// </summary>
    /// <remarks>The order is that of the string form, most specific first, so <c>CN=Example,O=Acme,C=AU</c>
    /// lists the common name first. A name is encoded in the reverse of this order.</remarks>
    /// <exception cref="ArgumentNullException">The list, or one of its relative names, is null.</exception>
    /// <exception cref="ArgumentException">A relative name has no attributes.</exception>
    public ImmutableList<X500AttributeSet> RelativeDistinguishedNames
    {
        get => _relativeDistinguishedNames;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            foreach (var relativeName in value) {
                ArgumentNullException.ThrowIfNull(relativeName, nameof(value));
                if (relativeName.Count == 0) {
                    throw new ArgumentException("A relative distinguished name needs at least one attribute.", nameof(value));
                }
            }
            _relativeDistinguishedNames = value;
        }
    }


    /// <summary>
    /// Builds and returns an <see cref="X500DistinguishedName"/> from the current RDNs.
    /// </summary>
    /// <returns>The constructed <see cref="X500DistinguishedName"/>.</returns>
    public X500DistinguishedName Create()
        => X500NameDer.Write(RelativeDistinguishedNames);


    /// <summary>
    /// Returns a new builder with a relative distinguished name holding all of the specified attributes,
    /// as in <c>CN=Example+OU=Sales</c>.
    /// </summary>
    /// <param name="attributes">The attributes of the relative name.</param>
    /// <exception cref="ArgumentNullException"><paramref name="attributes"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="attributes"/> is empty.</exception>
    public X500NameBuilder AddRelativeDistinguishedName(params IEnumerable<X500Attribute> attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        var relativeName = new X500AttributeSet(attributes);
        if (relativeName.Count == 0) {
            throw new ArgumentException("A relative distinguished name needs at least one attribute.", nameof(attributes));
        }
        return this with { RelativeDistinguishedNames = RelativeDistinguishedNames.Add(relativeName) };
    }


    /// <summary>
    /// Returns a new builder with all RDNs removed.
    /// </summary>
    public X500NameBuilder Clear()
        => this with { RelativeDistinguishedNames = RelativeDistinguishedNames.Clear() };


    /// <summary>
    /// Returns a new builder with all attributes matching the specified OID removed.
    /// </summary>
    /// <param name="oid">The OID to remove.</param>
    /// <remarks>A relative name left with no attributes is removed too.</remarks>
    public X500NameBuilder Remove(Oid oid)
        => this with { RelativeDistinguishedNames = [.. GetRelativeNamesWithoutOid(oid)] };


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
        => [
            .. RelativeDistinguishedNames
                .SelectMany(x => x)
                .Where(x => x.OID.Value == oid.Value && x.Value is not null)
                .Select(x => x.Value!)
        ];


    /// <summary>
    /// Gets the value of the first RDN matching the specified OID, or null if not found.
    /// </summary>
    /// <param name="oid">The OID to match.</param>
    private string? GetFirstMatchingValue(Oid oid)
        => RelativeDistinguishedNames
            .SelectMany(x => x)
            .FirstOrDefault(x => x.OID.Value == oid.Value && x.Value is not null)
            ?.Value;


    private static X500DistinguishedName? GetNameFromString(string? name)
    {
        if (name is null) {
            return null;
        }
        try {
            return new X500NameBuilder(name).Create();
        } catch (FormatException) {
            return null;
        }
    }


    private IEnumerable<X500AttributeSet> GetRelativeNamesWithoutOid(Oid oid)
        => RelativeDistinguishedNames
            .Select(x => x.GetSetWithoutOid(oid.Value))
            .Where(x => x.Count > 0);


    //The replacements take the place of the first relative name holding the OID, after whatever else that
    //relative name holds, and are appended only when no relative name held it
    private IEnumerable<X500AttributeSet> GetRelativeNamesWithOidReplaced(Oid oid, List<X500AttributeSet> replacements)
    {
        var placed = false;
        foreach (var relativeName in RelativeDistinguishedNames) {
            var remaining = relativeName.GetSetWithoutOid(oid.Value);
            if (remaining.Count > 0) {
                yield return remaining;
            }
            if (!placed && remaining.Count != relativeName.Count) {
                placed = true;
                foreach (var replacement in replacements) {
                    yield return replacement;
                }
            }
        }
        if (!placed) {
            foreach (var replacement in replacements) {
                yield return replacement;
            }
        }
    }


    private static X500AttributeSet CreateRelativeDistinguishedName(Oid oid, UniversalTagNumber valueEncoding, string value)
        => new([new X500Attribute(oid, valueEncoding, value)]);


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
                    .Select(x => CreateRelativeDistinguishedName(oid, valueEncoding, x))
            )
        };


    /// <summary>
    /// Returns a new builder with the specified values added as RDNs with the given OID.
    /// </summary>
    /// <param name="oid">The OID of the RDN.</param>
    /// <param name="values">The values to add.</param>
    /// <remarks>The values are encoded as the string type the attribute's standard fixes, such as a
    /// PrintableString for a serial number, and as UTF8String for any other attribute.</remarks>
    public X500NameBuilder Add(Oid oid, params string[] values)
        => Add(oid, AttributeEncodings.GetValueEncoding(oid.Value), values);


    /// <summary>
    /// Returns a new builder with the specified values added as RDNs with the given OID string and encoding.
    /// </summary>
    /// <param name="oid">The OID string of the RDN.</param>
    /// <param name="valueEncoding">The ASN.1 encoding for the value.</param>
    /// <param name="values">The values to add.</param>
    public X500NameBuilder Add(string oid, UniversalTagNumber valueEncoding, params string[] values)
        => Add(new Oid(oid), valueEncoding, values);


    /// <summary>
    /// Returns a new builder with the specified values added as RDNs with the given OID string.
    /// </summary>
    /// <param name="oid">The OID string of the RDN.</param>
    /// <param name="values">The values to add.</param>
    /// <remarks>The values are encoded as <see cref="Add(Oid,string[])"/> does.</remarks>
    public X500NameBuilder Add(string oid, params string[] values)
        => Add(new Oid(oid), values);


    /// <summary>
    /// Returns a new builder with the specified RDNs set (replacing any existing RDNs with the same OID).
    /// </summary>
    /// <param name="oid">The OID of the RDN.</param>
    /// <param name="valueEncoding">The ASN.1 encoding for the value.</param>
    /// <param name="values">The values to set.</param>
    /// <remarks>The new RDNs take the position of the first RDN that held the OID, so setting a value again
    /// does not reorder the name. They are appended when nothing held the OID.</remarks>
    public X500NameBuilder Set(Oid oid, UniversalTagNumber valueEncoding, params string[] values)
        => this with {
            RelativeDistinguishedNames = [
                .. GetRelativeNamesWithOidReplaced(
                    oid,
                    [
                        .. values
                            .Where(x => x != null)
                            .Select(x => CreateRelativeDistinguishedName(oid, valueEncoding, x))
                    ]
                )
            ]
        };


    /// <summary>
    /// Returns a new builder with the specified RDNs set (replacing any existing RDNs with the same OID).
    /// </summary>
    /// <param name="oid">The OID of the RDN.</param>
    /// <param name="values">The values to set.</param>
    /// <remarks>The values are encoded as <see cref="Add(Oid,string[])"/> does, and take the position of the
    /// first RDN that held the OID.</remarks>
    public X500NameBuilder Set(Oid oid, params string[] values)
        => Set(oid, AttributeEncodings.GetValueEncoding(oid.Value), values);


    /// <summary>
    /// Returns a new builder with the specified RDNs set (replacing any existing RDNs with the same OID string and encoding).
    /// </summary>
    /// <param name="oid">The OID string of the RDN.</param>
    /// <param name="valueEncoding">The ASN.1 encoding for the value.</param>
    /// <param name="values">The values to set.</param>
    public X500NameBuilder Set(string oid, UniversalTagNumber valueEncoding, params string[] values)
        => Set(new Oid(oid), valueEncoding, values);


    /// <summary>
    /// Returns a new builder with the specified RDNs set (replacing any existing RDNs with the same OID string).
    /// </summary>
    /// <param name="oid">The OID string of the RDN.</param>
    /// <param name="values">The values to set.</param>
    /// <remarks>The values are encoded as <see cref="Set(Oid,string[])"/> does.</remarks>
    public X500NameBuilder Set(string oid, params string[] values)
        => Set(new Oid(oid), values);


    /// <summary>
    /// Sets the Common Name (CN) RDN to the specified value.
    /// </summary>
    /// <param name="value">The common name value.</param>
    public X500NameBuilder SetCommonName(string value)
        => Set(Oids.CommonNameOid, value);


    /// <summary>
    /// Sets the Organization (O) RDN to the specified value.
    /// </summary>
    /// <param name="value">The organization value.</param>
    public X500NameBuilder SetOrganization(string value)
        => Set(Oids.OrganizationOid, value);


    /// <summary>
    /// Sets the Country (C) RDN to the specified value.
    /// </summary>
    /// <param name="value">The country value.</param>
    public X500NameBuilder SetCountry(string value)
        => Set(Oids.CountryOrRegionNameOid, value);


    /// <summary>
    /// Sets the Locality (L) RDN to the specified value.
    /// </summary>
    /// <param name="value">The locality value.</param>
    public X500NameBuilder SetLocality(string value)
        => Set(Oids.LocalityNameOid, value);


    /// <summary>
    /// Sets the Telephone Number RDN to the specified value.
    /// </summary>
    /// <param name="value">The phone number value.</param>
    public X500NameBuilder SetPhoneNumber(string value)
        => Set(Oids.TelephoneNumberOid, value);


    /// <summary>
    /// Sets the Street Address RDN to the specified value.
    /// </summary>
    /// <param name="value">The street address value.</param>
    public X500NameBuilder SetStreetAddress(string value)
        => Set(Oids.StreetAddressOid, value);


    /// <summary>
    /// Sets the State or Province (ST) RDN to the specified value.
    /// </summary>
    /// <param name="value">The state or province value.</param>
    public X500NameBuilder SetState(string value)
        => Set(Oids.StateOrProvinceNameOid, value);


    /// <summary>
    /// Sets the Postal Code RDN to the specified value.
    /// </summary>
    /// <param name="value">The postal code value.</param>
    public X500NameBuilder SetPostalCode(string value)
        => Set(Oids.PostalCodeOid, value);


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
        => Set(Oids.SerialNumberOid, value);


    /// <summary>
    /// Sets the Given Name RDN to the specified value.
    /// </summary>
    /// <param name="value">The given name value.</param>
    public X500NameBuilder SetGivenName(string value)
        => Set(Oids.GivenNameOid, value);


    /// <summary>
    /// Sets the Surname RDN to the specified value.
    /// </summary>
    /// <param name="value">The surname value.</param>
    public X500NameBuilder SetSurname(string value)
        => Set(Oids.SurnameOid, value);


    /// <summary>
    /// Sets the Title RDN to the specified value.
    /// </summary>
    /// <param name="value">The title value.</param>
    public X500NameBuilder SetTitle(string value)
        => Set(Oids.TitleOid, value);


    /// <summary>
    /// Sets the Distinguished Name Qualifier RDN to the specified value.
    /// </summary>
    /// <param name="value">The DN qualifier value.</param>
    public X500NameBuilder SetDistinguishedNameQualifier(string value)
        => Set(Oids.DnQualifierOid, value);


    /// <summary>
    /// Sets the Organizational Unit (OU) RDNs to the specified values.
    /// </summary>
    /// <param name="values">The organizational unit values.</param>
    public X500NameBuilder SetOrganizationalUnits(params string[] values)
        => Set(Oids.OrganizationalUnitOid, values);


    /// <summary>
    /// Sets the Domain Component (DC) RDNs to the specified values.
    /// </summary>
    /// <param name="values">The domain component values.</param>
    public X500NameBuilder SetDomainComponents(params string[] values)
        => Set(Oids.DomainComponentOid, values);


    /// <summary>
    /// Adds an Organizational Unit (OU) RDN with the specified value.
    /// </summary>
    /// <param name="value">The organizational unit value.</param>
    public X500NameBuilder AddOrganizationalUnit(string value)
        => Add(Oids.OrganizationalUnitOid, value);


    /// <summary>
    /// Adds Organizational Unit (OU) RDNs with the specified values.
    /// </summary>
    /// <param name="values">The organizational unit values.</param>
    public X500NameBuilder AddOrganizationalUnits(params string[] values)
        => Add(Oids.OrganizationalUnitOid, values);


    /// <summary>
    /// Adds a Domain Component (DC) RDN with the specified value.
    /// </summary>
    /// <param name="value">The domain component value.</param>
    public X500NameBuilder AddDomainComponent(string value)
        => Add(Oids.DomainComponentOid, value);


    /// <summary>
    /// Adds Domain Component (DC) RDNs with the specified values.
    /// </summary>
    /// <param name="values">The domain component values.</param>
    public X500NameBuilder AddDomainComponents(params string[] values)
        => Add(Oids.DomainComponentOid, values);


    /// <summary>
    /// Sets the Email Address RDN to the specified value.
    /// </summary>
    /// <param name="value">The email address value.</param>
    [Obsolete("Obsolete: use Subject Alternative Name extensions instead. If you're using CertificateBuilder then try its SetEmail method.")]
    public X500NameBuilder SetEmail(string value)
        => Set(Oids.EmailAddressOid, value);


    /// <summary>
    /// Returns the distinguished name as a string.
    /// </summary>
    /// <returns>The distinguished name as a string for display.</returns>
    /// <remarks>The string follows RFC 4514: relative names are listed most specific first with no spaces, a
    /// multi-valued one joins its attributes with <c>+</c>, and any attribute type without an RFC 4514 keyword is
    /// written as an OID. It is meant for display, so conformance is not guaranteed: the value of an attribute
    /// written as an OID is shown as text rather than the <c>#</c> and hex form RFC 4514 section 2.4 specifies.
    /// <see cref="X500NameBuilder(string)"/> reads the result back to an equivalent name, though not always one
    /// with the same string types, so compare with <see cref="EquivalentTo(string,IEqualityComparer{X500DistinguishedName})"/>
    /// rather than <see cref="Equals(string)"/>. To encode a name, use <see cref="Create"/>.</remarks>
    public override string ToString()
        => Rfc4514.Format(RelativeDistinguishedNames);


    /// <summary>
    /// Determines whether the current builder encodes to exactly the specified <see cref="X500DistinguishedName"/>.
    /// </summary>
    /// <param name="other">The distinguished name to compare.</param>
    /// <returns>True if equal; otherwise, false.</returns>
    /// <remarks>Compares the encoded bytes, as <see cref="X500NameComparer.Exact"/> does, so a name spelled
    /// with a different ASN.1 string type is a different name. Use <see cref="EquivalentTo(X500DistinguishedName,IEqualityComparer{X500DistinguishedName})"/>
    /// to compare by anything looser.</remarks>
    public bool Equals(X500DistinguishedName? other)
        => other != null && X500NameComparer.Exact.Equals(Create(), other);


    /// <summary>
    /// Determines whether the current builder encodes to exactly the specified distinguished name string.
    /// </summary>
    /// <param name="other">The distinguished name string to compare.</param>
    /// <returns>True if equal; otherwise, false.</returns>
    /// <remarks>Parses <paramref name="other"/> as <see cref="X500NameBuilder(string)"/> does, then compares
    /// the encoded bytes, as <see cref="X500NameComparer.Exact"/> does. A string that does not strictly conform to
    /// RFC 4514 equals no name. A builder read from an <see cref="X500DistinguishedName"/> keeps the string
    /// types that name used, so it can differ here from the same text parsed.</remarks>
    public bool Equals(string? other)
        => GetNameFromString(other) is { } name && X500NameComparer.Exact.Equals(Create(), name);


    /// <summary>Determines whether another builder holds the same relative distinguished names, in the same
    /// order, with the same value encodings.</summary>
    /// <param name="other">The other builder to compare.</param>
    /// <returns>True if equal; otherwise, false.</returns>
    /// <remarks>This is the record's value equality, so <see cref="ImmutableList{T}"/>'s reference equality
    /// does not stand in for it. It is order- and encoding-sensitive, matching <see cref="Equals(X500DistinguishedName)"/>;
    /// use <see cref="EquivalentTo(X500NameBuilder,IEqualityComparer{X500DistinguishedName})"/> for a comparison
    /// that disregards order.</remarks>
    public virtual bool Equals(X500NameBuilder? other)
    {
        if (other is null || other.GetType() != GetType()) {
            return false;
        }
        if (ReferenceEquals(this, other)) {
            return true;
        }

        return RelativeDistinguishedNames.SequenceEqual(other.RelativeDistinguishedNames);
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var rdn in RelativeDistinguishedNames) {
            hash.Add(rdn);
        }
        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether the current builder describes the same name as another builder.
    /// </summary>
    /// <param name="other">The other builder to compare.</param>
    /// <param name="comparer">How to compare the two names, or null for <see cref="X500NameComparer.Values"/>.</param>
    /// <returns>True if equivalent; otherwise, false.</returns>
    /// <remarks>The default is <see cref="X500NameComparer.Values"/>, so the order of the relative distinguished
    /// names counts, as RFC 5280 section 7.1 requires. Pass <see cref="X500NameComparer.ValuesAnyOrder"/> to disregard it.</remarks>
    public bool EquivalentTo(X500NameBuilder other, IEqualityComparer<X500DistinguishedName>? comparer = null)
        => (comparer ?? X500NameComparer.Values).Equals(Create(), other.Create());


    /// <summary>
    /// Determines whether the current builder describes the same name as the specified distinguished name string.
    /// </summary>
    /// <param name="other">The distinguished name string to compare.</param>
    /// <param name="comparer">How to compare the two names, or null for <see cref="X500NameComparer.Values"/>.</param>
    /// <returns>True if equivalent; otherwise, false.</returns>
    /// <remarks>A string that does not strictly conform to RFC 4514 is equivalent to no name.</remarks>
    public bool EquivalentTo(string? other, IEqualityComparer<X500DistinguishedName>? comparer = null)
        => GetNameFromString(other) is { } name && EquivalentTo(name, comparer);


    /// <summary>
    /// Determines whether the current builder describes the same name as the specified <see cref="X500DistinguishedName"/>.
    /// </summary>
    /// <param name="other">The distinguished name to compare.</param>
    /// <param name="comparer">How to compare the two names, or null for <see cref="X500NameComparer.Values"/>.</param>
    /// <returns>True if equivalent; otherwise, false.</returns>
    public bool EquivalentTo(X500DistinguishedName other, IEqualityComparer<X500DistinguishedName>? comparer = null)
        => (comparer ?? X500NameComparer.Values).Equals(Create(), other);


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


    private readonly ImmutableList<X500AttributeSet> _relativeDistinguishedNames = ImmutableList<X500AttributeSet>.Empty;
}
