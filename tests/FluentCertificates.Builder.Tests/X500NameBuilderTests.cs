using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1.X509;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class X500NameBuilderTests
{
    [Test]
    public async Task Create_Empty_Builder()
    {
        var builder = new X500NameBuilder();
        await Assert.That(builder.RelativeDistinguishedNames).IsEmpty();
        await Assert.That(builder.ToString()).IsEmpty();
    }


    [Test]
    public async Task Create_Builder_FromString()
    {
        const string expected = "DC=app, DC=fake";
        await Assert.That(new X500NameBuilder(expected).ToString()).IsEqualTo(expected);
    }


    [Test]
    public async Task Create_Builder_FromX509Name()
    {
        const string expected = "DC=app, DC=fake";
        await Assert.That(new X500NameBuilder(new X509Name(expected).ConvertToDotNet()).ToString()).IsEqualTo(expected);
    }


    [Test]
    public async Task Create_Builder_FromX500DistinguishedName()
    {
        const string expected = "DC=app, DC=fake";
        await Assert.That(new X500NameBuilder(new X500DistinguishedName(expected)).ToString()).IsEqualTo(expected);
    }


    [Test]
    public async Task Add_Multiple_Matching_Attributes()
    {
        var dcOid = Oid.FromFriendlyName("DC", OidGroup.Attribute);
        var expected = new[] {
            (dcOid, UniversalTagNumber.IA5String, "app"),
            (dcOid, UniversalTagNumber.IA5String, "fake")
        };

        //All of the assertions below demonstrate equivalent, alternative syntaxes

        await Assert
            .That(new X500NameBuilder().AddDomainComponent("app").AddDomainComponent("fake").RelativeDistinguishedNames)
            .IsEquivalentTo(expected, X500RdnTupleComparer, CollectionOrdering.Matching);

        await Assert
            .That(new X500NameBuilder().AddDomainComponents("app", "fake").RelativeDistinguishedNames)
            .IsEquivalentTo(expected, X500RdnTupleComparer, CollectionOrdering.Matching);

        await Assert
            .That(new X500NameBuilder()
                .Add(dcOid, UniversalTagNumber.IA5String, "app")
                .Add(dcOid, UniversalTagNumber.IA5String, "fake")
                .RelativeDistinguishedNames)
            .IsEquivalentTo(expected, X500RdnTupleComparer, CollectionOrdering.Matching);

        //Specify OID by an Oid instance
        await Assert
            .That(new X500NameBuilder()
                .Add(dcOid, UniversalTagNumber.IA5String, "app", "fake")
                .RelativeDistinguishedNames)
            .IsEquivalentTo(expected, X500RdnTupleComparer, CollectionOrdering.Matching);

        //Specify OID by its friendly-name string
        await Assert
            .That(new X500NameBuilder()
                .Add("DC", UniversalTagNumber.IA5String, "app", "fake")
                .RelativeDistinguishedNames)
            .IsEquivalentTo(expected, X500RdnTupleComparer, CollectionOrdering.Matching);

        //Specify OID by its value string
        await Assert
            .That(new X500NameBuilder()
                .Add("0.9.2342.19200300.100.1.25", UniversalTagNumber.IA5String, "app", "fake")
                .RelativeDistinguishedNames)
            .IsEquivalentTo(expected, X500RdnTupleComparer, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Clear_Removes_All_Attributes()
    {
        var builder = new X500NameBuilder()
            .SetOrganizationalUnits("services")
            .SetDomainComponents("app", "fake")
            .Clear();

        await Assert.That(builder.RelativeDistinguishedNames).IsEmpty();
        await Assert.That(builder.Create().Name).IsEmpty();
    }


    [Test]
    public async Task Converts_Implicitly_To_String()
    {
        const string expected = "DC=app, DC=fake";

        var actual = (string)new X500NameBuilder().SetDomainComponents("app", "fake");

        await Assert.That(actual).IsEqualTo(expected);
    }


    [Test]
    public async Task Converts_Implicitly_To_X500DistinguishedName()
    {
        var expected = new X500DistinguishedName("DC=app, DC=fake");

        X500DistinguishedName actual = new X500NameBuilder().SetDomainComponents("app", "fake");

        await Assert
            .That(actual.Decode(X500DistinguishedNameFlags.Reversed))
            .IsEqualTo(expected.Decode(X500DistinguishedNameFlags.Reversed));
    }


    [Test]
    public async Task Set_Removes_Matching_Attributes_Then_Adds()
    {
        await Assert
            .That(new X500NameBuilder()
                .SetDomainComponents("app", "fake")
                .Create()
                .Name)
            .IsEqualTo("DC=app, DC=fake");

        await Assert
            .That(new X500NameBuilder()
                .AddOrganizationalUnit("services")
                .AddDomainComponents("old", "domain", "to", "remove")
                .SetDomainComponents("app", "fake")
                .Create()
                .Name)
            .IsEqualTo("OU=services, DC=app, DC=fake");
    }


    [Test]
    [Arguments($"CN={nameof(Equality_With_X500DistinguishedName)}, O=SMMX, C=AU")]
    [Arguments($"CN={nameof(Equality_With_X500DistinguishedName)},O=SMMX,C=AU")]
    public async Task Equality_With_X500DistinguishedName(string dn)
    {
        var rightOrder = new X500NameBuilder()
            .SetCommonName(nameof(Equality_With_X500DistinguishedName))
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var wrongOrder = new X500NameBuilder()
            .SetOrganization("SMMX")
            .SetCommonName(nameof(Equality_With_X500DistinguishedName))
            .SetCountry("AU");

        var name = new X500DistinguishedName(dn);
        await Assert.That(rightOrder.EquivalentTo(name, true)).IsTrue();
        await Assert.That(wrongOrder.EquivalentTo(name, false)).IsTrue();
    }


    [Test]
    [Arguments($"CN={nameof(Inequality_With_X500DistinguishedName)}, O=SMMX, C=AU")]
    [Arguments($"CN={nameof(Inequality_With_X500DistinguishedName)},O=SMMX,C=AU")]
    public async Task Inequality_With_X500DistinguishedName(string dn)
    {
        var wrongOrder = new X500NameBuilder()
            .SetOrganization("SMMX")
            .SetCommonName(nameof(Inequality_With_X500DistinguishedName))
            .SetCountry("AU");

        var name = new X500DistinguishedName(dn);
        await Assert.That(wrongOrder.EquivalentTo(name, true)).IsFalse();
    }


    [Test]
    [Arguments($"CN={nameof(Equality_With_String)}, O=SMMX, C=AU")]
    [Arguments($"CN={nameof(Equality_With_String)},O=SMMX,C=AU")]
    public async Task Equality_With_String(string dn)
    {
        var rightOrder = new X500NameBuilder()
            .SetCommonName(nameof(Equality_With_String))
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var wrongOrder = new X500NameBuilder()
            .SetOrganization("SMMX")
            .SetCommonName(nameof(Equality_With_String))
            .SetCountry("AU");

        await Assert.That(rightOrder.EquivalentTo(dn, true)).IsTrue();
        await Assert.That(wrongOrder.EquivalentTo(dn, false)).IsTrue();
    }


    [Test]
    [Arguments($"CN={nameof(Inequality_With_String)}, O=SMMX, C=AU")]
    [Arguments($"CN={nameof(Inequality_With_String)},O=SMMX,C=AU")]
    public async Task Inequality_With_String(string dn)
    {
        var wrongOrder = new X500NameBuilder()
            .SetOrganization("SMMX")
            .SetCommonName(nameof(Inequality_With_String))
            .SetCountry("AU");

        await Assert.That(wrongOrder.EquivalentTo(dn, true)).IsFalse();
    }


    [Test]
    public async Task Equals_Null_ReturnsFalse()
    {
        var builder = new X500NameBuilder().SetCommonName("Null Test");

        await Assert.That(builder.Equals((X500DistinguishedName?)null)).IsFalse();
        await Assert.That(builder.Equals((string?)null)).IsFalse();
    }


    [Test]
    public async Task EquivalentTo_RepeatedRelativeDistinguishedNames_ComparesMultiplicity()
    {
        var twice = new X500NameBuilder().AddOrganizationalUnits("Eng", "Eng");
        var alsoTwice = new X500NameBuilder().AddOrganizationalUnits("Eng", "Eng");
        var once = new X500NameBuilder().AddOrganizationalUnit("Eng");

        //A repeated RDN is not the same as a single one: the comparison counts occurrences
        await Assert.That(twice.EquivalentTo(alsoTwice)).IsTrue();
        await Assert.That(twice.EquivalentTo(once)).IsFalse();
        await Assert.That(once.EquivalentTo(twice)).IsFalse();
    }


    [Test]
    public async Task Getters_ReturnTheMatchingRelativeDistinguishedNameValues()
    {
        //SetEmail is obsolete in favour of a SAN rfc822Name, but the getter still has to read
        //an emailAddress RDN that an existing name carries
#pragma warning disable CS0618 // Type or member is obsolete
        var builder = new X500NameBuilder()
            .SetCommonName("Common")
            .SetOrganization("Org")
            .SetCountry("AU")
            .SetLocality("Brisbane")
            .SetState("QLD")
            .SetPostalCode("4000")
            .SetStreetAddress("1 Example St")
            .SetPhoneNumber("+61700000000")
            .SetUserId("uid-1")
            .SetSerialNumber("SN-1")
            .SetGivenName("Given")
            .SetSurname("Sur")
            .SetTitle("Title")
            .SetDistinguishedNameQualifier("Qualifier")
            .SetEmail("user@example.com")
            .AddOrganizationalUnits("Eng", "Ops")
            .AddDomainComponents("example", "com");
#pragma warning restore CS0618 // Type or member is obsolete

        await Assert.That(builder.GetCommonName()).IsEqualTo("Common");
        await Assert.That(builder.GetOrganization()).IsEqualTo("Org");
        await Assert.That(builder.GetCountry()).IsEqualTo("AU");
        await Assert.That(builder.GetLocality()).IsEqualTo("Brisbane");
        await Assert.That(builder.GetState()).IsEqualTo("QLD");
        await Assert.That(builder.GetPostalCode()).IsEqualTo("4000");
        await Assert.That(builder.GetStreetAddress()).IsEqualTo("1 Example St");
        await Assert.That(builder.GetPhoneNumber()).IsEqualTo("+61700000000");
        await Assert.That(builder.GetUserId()).IsEqualTo("uid-1");
        await Assert.That(builder.GetSerialNumber()).IsEqualTo("SN-1");
        await Assert.That(builder.GetGivenName()).IsEqualTo("Given");
        await Assert.That(builder.GetSurname()).IsEqualTo("Sur");
        await Assert.That(builder.GetTitle()).IsEqualTo("Title");
        await Assert.That(builder.GetDistinguishedNameQualifier()).IsEqualTo("Qualifier");
        await Assert.That(builder.GetEmail()).IsEqualTo("user@example.com");

        //The multi-valued getters return every match, in order, rather than only the first
        await Assert.That(builder.GetOrganizationalUnits()).IsEquivalentTo(["Eng", "Ops"]);
        await Assert.That(builder.GetDomainComponents()).IsEquivalentTo(["example", "com"]);
    }


    [Test]
    public async Task Getters_ReturnNullOrEmptyWhenAbsent()
    {
        var builder = new X500NameBuilder();

        await Assert.That(builder.GetCommonName()).IsNull();
        await Assert.That(builder.GetEmail()).IsNull();
        await Assert.That(builder.GetOrganizationalUnits()).IsEmpty();
    }


    [Test]
    public async Task Remove_DropsEveryRelativeDistinguishedNameWithThatOid()
    {
        var builder = new X500NameBuilder()
            .SetCommonName("Common")
            .AddOrganizationalUnits("Eng", "Ops");

        var byOid = builder.Remove(Oids.OrganizationalUnitOid);
        var byString = builder.Remove(Oids.OrganizationalUnitOid.Value!);

        await Assert.That(byOid.GetOrganizationalUnits()).IsEmpty();
        await Assert.That(byOid.GetCommonName()).IsEqualTo("Common");
        await Assert.That(byString.GetOrganizationalUnits()).IsEmpty();

        //The builder is immutable, so the original still holds both units
        await Assert.That(builder.GetOrganizationalUnits()).IsEquivalentTo(["Eng", "Ops"]);
    }


    [Test]
    public async Task EquivalentTo_SameCountDifferentValues_IsFalse()
    {
        var a = new X500NameBuilder().SetCommonName("A");
        var b = new X500NameBuilder().SetCommonName("B");

        await Assert.That(a.EquivalentTo(b)).IsFalse();
        await Assert.That(b.EquivalentTo(a)).IsFalse();
    }


    /// <summary>
    /// Same length and same set of OIDs and values, but different multiplicities, so some per-key
    /// tallies land on zero and others do not. Equivalence requires every tally to be zero.
    /// </summary>
    [Test]
    public async Task EquivalentTo_SameValuesWithDifferentMultiplicities_IsFalse()
    {
        var a = new X500NameBuilder().AddOrganizationalUnits("A", "A", "B", "C");
        var b = new X500NameBuilder().AddOrganizationalUnits("A", "B", "B", "C");

        await Assert.That(a.EquivalentTo(b)).IsFalse();
        await Assert.That(b.EquivalentTo(a)).IsFalse();
    }


    [Test]
    public async Task Add_WithoutAnEncoding_DefaultsToUtf8String()
    {
        var ou = Oids.OrganizationalUnitOid;
        var expected = new[] {
            (ou, UniversalTagNumber.UTF8String, "Eng"),
            (ou, UniversalTagNumber.UTF8String, "Ops")
        };

        //By Oid instance and by OID value string, which are the two overloads that take no encoding
        await Assert
            .That(new X500NameBuilder().Add(ou, "Eng", "Ops").RelativeDistinguishedNames)
            .IsEquivalentTo(expected, X500RdnTupleComparer, CollectionOrdering.Matching);

        await Assert
            .That(new X500NameBuilder().Add(ou.Value!, "Eng", "Ops").RelativeDistinguishedNames)
            .IsEquivalentTo(expected, X500RdnTupleComparer, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Set_ByOid_ReplacesOnlyTheMatchingAttributes()
    {
        var ou = Oids.OrganizationalUnitOid;

        //An explicit encoding, given the OID as a string
        var withEncoding = new X500NameBuilder()
            .SetCommonName("Common")
            .AddOrganizationalUnits("old", "units")
            .Set(ou.Value!, UniversalTagNumber.PrintableString, "Eng", "Ops");

        await Assert.That(withEncoding.GetOrganizationalUnits()).IsEquivalentTo(["Eng", "Ops"], CollectionOrdering.Matching);
        await Assert.That(withEncoding.GetCommonName()).IsEqualTo("Common");
        await Assert
            .That(withEncoding.RelativeDistinguishedNames.Where(x => x.OID.Value == ou.Value).Select(x => x.ValueEncoding))
            .IsEquivalentTo([UniversalTagNumber.PrintableString, UniversalTagNumber.PrintableString], CollectionOrdering.Matching);

        //The default encoding, given the OID as a string and as an Oid instance
        var byString = new X500NameBuilder().AddOrganizationalUnits("old", "units").Set(ou.Value!, "Eng", "Ops");
        var byOid = new X500NameBuilder().AddOrganizationalUnits("old", "units").Set(ou, "Eng", "Ops");

        foreach (var builder in new[] { byString, byOid }) {
            await Assert.That(builder.GetOrganizationalUnits()).IsEquivalentTo(["Eng", "Ops"], CollectionOrdering.Matching);
            await Assert
                .That(builder.RelativeDistinguishedNames.Select(x => x.ValueEncoding))
                .IsEquivalentTo([UniversalTagNumber.UTF8String, UniversalTagNumber.UTF8String], CollectionOrdering.Matching);
        }
    }


    private static readonly IEqualityComparer<(Oid, UniversalTagNumber, string)> X500RdnTupleComparer
        = new DelegateEqualityComparer<(Oid OID, UniversalTagNumber ValueEncoding, string Value)>(
            (x, y) =>
                x.OID.Value == y.OID.Value &&
                x.ValueEncoding == y.ValueEncoding &&
                x.Value == y.Value
        );
}
