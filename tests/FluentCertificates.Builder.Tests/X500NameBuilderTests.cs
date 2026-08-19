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
                .Add(X509Name.DC, UniversalTagNumber.IA5String, "app")
                .Add(X509Name.DC, UniversalTagNumber.IA5String, "fake")
                .RelativeDistinguishedNames)
            .IsEquivalentTo(expected, X500RdnTupleComparer, CollectionOrdering.Matching);

        await Assert
            .That(new X500NameBuilder()
                .Add(X509Name.DC, UniversalTagNumber.IA5String, "app", "fake")
                .RelativeDistinguishedNames)
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


    private static readonly IEqualityComparer<(Oid, UniversalTagNumber, string)> X500RdnTupleComparer
        = new DelegateEqualityComparer<(Oid OID, UniversalTagNumber ValueEncoding, string Value)>(
            (x, y) =>
                x.OID.Value == y.OID.Value &&
                x.ValueEncoding == y.ValueEncoding &&
                x.Value == y.Value
        );
}
