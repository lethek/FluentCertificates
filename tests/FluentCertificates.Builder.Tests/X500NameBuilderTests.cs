using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

using Xunit;

namespace FluentCertificates;

public class X500NameBuilderTests
{
    [Fact]
    public void Create_Empty_Builder()
    {
        Assert.Empty(new X500NameBuilder().Attributes);
    }


    [Fact]
    public void Create_Builder_FromString()
    {
        const string expected = "DC=app,DC=fake";
        var builder = new X500NameBuilder(expected);
        Assert.Equal(expected, builder.ToString());
        
        //builder.Attributes.SequenceEqual(builder.Attributes, )

    }


    [Fact]
    public void Create_Builder_FromX509Name()
    {
        const string expected = "DC=app,DC=fake";
        Assert.Equal(expected, new X500NameBuilder(new X509Name(expected)).ToString());
    }


    [Fact]
    public void Create_Builder_FromX500DistinguishedName()
    {
        const string expected = "DC=app,DC=fake";
        Assert.Equal(expected, new X500NameBuilder(new X500DistinguishedName(expected)).ToString());
    }


    [Fact]
    public void Add_Multiple_Matching_Attributes()
    {
        var dcOid = Oid.FromFriendlyName("DC", OidGroup.Attribute);
        var exp = new[] {
            (dcOid, "app"),
            (dcOid, "fake")
        };

        //All of the assertions below demonstrate equivalent, alternative syntaxes

        Assert.Equal(
            exp, 
            new X500NameBuilder().AddDomainComponent("app").AddDomainComponent("fake").Attributes,
            X500AttributeTupleComparer
        );

        Assert.Equal(
            exp,
            new X500NameBuilder().AddDomainComponents("app", "fake").Attributes,
            X500AttributeTupleComparer
        );

        Assert.Equal(
            exp,
            new X500NameBuilder().Add(X509Name.DC, "app").Add(X509Name.DC, "fake").Attributes,
            X500AttributeTupleComparer
        );

        Assert.Equal(
            exp,
            new X500NameBuilder().Add(X509Name.DC, "app", "fake").Attributes,
            X500AttributeTupleComparer
        );

        Assert.Equal(
            exp,
            new X500NameBuilder().Add(dcOid, "app").Add(dcOid, "fake").Attributes,
            X500AttributeTupleComparer
        );

        //Specify OID by an Oid instance
        Assert.Equal(
            exp,
            new X500NameBuilder().Add(dcOid, "app", "fake").Attributes,
            X500AttributeTupleComparer
        );

        //Specify OID by its friendly-name string
        Assert.Equal(
            exp,
            new X500NameBuilder().Add("DC", "app", "fake").Attributes,
            X500AttributeTupleComparer
        );
        
        //Specify OID by its value string
        Assert.Equal(
            exp,
            new X500NameBuilder().Add("0.9.2342.19200300.100.1.25", "app", "fake").Attributes,
            X500AttributeTupleComparer
        );
    }


    [Fact]
    public void Clear_Removes_All_Attributes()
    {
        var builder = new X500NameBuilder()
            .SetOrganizationalUnits("services")
            .SetDomainComponents("app", "fake")
            .Clear();

        Assert.Empty(builder.Attributes);
        Assert.Empty(builder.Build().Name);
    }


    [Fact]
    public void Converts_Implicitly_To_String()
    {
        const string expected = "DC=app,DC=fake";

        string actual = new X500NameBuilder().SetDomainComponents("app", "fake");

        Assert.Equal(expected, actual);
    }


    [Fact]
    public void Converts_Implicitly_To_X509Name()
    {
        var expected = new X509Name(
            new List<DerObjectIdentifier> { X509Name.DC, X509Name.DC },
            new List<string> { "app", "fake" }
        );

        X509Name actual = new X500NameBuilder().SetDomainComponents("app", "fake");

        Assert.Equal(expected, actual);
    }


    [Fact]
    public void Converts_Implicitly_To_X500DistinguishedName()
    {
        var expected = new X500DistinguishedName("DC=app,DC=fake");

        X500DistinguishedName actual = new X500NameBuilder().SetDomainComponents("app", "fake");

        Assert.Equal(expected.RawData, actual.RawData);
    }


    [Fact]
    public void Set_Removes_Matching_Attributes_Then_Adds()
    {
        Assert.Equal("DC=app,DC=fake",
            new X500NameBuilder()
                .SetDomainComponents("app", "fake")
                .Build()
                .Name
        );

        Assert.Equal("OU=services,DC=app,DC=fake",
            new X500NameBuilder()
                .AddOrganizationalUnit("services")
                .AddDomainComponents("old", "domain", "to", "remove")
                .SetDomainComponents("app", "fake")
                .Build()
                .Name
        );
    }


    [Theory]
    [InlineData($"CN={nameof(Equality_With_X509Name)}, O=SMMX, C=AU")]
    [InlineData($"CN={nameof(Equality_With_X509Name)},O=SMMX,C=AU")]
    public void Equality_With_X509Name(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName(nameof(Equality_With_X509Name))
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var name = new X509Name(dn);
        Assert.True(builder == name);
        Assert.True(name == builder);
        Assert.True(builder.Equals(name));
    }


    [Theory]
    [InlineData($"O=SMMX, CN={nameof(Inequality_With_X509Name)}, C=AU")]
    [InlineData($"O=SMMX,CN={nameof(Inequality_With_X509Name)},C=AU")]
    public void Inequality_With_X509Name(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName(nameof(Inequality_With_X509Name))
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var name = new X509Name(dn);
        Assert.True(builder != name);
        Assert.True(name != builder);
        Assert.False(builder.Equals(name));
    }


    [Theory]
    [InlineData($"CN={nameof(Equality_With_X500DistinguishedName)}, O=SMMX, C=AU")]
    [InlineData($"CN={nameof(Equality_With_X500DistinguishedName)},O=SMMX,C=AU")]
    public void Equality_With_X500DistinguishedName(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName(nameof(Equality_With_X500DistinguishedName))
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var name = new X500DistinguishedName(dn);
        Assert.True(builder == name);
        Assert.True(name == builder);
        Assert.True(builder.Equals(name));
    }


    [Theory]
    [InlineData($"O=SMMX, CN={nameof(Inequality_With_X500DistinguishedName)}, C=AU")]
    [InlineData($"O=SMMX,CN={nameof(Inequality_With_X500DistinguishedName)},C=AU")]
    public void Inequality_With_X500DistinguishedName(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName(nameof(Inequality_With_X500DistinguishedName))
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var name = new X500DistinguishedName(dn);
        Assert.True(builder != name);
        Assert.True(name != builder);
        Assert.False(builder.Equals(name));
    }


    [Theory]
    [InlineData($"CN={nameof(Equality_With_String)}, O=SMMX, C=AU")]
    [InlineData($"CN={nameof(Equality_With_String)},O=SMMX,C=AU")]
    public void Equality_With_String(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName(nameof(Equality_With_String))
            .SetOrganization("SMMX")
            .SetCountry("AU");

        Assert.True(builder == dn);
        Assert.True(dn == builder);
        Assert.True(builder.Equals(dn));
    }


    [Theory]
    [InlineData($"O=SMMX, CN={nameof(Inequality_With_String)}, C=AU")]
    [InlineData($"O=SMMX,CN={nameof(Inequality_With_String)},C=AU")]
    public void Inequality_With_String(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName(nameof(Inequality_With_String))
            .SetOrganization("SMMX")
            .SetCountry("AU");

        Assert.True(builder != dn);
        Assert.True(dn != builder);
        Assert.False(builder.Equals(dn));
    }


    private static readonly IEqualityComparer<(Oid, string)> X500AttributeTupleComparer
        = new DelegateEqualityComparer<(Oid OID, string Value)>(
            (x, y) => x.OID.Value == y.OID.Value && x.Value == y.Value
        );
}
