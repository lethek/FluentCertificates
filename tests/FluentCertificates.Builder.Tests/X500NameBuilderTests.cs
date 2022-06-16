using System.Collections.Generic;
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
        Assert.Empty(X500NameBuilder.Create().Attributes);
        Assert.Empty(new X500NameBuilder().Attributes);
    }


    [Fact]
    public void Add_Multiple_Matching_Attributes()
    {
        //The multiple assertions below demonstrate alternative, equivalent syntaxes
        const string expected = "DC=app,DC=fake";

        Assert.Equal(expected,
            X500NameBuilder.Create()
                .AddDomainComponent("app")
                .AddDomainComponent("fake")
                .Build()
                .Name
        );

        Assert.Equal(expected,
            X500NameBuilder.Create()
                .AddDomainComponents("app", "fake")
                .Build()
                .Name
        );

        Assert.Equal(expected,
            X500NameBuilder.Create()
                .Add(X509Name.DC, "app")
                .Add(X509Name.DC, "fake")
                .Build()
                .Name
        );

        Assert.Equal(expected,
            X500NameBuilder.Create()
                .Add(X509Name.DC, "app", "fake")
                .Build()
                .Name
        );
    }


    [Fact]
    public void Clear_Removes_All_Attributes()
    {
        var builder = X500NameBuilder.Create()
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

        string actual = X500NameBuilder.Create().SetDomainComponents("app", "fake");

        Assert.Equal(expected, actual);
    }


    [Fact]
    public void Converts_Implicitly_To_X509Name()
    {
        var expected = new X509Name(
            new List<DerObjectIdentifier> { X509Name.DC, X509Name.DC },
            new List<string> { "app", "fake" }
        );

        X509Name actual = X500NameBuilder.Create().SetDomainComponents("app", "fake");

        Assert.Equal(expected, actual);
    }


    [Fact]
    public void Converts_Implicitly_To_X500DistinguishedName()
    {
        var expected = new X500DistinguishedName("DC=app,DC=fake");

        X500DistinguishedName actual = X500NameBuilder.Create().SetDomainComponents("app", "fake");

        Assert.Equal(expected.RawData, actual.RawData);
    }


    [Fact]
    public void Set_Removes_Matching_Attributes_Then_Adds()
    {
        Assert.Equal("DC=app,DC=fake",
            X500NameBuilder.Create()
                .SetDomainComponents("app", "fake")
                .Build()
                .Name
        );

        Assert.Equal("OU=services,DC=app,DC=fake",
            X500NameBuilder.Create()
                .AddOrganizationalUnit("services")
                .AddDomainComponents("old", "domain", "to", "remove")
                .SetDomainComponents("app", "fake")
                .Build()
                .Name
        );
    }


    [Theory]
    [InlineData("CN=Equality_With_X509Name, O=SMMX, C=AU")]
    [InlineData("CN=Equality_With_X509Name,O=SMMX,C=AU")]
    public void Equality_With_X509Name(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName("Equality_With_X509Name")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var name = new X509Name(dn);
        Assert.True(builder == name);
        Assert.True(name == builder);
        Assert.True(builder.Equals(name));
    }


    [Theory]
    [InlineData("O=SMMX, CN=Inequality_With_X509Name, C=AU")]
    [InlineData("O=SMMX,CN=Inequality_With_X509Name,C=AU")]
    public void Inequality_With_X509Name(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName("Inequality_With_X509Name")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var name = new X509Name(dn);
        Assert.True(builder != name);
        Assert.True(name != builder);
        Assert.False(builder.Equals(name));
    }


    [Theory]
    [InlineData("CN=Equality_With_X500DistinguishedName, O=SMMX, C=AU")]
    [InlineData("CN=Equality_With_X500DistinguishedName,O=SMMX,C=AU")]
    public void Equality_With_X500DistinguishedName(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName("Equality_With_X500DistinguishedName")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var name = new X500DistinguishedName(dn);
        Assert.True(builder == name);
        Assert.True(name == builder);
        Assert.True(builder.Equals(name));
    }


    [Theory]
    [InlineData("O=SMMX, CN=Inequality_With_X500DistinguishedName, C=AU")]
    [InlineData("O=SMMX,CN=Inequality_With_X500DistinguishedName,C=AU")]
    public void Inequality_With_X500DistinguishedName(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName("Inequality_With_X500DistinguishedName")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var name = new X500DistinguishedName(dn);
        Assert.True(builder != name);
        Assert.True(name != builder);
        Assert.False(builder.Equals(name));
    }


    [Theory]
    [InlineData("CN=Equality_With_String, O=SMMX, C=AU")]
    [InlineData("CN=Equality_With_String,O=SMMX,C=AU")]
    public void Equality_With_String(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName("Equality_With_String")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        Assert.True(builder == dn);
        Assert.True(dn == builder);
        Assert.True(builder.Equals(dn));
    }


    [Theory]
    [InlineData("O=SMMX, CN=Inequality_With_String, C=AU")]
    [InlineData("O=SMMX,CN=Inequality_With_String,C=AU")]
    public void Inequality_With_String(string dn)
    {
        var builder = new X500NameBuilder()
            .SetCommonName("Inequality_With_String")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        Assert.True(builder != dn);
        Assert.True(dn != builder);
        Assert.False(builder.Equals(dn));
    }
}
