using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

using Xunit;

namespace FluentCertificates;

public class X509NameBuilderTests
{
    [Fact]
    public void Add_Multiple_Matching_Attributes()
    {
        //The multiple assertions below demonstrate alternative, equivalent syntaxes
        const string expected = "DC=app,DC=fake";

        Assert.Equal(expected,
            X509NameBuilder.Create()
                .AddDomainComponent("app")
                .AddDomainComponent("fake")
                .Build().ToString()
        );

        Assert.Equal(expected,
            X509NameBuilder.Create()
                .AddDomainComponents("app", "fake")
                .Build().ToString()
        );

        Assert.Equal(expected,
            X509NameBuilder.Create()
                .Add(X509Name.DC, "app")
                .Add(X509Name.DC, "fake")
                .Build().ToString()
        );

        Assert.Equal(expected,
            X509NameBuilder.Create()
                .Add(X509Name.DC, "app", "fake")
                .Build().ToString()
        );
    }


    [Fact]
    public void Clear_Removes_All_Attributes()
    {
        Assert.Empty(
            X509NameBuilder.Create()
                .SetOrganizationalUnits("services")
                .SetDomainComponents("app", "fake")
                .Clear()
                .Build().ToString()
        );
    }


    [Fact]
    public void Converts_Implicitly_To_String()
    {
        const string expected = "DC=app,DC=fake";

        string actual = X509NameBuilder.Create().SetDomainComponents("app", "fake");

        Assert.Equal(expected, actual);
    }


    [Fact]
    public void Converts_Implicitly_To_X509Name()
    {
        var expected = new X509Name(
            new List<DerObjectIdentifier> { X509Name.DC, X509Name.DC },
            new List<string> { "app", "fake" }
        );

        X509Name actual = X509NameBuilder.Create().SetDomainComponents("app", "fake");

        Assert.Equal(expected, actual);
    }


    [Fact]
    public void Set_Removes_Matching_Attributes_Then_Adds()
    {
        Assert.Equal("DC=app,DC=fake",
            X509NameBuilder.Create()
                .SetDomainComponents("app", "fake")
                .Build().ToString()
        );

        Assert.Equal("OU=services,DC=app,DC=fake",
            X509NameBuilder.Create()
                .AddOrganizationalUnit("services")
                .AddDomainComponents("old", "domain", "to", "remove")
                .SetDomainComponents("app", "fake")
                .Build().ToString()
        );
    }


    //[Fact]
    //public void StaticInequality_With_X509Name()
    //{
    //    var name = new X509NameBuilder()
    //        .SetCommonName("Inequality_With_NullX509Name")
    //        .SetOrganization("SMMX")
    //        .SetCountry("AU");

    //    X509Name? other = null;
    //    Assert.True(name == other);
    //    Assert.True(other == name);
    //    Assert.True(name.Equals(other));
    //}



    [Theory]
    [InlineData("CN=Equality_With_X509Name, O=SMMX, C=AU")]
    [InlineData("CN=Equality_With_X509Name,O=SMMX,C=AU")]
    public void Equality_With_X509Name(string dn)
    {
        var name = new X509NameBuilder()
            .SetCommonName("Equality_With_X509Name")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var other = new X509Name(dn);
        Assert.True(name == other);
        Assert.True(other == name);
        Assert.True(name.Equals(other));
    }


    [Theory]
    [InlineData("O=SMMX, CN=Inequality_With_X509Name, C=AU")]
    [InlineData("O=SMMX,CN=Inequality_With_X509Name,C=AU")]
    public void Inequality_With_X509Name(string dn)
    {
        var name = new X509NameBuilder()
            .SetCommonName("Inequality_With_X509Name")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var other = new X509Name(dn);
        Assert.True(name != other);
        Assert.True(other != name);
        Assert.False(name.Equals(other));
    }


    [Theory]
    [InlineData("CN=Equality_With_X500DistinguishedName, O=SMMX, C=AU")]
    [InlineData("CN=Equality_With_X500DistinguishedName,O=SMMX,C=AU")]
    public void Equality_With_X500DistinguishedName(string dn)
    {
        var name = new X509NameBuilder()
            .SetCommonName("Equality_With_X500DistinguishedName")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var other = new X500DistinguishedName(dn);
        Assert.True(name == other);
        Assert.True(other == name);
        Assert.True(name.Equals(other));
    }


    [Theory]
    [InlineData("O=SMMX, CN=Inequality_With_X500DistinguishedName, C=AU")]
    [InlineData("O=SMMX,CN=Inequality_With_X500DistinguishedName,C=AU")]
    public void Inequality_With_X500DistinguishedName(string dn)
    {
        var name = new X509NameBuilder()
            .SetCommonName("Inequality_With_X500DistinguishedName")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        var other = new X500DistinguishedName(dn);
        Assert.True(name != other);
        Assert.True(other != name);
        Assert.False(name.Equals(other));
    }


    [Theory]
    [InlineData("CN=Equality_With_String, O=SMMX, C=AU")]
    [InlineData("CN=Equality_With_String,O=SMMX,C=AU")]
    public void Equality_With_String(string dn)
    {
        var name = new X509NameBuilder()
            .SetCommonName("Equality_With_String")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        Assert.True(name == dn);
        Assert.True(dn == name);
        Assert.True(name.Equals(dn));
    }


    [Theory]
    [InlineData("O=SMMX, CN=Inequality_With_String, C=AU")]
    [InlineData("O=SMMX,CN=Inequality_With_String,C=AU")]
    public void Inequality_With_String(string dn)
    {
        var name = new X509NameBuilder()
            .SetCommonName("Inequality_With_String")
            .SetOrganization("SMMX")
            .SetCountry("AU");

        Assert.True(name != dn);
        Assert.True(dn != name);
        Assert.False(name.Equals(dn));
    }
}
