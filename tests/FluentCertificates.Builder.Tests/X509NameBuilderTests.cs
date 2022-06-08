using System.Collections.Generic;

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
}
