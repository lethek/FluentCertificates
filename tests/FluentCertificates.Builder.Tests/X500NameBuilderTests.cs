﻿using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using Org.BouncyCastle.Asn1.X509;

using Xunit;

namespace FluentCertificates;

public class X500NameBuilderTests
{
    [Fact]
    public void Create_Empty_Builder()
    {
        var builder = new X500NameBuilder();
        Assert.Empty(builder.RelativeDistinguishedNames);
        Assert.Empty(builder.ToString());
    }


    [Fact]
    public void Create_Builder_FromString()
    {
        const string expected = "DC=app, DC=fake";
        Assert.Equal(expected, new X500NameBuilder(expected).ToString());
    }


    [Fact]
    public void Create_Builder_FromX509Name()
    {
        const string expected = "DC=app, DC=fake";
        Assert.Equal(expected, new X500NameBuilder(new X509Name(expected).ConvertToDotNet()).ToString());
    }


    [Fact]
    public void Create_Builder_FromX500DistinguishedName()
    {
        const string expected = "DC=app, DC=fake";
        Assert.Equal(expected, new X500NameBuilder(new X500DistinguishedName(expected)).ToString());
    }


    [Fact]
    public void Add_Multiple_Matching_Attributes()
    {
        var dcOid = Oid.FromFriendlyName("DC", OidGroup.Attribute);
        var expected = new[] {
            (dcOid, UniversalTagNumber.IA5String, "app"),
            (dcOid, UniversalTagNumber.IA5String, "fake")
        };

        //All of the assertions below demonstrate equivalent, alternative syntaxes

        Assert.Equal(
            expected, 
            new X500NameBuilder().AddDomainComponent("app").AddDomainComponent("fake").RelativeDistinguishedNames,
            X500RDNTupleComparer
        );

        Assert.Equal(
            expected,
            new X500NameBuilder().AddDomainComponents("app", "fake").RelativeDistinguishedNames,
            X500RDNTupleComparer
        );

        Assert.Equal(
            expected,
            new X500NameBuilder()
                .Add(X509Name.DC, UniversalTagNumber.IA5String, "app")
                .Add(X509Name.DC, UniversalTagNumber.IA5String, "fake")
                .RelativeDistinguishedNames,
            X500RDNTupleComparer
        );

        Assert.Equal(
            expected,
            new X500NameBuilder()
                .Add(X509Name.DC, UniversalTagNumber.IA5String, "app", "fake")
                .RelativeDistinguishedNames,
            X500RDNTupleComparer
        );

        Assert.Equal(
            expected,
            new X500NameBuilder()
                .Add(dcOid, UniversalTagNumber.IA5String, "app")
                .Add(dcOid, UniversalTagNumber.IA5String, "fake")
                .RelativeDistinguishedNames,
            X500RDNTupleComparer
        );

        //Specify OID by an Oid instance
        Assert.Equal(
            expected,
            new X500NameBuilder()
                .Add(dcOid, UniversalTagNumber.IA5String, "app", "fake")
                .RelativeDistinguishedNames,
            X500RDNTupleComparer
        );

        //Specify OID by its friendly-name string
        Assert.Equal(
            expected,
            new X500NameBuilder()
                .Add("DC", UniversalTagNumber.IA5String, "app", "fake")
                .RelativeDistinguishedNames,
            X500RDNTupleComparer
        );
        
        //Specify OID by its value string
        Assert.Equal(
            expected,
            new X500NameBuilder()
                .Add("0.9.2342.19200300.100.1.25", UniversalTagNumber.IA5String, "app", "fake")
                .RelativeDistinguishedNames,
            X500RDNTupleComparer
        );
    }


    [Fact]
    public void Clear_Removes_All_Attributes()
    {
        var builder = new X500NameBuilder()
            .SetOrganizationalUnits("services")
            .SetDomainComponents("app", "fake")
            .Clear();

        Assert.Empty(builder.RelativeDistinguishedNames);
        Assert.Empty(builder.Create().Name);
    }


    [Fact]
    public void Converts_Implicitly_To_String()
    {
        const string expected = "DC=app, DC=fake";

        string actual = (string)new X500NameBuilder().SetDomainComponents("app", "fake");

        Assert.Equal(expected, actual);
    }


    [Fact]
    public void Converts_Implicitly_To_X500DistinguishedName()
    {
        var expected = new X500DistinguishedName("DC=app, DC=fake");

        X500DistinguishedName actual = new X500NameBuilder().SetDomainComponents("app", "fake");

        Assert.Equal(expected.RawData, actual.RawData);
    }


    [Fact]
    public void Set_Removes_Matching_Attributes_Then_Adds()
    {
        Assert.Equal("DC=app, DC=fake",
            new X500NameBuilder()
                .SetDomainComponents("app", "fake")
                .Create()
                .Name
        );

        Assert.Equal("OU=services, DC=app, DC=fake",
            new X500NameBuilder()
                .AddOrganizationalUnit("services")
                .AddDomainComponents("old", "domain", "to", "remove")
                .SetDomainComponents("app", "fake")
                .Create()
                .Name
        );
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
        Assert.True(builder.Equivalent(name, false));
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
        Assert.False(builder.Equivalent(name, true));
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

        Assert.True(builder.Equivalent(dn, false));
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

        Assert.False(builder.Equivalent(dn, true));
    }


    private static readonly IEqualityComparer<(Oid, UniversalTagNumber, string)> X500RDNTupleComparer
        = new DelegateEqualityComparer<(Oid OID, UniversalTagNumber ValueEncoding, string Value)>(
            (x, y) =>
                x.OID.Value == y.OID.Value &&
                x.ValueEncoding == y.ValueEncoding &&
                x.Value == y.Value
        );
}
