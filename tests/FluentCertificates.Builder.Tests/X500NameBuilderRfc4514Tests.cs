using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class X500NameBuilderRfc4514Tests
{
    [Test]
    public async Task Parse_MultiValuedRdn_HoldsBothAttributesInOneRdn()
    {
        var builder = new X500NameBuilder("CN=Multi Valued+OU=Sales,O=Acme");

        await Assert.That(builder.RelativeDistinguishedNames.Count).IsEqualTo(2);
        await Assert.That(builder.RelativeDistinguishedNames[0].Attributes.Select(x => x.OID.Value!))
            .IsEquivalentTo([Oids.CommonName, Oids.OrganizationalUnit], CollectionOrdering.Matching);
        await Assert.That(builder.RelativeDistinguishedNames[1].Attributes.Select(x => x.OID.Value!))
            .IsEquivalentTo([Oids.Organization], CollectionOrdering.Matching);
        await Assert.That(builder.GetCommonName()).IsEqualTo("Multi Valued");
    }


    [Test]
    public async Task Parse_MultiValuedRdn_EncodesTheSameOnEveryPlatform()
    {
        var actual = new X500NameBuilder("CN=Multi Valued+OU=Sales,O=Acme").Create();

        await Assert.That(actual.RawData).IsEquivalentTo(MultiValuedName().RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Parse_ListsRdnsInStringOrder_AndEncodesThemInReverse()
    {
        var builder = new X500NameBuilder("CN=Example,O=Acme,C=AU");

        await Assert.That(builder.RelativeDistinguishedNames.Select(x => x.Attributes.Single().OID.Value!))
            .IsEquivalentTo([Oids.CommonName, Oids.Organization, Oids.CountryOrRegionName], CollectionOrdering.Matching);

        //The encoded Name starts with the country and ends with the common name
        var encoded = builder.Create().RawData;
        var countryAt = encoded.AsSpan().IndexOf(new byte[] { 0x55, 0x04, 0x06 });
        var commonNameAt = encoded.AsSpan().IndexOf(new byte[] { 0x55, 0x04, 0x03 });
        await Assert.That(countryAt).IsGreaterThan(0);
        await Assert.That(commonNameAt).IsGreaterThan(countryAt);
    }


    [Test]
    public async Task Parse_EncodesValuesAsUtf8String_AndCountryAsPrintableString()
    {
        var attributes = new X500NameBuilder("CN=Example,C=AU").RelativeDistinguishedNames
            .SelectMany(x => x.Attributes)
            .ToDictionary(x => x.OID.Value!, x => x.ValueEncoding);

        await Assert.That(attributes[Oids.CommonName]).IsEqualTo(UniversalTagNumber.UTF8String);
        await Assert.That(attributes[Oids.CountryOrRegionName]).IsEqualTo(UniversalTagNumber.PrintableString);
    }


    [Test]
    [Arguments("cn=Example", "Example")]
    [Arguments("2.5.4.3=Example", "Example")]
    [Arguments("CN=", "")]
    [Arguments("CN=a=b", "a=b")]
    [Arguments(@"CN=a\,b\+c\;d\""e\<f\>g\\h", @"a,b+c;d""e<f>g\h")]
    [Arguments(@"CN=\ lead and trail\ ", " lead and trail ")]
    [Arguments(@"CN=\#hash", "#hash")]
    [Arguments(@"CN=in ner  spaces", "in ner  spaces")]
    [Arguments(@"CN=caf\C3\A9", "café")]
    [Arguments("CN=café", "café")]
    [Arguments(@"CN=\2c\2C", ",,")]
    [Arguments("CN=#0C03616263", "abc")]
    public async Task Parse_Value_IsUnescapedAndDecoded(string name, string expected)
    {
        await Assert.That(new X500NameBuilder(name).GetCommonName()).IsEqualTo(expected);
    }


    [Test]
    [Arguments("cn", Oids.CommonName)]
    [Arguments("L", Oids.LocalityName)]
    [Arguments("st", Oids.StateOrProvinceName)]
    [Arguments("O", Oids.Organization)]
    [Arguments("Ou", Oids.OrganizationalUnit)]
    [Arguments("C", Oids.CountryOrRegionName)]
    [Arguments("STREET", Oids.StreetAddress)]
    [Arguments("DC", Oids.DomainComponent)]
    [Arguments("UID", Oids.UserId)]
    public async Task Parse_Keyword_IsCaseInsensitive(string keyword, string oid)
    {
        var builder = new X500NameBuilder($"{keyword}=x");

        await Assert.That(builder.RelativeDistinguishedNames.Single().Attributes.Single().OID.Value).IsEqualTo(oid);
    }


    [Test]
    public async Task Parse_Empty_IsAnEmptyBuilder()
    {
        await Assert.That(new X500NameBuilder("").RelativeDistinguishedNames).IsEmpty();
    }


    [Test]
    public async Task Parse_HexString_KeepsANonCharacterValueAsRawDer()
    {
        var attribute = new X500NameBuilder("1.2.3.4=#02020102").RelativeDistinguishedNames.Single().Attributes.Single();

        await Assert.That(attribute.Value).IsNull();
        await Assert.That(attribute.DerValue.ToArray()).IsEquivalentTo(new byte[] { 0x02, 0x02, 0x01, 0x02 }, CollectionOrdering.Matching);
    }


    /// <summary>RFC 4514 s2.4 and s3 define a #hex value as BER, so BER input is accepted and written out as DER.</summary>
    [Test]
    [Arguments("1.2.3.4=#30800401410000", new byte[] { 0x30, 0x03, 0x04, 0x01, 0x41 })]
    [Arguments("1.2.3.4=#300724800401410000", new byte[] { 0x30, 0x03, 0x04, 0x01, 0x41 })]
    [Arguments("1.2.3.4=#0481012A", new byte[] { 0x04, 0x01, 0x2A })]
    [Arguments("1.2.3.4=#010101", new byte[] { 0x01, 0x01, 0xFF })]
    [Arguments("1.2.3.4=#3106020102020101", new byte[] { 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 })]
    public async Task Parse_HexStringInBer_IsNormalisedToDer(string name, byte[] expected)
    {
        var attribute = new X500NameBuilder(name).RelativeDistinguishedNames.Single().Attributes.Single();

        await Assert.That(attribute.DerValue.ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
    }


    [Test]
    [Arguments("CN=#0C810161", "a")]
    [Arguments("CN=#2C800401610401620000", "ab")]
    public async Task Parse_HexStringInBer_AStringIsDecoded(string name, string expected)
    {
        await Assert.That(new X500NameBuilder(name).GetCommonName()).IsEqualTo(expected);
    }


    [Test]
    public async Task Constructor_FromDer_ABerValue_ThrowsCryptographicException()
    {
        //A Name read from DER keeps its bytes, so a value that is not DER is refused rather than rewritten
        var name = new X500DistinguishedName(Convert.FromHexString("300D310B300906035504030C810161"));

        await Assert.That(() => new X500NameBuilder(name)).Throws<CryptographicException>();
    }


    [Test]
    [Arguments("CN=a, O=b")]
    [Arguments("CN=a,O=b,")]
    [Arguments(",CN=a")]
    [Arguments("CN=a,,O=b")]
    [Arguments("CN=a+")]
    [Arguments("CN=a++OU=b")]
    [Arguments("+CN=a")]
    [Arguments("CN=a;O=b")]
    [Arguments("CN=\"a\"")]
    [Arguments(" CN=a")]
    [Arguments("CN =a")]
    [Arguments("CN= a")]
    [Arguments("CN=a ")]
    [Arguments("CN=#")]
    [Arguments("CN=#0")]
    [Arguments("CN=#ZZ")]
    [Arguments("CN=#0C0161FF")]
    [Arguments("1.2.3.4=#230403020041")]
    [Arguments("1.2.3.4=#0100")]
    [Arguments("1.2.3.4=#24800201010000")]
    [Arguments("CN=#0C")]
    [Arguments("CN=a<b")]
    [Arguments("CN=a>b")]
    [Arguments("CN=a#b,O=\\")]
    [Arguments(@"CN=a\")]
    [Arguments(@"CN=a\G0")]
    [Arguments(@"CN=\FF")]
    [Arguments("CN")]
    [Arguments("=a")]
    [Arguments("FOO=a")]
    [Arguments("1.40=a")]
    [Arguments("0.40=a")]
    [Arguments("1.100=a")]
    [Arguments("3.1=a")]
    [Arguments("01.2=a")]
    [Arguments("2.5.4.3.=a")]
    public async Task Parse_NonConformingString_ThrowsFormatException(string name)
    {
        await Assert.That(() => new X500NameBuilder(name)).Throws<FormatException>();
    }


    [Test]
    public async Task Parse_Null_ThrowsArgumentNullException()
    {
        await Assert.That(() => new X500NameBuilder((string)null!)).Throws<ArgumentNullException>();
    }


    [Test]
    public async Task ToString_ListsRdnsMostSpecificFirstWithoutSpaces()
    {
        var builder = new X500NameBuilder().SetCommonName("Example").SetOrganization("Acme").SetCountry("AU");

        await Assert.That(builder.ToString()).IsEqualTo("CN=Example,O=Acme,C=AU");
    }


    [Test]
    public async Task ToString_JoinsAMultiValuedRdnWithPlus()
    {
        //DER sorts a SET OF by encoding, and OU's shorter encoding comes before CN's longer one
        await Assert.That(new X500NameBuilder(MultiValuedName()).ToString()).IsEqualTo("OU=Sales+CN=Multi Valued,O=Acme");
    }


    [Test]
    [Arguments("a,b+c;d\"e<f>g\\h", @"a\,b\+c\;d\""e\<f\>g\\h")]
    [Arguments(" lead and trail ", @"\ lead and trail\ ")]
    [Arguments("#hash", @"\#hash")]
    [Arguments("a#b c", "a#b c")]
    [Arguments("a=b", "a=b")]
    [Arguments("café", "café")]
    [Arguments("nul\0here", @"nul\00here")]
    [Arguments("", "")]
    public async Task ToString_EscapesOnlyWhatRfc4514Requires(string value, string expected)
    {
        await Assert.That(new X500NameBuilder().SetCommonName(value).ToString()).IsEqualTo($"CN={expected}");
    }


    [Test]
    public async Task ToString_NamesAnAttributeWithoutAKeywordByItsOid()
    {
        var builder = new X500NameBuilder().SetSerialNumber("123").SetGivenName("Given");

        await Assert.That(builder.ToString()).IsEqualTo($"{Oids.SerialNumber}=123,{Oids.GivenName}=Given");
    }


    [Test]
    public async Task ToString_WritesARawValueAsHex()
    {
        await Assert.That(new X500NameBuilder("1.2.3.4=#02020102").ToString()).IsEqualTo("1.2.3.4=#02020102");
    }


    [Test]
    [Arguments("CN=Example,O=Acme,C=AU")]
    [Arguments("CN=Multi Valued+OU=Sales,O=Acme")]
    [Arguments(@"CN=a\,b\+c\;d\""e\<f\>g\\h\ ,O=\#x")]
    [Arguments("1.2.3.4=#02020102,CN=x")]
    [Arguments("DC=app,DC=fake")]
    [Arguments("")]
    public async Task ToString_OfAParsedString_ReturnsTheString(string name)
    {
        await Assert.That(new X500NameBuilder(name).ToString()).IsEqualTo(name);
    }


    [Test]
    public async Task Create_MultiValuedRdn_SortsItsSetOfAsDerRequires()
    {
        //DER orders a SET OF by encoding, and OU's shorter one sorts before CN's whichever way they are added
        var builder = new X500NameBuilder()
            .AddRelativeDistinguishedName(
                new X500Attribute(Oids.CommonNameOid, UniversalTagNumber.UTF8String, "Multi Valued"),
                new X500Attribute(Oids.OrganizationalUnitOid, UniversalTagNumber.UTF8String, "Sales")
            )
            .SetOrganization("Acme");

        await Assert.That(builder.Create().RawData).IsEquivalentTo(MultiValuedName().RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Constructor_FromDer_KeepsAMultiValuedRdnAndRoundTripsItsBytes()
    {
        var name = MultiValuedName();

        var builder = new X500NameBuilder(name);

        await Assert.That(builder.RelativeDistinguishedNames.Count).IsEqualTo(2);
        await Assert.That(builder.RelativeDistinguishedNames[0].Attributes.Count).IsEqualTo(2);
        await Assert.That(builder.Create().RawData).IsEquivalentTo(name.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Constructor_FromDer_KeepsANonCharacterValueAsRawDer()
    {
        var name = NameWithIntegerAttribute();

        var builder = new X500NameBuilder(name);
        var attribute = builder.RelativeDistinguishedNames.Single().Attributes.Single();

        await Assert.That(attribute.Value).IsNull();
        await Assert.That(attribute.DerValue.ToArray()).IsEquivalentTo(new byte[] { 0x02, 0x01, 0x07 }, CollectionOrdering.Matching);
        await Assert.That(builder.Create().RawData).IsEquivalentTo(name.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Constructor_FromDer_KeepsAT61StringAsRawDer()
    {
        //T61String is not a character set .NET decodes faithfully: E9 reads as Latin-1 and would be written back as UTF-8
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            using (writer.PushSetOf()) {
                using (writer.PushSequence()) {
                    writer.WriteObjectIdentifier(Oids.CommonName);
                    writer.WriteEncodedValue(new byte[] { 0x14, 0x01, 0xE9 });
                }
            }
        }
        var name = new X500DistinguishedName(writer.Encode());

        var builder = new X500NameBuilder(name);

        await Assert.That(builder.RelativeDistinguishedNames.Single().Attributes.Single().Value).IsNull();
        await Assert.That(builder.Create().RawData).IsEquivalentTo(name.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Constructor_FromDer_AnEmptyRdn_ThrowsCryptographicException()
    {
        //A relative distinguished name is a SET SIZE (1..MAX), so an empty one is not a Name
        var name = new X500DistinguishedName(new byte[] { 0x30, 0x02, 0x31, 0x00 });

        await Assert.That(() => new X500NameBuilder(name)).Throws<CryptographicException>();
    }


    [Test]
    public async Task Constructor_FromDer_AnEmptyName_IsAnEmptyBuilder()
    {
        await Assert.That(new X500NameBuilder(new X500DistinguishedName(new byte[] { 0x30, 0x00 })).RelativeDistinguishedNames).IsEmpty();
    }


    [Test]
    public async Task Create_AnRdnWithoutAttributes_Throws()
    {
        var builder = new X500NameBuilder { RelativeDistinguishedNames = [new X500RelativeDistinguishedName([])] };

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Remove_TakesTheAttributeOutOfAMultiValuedRdn_AndKeepsTheOthers()
    {
        var builder = new X500NameBuilder("CN=Multi Valued+OU=Sales,O=Acme").Remove(Oids.CommonNameOid);

        await Assert.That(builder.ToString()).IsEqualTo("OU=Sales,O=Acme");
    }


    [Test]
    public async Task Remove_AnRdnsOnlyAttribute_DropsTheRdn()
    {
        var builder = new X500NameBuilder("CN=Multi Valued+OU=Sales,O=Acme").Remove(Oids.OrganizationOid);

        await Assert.That(builder.RelativeDistinguishedNames.Count).IsEqualTo(1);
    }


    [Test]
    public async Task Equals_AMultiValuedRdnWritten_InEitherOrder_IsTheSameName()
    {
        var a = new X500NameBuilder("CN=x+OU=y");
        var b = new X500NameBuilder("OU=y+CN=x");

        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
    }


    [Test]
    public async Task Equals_String_UsesTheRfc4514Parser()
    {
        var builder = new X500NameBuilder().SetCommonName("Multi Valued").SetOrganization("Acme");

        await Assert.That(builder.Equals("CN=Multi Valued,O=Acme")).IsTrue();
        await Assert.That(builder.Equals("O=Acme,CN=Multi Valued")).IsFalse();
        await Assert.That(builder.EquivalentTo("O=Acme,CN=Multi Valued")).IsTrue();
        await Assert.That(() => builder.Equals("CN=a, O=b")).Throws<FormatException>();
    }


    [Test]
    public async Task EquivalentTo_AMultiValuedString_MatchesTheSameDer()
    {
        await Assert.That(new X500NameBuilder(MultiValuedName()).EquivalentTo("CN=Multi Valued+OU=Sales,O=Acme")).IsTrue();
    }


    /// <summary>"CN=Multi Valued+OU=Sales,O=Acme" as DER, spelt out by hand so it does not depend on the parser.</summary>
    private static X500DistinguishedName MultiValuedName()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            using (writer.PushSetOf()) {
                WriteAttribute(writer, Oids.Organization, "Acme");
            }
            using (writer.PushSetOf()) {
                WriteAttribute(writer, Oids.CommonName, "Multi Valued");
                WriteAttribute(writer, Oids.OrganizationalUnit, "Sales");
            }
        }
        return new X500DistinguishedName(writer.Encode());
    }


    private static X500DistinguishedName NameWithIntegerAttribute()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            using (writer.PushSetOf()) {
                using (writer.PushSequence()) {
                    writer.WriteObjectIdentifier("1.2.3.4");
                    writer.WriteInteger(7);
                }
            }
        }
        return new X500DistinguishedName(writer.Encode());
    }


    private static void WriteAttribute(AsnWriter writer, string oid, string value)
    {
        using (writer.PushSequence()) {
            writer.WriteObjectIdentifier(oid);
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
        }
    }
}
