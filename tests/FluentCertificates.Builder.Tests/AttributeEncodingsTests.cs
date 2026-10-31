using System.Formats.Asn1;
using System.Security.Cryptography;

using FluentCertificates.Internals;


namespace FluentCertificates;

public class AttributeEncodingsTests
{
    [Test]
    [Arguments(Oids.CountryOrRegionName, UniversalTagNumber.PrintableString)]
    [Arguments(Oids.SerialNumber, UniversalTagNumber.PrintableString)]
    [Arguments(Oids.DnQualifier, UniversalTagNumber.PrintableString)]
    [Arguments(Oids.TelephoneNumber, UniversalTagNumber.PrintableString)]
    [Arguments(Oids.DomainComponent, UniversalTagNumber.IA5String)]
    [Arguments(Oids.EmailAddress, UniversalTagNumber.IA5String)]
    [Arguments(Oids.DestinationIndicator, UniversalTagNumber.PrintableString)]
    [Arguments(Oids.X121Address, UniversalTagNumber.NumericString)]
    [Arguments(Oids.InternationalISDNNumber, UniversalTagNumber.NumericString)]
    [Arguments(Oids.CommonName, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.Organization, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.OrganizationalUnit, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.LocalityName, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.StateOrProvinceName, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.Title, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.UserId, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.GivenName, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.Surname, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.StreetAddress, UniversalTagNumber.UTF8String)]
    [Arguments(Oids.PostalCode, UniversalTagNumber.UTF8String)]
    [Arguments("1.2.3.4", UniversalTagNumber.UTF8String)]
    public async Task GetValueEncoding_IsThePrintableStringOrIa5StringAStandardFixes_OtherwiseUtf8String(string oid, UniversalTagNumber expected)
    {
        await Assert.That(AttributeEncodings.GetValueEncoding(oid)).IsEqualTo(expected);
    }


    [Test]
    public async Task GetValueEncoding_ForNoOid_IsUtf8String()
    {
        await Assert.That(AttributeEncodings.GetValueEncoding(null)).IsEqualTo(UniversalTagNumber.UTF8String);
    }


    /// <summary>
    /// The setters and the string parser both read one table, so a name is the same bytes however it was put
    /// together. Each case builds a one-attribute name with the setter for that attribute.
    /// </summary>
    [Test]
    [Arguments(Oids.CommonName)]
    [Arguments(Oids.Organization)]
    [Arguments(Oids.OrganizationalUnit)]
    [Arguments(Oids.LocalityName)]
    [Arguments(Oids.StateOrProvinceName)]
    [Arguments(Oids.CountryOrRegionName)]
    [Arguments(Oids.TelephoneNumber)]
    [Arguments(Oids.StreetAddress)]
    [Arguments(Oids.PostalCode)]
    [Arguments(Oids.UserId)]
    [Arguments(Oids.SerialNumber)]
    [Arguments(Oids.GivenName)]
    [Arguments(Oids.Surname)]
    [Arguments(Oids.Title)]
    [Arguments(Oids.DnQualifier)]
    [Arguments(Oids.DomainComponent)]
    [Arguments(Oids.EmailAddress)]
    public async Task ASetterAndTheStringParser_EncodeTheSameAttributeAsTheSameBytes(string oid)
    {
        var built = Setters[oid](new X500NameBuilder());

        await Assert.That(built.Equals($"{oid}=x")).IsTrue();
        await Assert.That(built.Create().RawData).IsEquivalentTo(new X500NameBuilder($"{oid}=x").Create().RawData);
    }


    [Test]
    [Arguments(Oids.X121Address, "123 456")]
    [Arguments(Oids.InternationalISDNNumber, "61 7")]
    [Arguments(Oids.DestinationIndicator, "x")]
    public async Task SetAndAdd_ByOidWithNoSetter_EncodeAsTheStringParserDoes(string oid, string value)
    {
        await Assert.That(new X500NameBuilder().Set(oid, value).Equals($"{oid}={value}")).IsTrue();
        await Assert.That(new X500NameBuilder().Add(new Oid(oid), value).Equals($"{oid}={value}")).IsTrue();
    }


    /// <summary>
    /// Given name, surname, street address and postal code are not restricted to a PrintableString, so text
    /// outside its character set is a valid value.
    /// </summary>
    [Test]
    public async Task ADirectoryStringAttribute_HoldsTextOutsidePrintableString()
    {
        var builder = new X500NameBuilder()
            .SetGivenName("José")
            .SetSurname("Zoë O'Brien")
            .SetStreetAddress("12 Smith & Sons, Unit #4")
            .SetPostalCode("6150 Ørsta");

        await Assert.That(builder.GetGivenName()).IsEqualTo("José");
        await Assert.That(builder.GetSurname()).IsEqualTo("Zoë O'Brien");
        await Assert.That(builder.GetStreetAddress()).IsEqualTo("12 Smith & Sons, Unit #4");
        await Assert.That(builder.GetPostalCode()).IsEqualTo("6150 Ørsta");
        await Assert.That(builder.RelativeDistinguishedNames.SelectMany(x => x).Select(x => x.ValueEncoding).Distinct())
            .IsEquivalentTo([UniversalTagNumber.UTF8String]);
        await Assert.That(new X500NameBuilder(builder.Create()).Equals(builder.Create())).IsTrue();
    }


    [Test]
    [Arguments(Oids.SerialNumber, "a_b")]
    [Arguments(Oids.DnQualifier, "a@b")]
    [Arguments(Oids.TelephoneNumber, "a*b")]
    [Arguments(Oids.X121Address, "12a")]
    public async Task AnAttributeWithARestrictedString_RefusesWhatThatTypeCannotHold(string oid, string value)
    {
        await Assert.That(() => new X500NameBuilder($"{oid}={value}")).Throws<FormatException>();
        await Assert.That(() => new X500NameBuilder().Set(oid, value)).Throws<ArgumentException>();
    }


    [Test]
    public async Task TheEmailAddress_IsAnIa5String_SoItHoldsAtAndUnderscoreButNotNonAscii()
    {
        var builder = new X500NameBuilder($"{Oids.EmailAddress}=a@b_c.example");

        await Assert.That(builder.RelativeDistinguishedNames.Single().Single().ValueEncoding).IsEqualTo(UniversalTagNumber.IA5String);
        await Assert.That(() => new X500NameBuilder($"{Oids.EmailAddress}=café@example.com")).Throws<FormatException>();
    }


    private static readonly Dictionary<string, Func<X500NameBuilder, X500NameBuilder>> Setters = new() {
        [Oids.CommonName] = x => x.SetCommonName("x"),
        [Oids.Organization] = x => x.SetOrganization("x"),
        [Oids.OrganizationalUnit] = x => x.SetOrganizationalUnits("x"),
        [Oids.LocalityName] = x => x.SetLocality("x"),
        [Oids.StateOrProvinceName] = x => x.SetState("x"),
        [Oids.CountryOrRegionName] = x => x.SetCountry("x"),
        [Oids.TelephoneNumber] = x => x.SetPhoneNumber("x"),
        [Oids.StreetAddress] = x => x.SetStreetAddress("x"),
        [Oids.PostalCode] = x => x.SetPostalCode("x"),
        [Oids.UserId] = x => x.SetUserId("x"),
        [Oids.SerialNumber] = x => x.SetSerialNumber("x"),
        [Oids.GivenName] = x => x.SetGivenName("x"),
        [Oids.Surname] = x => x.SetSurname("x"),
        [Oids.Title] = x => x.SetTitle("x"),
        [Oids.DnQualifier] = x => x.SetDistinguishedNameQualifier("x"),
        [Oids.DomainComponent] = x => x.SetDomainComponents("x"),
#pragma warning disable CS0618 // SetEmail is obsolete, but its encoding is what this checks
        [Oids.EmailAddress] = x => x.SetEmail("x")
#pragma warning restore CS0618
    };
}
