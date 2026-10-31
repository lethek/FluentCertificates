using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using FluentCertificates.Internals;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class DerValidatorTests
{
    [Test]
    [Arguments("0101FF")]
    [Arguments("010100")]
    [Arguments("020100")]
    [Arguments("02017F")]
    [Arguments("02020080")]
    [Arguments("0201FF")]
    [Arguments("020180")]
    [Arguments("0A0101")]
    [Arguments("0500")]
    [Arguments("0603550403")]
    [Arguments("0603558101")]
    [Arguments("030100")]
    [Arguments("03020780")]
    [Arguments("03020001")]
    [Arguments("0C0161")]
    [Arguments("040141")]
    [Arguments("0400")]
    [Arguments("1303616263")]
    [Arguments("3003040141")]
    [Arguments("3000")]
    [Arguments("3106020101020102")]
    [Arguments("3103040141")]
    [Arguments("A003020101")]
    [Arguments("8001FF")]
    [Arguments("9F1F0100")]
    [Arguments("9F7F0100")]
    [Arguments("9F810000")]
    public async Task Validate_ADerValue_IsAccepted(string hex)
    {
        await Assert.That(() => DerValidator.Validate(Convert.FromHexString(hex))).ThrowsNothing();
    }


    [Test]
    //Lengths
    [Arguments("")]
    [Arguments("04")]
    [Arguments("040241")]
    [Arguments("04014141")]
    [Arguments("0481012A")]
    [Arguments("0482000141")]
    [Arguments("048000")]
    [Arguments("04FF")]
    [Arguments("04850000000141")]
    //Tags
    [Arguments("9F0100")]
    [Arguments("9F801F00")]
    [Arguments("9F")]
    [Arguments("9F8181818101")]
    //Constructed where DER forbids it
    [Arguments("2403040141")]
    [Arguments("2C03040141")]
    [Arguments("2303000000")]
    [Arguments("2100")]
    //Primitive where a SEQUENCE or SET is needed
    [Arguments("1000")]
    [Arguments("110100")]
    //BOOLEAN
    [Arguments("010101")]
    [Arguments("0100")]
    [Arguments("01020000")]
    //INTEGER and ENUMERATED
    [Arguments("0200")]
    [Arguments("02020001")]
    [Arguments("0202FF80")]
    [Arguments("02020000")]
    [Arguments("0A00")]
    //NULL
    [Arguments("050100")]
    //OBJECT IDENTIFIER
    [Arguments("0600")]
    [Arguments("0603558001")]
    [Arguments("06025583")]
    //BIT STRING
    [Arguments("0300")]
    [Arguments("030107")]
    [Arguments("03020701")]
    [Arguments("03020800")]
    //SET ordering and nesting
    [Arguments("3106020102020101")]
    [Arguments("A0800201010000")]
    [Arguments("300730800201010000")]
    public async Task Validate_ANonDerValue_Throws(string hex)
    {
        await Assert.That(() => DerValidator.Validate(Convert.FromHexString(hex))).Throws<AsnContentException>();
    }


    [Test]
    [Arguments(UniversalTagNumber.UtcTime, "200101000000Z")]
    [Arguments(UniversalTagNumber.UtcTime, "991231235959Z")]
    [Arguments(UniversalTagNumber.UtcTime, "240229120000Z")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20200101000000Z")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20200101000000.5Z")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20200101000000.123Z")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20240229000000Z")]
    public async Task Validate_ADerTime_IsAccepted(UniversalTagNumber tag, string text)
    {
        await Assert.That(() => DerValidator.Validate(Tlv(tag, text))).ThrowsNothing();
    }


    [Test]
    [Arguments(UniversalTagNumber.UtcTime, "2001010000Z")]
    [Arguments(UniversalTagNumber.UtcTime, "200101000000+0000")]
    [Arguments(UniversalTagNumber.UtcTime, "200101000000")]
    [Arguments(UniversalTagNumber.UtcTime, "201301000000Z")]
    [Arguments(UniversalTagNumber.UtcTime, "200132000000Z")]
    [Arguments(UniversalTagNumber.UtcTime, "230229120000Z")]
    [Arguments(UniversalTagNumber.UtcTime, "200101240000Z")]
    [Arguments(UniversalTagNumber.UtcTime, "200101006000Z")]
    [Arguments(UniversalTagNumber.UtcTime, "20010100000aZ")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20200101000000")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20200101000000+0000")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "202001010000Z")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20200101000000.Z")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20200101000000.50Z")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20200101000000.0Z")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20200101000000,5Z")]
    [Arguments(UniversalTagNumber.GeneralizedTime, "20230229000000Z")]
    public async Task Validate_ANonDerTime_Throws(UniversalTagNumber tag, string text)
    {
        await Assert.That(() => DerValidator.Validate(Tlv(tag, text))).Throws<AsnContentException>();
    }


    [Test]
    public async Task Validate_ALongValue_UsesTheLongLengthForm()
    {
        await Assert.That(() => DerValidator.Validate(Wrap(0x04, new byte[300]))).ThrowsNothing();
    }


    [Test]
    public async Task Validate_ValuesNestedTooDeeply_Throws()
    {
        var value = new byte[] { 0x05, 0x00 };
        for (var i = 0; i < 100; i++) {
            value = Wrap(0x30, value);
        }

        await Assert.That(() => DerValidator.Validate(value)).Throws<AsnContentException>();
    }


    [Test]
    [Arguments("040541")]
    [Arguments("0401")]
    [Arguments("3080020101")]
    public async Task Constructor_FromDer_AValueThatIsNotOneCompleteBerValue_ThrowsCryptographicException(string valueHex)
    {
        var name = NameWithValue(Convert.FromHexString(valueHex));

        await Assert.That(() => new X500NameBuilder(name)).Throws<CryptographicException>();
    }


    [Test]
    [Arguments("0C01FF")]
    [Arguments("0C02C328")]
    [Arguments("1E0141")]
    [Arguments("1E02D800")]
    public async Task Constructor_FromDer_AUtf8OrBmpStringThatIsNotText_ThrowsCryptographicException(string valueHex)
    {
        var name = NameWithValue(Convert.FromHexString(valueHex));

        await Assert.That(() => new X500NameBuilder(name)).Throws<CryptographicException>();
    }


    /// <summary>
    /// Only a UTF8String or BMPString must decode. A value outside the character set of a restricted type is
    /// kept as raw DER, since CAs have issued them.
    /// </summary>
    [Test]
    [Arguments("1601E9")]
    [Arguments("13012A")]
    public async Task Constructor_FromDer_AValueOutsideTheCharacterSetOfItsType_IsKeptAsRawDer(string valueHex)
    {
        var name = NameWithValue(Convert.FromHexString(valueHex));

        var builder = new X500NameBuilder(name);

        await Assert.That(builder.GetCommonName()).IsNull();
        await Assert.That(builder.Create().RawData).IsEquivalentTo(name.RawData, CollectionOrdering.Matching);
    }


    [Test]
    [Arguments("2403040141", "040141")]
    [Arguments("010101", "0101FF")]
    [Arguments("300730800201010000", "30053003020101")]
    public async Task Constructor_FromDer_ABerValue_IsWrittenBackAsDer(string berHex, string derHex)
    {
        var name = NameWithValue(Convert.FromHexString(berHex));

        var builder = new X500NameBuilder(name);

        await Assert.That(builder.Create().RawData).IsEquivalentTo(NameWithValue(Convert.FromHexString(derHex)).RawData, CollectionOrdering.Matching);
    }


    /// <summary>
    /// A wildcard in a PrintableString breaks the character set of the type, which is not a DER rule, and
    /// CAs have issued such names. The name is read and written back byte for byte.
    /// </summary>
    [Test]
    public async Task Constructor_FromDer_APrintableStringWithAnAsterisk_IsKeptAsRawDer()
    {
        var name = NameWithValue(Tlv(UniversalTagNumber.PrintableString, "*.example.com"));

        var builder = new X500NameBuilder(name);

        await Assert.That(builder.GetCommonName()).IsNull();
        await Assert.That(builder.Create().RawData).IsEquivalentTo(name.RawData, CollectionOrdering.Matching);
    }


    private static byte[] Tlv(UniversalTagNumber tag, string text)
        => Wrap((byte)tag, Encoding.ASCII.GetBytes(text));


    private static byte[] Wrap(byte tag, byte[] content)
    {
        byte[] length = content.Length switch {
            < 0x80 => [(byte)content.Length],
            < 0x100 => [0x81, (byte)content.Length],
            _ => [0x82, (byte)(content.Length >> 8), (byte)content.Length]
        };
        return [tag, .. length, .. content];
    }


    /// <summary>Hand-built so that a value which is not DER is not stopped by the writer.</summary>
    private static X500DistinguishedName NameWithValue(byte[] value)
    {
        byte[] oid = [0x06, 0x03, 0x55, 0x04, 0x03];
        var attribute = Wrap(0x30, [.. oid, .. value]);
        return new X500DistinguishedName(Wrap(0x30, Wrap(0x31, attribute)));
    }
}
