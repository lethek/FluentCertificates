using System.Formats.Asn1;

using FluentCertificates.Internals;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class BerToDerTests
{
    [Test]
    [Arguments("3003020101")]
    [Arguments("0C0161")]
    [Arguments("300A3106020101020102" + "0500")]
    public async Task Normalize_ADerValue_IsReturnedUnchanged(string hex)
    {
        var der = Convert.FromHexString(hex);

        await Assert.That(BerToDer.Normalize(der)).IsEquivalentTo(der, CollectionOrdering.Matching);
    }


    [Test]
    [Arguments("30800401410000", "3003040141")]
    [Arguments("308030800401410000" + "0000", "30053003040141")]
    [Arguments("0481012A", "04012A")]
    [Arguments("010101", "0101FF")]
    [Arguments("010100", "010100")]
    [Arguments("300A3106020102020101" + "0500", "300A3106020101020102" + "0500")]
    public async Task Normalize_BerValue_IsRewrittenAsDer(string berHex, string derHex)
    {
        var result = BerToDer.Normalize(Convert.FromHexString(berHex));

        await Assert.That(result).IsEquivalentTo(Convert.FromHexString(derHex), CollectionOrdering.Matching);
    }


    [Test]
    public async Task Normalize_AConstructedStringOfMoreThan127Bytes_UsesTheLongLengthForm()
    {
        //A constructed OCTET STRING holding a 200 byte segment and a 1 byte segment
        byte[] ber = [0x24, 0x80, 0x04, 0x81, 0xC8, .. Enumerable.Repeat((byte)'A', 200), 0x04, 0x01, (byte)'B', 0x00, 0x00];
        byte[] expected = [0x04, 0x81, 0xC9, .. Enumerable.Repeat((byte)'A', 200), (byte)'B'];

        await Assert.That(BerToDer.Normalize(ber)).IsEquivalentTo(expected, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Normalize_ANestedConstructedString_IsFlattened()
    {
        byte[] ber = [0x24, 0x80, 0x24, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00, 0x04, 0x01, 0x42, 0x00, 0x00];

        await Assert.That(BerToDer.Normalize(ber)).IsEquivalentTo(new byte[] { 0x04, 0x02, 0x41, 0x42 }, CollectionOrdering.Matching);
    }


    [Test]
    [Arguments("050000")]
    [Arguments("2303030100")]
    [Arguments("0401")]
    [Arguments("30800201")]
    [Arguments("0100")]
    [Arguments("2402020100")]
    public async Task Normalize_ValueThatCannotBeRewritten_Throws(string hex)
    {
        await Assert.That(() => BerToDer.Normalize(Convert.FromHexString(hex))).Throws<AsnContentException>();
    }


    [Test]
    public async Task Normalize_ValuesNestedTooDeeply_Throws()
    {
        //Indefinite lengths, so the value is BER and is not returned as it is
        byte[] ber = [
            .. Enumerable.Repeat<byte>(0x30, 100).SelectMany(x => new byte[] { x, 0x80 }),
            0x05, 0x00,
            .. new byte[200]
        ];

        await Assert.That(() => BerToDer.Normalize(ber)).Throws<AsnContentException>();
    }
}
