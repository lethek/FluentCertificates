using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals.GeneralNames;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

/// <summary>
/// The otherName, directoryName and registeredID general names. Unlike the IA5 string forms, the tag alone
/// does not settle how these encode: otherName's value type is chosen by its OID, and both otherName's inner
/// value and directoryName's name are explicitly tagged while the general name itself is implicitly tagged.
/// </summary>
public class GeneralNameOtherFormsTests
{
    [Test]
    public async Task AddUserPrincipalName_EncodesTheMicrosoftOtherNameExactly()
    {
        var encoded = new GeneralNameListBuilder()
            .AddUserPrincipalName("user@example.com")
            .Create()
            .Encode();

        //30 22                                    SEQUENCE, the GeneralNames of the SAN itself
        //  A0 20                                  [0] IMPLICIT AnotherName, replacing the SEQUENCE tag
        //    06 0A 2B 06 01 04 01 82 37 14 02 03  type-id 1.3.6.1.4.1.311.20.2.3
        //    A0 12                                [0] EXPLICIT, wrapping the value rather than retagging it
        //      0C 10 ...                          UTF8String "user@example.com"
        await Assert.That(Convert.ToHexString(encoded)).IsEqualTo(
            "3022"
            + "A020"
            + "060A2B060104018237140203"
            + "A012"
            + "0C10" + Convert.ToHexString("user@example.com"u8.ToArray()));
    }


    [Test]
    public async Task AddUserPrincipalName_DecodesBackToTheSameString()
    {
        var names = new AsnReader(
                new GeneralNameListBuilder().AddUserPrincipalName("alice@corp.example").Create().Encode(),
                AsnEncodingRules.DER)
            .ReadSequence();

        var otherName = names.ReadSequence(ContextTag(0));
        var typeId = otherName.ReadObjectIdentifier();
        var value = otherName.ReadSequence(ContextTag(0));

        await Assert.That(typeId).IsEqualTo(Oids.UserPrincipalName);
        await Assert.That(value.ReadCharacterString(UniversalTagNumber.UTF8String)).IsEqualTo("alice@corp.example");
    }


    [Test]
    public async Task AddOtherName_WrapsTheCallersValueWithoutReinterpretingIt()
    {
        //An INTEGER, to show the value's type comes from the caller's bytes rather than from the method
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteInteger(42);

        var encoded = new GeneralNameListBuilder()
            .AddOtherName(new Oid("1.2.3.4"), writer.Encode())
            .Create()
            .Encode();

        //30 0C  A0 0A  06 03 2A 03 04  A0 03  02 01 2A
        await Assert.That(Convert.ToHexString(encoded))
            .IsEqualTo("300C" + "A00A" + "06032A0304" + "A003" + "02012A");
    }


    [Test]
    public async Task AddOtherName_WithoutAUsableOid_Throws()
    {
        await Assert
            .That(() => new GeneralNameListBuilder().AddOtherName(null!, new byte[] { 0x05, 0x00 }))
            .ThrowsExactly<ArgumentNullException>();

        //An Oid can be constructed with no dotted-decimal value at all, which cannot be encoded
        await Assert
            .That(() => new GeneralNameListBuilder().AddOtherName(new Oid(), new byte[] { 0x05, 0x00 }))
            .ThrowsExactly<ArgumentException>();
    }


    [Test]
    public async Task AddOtherName_WithAnEmptyValue_Throws()
        => await Assert
            .That(() => new GeneralNameListBuilder().AddOtherName(new Oid("1.2.3.4"), ReadOnlySpan<byte>.Empty))
            .ThrowsExactly<ArgumentException>();


    [Test]
    public async Task AddUserPrincipalName_Null_Throws()
        => await Assert
            .That(() => new GeneralNameListBuilder().AddUserPrincipalName(null!))
            .ThrowsExactly<ArgumentNullException>();


    [Test]
    public async Task AddDirectoryName_WrapsTheNameInAnExplicitTag()
    {
        var name = new X500DistinguishedName("CN=Test Directory");

        var encoded = new GeneralNameListBuilder().AddDirectoryName(name).Create().Encode();

        //An implicit [4] would have replaced the RDNSequence's own SEQUENCE tag, leaving the RDN SET
        //immediately after the length. An explicit one keeps the name's encoding whole inside the wrapper.
        await Assert.That(encoded[0]).IsEqualTo((byte)0x30);
        await Assert.That(encoded[2]).IsEqualTo((byte)0xA4);
        await Assert.That(encoded[3]).IsEqualTo((byte)name.RawData.Length);
        await Assert.That(encoded.Skip(4)).IsEquivalentTo(name.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddDirectoryName_FromABuilderOrItsCreatedName_Agree()
    {
        var nameBuilder = new X500NameBuilder().SetCommonName("Same");

        var fromBuilder = new GeneralNameListBuilder().AddDirectoryName(nameBuilder).Create().Encode();
        var fromName = new GeneralNameListBuilder().AddDirectoryName(nameBuilder.Create()).Create().Encode();
        var fromFunc = new GeneralNameListBuilder().AddDirectoryName(x => x.SetCommonName("Same")).Create().Encode();

        await Assert.That(fromName).IsEquivalentTo(fromBuilder, CollectionOrdering.Matching);
        await Assert.That(fromFunc).IsEquivalentTo(fromBuilder, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddDirectoryName_FromAString_MatchesTheParsedName()
    {
        //The string overload parses through X500DistinguishedName, which picks its own value encodings and
        //so need not agree with X500NameBuilder's
        var fromString = new GeneralNameListBuilder().AddDirectoryName("CN=Parsed").Create().Encode();
        var fromName = new GeneralNameListBuilder().AddDirectoryName(new X500DistinguishedName("CN=Parsed")).Create().Encode();

        await Assert.That(fromString).IsEquivalentTo(fromName, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddRegisteredId_EncodesAPrimitiveContextEightOid()
    {
        var encoded = new GeneralNameListBuilder().AddRegisteredId(new Oid("1.3.6.1.5.5.7.3.2")).Create().Encode();

        //registeredID is IMPLICIT, so the OID's universal tag is replaced rather than wrapped: 88, not A8
        await Assert.That(Convert.ToHexString(encoded)).IsEqualTo("300A" + "8808" + "2B06010505070302");
    }


    [Test]
    public async Task AddRegisteredId_WithoutAUsableOid_Throws()
    {
        await Assert
            .That(() => new GeneralNameListBuilder().AddRegisteredId(null!))
            .ThrowsExactly<ArgumentNullException>();

        await Assert
            .That(() => new GeneralNameListBuilder().AddRegisteredId(new Oid()))
            .ThrowsExactly<ArgumentException>();
    }


    [Test]
    public async Task ThePluralOverloads_AddEveryNameInOrder()
    {
        var names = new GeneralNameListBuilder()
            .AddUserPrincipalNames("a@example.com", "b@example.com")
            .AddRegisteredIds(new Oid("1.2.3"), new Oid("1.2.4"))
            .AddDirectoryNames("CN=A", "CN=B")
            .AddOtherNames((new Oid("1.2.5"), new byte[] { 0x05, 0x00 }))
            .Create();

        await Assert
            .That(names.Select(x => x.GetType().Name))
            .IsEquivalentTo([
                nameof(OtherNameAsn), nameof(OtherNameAsn),
                nameof(RegisteredIdNameAsn), nameof(RegisteredIdNameAsn),
                nameof(DirectoryNameAsn), nameof(DirectoryNameAsn),
                nameof(OtherNameAsn)
            ], CollectionOrdering.Matching);
    }


    [Test]
    public async Task ThePluralOverloads_AcceptAnyEnumerableNotJustAnArray()
    {
        //params IEnumerable<T> rather than params T[], so a lazy sequence needs no ToArray at the call site
        var names = new GeneralNameListBuilder()
            .AddUserPrincipalNames(Enumerable.Range(1, 3).Select(x => $"user{x}@example.com"))
            .Create();

        await Assert.That(names.Count).IsEqualTo(3);
    }


    [Test]
    public async Task Equals_OtherNamesWithEqualBytesInDistinctArrays_AreEqual()
    {
        //The value is a byte array, which a record compares by reference unless told otherwise
        var a = new GeneralNameListBuilder().AddOtherName(new Oid("1.2.3"), new byte[] { 0x02, 0x01, 0x07 });
        var b = new GeneralNameListBuilder().AddOtherName(new Oid("1.2.3"), new byte[] { 0x02, 0x01, 0x07 });

        await Assert.That(a).IsEqualTo(b);
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
    }


    [Test]
    public async Task Equals_OtherNamesDifferingInTheValueOrTheOid_AreNotEqual()
    {
        var baseline = new GeneralNameListBuilder().AddOtherName(new Oid("1.2.3"), new byte[] { 0x02, 0x01, 0x07 });

        await Assert
            .That(baseline)
            .IsNotEqualTo(new GeneralNameListBuilder().AddOtherName(new Oid("1.2.3"), new byte[] { 0x02, 0x01, 0x08 }));
        await Assert
            .That(baseline)
            .IsNotEqualTo(new GeneralNameListBuilder().AddOtherName(new Oid("1.2.4"), new byte[] { 0x02, 0x01, 0x07 }));
    }


    [Test]
    public async Task Equals_DirectoryNamesOverTheSameName_AreEqual()
    {
        //X500DistinguishedName does not carry value equality of its own, so this compares the encoded name
        var a = new GeneralNameListBuilder().AddDirectoryName(new X500DistinguishedName("CN=Equal"));
        var b = new GeneralNameListBuilder().AddDirectoryName(new X500DistinguishedName("CN=Equal"));

        await Assert.That(a).IsEqualTo(b);
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
        await Assert
            .That(a)
            .IsNotEqualTo(new GeneralNameListBuilder().AddDirectoryName(new X500DistinguishedName("CN=Different")));
    }


    [Test]
    public async Task Create_CarriesTheNewNameFormsIntoTheCertificate()
    {
        GeneralNameListBuilder AddAll(GeneralNameListBuilder san)
            => san
                .AddUserPrincipalName("holder@corp.example")
                .AddDirectoryName("CN=Directory")
                .AddRegisteredId(new Oid("1.2.3.4"));

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Holder")
            .SetSubjectAlternativeNames(AddAll)
            .Create();

        var san = cert.Extensions.First(x => x.Oid?.Value == Oids.SubjectAltName);

        await Assert
            .That(san.RawData)
            .IsEquivalentTo(AddAll(new GeneralNameListBuilder()).Create().Encode(), CollectionOrdering.Matching);
    }


    private static Asn1Tag ContextTag(int tagNumber)
        => new(TagClass.ContextSpecific, tagNumber);
}
