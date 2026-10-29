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
    [Arguments("02")]
    [Arguments("020500")]
    [Arguments("05000500")]
    [Arguments("0500FF")]
    [Arguments("308005000000")]
    [Arguments("02812A")]
    public async Task AddOtherName_WithAValueThatIsNotOneCompleteDerValue_ThrowsNamingTheValue(string hex)
    {
        //In order: a tag with no length, content shorter than its length, two values, a byte after the value,
        //an indefinite length, and a length encoded in more bytes than it needs
        var ex = await Assert
            .That(() => new GeneralNameListBuilder().AddOtherName(new Oid("1.2.3.4"), Convert.FromHexString(hex)))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.ParamName).IsEqualTo("derEncodedValue");
    }


    [Test]
    [Arguments("02")]
    [Arguments("05000500")]
    [Arguments("0500FF")]
    public async Task AddOtherNames_WithAValueThatIsNotOneCompleteDerValue_ThrowsNamingTheNames(string hex)
    {
        var ex = await Assert
            .That(() => new GeneralNameListBuilder().AddOtherNames((new Oid("1.2.3.4"), Convert.FromHexString(hex))))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.ParamName).IsEqualTo("otherNames");
    }


    [Test]
    public async Task AddOtherName_WithAValueWhoseLengthNeedsSeveralBytes_Accepts()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(new byte[300]);
        var value = writer.Encode();

        var encoded = new GeneralNameListBuilder().AddOtherName(new Oid("1.2.3.4"), value).Create().Encode();

        await Assert.That(Convert.ToHexString(encoded)).Contains(Convert.ToHexString(value));
    }


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
        await Assert.That(encoded[1]).IsEqualTo((byte)(2 + name.RawData.Length));
        await Assert.That(encoded[2]).IsEqualTo((byte)0xA4);
        await Assert.That(encoded[3]).IsEqualTo((byte)name.RawData.Length);
        await Assert.That(encoded.Skip(4)).IsEquivalentTo(name.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddDirectoryName_WithANameWhoseLengthNeedsSeveralBytes_KeepsTheNameWhole()
    {
        var name = new X500NameBuilder().SetCommonName(new string('x', 200)).Create();

        var encoded = new GeneralNameListBuilder().AddDirectoryName(name).Create().Encode();

        //Both the wrapper and the outer sequence now use the long length form, which a one-byte length cannot express
        await Assert.That(name.RawData.Length).IsGreaterThan(127);

        var wrapper = new AsnReader(encoded, AsnEncodingRules.DER).ReadSequence().ReadSequence(ContextTag(4));

        await Assert.That(wrapper.ReadEncodedValue().ToArray()).IsEquivalentTo(name.RawData, CollectionOrdering.Matching);
        await Assert.That(wrapper.HasData).IsFalse();
    }


    [Test]
    public async Task AddDirectoryName_LaterChangesToTheCallersName_DoNotReachTheBuilder()
    {
        var name = new X500DistinguishedName("CN=Test Directory");
        var builder = new GeneralNameListBuilder().AddDirectoryName(name);
        var encodedBefore = builder.Create().Encode();
        var hashBefore = builder.GetHashCode();

        //RawData hands out the name's own array rather than a copy, so this writes through to the name
        name.RawData[^1] ^= 0x01;

        await Assert.That(builder.Create().Encode()).IsEquivalentTo(encodedBefore, CollectionOrdering.Matching);
        await Assert.That(builder.GetHashCode()).IsEqualTo(hashBefore);
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
        //The string overload parses as RFC 4514, so it encodes as UTF8String on every platform
        var fromString = new GeneralNameListBuilder().AddDirectoryName("CN=Parsed").Create().Encode();
        var fromBuilder = new GeneralNameListBuilder().AddDirectoryName(x => x.SetCommonName("Parsed")).Create().Encode();

        await Assert.That(fromString).IsEquivalentTo(fromBuilder, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddDirectoryName_Null_ThrowsNamingTheNameParameter()
    {
        var fromName = await Assert.That(() => new GeneralNameListBuilder().AddDirectoryName((X500DistinguishedName)null!))
            .ThrowsExactly<ArgumentNullException>();
        var fromBuilder = await Assert.That(() => new GeneralNameListBuilder().AddDirectoryName((X500NameBuilder)null!))
            .ThrowsExactly<ArgumentNullException>();
        var fromString = await Assert.That(() => new GeneralNameListBuilder().AddDirectoryName((string)null!))
            .ThrowsExactly<ArgumentNullException>();

        await Assert.That(fromName!.ParamName).IsEqualTo("name");
        await Assert.That(fromBuilder!.ParamName).IsEqualTo("name");
        await Assert.That(fromString!.ParamName).IsEqualTo("name");
    }


    [Test]
    public async Task AddDirectoryName_NullFunction_ThrowsNamingTheConfigureNameParameter()
    {
        var ex = await Assert.That(() => new GeneralNameListBuilder().AddDirectoryName((Func<X500NameBuilder, X500NameBuilder>)null!))
            .ThrowsExactly<ArgumentNullException>();

        await Assert.That(ex!.ParamName).IsEqualTo("configureName");
    }


    [Test]
    public async Task AddDirectoryName_FunctionReturningNull_Throws()
    {
        var ex = await Assert.That(() => new GeneralNameListBuilder().AddDirectoryName(_ => null!))
            .ThrowsExactly<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("configureName");
    }


    [Test]
    public async Task AddDirectoryNames_NullOrWithANullElement_ThrowsNamingTheNamesParameter()
    {
        var thrown = new List<ArgumentNullException?> {
            await Assert.That(() => new GeneralNameListBuilder().AddDirectoryNames((IEnumerable<X500DistinguishedName>)null!)).ThrowsExactly<ArgumentNullException>(),
            await Assert.That(() => new GeneralNameListBuilder().AddDirectoryNames((IEnumerable<X500NameBuilder>)null!)).ThrowsExactly<ArgumentNullException>(),
            await Assert.That(() => new GeneralNameListBuilder().AddDirectoryNames((IEnumerable<string>)null!)).ThrowsExactly<ArgumentNullException>(),
            await Assert.That(() => new GeneralNameListBuilder().AddDirectoryNames(new X500DistinguishedName[] { null! })).ThrowsExactly<ArgumentNullException>(),
            await Assert.That(() => new GeneralNameListBuilder().AddDirectoryNames(new X500NameBuilder[] { null! })).ThrowsExactly<ArgumentNullException>(),
            await Assert.That(() => new GeneralNameListBuilder().AddDirectoryNames(new string[] { null! })).ThrowsExactly<ArgumentNullException>()
        };

        await Assert.That(thrown.Select(x => x!.ParamName!)).IsEquivalentTo(Enumerable.Repeat("names", 6));
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
    public async Task ThePluralOverloads_EncodeAsTheSingularOnesCalledInTheSameOrder()
    {
        var plural = new GeneralNameListBuilder()
            .AddUserPrincipalNames("a@example.com", "b@example.com")
            .AddRegisteredIds(new Oid("1.2.3"), new Oid("1.2.4"))
            .AddDirectoryNames(new X500DistinguishedName("CN=A"), new X500DistinguishedName("CN=B"))
            .AddDirectoryNames(new X500NameBuilder().SetCommonName("C"), new X500NameBuilder().SetCommonName("D"))
            .AddDirectoryNames("CN=E", "CN=F")
            .AddOtherNames((new Oid("1.2.5"), new byte[] { 0x05, 0x00 }), (new Oid("1.2.6"), new byte[] { 0x05, 0x00 }));

        var singular = new GeneralNameListBuilder()
            .AddUserPrincipalName("a@example.com")
            .AddUserPrincipalName("b@example.com")
            .AddRegisteredId(new Oid("1.2.3"))
            .AddRegisteredId(new Oid("1.2.4"))
            .AddDirectoryName(new X500DistinguishedName("CN=A"))
            .AddDirectoryName(new X500DistinguishedName("CN=B"))
            .AddDirectoryName(new X500NameBuilder().SetCommonName("C"))
            .AddDirectoryName(new X500NameBuilder().SetCommonName("D"))
            .AddDirectoryName("CN=E")
            .AddDirectoryName("CN=F")
            .AddOtherName(new Oid("1.2.5"), new byte[] { 0x05, 0x00 })
            .AddOtherName(new Oid("1.2.6"), new byte[] { 0x05, 0x00 });

        await Assert.That(plural.Create().Encode()).IsEquivalentTo(singular.Create().Encode(), CollectionOrdering.Matching);
        await Assert.That(plural.Create().Count).IsEqualTo(12);
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
        using var cert = new CertificateBuilder()
            .SetSubject("CN=Holder")
            .SetSubjectAlternativeNames(san => san
                .AddUserPrincipalName("holder@corp.example")
                .AddDirectoryName(x => x.SetCommonName("Directory"))
                .AddRegisteredId(new Oid("1.2.3.4")))
            .Create();

        var san = cert.Extensions.First(x => x.Oid?.Value == Oids.SubjectAltName);

        //Written out by hand rather than produced by the encoder under test, so a wrong encoding cannot pass by agreeing with itself
        //30 42                                    SEQUENCE, 66 bytes: 37 + 24 + 5
        //  A0 23 06 0A <UPN OID> A0 15 0C 13 ...  otherName, 35 bytes: 12 for the OID, 23 for the explicit value
        //  A4 16 30 14 31 12 30 10 06 03 55 04 03 0C 09 ...  directoryName CN=Directory, as UTF8String
        //  88 03 2A 03 04                         registeredID 1.2.3.4
        await Assert.That(Convert.ToHexString(san.RawData)).IsEqualTo(
            "3042"
            + "A023" + "060A2B060104018237140203" + "A015" + "0C13" + Convert.ToHexString("holder@corp.example"u8.ToArray())
            + "A416" + "3014" + "3112" + "3010" + "0603550403" + "0C09" + Convert.ToHexString("Directory"u8.ToArray())
            + "8803" + "2A0304");
    }


    private static Asn1Tag ContextTag(int tagNumber)
        => new(TagClass.ContextSpecific, tagNumber);
}
