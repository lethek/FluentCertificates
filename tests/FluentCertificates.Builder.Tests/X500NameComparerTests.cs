using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

public class X500NameComparerTests
{
    [Test]
    public async Task CanFold_ReflectsRuntimeGlobalizationSupport()
        //Probed rather than assumed: this suite does not run globalization-invariant, so folding must be available.
        => await Assert.That(X500NameComparer.CanFold).IsTrue();


    [Test]
    public async Task Read_InvalidDer_ReturnsNull()
        => await Assert.That(X500NameComparer.Read(InvalidName())).IsNull();


    [Test]
    public async Task Read_WhitespaceDifferences_CollapseToTheSameCanonicalForm()
    {
        var single = X500NameComparer.Read(new X500DistinguishedName("CN=Exam ple"));
        var doubled = X500NameComparer.Read(new X500DistinguishedName("CN=Exam  ple"));

        await Assert.That(single).IsNotNull();
        await Assert.That(doubled).IsNotNull();
        await Assert.That(doubled!.Value.Value).IsEqualTo(single!.Value.Value);
    }


    [Test]
    public async Task Read_DifferentAttributeValues_ProduceDifferentCanonicalForms()
    {
        var a = X500NameComparer.Read(new X500DistinguishedName("CN=A"));
        var b = X500NameComparer.Read(new X500DistinguishedName("CN=B"));

        await Assert.That(a).IsNotNull();
        await Assert.That(b).IsNotNull();
        await Assert.That(a!.Value.Value).IsNotEqualTo(b!.Value.Value);
    }


    [Test]
    public async Task Read_ValueAlreadyContainingASeparatorCharacter_IsEscapedRatherThanCountedAsAFold()
    {
        //RFC 4514 quoting, not folding: the comma is in the DER-encoded value from the start
        var canonical = X500NameComparer.Read(new X500DistinguishedName("CN=\"A,B\""));

        await Assert.That(canonical).IsNotNull();
        await Assert.That(canonical!.Value.FoldsIntoSeparator).IsFalse();
    }


    [Test]
    public async Task Read_ValueThatFoldsIntoASeparator_SetsFoldsIntoSeparator()
    {
        Skip.Unless(X500NameComparer.CanFold, "Folding is unavailable in this run's globalization mode");

        //U+FF0C (fullwidth comma) is not itself a separator, but its FormKD normalisation is an ordinary
        //comma - the ambiguity the class's own remarks describe for Java's X500Principal.
        var canonical = X500NameComparer.Read(new X500DistinguishedName("CN=Issuing CA，OU=PKI"));

        await Assert.That(canonical).IsNotNull();
        await Assert.That(canonical!.Value.FoldsIntoSeparator).IsTrue();
    }


    [Test]
    public async Task IsSameName_IdenticalNames_IsTrue()
        => await Assert.That(X500NameComparer.IsSameName("CN=A", "CN=A")).IsTrue();


    [Test]
    public async Task IsSameName_DifferentCase_IsTrue()
        => await Assert.That(X500NameComparer.IsSameName("CN=Example", "CN=EXAMPLE")).IsTrue();


    [Test]
    public async Task IsSameName_DifferentNames_IsFalse()
        => await Assert.That(X500NameComparer.IsSameName("CN=A", "CN=B")).IsFalse();


    [Test]
    public async Task IsSameName_GermanEszettFoldedAgainstDoubleS_IsTrue()
    {
        Skip.Unless(X500NameComparer.CanFold, "Folding is unavailable in this run's globalization mode");
        await Assert.That(X500NameComparer.IsSameName("Große", "Grosse")).IsTrue();
    }


    [Test]
    public async Task IsSameName_DotlessIFoldedAgainstI_IsTrue()
    {
        Skip.Unless(X500NameComparer.CanFold, "Folding is unavailable in this run's globalization mode");
        //Under en-US the upper/lower round trip carries a dotless i (U+0131) onto an i - the fold Java performs
        await Assert.That(X500NameComparer.IsSameName("kız", "kiz")).IsTrue();
    }


    [Test]
    public async Task IsSameName_ByX500DistinguishedName_UsesTheSameComparison()
        => await Assert
            .That(X500NameComparer.IsSameName(new X500DistinguishedName("CN=Exam  ple"), new X500DistinguishedName("CN=Exam ple")))
            .IsTrue();


    [Test]
    public async Task IsSameName_ByX500DistinguishedName_DifferentNames_IsFalse()
        => await Assert
            .That(X500NameComparer.IsSameName(new X500DistinguishedName("CN=Example"), new X500DistinguishedName("CN=Other")))
            .IsFalse();


    [Test]
    public async Task IsSameName_ByX500DistinguishedName_OneSideUnreadable_IsFalse()
        => await Assert.That(X500NameComparer.IsSameName(InvalidName(), new X500DistinguishedName("CN=Example"))).IsFalse();


    //A SEQUENCE containing an INTEGER: valid DER, but not shaped like a sequence of RDNs
    private static X500DistinguishedName InvalidName()
        => new([0x30, 0x03, 0x02, 0x01, 0x00]);
}
