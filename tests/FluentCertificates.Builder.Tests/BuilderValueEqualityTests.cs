using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// FC-99: the builder records advertise value equality (they are records), so two identically-configured
/// instances must compare equal and share a hash code. Their immutable-collection fields compared by
/// reference before this, so they did not.
/// </summary>
public class X500NameBuilderEqualityTests
{
    [Test]
    public async Task Equals_TwoIdenticallyBuiltNames_AreEqualWithMatchingHashCode()
    {
        var a = new X500NameBuilder().SetCommonName("Test").SetOrganization("Acme");
        var b = new X500NameBuilder().SetCommonName("Test").SetOrganization("Acme");

        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
    }


    [Test]
    public async Task Equals_NamesDifferingInValue_AreNotEqual()
    {
        var a = new X500NameBuilder().SetCommonName("Test");
        var b = new X500NameBuilder().SetCommonName("Other");

        await Assert.That(a.Equals(b)).IsFalse();
    }


    [Test]
    public async Task Equals_NamesDifferingOnlyInEncoding_AreNotEqual()
    {
        var a = new X500NameBuilder().Add(Oids.CommonNameOid, UniversalTagNumber.UTF8String, "Test");
        var b = new X500NameBuilder().Add(Oids.CommonNameOid, UniversalTagNumber.PrintableString, "Test");

        await Assert.That(a.Equals(b)).IsFalse();
    }


    [Test]
    public async Task Equals_NamesDifferingOnlyInRdnOrder_AreNotEqualButRemainEquivalent()
    {
        var a = new X500NameBuilder().SetCommonName("Test").SetOrganization("Acme");
        var b = new X500NameBuilder().SetOrganization("Acme").SetCommonName("Test");

        //Self-equality is exact and order-sensitive; EquivalentTo is the order-insensitive comparison
        await Assert.That(a.Equals(b)).IsFalse();
        await Assert.That(a.EquivalentTo(b)).IsTrue();
    }
}


public class GeneralNameListBuilderEqualityTests
{
    [Test]
    public async Task Equals_TwoIdenticallyBuiltLists_AreEqualWithMatchingHashCode()
    {
        var a = new GeneralNameListBuilder().AddDnsName("a.example").AddEmailAddress("x@example.com");
        var b = new GeneralNameListBuilder().AddDnsName("a.example").AddEmailAddress("x@example.com");

        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
    }


    [Test]
    public async Task Equals_ListsDifferingInEntries_AreNotEqual()
    {
        var a = new GeneralNameListBuilder().AddDnsName("a.example");
        var b = new GeneralNameListBuilder().AddDnsName("b.example");

        await Assert.That(a.Equals(b)).IsFalse();
    }


    [Test]
    public async Task Equals_ListsDifferingOnlyInOrder_AreNotEqual()
    {
        var a = new GeneralNameListBuilder().AddDnsName("a.example").AddDnsName("b.example");
        var b = new GeneralNameListBuilder().AddDnsName("b.example").AddDnsName("a.example");

        await Assert.That(a.Equals(b)).IsFalse();
    }
}


public class CertificateBuilderEqualityTests
{
    //The clock-dependent NotBefore/NotAfter defaults would confound equality, so pin them
    private static CertificateBuilder Fixed()
        => new CertificateBuilder()
            .SetNotBefore(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero))
            .SetNotAfter(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));


    [Test]
    public async Task Equals_TwoDefaultBuilders_AreEqual()
    {
        await Assert.That(Fixed().Equals(Fixed())).IsTrue();
        await Assert.That(Fixed().GetHashCode()).IsEqualTo(Fixed().GetHashCode());
    }


    [Test]
    public async Task Equals_TwoIdenticallyConfiguredBuilders_AreEqualWithMatchingHashCode()
    {
        //Exercises every setter the ticket measured as breaking equality (SetSubject, SetUsage,
        //SetKeyAlgorithm, AddExtension, SetSubjectAlternativeNames) alongside the ones it measured equal
        var custom = new X509Extension(new Oid("1.2.3.4.5"), [1, 2, 3], false);

        CertificateBuilder Build()
            => Fixed()
                .SetSubject("CN=Test")
                .SetUsage(CertificateUsage.Server)
                .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
                .SetPathLength(2)
                .SetHashAlgorithm(HashAlgorithmName.SHA512)
                .SetFriendlyName("friendly")
                .AddExtension(custom)
                .SetSubjectAlternativeNames(san => san.AddDnsName("example.com"));

        var a = Build();
        var b = Build();

        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
    }


    [Test]
    public async Task Equals_BuildersDifferingInSubject_AreNotEqual()
    {
        var a = Fixed().SetSubject("CN=A");
        var b = Fixed().SetSubject("CN=B");

        await Assert.That(a.Equals(b)).IsFalse();
    }


    [Test]
    public async Task Equals_BuildersDifferingInOneExtensionValue_AreNotEqual()
    {
        //Same OID, different contents: the comparison must look past the OID the extension set keys on
        var a = Fixed().AddExtension(new X509Extension(new Oid("1.2.3.4.5"), [1], false));
        var b = Fixed().AddExtension(new X509Extension(new Oid("1.2.3.4.5"), [2], false));

        await Assert.That(a.Equals(b)).IsFalse();
    }


    [Test]
    public async Task Equals_BuildersDifferingInSubjectAlternativeNames_AreNotEqual()
    {
        var a = Fixed().SetSubjectAlternativeNames(san => san.AddDnsName("a.example"));
        var b = Fixed().SetSubjectAlternativeNames(san => san.AddDnsName("b.example"));

        await Assert.That(a.Equals(b)).IsFalse();
    }


    [Test]
    public async Task Equals_KeyPairsWithTheSameKeyButDistinctObjects_AreEqual()
    {
        //Key identity is the public SubjectPublicKeyInfo, so two builders holding the same key through
        //different objects are equal
        using var source = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = source.ExportParameters(true);
        using var first = ECDsa.Create(parameters);
        using var second = ECDsa.Create(parameters);

        var a = Fixed().SetKeyPair(first);
        var b = Fixed().SetKeyPair(second);

        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
    }


    [Test]
    public async Task Equals_BuildersWithDifferentKeys_AreNotEqual()
    {
        using var first = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var a = Fixed().SetKeyPair(first);
        var b = Fixed().SetKeyPair(second);

        await Assert.That(a.Equals(b)).IsFalse();
    }


    [Test]
    public async Task Equals_PublicKeyOnly_EqualsAFullKeyPairWithTheSamePublicKey()
    {
        //The documented trade-off of SPKI-only key identity: a builder holding only the public key compares
        //equal to one holding the full pair, even though only the latter can self-sign
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var withPair = Fixed().SetKeyPair(ecdsa);
        var withPublicOnly = Fixed().SetPublicKey(new PublicKey(ecdsa));

        await Assert.That(withPair.Equals(withPublicOnly)).IsTrue();
        await Assert.That(withPair.GetHashCode()).IsEqualTo(withPublicOnly.GetHashCode());
    }


    [Test]
    public async Task Equals_SameSignatureGeneratorReference_IsEqual_DifferentObject_IsNot()
    {
        using var rsa = RSA.Create(2048);
        var generator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);

        var a = Fixed().SetPublicKey(new PublicKey(rsa)).SetSignatureGenerator(generator);
        var b = Fixed().SetPublicKey(new PublicKey(rsa)).SetSignatureGenerator(generator);
        var c = Fixed().SetPublicKey(new PublicKey(rsa)).SetSignatureGenerator(X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1));

        //A generator has no value equality, so equality is by reference
        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a.Equals(c)).IsFalse();
    }


    [Test]
    public async Task Equals_SameSerialNumberGeneratorReference_IsEqual_DifferentObject_IsNot()
    {
        Func<byte[]> generator = () => [1, 2, 3];

        var a = Fixed().SetSerialNumberGenerator(generator);
        var b = Fixed().SetSerialNumberGenerator(generator);
        var c = Fixed().SetSerialNumberGenerator(() => [1, 2, 3]);

        //A delegate has no value equality, so equality is by reference
        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a.Equals(c)).IsFalse();
    }


    [Test]
    public async Task Equals_EqualButDistinctIssuerCertificates_AreEqual()
    {
        using var issuerCert = new CertificateBuilder().SetSubject("CN=Issuer").Create();
        using var first = Internals.CertTools.LoadCertificate(issuerCert.RawData);
        using var second = Internals.CertTools.LoadCertificate(issuerCert.RawData);

        var a = Fixed().SetIssuer(first);
        var b = Fixed().SetIssuer(second);

        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
    }


    [Test]
    public async Task Equals_BuildersWithDifferentIssuers_AreNotEqual()
    {
        using var issuer1 = new CertificateBuilder().SetSubject("CN=Issuer1").Create();
        using var issuer2 = new CertificateBuilder().SetSubject("CN=Issuer2").Create();

        var a = Fixed().SetIssuer(issuer1);
        var b = Fixed().SetIssuer(issuer2);

        await Assert.That(a.Equals(b)).IsFalse();
    }
}
