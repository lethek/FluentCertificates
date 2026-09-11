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
    [Arguments("Usage")]
    [Arguments("NotBefore")]
    [Arguments("NotAfter")]
    [Arguments("FriendlyName")]
    [Arguments("PathLength")]
    [Arguments("KeyAlgorithm")]
    [Arguments("HashAlgorithm")]
    [Arguments("RSASignaturePadding")]
    [Arguments("KeyStorageFlags")]
    public async Task Equals_BuildersDifferingInOneMember_AreNotEqual(string member)
    {
        //One case per member equality compares directly, so dropping any one of them from the comparison
        //fails a test rather than silently making two different configurations equal
        var baseline = Fixed();
        var mutated = member switch {
            "Usage" => baseline.SetUsage(CertificateUsage.Server),
            "NotBefore" => baseline.SetNotBefore(baseline.NotBefore.AddDays(-1)),
            "NotAfter" => baseline.SetNotAfter(baseline.NotAfter.AddDays(1)),
            "FriendlyName" => baseline.SetFriendlyName("another name"),
            "PathLength" => baseline.SetPathLength(3),
            "KeyAlgorithm" => baseline.SetKeyAlgorithm(KeyAlgorithm.ECDsa()),
            "HashAlgorithm" => baseline.SetHashAlgorithm(HashAlgorithmName.SHA384),
            "RSASignaturePadding" => baseline.SetRSASignaturePadding(RSASignaturePadding.Pss),
            "KeyStorageFlags" => baseline.SetKeyStorageFlags(X509KeyStorageFlags.Exportable),
            _ => throw new ArgumentOutOfRangeException(nameof(member), member, "Unhandled member")
        };

        await Assert.That(baseline.Equals(mutated)).IsFalse();
    }


    [Test]
    public async Task Equals_ANullSubjectOrPadding_ComparesInsteadOfThrowing()
    {
        //Both are declared non-nullable, but a `with` expression can still write a null into them, and
        //Equals must answer rather than throw
        var withNullSubject = Fixed() with { Subject = null! };
        var withNullPadding = Fixed() with { RSASignaturePadding = null! };

        await Assert.That(withNullSubject.Equals(Fixed())).IsFalse();
        await Assert.That(Fixed().Equals(withNullSubject)).IsFalse();
        await Assert.That(withNullSubject.Equals(Fixed() with { Subject = null! })).IsTrue();

        await Assert.That(withNullPadding.Equals(Fixed())).IsFalse();
        await Assert.That(Fixed().Equals(withNullPadding)).IsFalse();
        await Assert.That(withNullPadding.Equals(Fixed() with { RSASignaturePadding = null! })).IsTrue();
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
    public async Task Equals_SameExtensionsAddedInDifferentOrder_AreEqualWithMatchingHashCode()
    {
        //Extensions are a set keyed by OID, so the order they were added in is not part of the configuration
        var first = new X509Extension(new Oid("1.2.3.4.5"), [1, 2, 3], false);
        var second = new X509Extension(new Oid("1.2.3.4.6"), [4, 5, 6], true);

        var a = Fixed().AddExtension(first).AddExtension(second);
        var b = Fixed().AddExtension(second).AddExtension(first);

        await Assert.That(a.Equals(b)).IsTrue();
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
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
        //The documented trade-off of SPKI-only key identity: the private half adds nothing to equality, so
        //two builders differing only in whether it is present compare equal, even though only one can self-sign.
        //RSA-4096 is the key this can be stated on: SetKeyPair reads the algorithm off the key while
        //SetPublicKey falls back to the default, and those two agree only at the default key length. For an
        //elliptic-curve key they disagree, and disagree differently per platform, since KeyAlgorithm.Name is
        //built from the curve's platform-specific friendly name.
        using var rsa = RSA.Create(4096);

        var withPair = Fixed().SetKeyPair(rsa);
        var withPublicOnly = Fixed().SetPublicKey(new PublicKey(rsa));

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
        //An elliptic-curve key because the test only needs some certificate to hold, and the default RSA-4096 is slow to generate
        using var issuerCert = new CertificateBuilder().SetSubject("CN=Issuer").SetKeyAlgorithm(KeyAlgorithm.ECDsa()).Create();
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
        using var issuer1 = new CertificateBuilder().SetSubject("CN=Issuer1").SetKeyAlgorithm(KeyAlgorithm.ECDsa()).Create();
        using var issuer2 = new CertificateBuilder().SetSubject("CN=Issuer2").SetKeyAlgorithm(KeyAlgorithm.ECDsa()).Create();

        var a = Fixed().SetIssuer(issuer1);
        var b = Fixed().SetIssuer(issuer2);

        await Assert.That(a.Equals(b)).IsFalse();
    }
}
