using System.Security.Cryptography;

namespace FluentCertificates;

public class CertificateKeyTests
{
    [Test]
    public async Task ImplicitConversion_Null_ProducesNull()
    {
        CertificateKey? key = (AsymmetricAlgorithm?)null;

        await Assert.That(key).IsNull();
    }


    [Test]
    public async Task ImplicitConversion_Key_WrapsIt()
    {
        using var ecdsa = ECDsa.Create();

        CertificateKey? key = ecdsa;

        await Assert.That(key).IsNotNull();
        await Assert.That(key!.Family).IsEqualTo(KeyAlgorithmFamily.ECDsa);
        await Assert.That(key.AsAsymmetricAlgorithm).IsSameReferenceAs(ecdsa);
    }


    [Test]
    public async Task Family_IsTakenFromTheRuntimeTypeOfTheKey()
    {
        using var rsa = RSA.Create(2048);
        using var ecdsa = ECDsa.Create();
        using var ecdh = ECDiffieHellman.Create();

        await Assert.That(new CertificateKey(rsa).Family).IsEqualTo(KeyAlgorithmFamily.Rsa);
        await Assert.That(new CertificateKey(ecdsa).Family).IsEqualTo(KeyAlgorithmFamily.ECDsa);
        await Assert.That(new CertificateKey(ecdh).Family).IsEqualTo(KeyAlgorithmFamily.ECDiffieHellman);
    }


    /// <summary>
    /// An ECDH key has no signing operation, so it is the one classical family that cannot sign. Every other
    /// classical family can, and only ML-KEM joins ECDH among the post-quantum ones.
    /// </summary>
    [Test]
    public async Task CanSign_IsFalseOnlyForKeyAgreement()
    {
        using var rsa = RSA.Create(2048);
        using var ecdsa = ECDsa.Create();
        using var ecdh = ECDiffieHellman.Create();

        await Assert.That(new CertificateKey(rsa).CanSign).IsTrue();
        await Assert.That(new CertificateKey(ecdsa).CanSign).IsTrue();
        await Assert.That(new CertificateKey(ecdh).CanSign).IsFalse();
    }


    [Test]
    public async Task IsPostQuantum_IsFalseForClassicalKeys()
    {
        using var rsa = RSA.Create(2048);
        using var ecdh = ECDiffieHellman.Create();

        await Assert.That(new CertificateKey(rsa).IsPostQuantum).IsFalse();
        await Assert.That(new CertificateKey(ecdh).IsPostQuantum).IsFalse();
    }


    [Test]
    public async Task Constructor_UnsupportedAlgorithm_NamesTheOffendingType()
    {
        using var unsupported = new UnsupportedAlgorithm();

        var ex = await Assert.That(() => new CertificateKey(unsupported)).ThrowsExactly<NotSupportedException>();

        await Assert.That(ex!.Message).Contains(nameof(AsymmetricAlgorithm));
        await Assert.That(ex.Message).Contains(nameof(UnsupportedAlgorithm));
    }


    private sealed class UnsupportedAlgorithm : AsymmetricAlgorithm;
}
