using System.Security.Cryptography;

using TUnit.Assertions.Enums;

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


    /// <summary>
    /// The export methods reach a post-quantum key through its own type rather than through
    /// <see cref="AsymmetricAlgorithm"/>, so each one needs its own arm and each arm needs exercising.
    /// </summary>
    [Test]
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
    [SkipUnlessAlgorithmSupported(KeyAlgorithmFamily.MLDsa)]
    public async Task PostQuantumKey_ExportsTheSameMaterialThroughEveryFormat()
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("ML-DSA Export"))
            .Create();
#pragma warning restore FLUENTCERT001

        using var key = cert.GetPrivateKey();

        //The public half is the one the certificate carries
        await Assert
            .That(key.ExportSubjectPublicKeyInfo())
            .IsEquivalentTo(cert.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);

        //The DER and the PEM are the same PKCS#8, so each proves the other's arm was taken
        await Assert
            .That(Base64BodyOf(key.ExportPkcs8PrivateKeyPem()))
            .IsEquivalentTo(key.ExportPkcs8PrivateKey(), CollectionOrdering.Matching);

        var encrypted = key.ExportEncryptedPkcs8PrivateKeyPem(
            "correct horse battery staple",
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000)
        );

        await Assert.That(encrypted).StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----");
        await Assert.That(Base64BodyOf(encrypted)).IsNotEquivalentTo(key.ExportPkcs8PrivateKey());
    }


    /// <summary>Decodes the base64 body of a PEM document, ignoring its header and footer lines.</summary>
    private static byte[] Base64BodyOf(string pem)
        => Convert.FromBase64String(
            String.Concat(
                pem.Split('\n')
                    .Select(x => x.Trim())
                    .Where(x => x.Length > 0 && !x.StartsWith("-----"))
            )
        );


    private sealed class UnsupportedAlgorithm : AsymmetricAlgorithm;
}
