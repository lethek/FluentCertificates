using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using TUnit.Assertions.Enums;

namespace FluentCertificates;

public class GetPrivateKeyAndSignatureAlgorithmTests
{
    [Test]
    public async Task GetPrivateKey_RsaCertificate_ReturnsAnRsaKey()
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.RSA(2048))
            .SetSubject(x => x.SetCommonName("RSA"))
            .Create();

        using var key = cert.GetPrivateKey();

        await Assert.That(key.Family).IsEqualTo(KeyAlgorithmFamily.Rsa);

        //Family is read off the runtime type, so asserting the type as well says nothing new. What matters
        //is that the key returned is this certificate's, and that its private half works.
        await Assert
            .That(key.ExportSubjectPublicKeyInfo())
            .IsEquivalentTo(cert.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);

        var rsa = (RSA)key.AsAsymmetricAlgorithm!;
        var data = new byte[] { 1, 2, 3 };
        var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certPublic = cert.GetRSAPublicKey()!;
        await Assert
            .That(certPublic.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            .IsTrue();
    }


    [Test]
    public async Task GetPrivateKey_ECDsaCertificate_ReturnsAnECDsaKey()
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
            .SetSubject(x => x.SetCommonName("ECDsa"))
            .Create();

        using var key = cert.GetPrivateKey();

        await Assert.That(key.Family).IsEqualTo(KeyAlgorithmFamily.ECDsa);
    }


    /// <summary>
    /// An ECDH and an ECDsa key share the id-ecPublicKey OID, so the lookup asks for an ECDsa key first and
    /// falls back to an agreement key. A certificate asserting keyAgreement has no ECDsa private key to
    /// give, so the fallback is what makes its key reachable at all.
    /// </summary>
    [Test]
    public async Task GetPrivateKey_ECDiffieHellmanCertificate_FallsBackToTheAgreementKey()
    {
        using var issuer = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Issuer"))
            .Create();

        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman())
            .SetUsage(CertificateUsage.Client)
            .SetSubject(x => x.SetCommonName("ECDH"))
            .SetIssuer(issuer)
            .Create();

        using var key = cert.GetPrivateKey();

        await Assert.That(key.Family).IsEqualTo(KeyAlgorithmFamily.ECDiffieHellman);
        await Assert.That(key.CanSign).IsFalse();
        await Assert.That(cert.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages)
            .IsEqualTo(X509KeyUsageFlags.KeyAgreement);
    }


    [Test]
    public async Task GetPrivateKey_NoPrivateKey_Throws()
    {
        using var withKey = new CertificateBuilder().SetSubject(x => x.SetCommonName("Keyless")).Create();
        using var keyless = X509Certificate2.CreateFromPem(withKey.ExportCertificatePem());

        var ex = await Assert.That(() => keyless.GetPrivateKey()).ThrowsExactly<CryptographicException>();

        await Assert.That(ex!.Message).Contains("Private key not found");
    }


    [Test]
    [Arguments(KeyAlgorithmFamily.Rsa)]
    [Arguments(KeyAlgorithmFamily.ECDsa)]
    public async Task ForPostQuantum_ClassicalAlgorithm_Throws(KeyAlgorithmFamily family)
    {
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
        var ex = await Assert.That(() => SignatureAlgorithm.ForPostQuantum(KeyAlgorithm.Default(family)))
            .ThrowsExactly<ArgumentException>();
#pragma warning restore FLUENTCERT001

        await Assert.That(ex!.Message).Contains("is not a post-quantum signature algorithm");
        await Assert.That(ex.ParamName).IsEqualTo("algorithm");
    }


    /// <summary>
    /// ML-KEM is post-quantum but cannot sign, so it is refused for the same reason a classical algorithm is.
    /// Both halves of the guard have to hold.
    /// </summary>
    [Test]
    public async Task ForPostQuantum_KeyEncapsulation_Throws()
    {
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
        await Assert.That(() => SignatureAlgorithm.ForPostQuantum(KeyAlgorithm.MLKem768))
            .ThrowsExactly<ArgumentException>();
#pragma warning restore FLUENTCERT001
    }


    [Test]
    public async Task ForPostQuantum_Null_Throws()
    {
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
        await Assert.That(() => SignatureAlgorithm.ForPostQuantum(null!)).ThrowsExactly<ArgumentNullException>();
#pragma warning restore FLUENTCERT001
    }


    [Test]
    public async Task ForPostQuantum_SigningParameterSet_CarriesNoHashAlgorithm()
    {
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
        var algorithm = SignatureAlgorithm.ForPostQuantum(KeyAlgorithm.MLDsa65);

        //A post-quantum parameter set fixes both key and signature algorithm, so there is no separate hash
        await Assert.That(algorithm.HashAlgorithm).IsNull();
        await Assert.That(algorithm.Oid).IsEqualTo(KeyAlgorithm.MLDsa65.Oid);
#pragma warning restore FLUENTCERT001
    }


    [Test]
    public async Task FromOid_KnownAlgorithm_ResolvesTheSameInstanceAsTheStringLookup()
    {
        var algorithm = SignatureAlgorithm.FromOid(new Oid(SignatureAlgorithm.SHA256RSA.Oid));

        await Assert.That(algorithm).IsSameReferenceAs(SignatureAlgorithm.SHA256RSA);
        await Assert.That(algorithm.Family).IsEqualTo(KeyAlgorithmFamily.Rsa);
        await Assert.That(algorithm.HashAlgorithm).IsEqualTo(HashAlgorithmName.SHA256);
        await Assert.That(algorithm.RSASignaturePadding).IsEqualTo(RSASignaturePadding.Pkcs1);
    }


    [Test]
    public async Task FromOid_UnknownOid_Throws()
    {
        var ex = await Assert
            .That(() => SignatureAlgorithm.FromOid(new Oid("1.3.6.1.4.1.99999.7", "Nothing")))
            .ThrowsExactly<NotSupportedException>();

        await Assert.That(ex!.Message).Contains("1.3.6.1.4.1.99999.7");
        await Assert.That(ex.Message).Contains("Nothing");
    }


    [Test]
    public async Task FromOid_OidCarryingNoValue_Throws()
        //An Oid can name a friendly name alone, and nothing can be looked up from that
        => await Assert
            .That(() => SignatureAlgorithm.FromOid(new Oid(null, "Nothing")))
            .ThrowsExactly<NotSupportedException>();


    [Test]
    public async Task FromOidValue_UnknownOrMissingOid_Throws()
    {
        await Assert.That(() => SignatureAlgorithm.FromOidValue("1.3.6.1.4.1.99999.7")).ThrowsExactly<NotSupportedException>();
        await Assert.That(() => SignatureAlgorithm.FromOidValue(null)).ThrowsExactly<NotSupportedException>();
    }
}
