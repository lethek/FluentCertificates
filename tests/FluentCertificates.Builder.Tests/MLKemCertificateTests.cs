using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// Coverage for ML-KEM (FIPS 203) key-encapsulation certificates.
/// </summary>
/// <remarks>
/// ML-KEM cannot sign, so most of what matters here is what it refuses to do. It mirrors the existing
/// <see cref="KeyAlgorithmFamily.ECDiffieHellman"/> handling, with one deliberate difference: an ECDH key
/// performs Diffie-Hellman key agreement and asserts <c>keyAgreement</c>, while ML-KEM encapsulates to the
/// certified public key, which is key transport and asserts <c>keyEncipherment</c> instead.
/// </remarks>
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
[SkipUnlessAlgorithmSupported(KeyAlgorithmFamily.MLKem)]
public class MLKemCertificateTests
{
    public static IEnumerable<KeyAlgorithm> ParameterSets()
    {
        yield return KeyAlgorithm.MLKem512;
        yield return KeyAlgorithm.MLKem768;
        yield return KeyAlgorithm.MLKem1024;
    }


    private static CertificateBuilder IssuerBuilder()
        => new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("ML-KEM Test CA"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddHours(1));


    [Test]
    [MethodDataSource(nameof(ParameterSets))]
    public async Task CaIssued_BuildsAndCarriesTheParameterSetOid(KeyAlgorithm algorithm)
    {
        using var issuer = IssuerBuilder().Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(issuer)
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} Leaf"))
            .Create();

        await Assert.That(cert.GetKeyAlgorithm()).IsEqualTo(algorithm.Oid);
        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.IsIssuedBy(issuer, true)).IsTrue();

        //Straight out of SubjectPublicKeyInfo, so this checks the encoding rather than our own mapping
        //agreeing with itself
        var spki = cert.PublicKey.ExportSubjectPublicKeyInfo();
        var oid = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence().ReadSequence().ReadObjectIdentifier();
        await Assert.That(oid).IsEqualTo(algorithm.Oid);
    }


    /// <summary>
    /// RFC 9935 s5: "If the keyUsage extension is present in certificates, then keyEncipherement MUST be the
    /// only key usage set for certificates that indicate id-alg-ml-kem-* in SubjectPublicKeyInfo." Every usage
    /// profile an ML-KEM key is allowed to take therefore lands on the same single bit, so each is asserted
    /// exactly rather than by flag: an extra bit breaks the "only", and none at all leaves an empty critical
    /// keyUsage, which RFC 5280 s4.2.1.3 forbids.
    /// </summary>
    [Test]
    [Arguments(CertificateUsage.Server)]
    [Arguments(CertificateUsage.Client)]
    [Arguments(CertificateUsage.SMime)]
    public async Task KeyUsage_IsKeyEnciphermentAlone_WhateverTheUsage(CertificateUsage usage)
    {
        using var issuer = IssuerBuilder().Create();

        using var cert = new CertificateBuilder()
            .SetUsage(usage)
            .SetIssuer(issuer)
            .SetKeyAlgorithm(KeyAlgorithm.MLKem768)
            .SetSubject(x => x.SetCommonName($"ML-KEM {usage}"))
            .Create();

        var extension = cert.Extensions.OfType<X509KeyUsageExtension>().Single();

        //Unlike ECDH: encapsulation is key transport, not Diffie-Hellman agreement, so keyAgreement is
        //excluded along with digitalSignature and nonRepudiation
        await Assert.That(extension.KeyUsages).IsEqualTo(X509KeyUsageFlags.KeyEncipherment);

        //A BIT STRING with one bit set, rather than the empty 03 01 00 an unset usage would encode to
        await Assert.That(extension.RawData).IsEquivalentTo(new byte[] { 0x03, 0x02, 0x05, 0x20 });
    }


    [Test]
    public async Task SelfSigning_Throws_BecauseThereIsNothingToSignWith()
    {
        await Assert
            .That(() => new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.MLKem768).Validate())
            .ThrowsExactly<ArgumentException>();
    }


    [Test]
    [Arguments(CertificateUsage.CA)]
    [Arguments(CertificateUsage.CodeSign)]
    [Arguments(CertificateUsage.OcspSigning)]
    [Arguments(CertificateUsage.TimeStamping)]
    public async Task SigningUsages_Throw(CertificateUsage usage)
    {
        using var issuer = IssuerBuilder().Create();

        await Assert
            .That(() => new CertificateBuilder()
                .SetKeyAlgorithm(KeyAlgorithm.MLKem768)
                .SetIssuer(issuer)
                .SetUsage(usage)
                .Validate())
            .ThrowsExactly<ArgumentException>();
    }


    [Test]
    public async Task CertificateSigningRequest_Throws()
    {
        //PKCS#10 proves possession by signing the request with the key being certified, which ML-KEM
        //cannot do. A supplied SignatureGenerator is no substitute: it signs with an unrelated key.
        await Assert
            .That(() => new CertificateBuilder()
                .SetKeyAlgorithm(KeyAlgorithm.MLKem768)
                .SetSubject(x => x.SetCommonName("ML-KEM CSR"))
                .CreateCertificateSigningRequest())
            .ThrowsExactly<NotSupportedException>();
    }


    [Test]
    public async Task CanSign_IsFalse()
    {
        using var issuer = IssuerBuilder().Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(issuer)
            .SetKeyAlgorithm(KeyAlgorithm.MLKem768)
            .SetSubject(x => x.SetCommonName("ML-KEM CanSign"))
            .Create();

        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.CanSign()).IsFalse();

        using var key = cert.GetPrivateKey();
        await Assert.That(key.Family).IsEqualTo(KeyAlgorithmFamily.MLKem);
        await Assert.That(key.CanSign).IsFalse();
        await Assert.That(key.IsPostQuantum).IsTrue();
    }


    [Test]
    public async Task PublicKeyOid_IdentifiesMLKemUnambiguously()
    {
        //Unlike the EC pair, where ECDH and ECDsa are byte-identical in SubjectPublicKeyInfo and
        //KeepEcChoice exists to stop the guess overwriting the caller, an ML-KEM public key carries its
        //own algorithm OID. Reading it back needs no equivalent workaround.
        using var issuer = IssuerBuilder().Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(issuer)
            .SetKeyAlgorithm(KeyAlgorithm.MLKem1024)
            .SetSubject(x => x.SetCommonName("ML-KEM OID"))
            .Create();

        var rebuilt = new CertificateBuilder().SetPublicKey(cert.PublicKey);

        await Assert.That(rebuilt.KeyAlgorithm).IsEqualTo(KeyAlgorithm.MLKem1024);
        await Assert.That(rebuilt.KeyAlgorithm.CanSign).IsFalse();
    }


    [Test]
    public async Task Export_RoundTripsThePrivateKey()
    {
        using var issuer = IssuerBuilder().Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(issuer)
            .SetKeyAlgorithm(KeyAlgorithm.MLKem768)
            .SetSubject(x => x.SetCommonName("ML-KEM Export"))
            .Create();

        const string password = "correct horse battery staple";
        var pfx = cert.Export().WithPrivateKey().WithPassword(password).AsPkcs12().ToByteArray();

        using var reloaded = Internals.CertTools.LoadPkcs12(pfx, password, X509KeyStorageFlags.Exportable);
        await Assert.That(reloaded.Thumbprint).IsEqualTo(cert.Thumbprint);
        await Assert.That(reloaded.HasPrivateKey).IsTrue();

        var pem = cert.Export().WithPrivateKey().AsPem().ToPemString();
        await Assert.That(pem).Contains("BEGIN PRIVATE KEY");
    }


    [Test]
    public async Task ExistingECDiffieHellmanPath_StaysIntact()
    {
        //The two key-agreement-ish paths must not entangle: ECDH keeps keyAgreement, ML-KEM does not get it
        using var issuer = IssuerBuilder().Create();

        using var ecdh = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(issuer)
            .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman())
            .SetSubject(x => x.SetCommonName("ECDH Server"))
            .Create();

        var usages = ecdh.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages;

        await Assert.That(usages.HasFlag(X509KeyUsageFlags.KeyAgreement)).IsTrue();
        await Assert.That(usages.HasFlag(X509KeyUsageFlags.DigitalSignature)).IsFalse();
        await Assert.That(usages.HasFlag(X509KeyUsageFlags.KeyEncipherment)).IsFalse();
    }
}
#pragma warning restore FLUENTCERT001
