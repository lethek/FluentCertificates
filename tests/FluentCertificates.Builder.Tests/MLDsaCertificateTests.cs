using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

/// <summary>
/// End-to-end coverage for ML-DSA (FIPS 204) certificates.
/// </summary>
/// <remarks>
/// Gated on capability rather than on OS: the types exist only from .NET 10, and even there availability is
/// the platform provider's to decide. Every test here reports as skipped where ML-DSA is unavailable.
/// </remarks>
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
[SkipUnlessAlgorithmSupported(KeyAlgorithmFamily.MLDsa)]
public class MLDsaCertificateTests
{
    public static IEnumerable<KeyAlgorithm> ParameterSets()
    {
        yield return KeyAlgorithm.MLDsa44;
        yield return KeyAlgorithm.MLDsa65;
        yield return KeyAlgorithm.MLDsa87;
    }


    [Test]
    [MethodDataSource(nameof(ParameterSets))]
    public async Task SelfSigned_BuildsAndCarriesTheParameterSetOid(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} Self-Signed"))
            .Create();

        await Assert.That(cert.GetKeyAlgorithm()).IsEqualTo(algorithm.Oid);
        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.IsSelfSigned()).IsTrue();
        await Assert.That(cert.IsValidNow()).IsTrue();
    }


    [Test]
    [MethodDataSource(nameof(ParameterSets))]
    public async Task CaIssued_VerifiesAgainstItsIssuer(KeyAlgorithm algorithm)
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} Root CA"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddHours(1))
            .Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(rootCa)
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} Leaf"))
            .Create();

        await Assert.That(cert.IsIssuedBy(rootCa, true)).IsTrue();
    }


    [Test]
    public async Task CanSign_IsTrueForAnMLDsaCertificateHoldingItsKey()
    {
        //Before ML-DSA was plumbed through, GetPrivateKey threw NotSupportedException here and CanSign
        //swallowed it, so a perfectly usable signing key reported false
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("CanSign Test"))
            .Create();

        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.CanSign()).IsTrue();

        using var key = cert.GetPrivateKey();
        await Assert.That(key.Family).IsEqualTo(KeyAlgorithmFamily.MLDsa);
        await Assert.That(key.CanSign).IsTrue();
        await Assert.That(key.IsPostQuantum).IsTrue();
        await Assert.That(key.AsAsymmetricAlgorithm).IsNull();
    }


    [Test]
    [MethodDataSource(nameof(ParameterSets))]
    public async Task SignatureAlgorithm_FromOid_ResolvesTheParameterSet(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} OID Test"))
            .Create();

        var resolved = SignatureAlgorithm.FromOid(cert.SignatureAlgorithm);

        await Assert.That(resolved.Family).IsEqualTo(KeyAlgorithmFamily.MLDsa);
        await Assert.That(resolved.Oid).IsEqualTo(algorithm.Oid);
        //ML-DSA absorbs the message directly, so there is no separate hash to report
        await Assert.That(resolved.HashAlgorithm).IsNull();
    }


    [Test]
    public async Task Export_PemRoundTripsThePrivateKey()
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("PEM Round Trip"))
            .Create();

        var pem = cert.Export().WithPrivateKey().AsPem().ToPemString();

        await Assert.That(pem).Contains("BEGIN PRIVATE KEY");
        await Assert.That(pem).Contains("BEGIN CERTIFICATE");

        using var reloaded = X509Certificate2.CreateFromPem(pem, pem);
        await Assert.That(reloaded.GetKeyAlgorithm()).IsEqualTo(KeyAlgorithm.MLDsa65.Oid);
        await Assert.That(reloaded.HasPrivateKey).IsTrue();
    }


    [Test]
    public async Task Export_Pkcs12RoundTripsThePrivateKey()
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("PKCS12 Round Trip"))
            .Create();

        const string password = "correct horse battery staple";
        var pfx = cert.Export().WithPrivateKey().WithPassword(password).AsPkcs12().ToByteArray();

        //CertTools rather than X509CertificateLoader: this file must still compile for net8.0, where the
        //loader does not exist, even though the test itself only ever runs on net10.0
        using var reloaded = CertTools.LoadPkcs12(pfx, password, X509KeyStorageFlags.Exportable);
        await Assert.That(reloaded.Thumbprint).IsEqualTo(cert.Thumbprint);
        await Assert.That(reloaded.HasPrivateKey).IsTrue();
        await Assert.That(reloaded.CanSign()).IsTrue();
    }


    [Test]
    public async Task Export_WithoutAskingForKeys_WritesNoPrivateKey()
    {
        //The ExportKeys.None default is not relaxed for post-quantum keys
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("Keyless Export"))
            .Create();

        var pem = cert.Export().AsPem().ToPemString();

        await Assert.That(pem).DoesNotContain("PRIVATE KEY");
        await Assert.That(pem).Contains("BEGIN CERTIFICATE");
    }


    [Test]
    public async Task MixedChain_MLDsaIssuerSignsClassicalLeaf()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("ML-DSA Root CA"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddHours(1))
            .Create();

        using var leaf = new CertificateBuilder()
            .SetIssuer(rootCa)
            .SetKeyAlgorithm(KeyAlgorithm.RSA(2048))
            .SetSubject(x => x.SetCommonName("RSA Leaf"))
            .Create();

        await Assert.That(leaf.IsIssuedBy(rootCa, true)).IsTrue();
    }


    [Test]
    public async Task MixedChain_ClassicalIssuerSignsMLDsaLeaf()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetKeyAlgorithm(KeyAlgorithm.RSA(2048))
            .SetSubject(x => x.SetCommonName("RSA Root CA"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddHours(1))
            .Create();

        using var leaf = new CertificateBuilder()
            .SetIssuer(rootCa)
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("ML-DSA Leaf"))
            .Create();

        await Assert.That(leaf.IsIssuedBy(rootCa, true)).IsTrue();
    }


    [Test]
    public async Task KeyUsage_IsDigitalSignatureNotKeyAgreement()
    {
        using var issuer = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("ML-DSA CA"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddHours(1))
            .Create();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(issuer)
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("ML-DSA Server"))
            .Create();

        var usages = cert.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages;

        await Assert.That(usages.HasFlag(X509KeyUsageFlags.DigitalSignature)).IsTrue();
        await Assert.That(usages.HasFlag(X509KeyUsageFlags.KeyAgreement)).IsFalse();
        //keyEncipherment is RSA-only; an ML-DSA key cannot do key transport
        await Assert.That(usages.HasFlag(X509KeyUsageFlags.KeyEncipherment)).IsFalse();
    }


    [Test]
    public async Task CertificateSigningRequest_IsSignedByTheKeyBeingCertified()
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("ML-DSA CSR"))
            .Create();

        using var key = cert.GetPrivateKey();

        var csr = new CertificateBuilder()
            .SetKeyPair(key)
            .SetSubject(x => x.SetCommonName("ML-DSA CSR"))
            .CreateCertificateSigningRequest();

        //The PEM body must be the request's own DER, not merely a well-formed block
        var pem = csr.ToPemString();
        var fields = PemEncoding.Find(pem);
        await Assert.That(pem[fields.Label].ToString()).IsEqualTo("CERTIFICATE REQUEST");
        await Assert
            .That(Convert.FromBase64String(pem[fields.Base64Data].ToString()))
            .IsEquivalentTo(csr.RawData, CollectionOrdering.Matching);

        //The parameter set fixes both halves, so the request is signed under the same OID it certifies
        await Assert.That(csr.GetSignatureAlgorithm().Oid).IsEqualTo(KeyAlgorithm.MLDsa65.Oid);
        await Assert
            .That(csr.CertificateRequest.PublicKey.ExportSubjectPublicKeyInfo())
            .IsEquivalentTo(cert.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);

#if NET10_0_OR_GREATER
        //Proof of possession is the point of a PKCS#10 request: the signature must verify under the very
        //public key the request is asking to have certified, not merely be present
        #pragma warning disable SYSLIB5006
        using var certified = MLDsa.ImportSubjectPublicKeyInfo(cert.PublicKey.ExportSubjectPublicKeyInfo());
        await Assert
            .That(certified.VerifyData(csr.GetRequestData().Span, csr.GetSignatureData().Span))
            .IsTrue();

        //A tampered request must not verify, so the check above is not vacuously true
        var tampered = csr.GetRequestData().ToArray();
        tampered[^1] ^= 0xFF;
        await Assert.That(certified.VerifyData(tampered, csr.GetSignatureData().Span)).IsFalse();
        #pragma warning restore SYSLIB5006
#endif
    }


    [Test]
    public async Task CertificateSigningRequest_FromDer_RoundTripsAnMLDsaRequest()
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("ML-DSA Parsed CSR"))
            .Create();

        using var key = cert.GetPrivateKey();

        var csr = new CertificateBuilder()
            .SetKeyPair(key)
            .SetSubject(x => x.SetCommonName("ML-DSA Parsed CSR"))
            .CreateCertificateSigningRequest();

        //ML-DSA absorbs the message directly, so the request names no hash for the parser to read back
        var parsed = CertificateSigningRequest.FromDer(csr.RawData);

        await Assert.That(parsed.RawData).IsEquivalentTo(csr.RawData, CollectionOrdering.Matching);
        await Assert.That(parsed.CertificateRequest.SubjectName.Name).IsEqualTo("CN=ML-DSA Parsed CSR");
        await Assert.That(parsed.GetSignatureAlgorithm().Oid).IsEqualTo(KeyAlgorithm.MLDsa65.Oid);
        await Assert.That(parsed.SignatureGenerator).IsNull();

        var tampered = csr.RawData;
        tampered[^1] ^= 0xFF;
        await Assert.That(() => CertificateSigningRequest.FromDer(tampered)).Throws<CryptographicException>();
    }


    [Test]
    public async Task Chain_BuildsOverASelfSignedMLDsaCertificate()
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
            .SetSubject(x => x.SetCommonName("ML-DSA Chain Root"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddHours(1))
            .Create();

        using var result = cert.BuildChain().TrustRoot(cert).Create();

        await Assert.That(result.Verified).IsTrue();
        await Assert.That(result.ChainStatus).IsEmpty();
    }
}
#pragma warning restore FLUENTCERT001
