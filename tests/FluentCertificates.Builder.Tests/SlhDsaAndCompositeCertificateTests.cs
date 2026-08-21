using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// Coverage for the two remaining post-quantum signature families: SLH-DSA (FIPS 205) and Composite ML-DSA.
/// </summary>
/// <remarks>
/// <para>
/// Gated per parameter set rather than per family. SLH-DSA is unavailable on Windows entirely, and several
/// Composite parameter sets are unavailable on every platform tested, so a family-wide gate would either
/// skip work that could run or run work that cannot.
/// </para>
/// <para>
/// A test that finds nothing to exercise fails rather than passing silently, because a capability gate that
/// quietly matches nothing claims coverage it does not have.
/// </para>
/// </remarks>
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
public class SlhDsaAndCompositeCertificateTests
{
    public static IEnumerable<KeyAlgorithm> SlhDsaAlgorithms()
        => KeyAlgorithm.PostQuantumAlgorithms.Where(x => x.Family == KeyAlgorithmFamily.SlhDsa);

    public static IEnumerable<KeyAlgorithm> CompositeAlgorithms()
        => KeyAlgorithm.PostQuantumAlgorithms.Where(x => x.Family == KeyAlgorithmFamily.CompositeMLDsa);


    [Test]
    [MethodDataSource(nameof(SlhDsaAlgorithms))]
    public async Task SlhDsa_SelfSigned_BuildsAndVerifies(KeyAlgorithm algorithm)
    {
        Skip.Unless(algorithm.IsSupported, $"{algorithm.Name} is not available on this runtime or platform");

        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} Self-Signed"))
            .Create();

        await Assert.That(cert.GetKeyAlgorithm()).IsEqualTo(algorithm.Oid);
        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.IsSelfSigned()).IsTrue();
        await Assert.That(cert.CanSign()).IsTrue();
    }


    [Test]
    [MethodDataSource(nameof(CompositeAlgorithms))]
    public async Task Composite_SelfSigned_BuildsAndVerifies(KeyAlgorithm algorithm)
    {
        Skip.Unless(algorithm.IsSupported, $"{algorithm.Name} is not available on this runtime or platform");

        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} Self-Signed"))
            .Create();

        await Assert.That(cert.GetKeyAlgorithm()).IsEqualTo(algorithm.Oid);
        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.IsSelfSigned()).IsTrue();
        await Assert.That(cert.CanSign()).IsTrue();
    }


    [Test]
    [MethodDataSource(nameof(SlhDsaAlgorithms))]
    public async Task SlhDsa_KeyRoundTripsThroughPkcs12(KeyAlgorithm algorithm)
    {
        Skip.Unless(algorithm.IsSupported, $"{algorithm.Name} is not available on this runtime or platform");

        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} PKCS12"))
            .Create();

        const string password = "correct horse battery staple";
        var pfx = cert.Export().WithPrivateKey().WithPassword(password).AsPkcs12().ToByteArray();

        using var reloaded = Internals.CertTools.LoadPkcs12(pfx, password, X509KeyStorageFlags.Exportable);
        await Assert.That(reloaded.Thumbprint).IsEqualTo(cert.Thumbprint);
        await Assert.That(reloaded.HasPrivateKey).IsTrue();
    }


    /// <summary>
    /// Asserts every declared OID against the one the runtime actually emits.
    /// </summary>
    /// <remarks>
    /// Five Composite parameter sets are unimplemented on every platform tested, so their OIDs could not be
    /// read off a generated key and were inferred from the arc being contiguous. This test is what keeps
    /// that inference honest: the moment a platform implements one of them, a wrong OID fails here rather
    /// than silently producing an unusable certificate.
    /// </remarks>
    [Test]
    [MethodDataSource(nameof(AllPostQuantumSigningAlgorithms))]
    public async Task DeclaredOid_MatchesTheGeneratedKey(KeyAlgorithm algorithm)
    {
        Skip.Unless(algorithm.IsSupported, $"{algorithm.Name} is not available on this runtime or platform");

        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} OID"))
            .Create();

        //Straight out of SubjectPublicKeyInfo rather than via GetKeyAlgorithm, so this checks the encoding
        //itself rather than the library's own mapping agreeing with itself
        var spki = cert.PublicKey.ExportSubjectPublicKeyInfo();
        var oid = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence().ReadSequence().ReadObjectIdentifier();

        await Assert.That(oid).IsEqualTo(algorithm.Oid);
        //The signature algorithm shares the OID: a post-quantum parameter set fixes both halves
        await Assert.That(cert.SignatureAlgorithm.Value).IsEqualTo(algorithm.Oid);
    }


    public static IEnumerable<KeyAlgorithm> AllPostQuantumSigningAlgorithms()
        => KeyAlgorithm.PostQuantumAlgorithms.Where(x => x.CanSign);


    [Test]
    [MethodDataSource(nameof(AllPostQuantumSigningAlgorithms))]
    public async Task SignatureAlgorithm_FromOid_ResolvesEveryPostQuantumSet(KeyAlgorithm algorithm)
    {
        //No platform gate: this is a pure lookup and must resolve even where the algorithm cannot be used
        var resolved = SignatureAlgorithm.FromOidValue(algorithm.Oid);

        await Assert.That(resolved.Family).IsEqualTo(algorithm.Family);
        await Assert.That(resolved.Oid).IsEqualTo(algorithm.Oid);
        await Assert.That(resolved.HashAlgorithm).IsNull();
    }


    [Test]
    public async Task SlhDsa_MixedChain_SignsAClassicalLeaf()
    {
        var algorithm = KeyAlgorithm.SlhDsaSha2_128f;
        Skip.Unless(algorithm.IsSupported, $"{algorithm.Name} is not available on this runtime or platform");

        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName("SLH-DSA Root CA"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddHours(1))
            .Create();

        using var leaf = new CertificateBuilder()
            .SetIssuer(rootCa)
            .SetKeyAlgorithm(KeyAlgorithm.RSA(2048))
            .SetSubject(x => x.SetCommonName("RSA Leaf"))
            .Create();

        await Assert.That(leaf.IsIssuedBy(rootCa)).IsTrue();
    }


    [Test]
    public async Task Composite_MixedChain_SignsAClassicalLeaf()
    {
        var algorithm = KeyAlgorithm.MLDsa44WithECDsaP256;
        Skip.Unless(algorithm.IsSupported, $"{algorithm.Name} is not available on this runtime or platform");

        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName("Composite Root CA"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddHours(1))
            .Create();

        using var leaf = new CertificateBuilder()
            .SetIssuer(rootCa)
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
            .SetSubject(x => x.SetCommonName("ECDsa Leaf"))
            .Create();

        await Assert.That(leaf.IsIssuedBy(rootCa)).IsTrue();
    }


    [Test]
    public async Task UnsupportedAlgorithm_ThrowsRatherThanProducingABadCertificate()
    {
        var unsupported = KeyAlgorithm.PostQuantumAlgorithms.FirstOrDefault(x => !x.IsSupported);

        if (unsupported == null) {
            //Every algorithm is supported here, so there is nothing to assert. Not a failure: it just means
            //this platform implements the lot.
            return;
        }

        await Assert
            .That(() => {
                using var cert = new CertificateBuilder().SetKeyAlgorithm(unsupported).Create();
            })
            .ThrowsExactly<PlatformNotSupportedException>();
    }


    [Test]
    public async Task CapabilityGate_ReportsSomethingRatherThanSilentlyMatchingNothing()
    {
        //Guards the gate itself. If PostQuantumAlgorithms were ever empty, or IsSupported wrongly returned
        //false everywhere, every test above would skip and the suite would still be green.
        await Assert.That(KeyAlgorithm.PostQuantumAlgorithms).IsNotEmpty();
        await Assert.That(SlhDsaAlgorithms().Count()).IsEqualTo(12);
        await Assert.That(CompositeAlgorithms().Count()).IsEqualTo(18);

        var supported = KeyAlgorithm.PostQuantumAlgorithms.Count(x => x.IsSupported);

        if (Environment.Version.Major >= 10) {
            //ML-DSA is available on every platform .NET 10 runs on, so at least those three must be usable
            await Assert.That(supported).IsGreaterThanOrEqualTo(3);
        } else {
            //Before net10.0 the types do not exist, so nothing can be supported
            await Assert.That(supported).IsEqualTo(0);
        }
    }


    [Test]
    public async Task Composite_IsUnsupportedForCertificates_OnEveryPlatformSoFar()
    {
        //Composite keys generate fine, but no .NET 10 platform can build an X509SignatureGenerator from
        //one - verified on both Windows and Linux. IsSupported reports certificate usability, so it must
        //say false here rather than reporting the key generation and failing later in Create().
        //
        //This test is deliberately written to fail when that changes: the probe behind IsSupported needs no
        //edit to pick up new platform support, but this expectation does, and a green suite should not
        //quietly hide the day composite certificates start working.
        if (Environment.Version.Major < 10) {
            return;
        }

        var composite = CompositeAlgorithms().ToList();

        await Assert.That(composite.Any(x => x.IsSupported)).IsFalse();
    }
}
#pragma warning restore FLUENTCERT001
