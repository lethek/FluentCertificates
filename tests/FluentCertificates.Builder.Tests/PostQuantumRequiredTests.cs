using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// Asserts that a run which is meant to exercise post-quantum cryptography actually can.
/// </summary>
/// <remarks>
/// <para>
/// Every other post-quantum test is capability-gated, so on a runtime without the algorithms they all skip
/// and the suite reports green having built nothing. That is the right answer on Windows and on OpenSSL 3.0,
/// and the wrong one for the CI job whose entire purpose is to cover post-quantum support: were its image to
/// regress to an OpenSSL without it, the job would keep passing while testing nothing at all.
/// </para>
/// <para>
/// Setting <c>FLUENTCERT_REQUIRE_PQC=1</c> inverts the gate for such a run: the algorithms are no longer
/// optional, and a certificate must really be produced rather than merely reported as possible. The <c>pqc</c>
/// job in <c>.github/workflows/dotnet.yml</c> sets it, as should any local container run meant to verify the
/// same thing. Unset, every test here skips.
/// </para>
/// <para>
/// Composite ML-DSA is deliberately not required: no platform can build a composite certificate yet.
/// <c>Composite_IsUnsupportedForCertificates_OnEveryPlatformSoFar</c> is the test that fails the day that
/// changes.
/// </para>
/// </remarks>
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
public class PostQuantumRequiredTests
{
    /// <summary>
    /// Whether this run has declared that post-quantum support must be present.
    /// </summary>
    /// <remarks>
    /// Read per call rather than cached in a static, so the reason string below reports the current
    /// environment rather than whatever it held when the class was first touched.
    /// </remarks>
    private static bool PostQuantumRequired
        => Environment.GetEnvironmentVariable("FLUENTCERT_REQUIRE_PQC") is "1" or "true" or "TRUE";


    private const string NotRequired
        = "FLUENTCERT_REQUIRE_PQC is not set, so this runtime is not expected to implement post-quantum algorithms";


    /// <summary>
    /// The families a post-quantum-capable runtime must implement. Composite ML-DSA is excluded because no
    /// platform implements certificate signing for it.
    /// </summary>
    public static IEnumerable<KeyAlgorithm> RequiredAlgorithms()
    {
        yield return KeyAlgorithm.MLDsa65;
        yield return KeyAlgorithm.SlhDsaSha2_128f;
        yield return KeyAlgorithm.MLKem768;
    }


    [Test]
    [MethodDataSource(nameof(RequiredAlgorithms))]
    public async Task RequiredAlgorithm_ReportsSupported(KeyAlgorithm algorithm)
    {
        Skip.Unless(PostQuantumRequired, NotRequired);

        await Assert
            .That(algorithm.IsSupported)
            .IsTrue()
            .Because($"{algorithm.Name} must be available on a runtime that declares FLUENTCERT_REQUIRE_PQC");
    }


    [Test]
    [MethodDataSource(nameof(RequiredAlgorithms))]
    public async Task RequiredAlgorithm_ProducesARealCertificate(KeyAlgorithm algorithm)
    {
        Skip.Unless(PostQuantumRequired, NotRequired);

        //IsSupported reporting true is what the test above checks. This one checks the claim was true, so
        //that a job cannot pass on capability flags alone without a certificate ever being built.
        //
        //Issued by a classical CA rather than self-signed, so that ML-KEM - which cannot sign, and so cannot
        //self-sign - is covered by the same test as the signature algorithms.
        using var issuer = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
            .SetSubject(x => x.SetCommonName("Post-Quantum Gate Issuer"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddHours(1))
            .Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(issuer)
            .SetKeyAlgorithm(algorithm)
            .SetSubject(x => x.SetCommonName($"{algorithm.Name} Required"))
            .Create();

        await Assert.That(cert.GetKeyAlgorithm()).IsEqualTo(algorithm.Oid);
        await Assert.That(cert.HasPrivateKey).IsTrue();
    }
}
