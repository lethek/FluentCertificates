namespace FluentCertificates;

/// <summary>
/// Asserts up front that a run declaring <c>FLUENTCERT_REQUIRE_PQC</c> really does have post-quantum support.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="PostQuantumGate"/> already stops every other post-quantum test from skipping on such a run, so
/// a missing algorithm cannot hide. What it cannot do is say so clearly: the failure arrives as a
/// <see cref="PlatformNotSupportedException"/> from whichever of forty-odd tests happened to touch the
/// algorithm first. These two assertions name the missing family directly, before the rest of the suite turns
/// it into noise.
/// </para>
/// <para>
/// Composite ML-DSA is excluded, since no platform can sign a certificate with one yet.
/// </para>
/// </remarks>
#pragma warning disable FLUENTCERT001 // Exercising the experimental post-quantum surface is the point here
public class PostQuantumRequiredTests
{
    /// <summary>The families a post-quantum-capable runtime must implement.</summary>
    public static IEnumerable<KeyAlgorithm> RequiredAlgorithms()
        => KeyAlgorithm.PostQuantumAlgorithms.Where(x => x.Family != KeyAlgorithmFamily.CompositeMLDsa);


    [Test]
    [MethodDataSource(nameof(RequiredAlgorithms))]
    public async Task RequiredAlgorithm_ReportsSupported(KeyAlgorithm algorithm)
    {
        Skip.Unless(
            PostQuantumGate.Required,
            $"{PostQuantumGate.RequireVariable} is not set, so this runtime is not expected to implement post-quantum algorithms"
        );

        await Assert
            .That(algorithm.IsSupported)
            .IsTrue()
            .Because($"{algorithm.Name} must be available on a runtime that sets {PostQuantumGate.RequireVariable}");
    }
}
#pragma warning restore FLUENTCERT001
