namespace FluentCertificates;

/// <summary>
/// Skips a test unless the named key algorithm can actually be used on the current runtime and platform.
/// </summary>
/// <remarks>
/// <para>
/// This is the capability counterpart to <see cref="SkipUnsupportedOSPlatformAttribute"/>, and the two are
/// not interchangeable. Post-quantum availability is not a property of the operating system that
/// <c>[SupportedOSPlatform]</c> could describe: it depends on the target framework the test is running under
/// and on what the platform's cryptographic provider implements. SLH-DSA is the clearest case - it is
/// unavailable on Windows while ML-DSA and ML-KEM are not, and it can appear or disappear with the
/// provider's version rather than with the OS.
/// </para>
/// <para>
/// A skipped test reports as skipped. A capability gate that silently turned into a no-op passing test would
/// be worse than no gate at all, since the suite would then claim coverage it never had.
/// </para>
/// <para>
/// On a run that sets <c>FLUENTCERT_REQUIRE_PQC</c> this stops skipping altogether, so a CI job meant to
/// cover post-quantum support cannot pass by skipping everything. See <see cref="PostQuantumGate"/>.
/// </para>
/// </remarks>
/// <param name="family">The algorithm family the test needs.</param>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class SkipUnlessAlgorithmSupportedAttribute(KeyAlgorithmFamily family)
    : SkipAttribute($"{family} is not available on this runtime or platform")
{
    /// <inheritdoc />
    public override Task<bool> ShouldSkip(TestRegisteredContext context)
    {
        try {
            var algorithm = KeyAlgorithm.Default(family);

            //A run that declares the algorithms must work does not get to skip: letting the test proceed
            //turns a silent skip into the PlatformNotSupportedException it really is. See PostQuantumGate.
            return Task.FromResult(!algorithm.IsSupported && PostQuantumGate.MaySkip(algorithm));

        } catch (ArgumentOutOfRangeException) {
            //A family the library has no default parameters for cannot be exercised either
            return Task.FromResult(true);
        }
    }
}
