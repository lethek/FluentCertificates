namespace FluentCertificates;

/// <summary>
/// Decides whether an unavailable post-quantum algorithm is a reason to skip a test or a reason to fail it.
/// </summary>
/// <remarks>
/// <para>
/// Post-quantum tests are gated on runtime capability, so on Windows or an OpenSSL 3.0 Linux they skip and
/// the suite reports green having built nothing. That is right for a run where the algorithms genuinely are
/// unavailable, and wrong for one whose whole purpose is to cover them: were the CI image to lose post-quantum
/// support, every gate would skip and the job would keep passing.
/// </para>
/// <para>
/// Setting <c>FLUENTCERT_REQUIRE_PQC</c> declares that this run must have the algorithms. The gates then stop
/// skipping and let the test run, so an unavailable algorithm surfaces as the
/// <see cref="PlatformNotSupportedException"/> it really is, naming the parameter set that went missing. Every
/// gate consults this, so a partial regression - one family, or a handful of parameter sets - fails just as
/// loudly as a total one.
/// </para>
/// <para>
/// Composite ML-DSA is exempt: no platform can sign a certificate with a composite key yet, so requiring it
/// would fail everywhere. <c>Composite_IsUnsupportedForCertificates_OnEveryPlatformSoFar</c> is the test that
/// fails the day that changes.
/// </para>
/// </remarks>
public static class PostQuantumGate
{
    /// <summary>
    /// The environment variable declaring that this run must have working post-quantum support.
    /// </summary>
    public const string RequireVariable = "FLUENTCERT_REQUIRE_PQC";


    /// <summary>
    /// Whether this run has declared that post-quantum support must be present.
    /// </summary>
    /// <remarks>
    /// Accepts <c>1</c> as well as anything <see cref="bool.TryParse(string, out bool)"/> reads as true, so
    /// the <c>True</c> that <see cref="bool.ToString()"/> produces works as well as the <c>true</c> and <c>1</c>
    /// that a YAML or <c>docker -e</c> author is likely to write. A spelling that silently failed to match
    /// would turn the gate back off, which is the exact failure it exists to prevent.
    /// </remarks>
    public static bool Required
    {
        get {
            var value = Environment.GetEnvironmentVariable(RequireVariable);
            return value == "1" || (bool.TryParse(value, out var parsed) && parsed);
        }
    }


    /// <summary>
    /// Whether an algorithm being unavailable should skip the test rather than fail it.
    /// </summary>
    /// <param name="algorithm">The algorithm the test needs.</param>
#pragma warning disable FLUENTCERT001 // Classifying a family is not use of the experimental surface
    public static bool MaySkip(KeyAlgorithm algorithm)
        => !Required || algorithm.Family == KeyAlgorithmFamily.CompositeMLDsa;
#pragma warning restore FLUENTCERT001


    /// <summary>
    /// Skips the calling test when the algorithm is unavailable, unless this run requires it, in which case
    /// the test proceeds and fails on its own.
    /// </summary>
    /// <param name="algorithm">The algorithm the test needs.</param>
    public static void SkipUnlessSupported(KeyAlgorithm algorithm)
    {
        if (algorithm.IsSupported || !MaySkip(algorithm)) {
            return;
        }

        Skip.Test($"{algorithm.Name} is not available on this runtime or platform");
    }
}
