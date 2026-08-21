namespace FluentCertificates;

/// <summary>
/// Diagnostic IDs for the library's experimental API surface.
/// </summary>
public static class Experiments
{
    /// <summary>
    /// Post-quantum cryptography support: ML-DSA, SLH-DSA, Composite ML-DSA and ML-KEM.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The .NET types these APIs are built on are themselves marked experimental under
    /// <c>SYSLIB5006</c>, so any code naming one already has to suppress that. This library adds its own ID
    /// rather than hiding behind theirs: the shape of this surface may still change while the underlying BCL
    /// surface is moving, and that is worth saying out loud rather than implying that only Microsoft's half is
    /// unsettled.
    /// </para>
    /// <para>
    /// Suppress it per call site with <c>#pragma warning disable FLUENTCERT001</c>, or project-wide with
    /// <c>&lt;NoWarn&gt;$(NoWarn);FLUENTCERT001&lt;/NoWarn&gt;</c>.
    /// </para>
    /// </remarks>
    public const string PostQuantumCryptography = "FLUENTCERT001";
}
