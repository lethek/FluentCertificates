using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;

/// <summary>
/// An immutable fluent builder that builds and verifies an <see cref="X509Chain"/> for one certificate.
/// Obtain one from <c>cert.BuildChain()</c>; configure with <see cref="TrustRoot"/>,
/// <see cref="AddCertificates"/>, <see cref="AllowInvalidTime"/> and <see cref="WithPolicy"/>; then
/// terminate with <see cref="Create"/> to inspect the result. Every method returns a new instance.
/// </summary>
/// <remarks>No revocation checks are performed unless enabled via <see cref="WithPolicy"/>.</remarks>
public record X509ChainBuilder
{
    internal X509ChainBuilder(X509Certificate2 certificate)
        => Certificate = certificate;


    /// <summary>The certificate the chain is built for.</summary>
    public X509Certificate2 Certificate { get; init; }

    /// <summary>Roots to trust exclusively. Non-empty switches the chain to
    /// <see cref="X509ChainTrustMode.CustomRootTrust"/>; empty leaves the system trust store in effect.</summary>
    public ImmutableList<X509Certificate2> TrustedRoots { get; init; } = ImmutableList<X509Certificate2>.Empty;

    /// <summary>Extra certificates offered to path building via <see cref="X509ChainPolicy.ExtraStore"/>.</summary>
    public ImmutableList<X509Certificate2> ExtraCertificates { get; init; } = ImmutableList<X509Certificate2>.Empty;

    /// <summary>Whether time-validity failures are ignored. See <see cref="AllowInvalidTime"/>.</summary>
    public bool InvalidTimeAllowed { get; init; }

    internal Action<X509ChainPolicy>? PolicyAction { get; init; }


    /// <summary>
    /// Trusts the given certificates as the only valid roots, replacing the system trust store
    /// (<see cref="X509ChainTrustMode.CustomRootTrust"/>). Never calling this keeps system trust.
    /// </summary>
    /// <param name="roots">The root certificates to trust.</param>
    /// <returns>A new builder with the roots added.</returns>
    public X509ChainBuilder TrustRoot(params IEnumerable<X509Certificate2> roots)
        => this with { TrustedRoots = TrustedRoots.AddRange(roots) };


    /// <summary>
    /// Offers additional certificates (typically intermediates) to path building. They are candidates,
    /// not trust decisions: an untrusted root stays untrusted however it arrives here.
    /// </summary>
    /// <param name="certs">The candidate certificates.</param>
    /// <returns>A new builder with the certificates added.</returns>
    public X509ChainBuilder AddCertificates(params IEnumerable<X509Certificate2> certs)
        => this with { ExtraCertificates = ExtraCertificates.AddRange(certs) };


    /// <summary>
    /// Ignores time-validity failures (expired or not-yet-valid certificates anywhere in the chain),
    /// for cases like exporting a fullchain mid-renewal. Structural and trust failures still fail.
    /// </summary>
    /// <returns>A new builder with time validation relaxed.</returns>
    public X509ChainBuilder AllowInvalidTime()
        => this with { InvalidTimeAllowed = true };


    /// <summary>
    /// Registers an action that receives the <see cref="X509ChainPolicy"/> after this builder's own
    /// settings are applied, so it always wins. Multiple registrations run in order.
    /// </summary>
    /// <param name="configure">The policy configuration action.</param>
    /// <returns>A new builder with the action registered.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="configure"/> is null.</exception>
    public X509ChainBuilder WithPolicy(Action<X509ChainPolicy> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var previous = PolicyAction;
        return this with {
            PolicyAction = previous is null
                ? configure
                : policy => { previous(policy); configure(policy); }
        };
    }


    /// <summary>
    /// Builds the chain and reports the outcome. Never throws on verification failure: read
    /// <see cref="ChainResult.Verified"/>, or call <see cref="ChainResult.EnsureVerified"/> to throw.
    /// The caller owns the result and should dispose it.
    /// </summary>
    /// <returns>A <see cref="ChainResult"/> owning the built chain.</returns>
    public ChainResult Create()
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        if (!TrustedRoots.IsEmpty) {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(TrustedRoots.ToArray());
        }

        if (!ExtraCertificates.IsEmpty) {
            chain.ChainPolicy.ExtraStore.AddRange(ExtraCertificates.ToArray());
        }

        if (InvalidTimeAllowed) {
            chain.ChainPolicy.VerificationFlags |= X509VerificationFlags.IgnoreNotTimeValid
                | X509VerificationFlags.IgnoreCtlNotTimeValid
                | X509VerificationFlags.IgnoreNotTimeNested;
        }

        PolicyAction?.Invoke(chain.ChainPolicy);

        var verified = chain.Build(Certificate);
        return new ChainResult(verified, chain);
    }


    /// <summary>
    /// Builds and verifies the chain, then creates a <see cref="CertificateExportBuilder"/> over its
    /// certificates, leaf first, anchored on <see cref="Certificate"/>. Throws when the chain does not
    /// verify, so a gap can never silently reach the exported file. The internal chain is disposed
    /// before returning: <see cref="Certificate"/> is passed through as-is (keeping its private key),
    /// and the remaining chain certificates are key-less copies created here, which the caller must
    /// not dispose (the same rule as <c>FilterPrivateKeys</c>).
    /// </summary>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing the verified chain's certificates.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The chain did not verify; the message names each failed status.</exception>
    public CertificateExportBuilder Export()
    {
        using var result = Create();
        result.EnsureVerified();

        var certs = new List<X509Certificate2> { Certificate };
        certs.AddRange(result.Chain.ChainElements
            .Skip(1)
            .Select(x => CertTools.LoadCertificate(x.Certificate.RawDataMemory.Span)));

        return new CertificateExportBuilder(certs, Certificate);
    }
}
