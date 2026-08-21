using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;

/// <summary>
/// An immutable fluent builder that builds and verifies an <see cref="X509Chain"/> for one certificate.
/// Obtain one from <c>cert.BuildChain()</c>; configure with <see cref="TrustRoot"/>,
/// <see cref="AddCertificates"/>, <see cref="AllowInvalidTime"/> and <see cref="WithPolicy"/>; then
/// terminate with <see cref="Create"/> to inspect the result, or <see cref="Export"/> to go straight to
/// a verified chain export. Every method returns a new instance.
/// </summary>
/// <remarks>No revocation checks are performed unless enabled via <see cref="WithPolicy"/>.</remarks>
public record X509ChainBuilder
{
    internal X509ChainBuilder(X509Certificate2 certificate)
        => Certificate = certificate;


    /// <summary>The certificate the chain is built for.</summary>
    public X509Certificate2 Certificate { get; init; }

    /// <summary>Roots to trust exclusively, when <see cref="CustomTrustEnabled"/> is set.</summary>
    public ImmutableList<X509Certificate2> TrustedRoots { get; init; } = ImmutableList<X509Certificate2>.Empty;

    /// <summary>
    /// Whether <see cref="TrustRoot"/> has been called, which switches the chain to
    /// <see cref="X509ChainTrustMode.CustomRootTrust"/>. Never calling it leaves the system trust store
    /// in effect. This is tracked separately from <see cref="TrustedRoots"/> so that trusting an empty
    /// set of roots trusts nothing, rather than silently falling back to system trust.
    /// </summary>
    public bool CustomTrustEnabled { get; init; }

    /// <summary>Extra certificates offered to path building via <see cref="X509ChainPolicy.ExtraStore"/>.</summary>
    public ImmutableList<X509Certificate2> ExtraCertificates { get; init; } = ImmutableList<X509Certificate2>.Empty;

    /// <summary>Whether time-validity failures are ignored. See <see cref="AllowInvalidTime"/>.</summary>
    public bool InvalidTimeAllowed { get; init; }

    internal Action<X509ChainPolicy>? PolicyAction { get; init; }


    /// <summary>
    /// Trusts the given certificates as the only valid roots, replacing the system trust store
    /// (<see cref="X509ChainTrustMode.CustomRootTrust"/>). Never calling this keeps system trust.
    /// </summary>
    /// <param name="roots">The root certificates to trust. An empty set trusts no root at all: calling
    /// this is what replaces system trust, not the number of certificates passed.</param>
    /// <returns>A new builder with the roots added.</returns>
    public X509ChainBuilder TrustRoot(params IEnumerable<X509Certificate2> roots)
        => this with { TrustedRoots = TrustedRoots.AddRange(roots), CustomTrustEnabled = true };


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
        //A multicast delegate already invokes in registration order
        return this with { PolicyAction = PolicyAction + configure };
    }


    /// <summary>
    /// Builds the chain and reports the outcome. Never throws on verification failure: read
    /// <see cref="ChainResult.Verified"/>, or call <see cref="ChainResult.EnsureVerified"/> to throw.
    /// The caller owns the result and should dispose it.
    /// </summary>
    /// <returns>A <see cref="ChainResult"/> owning the built chain.</returns>
    public ChainResult Create()
    {
        //Ownership only transfers to the ChainResult on the last line, so anything throwing before then
        //(a caller's PolicyAction, or Build on a malformed certificate) must release the chain here
        var chain = new X509Chain();
        try {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            if (CustomTrustEnabled) {
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

        } catch {
            chain.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Builds and verifies the chain, then creates a <see cref="CertificateExportBuilder"/> over its
    /// certificates, leaf first, anchored on <see cref="Certificate"/>. Throws when the chain does not
    /// verify, so a gap can never silently reach the exported file.
    /// </summary>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing the verified chain's certificates,
    /// seeded with <see cref="ExportKeys.Primary"/>.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The chain did not verify; the message names each failed status.</exception>
    /// <remarks>
    /// The internal chain is disposed before returning, so its element certificates cannot be handed out.
    /// Each element is instead mapped back to the instance the caller supplied through
    /// <see cref="Certificate"/>, <see cref="TrustedRoots"/>, <see cref="ExtraCertificates"/> or a
    /// <see cref="WithPolicy"/> action that populated <see cref="X509ChainPolicy.ExtraStore"/> or
    /// <see cref="X509ChainPolicy.CustomTrustStore"/>. That instance outlives this call and the caller
    /// already owns it. Only an element the platform supplied itself, such as a root from the system
    /// store or an intermediate fetched via AIA, has no such instance and is copied here; that copy is
    /// keyless and must not be disposed by the caller (the same rule as <c>FilterPrivateKeys</c>).
    /// Where the same certificate was supplied more than once as different instances, the later source
    /// in that list wins, so <see cref="Certificate"/> always keeps its own instance and its key.
    /// <para>
    /// The result is seeded with <see cref="ExportKeys.Primary"/> so a chain export carries only the
    /// leaf's private key by default, which is what a fullchain wants. Any CA keys the caller happens
    /// to hold are stripped by the exporter, which disposes the keyless certificates it creates.
    /// Call <see cref="CertificateExportBuilder.WithPrivateKeys"/> to include them instead.
    /// </para>
    /// </remarks>
    public CertificateExportBuilder Export()
    {
        using var result = Create();
        result.EnsureVerified();

        //The policy's own stores come first: they hold whatever a WithPolicy action added directly,
        //which this builder never saw, and an instance registered here as well should win as that copy
        var policy = result.Chain.ChainPolicy;
        var supplied = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
        foreach (var cert in policy.CustomTrustStore
                     .Concat(policy.ExtraStore)
                     .Concat(TrustedRoots)
                     .Concat(ExtraCertificates)) {
            supplied[cert.Thumbprint] = cert;
        }

        //Assigned last so the anchor's own instance always wins, keeping its private key and keeping
        //the anchor among the exported certificates even when it also appears as a trusted root
        supplied[Certificate.Thumbprint] = Certificate;

        var certs = result.Chain.ToEnumerable()
            .Select(x => supplied.TryGetValue(x.Thumbprint, out var mine)
                ? mine
                : CertTools.LoadCertificate(x.RawDataMemory.Span))
            .ToList();

        return new CertificateExportBuilder(certs, Certificate) { Keys = ExportKeys.Primary };
    }
}
