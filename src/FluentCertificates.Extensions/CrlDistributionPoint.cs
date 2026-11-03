using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Where a CRL is published and which certificates it covers. The same value describes the CRL on both
/// sides: <c>CertificateBuilder.SetCrlDistributionPoints</c> writes it into the certificates the CRL covers,
/// and <c>X509CrlBuilder.SetDistributionPoint</c> writes it into the CRL itself, so the two cannot disagree.
/// </summary>
/// <remarks>
/// <para>RFC 5280 s5.2.5 requires the address in a CRL's Issuing Distribution Point to match the one in the
/// certificate's CRL Distribution Points, which is what lets a relying party tell that it was handed the
/// right CRL.</para>
/// <para>Windows and .NET on Linux honour a scope, and treat a CRL that does not match as unusable. Neither
/// honours <see cref="CrlIssuer"/> (an indirect CRL). Browsers do not read CRLs named in certificates.</para>
/// </remarks>
public sealed record CrlDistributionPoint
{
    /// <summary>Creates a distribution point published at one or more addresses.</summary>
    /// <param name="uris">The addresses the CRL can be downloaded from. Each must be ASCII.</param>
    /// <exception cref="ArgumentNullException"><paramref name="uris"/> is <see langword="null"/>.</exception>
    public CrlDistributionPoint(params IEnumerable<string> uris)
    {
        ArgumentNullException.ThrowIfNull(uris);
        Uris = [.. uris];
    }


    /// <summary>Gets the addresses the CRL can be downloaded from.</summary>
    public ImmutableList<string> Uris { get; }

    /// <summary>Gets the addresses the matching delta CRL can be downloaded from. Empty when there is none.</summary>
    /// <remarks>Written as the Freshest CRL extension of a full CRL or a certificate. A delta CRL carries none,
    /// since RFC 5280 s5.2.6 forbids it.</remarks>
    public ImmutableList<string> DeltaUris { get; init; } = [];

    /// <summary>Gets the name of the party that signs the CRL where that is not the certificate's issuer,
    /// which makes it an indirect CRL, or <see langword="null"/> where the issuer signs its own CRL.</summary>
    public X500DistinguishedName? CrlIssuer { get; init; }

    /// <summary>Gets which certificates the CRL covers. Defaults to <see cref="CrlCoverage.AllCertificates"/>.</summary>
    public CrlCoverage Covers { get; init; } = CrlCoverage.AllCertificates;
}
