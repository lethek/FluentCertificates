using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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
    /// <exception cref="ArgumentException">An address is empty, <see langword="null"/> or not ASCII.</exception>
    public CrlDistributionPoint(params IEnumerable<string> uris)
    {
        ArgumentNullException.ThrowIfNull(uris);
        Uris = [.. uris];
        CheckAddresses(Uris, nameof(uris));
    }

    private CrlDistributionPoint(ImmutableList<string> uris, ImmutableList<string> deltaUris)
    {
        Uris = uris;
        _deltaUris = deltaUris;
    }


    private ImmutableList<string> _deltaUris = [];

    /// <summary>Gets the addresses the CRL can be downloaded from.</summary>
    public ImmutableList<string> Uris { get; }

    /// <summary>Gets the addresses the matching delta CRL can be downloaded from. Empty when there is none.</summary>
    /// <remarks>Written as the Freshest CRL extension of a full CRL or a certificate. A delta CRL carries none,
    /// since RFC 5280 s5.2.6 forbids it.</remarks>
    /// <exception cref="ArgumentException">Setting it to a list with an address that is empty, <see langword="null"/> or not ASCII.</exception>
    public ImmutableList<string> DeltaUris
    {
        get => _deltaUris;
        init {
            ArgumentNullException.ThrowIfNull(value);
            CheckAddresses(value, nameof(DeltaUris));
            _deltaUris = value;
        }
    }

    /// <summary>Gets the name of the party that signs the CRL where that is not the certificate's issuer,
    /// which makes it an indirect CRL, or <see langword="null"/> where the issuer signs its own CRL.</summary>
    public X500DistinguishedName? CrlIssuer { get; init; }

    /// <summary>Gets which certificates the CRL covers. Defaults to <see cref="CrlCoverage.AllCertificates"/>.</summary>
    public CrlCoverage Covers { get; init; } = CrlCoverage.AllCertificates;


    /// <summary>Creates a point without checking its addresses, for one read out of a CRL that another tool wrote
    /// and that can carry an address the constructor would refuse.</summary>
    internal static CrlDistributionPoint CreateUnchecked(ImmutableList<string> uris, ImmutableList<string> deltaUris, CrlCoverage covers, X500DistinguishedName? crlIssuer)
        => new(uris, deltaUris) { Covers = covers, CrlIssuer = crlIssuer };

    private static void CheckAddresses(IEnumerable<string> uris, string paramName)
    {
        foreach (var uri in uris) {
            if (String.IsNullOrEmpty(uri) || !Ascii.IsValid(uri)) {
                throw new ArgumentException($"A distribution point address must be a non-empty ASCII string, but was '{uri}'", paramName);
            }
        }
    }
}
