using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

/// <summary>
/// A certificate found by a <see cref="CertificateFinder"/>, together with where it was found.
/// </summary>
public record CertificateFinderResult
{
    /// <summary>The source the certificate was found in.</summary>
    public required AbstractCertificateSource Source { get; init; }


    /// <summary>
    /// Identifies the certificate within its source: the full path for a file, or the location and name
    /// for a store. Two sources whose reach overlaps report the same location for the same certificate,
    /// so a caller who wants one result rather than two can collapse them on it.
    /// </summary>
    public required string Location { get; init; }


    /// <summary>The certificate that was found.</summary>
    public required X509Certificate2 Certificate { get; init; }


    /// <summary>Whether <see cref="Certificate"/>'s issuer is the same name as <paramref
    /// name="candidateIssuer"/>'s subject, per RFC 5280 s7.1. A name match only: it says nothing about
    /// whether <paramref name="candidateIssuer"/>'s key actually signed <see cref="Certificate"/>.</summary>
    /// <param name="candidateIssuer">The certificate to test as the issuer.</param>
    /// <returns><see langword="true"/> if the names match.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="candidateIssuer"/> is null.</exception>
    public bool IsIssuedBy(X509Certificate2 candidateIssuer)
    {
        ArgumentNullException.ThrowIfNull(candidateIssuer);
        return X500NameComparer.IsSameName(Certificate.IssuerName, candidateIssuer.SubjectName);
    }
}
