using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// A certificate found by a <see cref="CertificateFinder"/>, together with where it was found.
/// </summary>
public record CertificateFinderResult
{
    /// <summary>The source the certificate was found in.</summary>
    public required AbstractCertificateSource Source { get; init; }


    /// <summary>
    /// Identifies the certificate within its source: the full path for a file, the location and name
    /// for a store, or the thumbprint for a collection. Two sources whose reach overlaps report the same location for the same certificate,
    /// so a caller who wants one result rather than two can collapse them on it.
    /// </summary>
    public required string Location { get; init; }


    /// <summary>The certificate that was found.</summary>
    /// <remarks>
    /// A store or directory source returns a new instance, which the caller must dispose. A collection
    /// source returns the caller's own instance, which the finder never disposes.
    /// </remarks>
    public required X509Certificate2 Certificate { get; init; }
}
