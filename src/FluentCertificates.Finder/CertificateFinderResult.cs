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
    /// Identifies the certificate within its source: the full path for a file, or the location and name
    /// for a store. Two sources whose reach overlaps report the same location for the same certificate,
    /// which is what lets <see cref="CertificateFinder"/> recognise the repeat.
    /// </summary>
    public required string Location { get; init; }


    /// <summary>The certificate that was found.</summary>
    public required X509Certificate2 Certificate { get; init; }
}
