using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Certificates a source produced together, sharing one location.
/// </summary>
/// <remarks>
/// Handing a batch to the finder hands over the certificates in it. The finder returns the ones that match
/// and reach the caller, and releases every other one through
/// <see cref="AbstractCertificateSource.Release"/>, including the ones past the point a caller stopped
/// reading. A source that yields batches therefore cannot leak: it holds nothing of its own between them.
/// <para>
/// The certificates are copied into the batch as it is constructed, so what the caller does not take is
/// already in memory and releasing it costs nothing. Produce one batch per group the source materialises
/// at once, such as a file, a store or a page of a remote query, rather than one batch of everything:
/// batches are pulled one at a time and only as far as the caller reads.
/// </para>
/// </remarks>
public sealed class CertificateBatch
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateBatch"/> class.
    /// </summary>
    /// <param name="certificates">The certificates, copied into the batch.</param>
    /// <param name="location">Where they were found. See <see cref="CertificateFinderResult.Location"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="certificates"/> or <paramref name="location"/> is null.</exception>
    public CertificateBatch(IEnumerable<X509Certificate2> certificates, string location)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(location);

        _certificates = certificates.ToArray();
        Location = location;
    }


    /// <summary>The certificates in this batch, in the order the source produced them.</summary>
    public IReadOnlyList<X509Certificate2> Certificates => _certificates;


    /// <summary>Where every certificate in this batch was found.</summary>
    public string Location { get; }


    private readonly X509Certificate2[] _certificates;
}
