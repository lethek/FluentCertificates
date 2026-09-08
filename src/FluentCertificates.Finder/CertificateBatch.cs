using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>Certificates a source produced together, sharing one location.</summary>
/// <remarks>
/// Handing a batch to the finder hands over the certificates in it: every one that does not reach the
/// caller is released through <see cref="AbstractCertificateSource.Release"/>. Produce one batch per group
/// the source materialises at once, such as a file or a store, since batches are pulled one at a time and
/// only as far as the caller reads.
/// </remarks>
public sealed class CertificateBatch
{
    /// <summary>Initializes a new instance of the <see cref="CertificateBatch"/> class.</summary>
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
