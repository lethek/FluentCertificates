using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>A certificate source over a sequence the caller supplied.</summary>
/// <remarks>
/// The certificates belong to the caller, so this source never disposes one the filter rejects. Equality is
/// by the identity of the sequence, so adding an equivalent copy makes a second source.
/// </remarks>
/// <param name="Certificates">The certificates this source offers.</param>
public sealed record CertificateCollectionSource(IEnumerable<X509Certificate2> Certificates) : AbstractCertificateSource
{
    /// <inheritdoc/>
    public override string Kind => "Collection";


    /// <summary>Yields the supplied certificates, one to a batch, enumerating the sequence lazily.</summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>One batch per supplied certificate.</returns>
    protected override IEnumerable<CertificateBatch> Enumerate(CertificateFilter filter)
        //A supplied certificate has no location of its own, so its thumbprint stands in as the id
        => Certificates.Select(cert => new CertificateBatch([cert], cert.Thumbprint));


    /// <summary>Yields the supplied certificates last first, running a lazy sequence to completion.</summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>One batch per supplied certificate, last first.</returns>
    protected override IEnumerable<CertificateBatch> EnumerateDescending(CertificateFilter filter)
        => Certificates.Reverse().Select(cert => new CertificateBatch([cert], cert.Thumbprint));


    /// <summary>These certificates are the caller's, so a discarded one must never be disposed.</summary>
    /// <param name="result">The result being discarded; left alone.</param>
    public override void Release(CertificateFinderResult result) { }
}
