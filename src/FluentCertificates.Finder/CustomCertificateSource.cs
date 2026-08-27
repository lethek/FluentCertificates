using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// A certificate source over a sequence the caller supplied, for certificates already in hand rather than
/// read from a store or a directory.
/// </summary>
/// <remarks>
/// The certificates belong to the caller, so this source never disposes one the filter rejects. Equality
/// is by the identity of the sequence, since an arbitrary <see cref="IEnumerable{T}"/> has no value to
/// compare: adding the same sequence twice is one source, adding an equivalent copy is two.
/// </remarks>
/// <param name="Certificates">The certificates this source offers.</param>
public sealed record CustomCertificateSource(IEnumerable<X509Certificate2> Certificates) : AbstractCertificateSource
{
    /// <inheritdoc/>
    public override string Kind => "Custom";


    /// <summary>
    /// Yields the supplied certificates. The sequence is enumerated lazily, so a generator is only run as
    /// far as the caller reads.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>The supplied certificates.</returns>
    protected override IEnumerable<CertificateFinderResult> Enumerate(CertificateFilter filter)
        => Certificates.Select(cert => new CertificateFinderResult {
            Source = this,
            //A supplied certificate has no location of its own, so its thumbprint stands in as the id
            Location = cert.Thumbprint,
            Certificate = cert
        });


    /// <summary>These certificates are the caller's, so a discarded one must never be disposed.</summary>
    public override bool OwnsCertificates => false;
}
