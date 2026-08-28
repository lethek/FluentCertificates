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
public sealed record CertificateCollectionSource(IEnumerable<X509Certificate2> Certificates) : AbstractCertificateSource
{
    /// <inheritdoc/>
    public override string Kind => "Collection";


    /// <summary>
    /// Yields the supplied certificates. The sequence is enumerated lazily, so a generator is only run as
    /// far as the caller reads.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>The supplied certificates.</returns>
    protected override IEnumerable<CertificateFinderResult> Enumerate(CertificateFilter filter)
        //A supplied certificate has no location of its own, so its thumbprint stands in as the id
        => SelectResults(Certificates, cert => cert.Thumbprint);


    /// <summary>
    /// Reversing buffers references to certificates that already exist, rather than creating anything.
    /// A lazy sequence is still run to completion to do it, unlike <see cref="Enumerate"/>.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>The supplied certificates, last first.</returns>
    protected override IEnumerable<CertificateFinderResult> EnumerateDescending(CertificateFilter filter)
        => SelectResults(Certificates.Reverse(), cert => cert.Thumbprint);


    /// <summary>These certificates are the caller's, so a discarded one must never be disposed.</summary>
    /// <param name="result">The result being discarded; left alone.</param>
    public override void Release(CertificateFinderResult result) { }
}
