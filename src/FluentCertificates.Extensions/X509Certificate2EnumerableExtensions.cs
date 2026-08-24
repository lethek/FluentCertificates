// ReSharper disable PossibleMultipleEnumeration

using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;

/// <summary>
/// Provides extension methods for sequences of <see cref="X509Certificate2"/>.
/// </summary>
public static class X509Certificate2EnumerableExtensions
{
    /// <summary>
    /// Copies the sequence into a new <see cref="X509Certificate2Collection"/>.
    /// </summary>
    /// <param name="enumerable">The certificates to copy.</param>
    /// <returns>A new collection containing the same certificates, in the same order.</returns>
    public static X509Certificate2Collection ToCollection(this IEnumerable<X509Certificate2> enumerable)
        => new(enumerable.ToArray());


    /// <summary>
    /// Remove/keep private keys from certificates based on the <paramref name="include"/> parameter. When <paramref name="include"/> is set to <see cref="ExportKeys.Primary"/>,
    /// the primary certificate is taken to be the first one in the sequence, since a bare sequence
    /// designates none.
    /// </summary>
    /// <remarks>
    /// Stripping a private key produces a new certificate, while a certificate that keeps its key is passed
    /// through unchanged. The result therefore mixes certificates created by this call with the ones you
    /// supplied, and they cannot be told apart, so do not dispose the elements of the returned sequence.
    /// </remarks>
    /// <param name="enumerable">The certificates to filter.</param>
    /// <param name="include">Which private keys to keep.</param>
    /// <returns>The certificates, with private keys removed as requested.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="include"/> is not a defined <see cref="ExportKeys"/> value.</exception>
    public static IEnumerable<X509Certificate2> FilterPrivateKeys(this IEnumerable<X509Certificate2> enumerable, ExportKeys include)
        => enumerable.FilterPrivateKeys(include, new List<X509Certificate2>());


    /// <summary>
    /// As <see cref="FilterPrivateKeys(IEnumerable{X509Certificate2},ExportKeys)"/>, but records every
    /// certificate this call creates into <paramref name="created"/> so the caller can dispose them once the
    /// sequence has been consumed. Certificates passed through unchanged are not recorded: those belong to
    /// whoever supplied them. Note the sequence is lazy, so <paramref name="created"/> is only complete after
    /// it has been enumerated.
    /// </summary>
    /// <param name="enumerable">The certificates to filter.</param>
    /// <param name="include">Which private keys to keep.</param>
    /// <param name="created">Receives the keyless certificates this call creates.</param>
    /// <param name="primary">
    /// The certificate whose key <see cref="ExportKeys.Primary"/> keeps, so a caller's anchor survives
    /// whatever order the list ends up in. When <see langword="null"/>, the first certificate in the sequence
    /// is taken as the primary one, since a bare sequence designates none.
    /// </param>
    internal static IEnumerable<X509Certificate2> FilterPrivateKeys(this IEnumerable<X509Certificate2> enumerable, ExportKeys include, ICollection<X509Certificate2> created, X509Certificate2? primary = null)
        => include switch {
            ExportKeys.All => enumerable,
            ExportKeys.Primary => enumerable.Select((x, i) => x.HasPrivateKey && !IsPrimary(x, i, primary) ? StripPrivateKey(x, created) : x),
            ExportKeys.None => enumerable.Select(x => x.HasPrivateKey ? StripPrivateKey(x, created) : x),
            _ => throw new ArgumentOutOfRangeException(nameof(include))
        };


    /// <summary>
    /// Reports whether <paramref name="cert"/> is the one <see cref="ExportKeys.Primary"/> keeps the key of:
    /// <paramref name="primary"/> where one was named, and otherwise whichever certificate arrived first.
    /// </summary>
    private static bool IsPrimary(X509Certificate2 cert, int index, X509Certificate2? primary)
        => primary == null
            ? index == 0
            : String.Equals(cert.Thumbprint, primary.Thumbprint, StringComparison.OrdinalIgnoreCase);


    private static X509Certificate2 StripPrivateKey(X509Certificate2 cert, ICollection<X509Certificate2> created)
    {
        var keyless = CertTools.LoadCertificate(cert.RawDataMemory.Span);
        created.Add(keyless);
        return keyless;
    }


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this sequence,
    /// treated as a bundle: they are written in exactly this order and never reordered.
    /// </summary>
    /// <remarks>
    /// A bundle designates no leaf, so no <see cref="CertificateExportBuilder.Anchor"/> is set and
    /// <see cref="CertificateExportBuilder.AsCert"/> and <see cref="ExportKeys.Primary"/> throw, unless the
    /// sequence holds exactly one certificate. Seed from <c>cert.Export()</c> or <c>chain.Export()</c>
    /// when the export is about a particular certificate.
    /// </remarks>
    /// <param name="enumerable">The certificates to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing all certificates in the sequence.</returns>
    public static CertificateExportBuilder Export(this IEnumerable<X509Certificate2> enumerable)
        => new(enumerable);
}
