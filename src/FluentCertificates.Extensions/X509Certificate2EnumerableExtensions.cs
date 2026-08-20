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
    internal static IEnumerable<X509Certificate2> FilterPrivateKeys(this IEnumerable<X509Certificate2> enumerable, ExportKeys include, ICollection<X509Certificate2> created)
        => include switch {
            ExportKeys.All => enumerable,
            ExportKeys.Primary => enumerable.Select((x, i) => x.HasPrivateKey && i > 0 ? StripPrivateKey(x, created) : x),
            ExportKeys.None => enumerable.Select(x => x.HasPrivateKey ? StripPrivateKey(x, created) : x),
            _ => throw new ArgumentOutOfRangeException(nameof(include))
        };


    /// <summary>
    /// As <see cref="FilterPrivateKeys(IEnumerable{X509Certificate2},ExportKeys,ICollection{X509Certificate2})"/>,
    /// but <see cref="ExportKeys.Primary"/> keeps <paramref name="primary"/>'s key rather than the first
    /// certificate's, so a caller's anchor survives whatever order the list ends up in.
    /// </summary>
    internal static IEnumerable<X509Certificate2> FilterPrivateKeys(this IEnumerable<X509Certificate2> enumerable, ExportKeys include, X509Certificate2 primary, ICollection<X509Certificate2> created)
        => include switch {
            ExportKeys.All => enumerable,
            ExportKeys.Primary => enumerable.Select(x => x.HasPrivateKey && !String.Equals(x.Thumbprint, primary.Thumbprint, StringComparison.OrdinalIgnoreCase) ? StripPrivateKey(x, created) : x),
            ExportKeys.None => enumerable.Select(x => x.HasPrivateKey ? StripPrivateKey(x, created) : x),
            _ => throw new ArgumentOutOfRangeException(nameof(include))
        };


    private static X509Certificate2 StripPrivateKey(X509Certificate2 cert, ICollection<X509Certificate2> created)
    {
        var keyless = CertTools.LoadCertificate(cert.RawDataMemory.Span);
        created.Add(keyless);
        return keyless;
    }


    #region Export to a Writer

    // ReSharper disable once SuspiciousTypeConversion.Global

    #endregion


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this sequence.
    /// </summary>
    /// <param name="enumerable">The certificates to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing all certificates in the sequence.</returns>
    public static CertificateExportBuilder Export(this IEnumerable<X509Certificate2> enumerable)
        => new(enumerable);
}
