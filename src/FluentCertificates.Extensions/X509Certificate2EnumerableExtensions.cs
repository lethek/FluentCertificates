// ReSharper disable PossibleMultipleEnumeration

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;

public static class X509Certificate2EnumerableExtensions
{
    public static X509Certificate2Collection ToCollection(this IEnumerable<X509Certificate2> enumerable)
        => new(enumerable.ToArray());


    /// <summary>
    /// Remove/keep private keys from certificates based on the <paramref name="include"/> parameter. When <paramref name="include"/> is set to <see cref="ExportKeys.Leaf"/>,
    /// the leaf certificate is assumed to be the final one.
    /// </summary>
    /// <param name="enumerable"></param>
    /// <param name="include"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static IEnumerable<X509Certificate2> FilterPrivateKeys(this IEnumerable<X509Certificate2> enumerable, ExportKeys include)
        => include switch {
            ExportKeys.All => enumerable,
            ExportKeys.Leaf => enumerable.Reverse().Select((x, i) => x.HasPrivateKey && i > 0 ? CertTools.LoadCertificate(x.RawDataMemory.Span) : x).Reverse(),
            ExportKeys.None => enumerable.Select(x => x.HasPrivateKey ? CertTools.LoadCertificate(x.RawDataMemory.Span) : x),
            _ => throw new ArgumentOutOfRangeException(nameof(include))
        };


    #region Export to a Writer

    // ReSharper disable once SuspiciousTypeConversion.Global

    #endregion


    #region Export to a File

    #endregion


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this sequence.
    /// </summary>
    /// <param name="enumerable">The certificates to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing all certificates in the sequence.</returns>
    public static CertificateExportBuilder Export(this IEnumerable<X509Certificate2> enumerable)
        => new(enumerable);
}
