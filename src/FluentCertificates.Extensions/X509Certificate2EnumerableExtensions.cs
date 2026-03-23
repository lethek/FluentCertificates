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
    /// <summary>
    /// Exports the certificates in PKCS#7 format to a <see cref="BinaryWriter"/>.
    /// </summary>
    /// <remarks>Deprecated. Use <c>certs.Export().AsPkcs7().ToStream(writer.BaseStream)</c> instead.</remarks>
    /// <param name="enumerable">The enumerable of certificates to export.</param>
    /// <param name="writer">The binary writer to write to.</param>
    /// <returns>The original enumerable.</returns>
    [Obsolete("Use certs.Export().AsPkcs7().ToStream(writer.BaseStream) instead.")]
    public static IEnumerable<X509Certificate2> ExportAsPkcs7(this IEnumerable<X509Certificate2> enumerable, BinaryWriter writer)
    {
        //In .NET 6 and up, X509Certificate2Collection implements IEnumerable<X509Certificate2>, so no need to allocate & copy
        var collection = enumerable as X509Certificate2Collection ?? enumerable.ToCollection();

        var data = collection.Export(X509ContentType.Pkcs7)
            ?? throw new ArgumentException("Nothing to export", nameof(enumerable));

        writer.Write(data);
        return enumerable;
    }


    /// <summary>
    /// Exports the certificates in PKCS#12 format to a <see cref="BinaryWriter"/>.
    /// </summary>
    /// <remarks>Deprecated. Use <c>certs.Export().WithPassword(password).AsPkcs12().ToStream(writer.BaseStream)</c> instead.</remarks>
    /// <param name="enumerable">The enumerable of certificates to export.</param>
    /// <param name="writer">The binary writer to write to.</param>
    /// <param name="password">Optional password for the PKCS#12 file.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original enumerable.</returns>
    [Obsolete("Use certs.Export().WithPassword(password).AsPkcs12().ToStream(writer.BaseStream) instead.")]
    public static IEnumerable<X509Certificate2> ExportAsPkcs12(this IEnumerable<X509Certificate2> enumerable, BinaryWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
    {
        var data =
            enumerable
                .FilterPrivateKeys(include)
                .ToCollection()
                .Export(X509ContentType.Pkcs12, password)
            ?? throw new ArgumentException("Nothing to export", nameof(enumerable));

        writer.Write(data);
        return enumerable;
    }


    /// <summary>
    /// Exports the certificates in PEM format to a <see cref="TextWriter"/>.
    /// </summary>
    /// <remarks>Deprecated. Use <c>certs.Export().AsPem().ToPemString()</c> and write the result to the TextWriter instead.</remarks>
    /// <param name="enumerable">The enumerable of certificates to export.</param>
    /// <param name="writer">The text writer to write to.</param>
    /// <param name="password">Optional password for encrypted private key export.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original enumerable.</returns>
    [Obsolete("Use certs.Export().AsPem().ToPemString() and write the result to the TextWriter instead.")]
    public static IEnumerable<X509Certificate2> ExportAsPem(this IEnumerable<X509Certificate2> enumerable, TextWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        writer.Write(enumerable.ToPemString(password, include));
        #pragma warning restore CS0618
        return enumerable;
    }

    #endregion


    #region Export to a File

    /// <summary>
    /// Exports the certificates in PKCS#7 format to a file path.
    /// </summary>
    /// <remarks>Deprecated. Use <c>certs.Export().AsPkcs7().ToFile(path)</c> instead.</remarks>
    /// <param name="enumerable">The enumerable of certificates to export.</param>
    /// <param name="path">The file path to write to.</param>
    /// <returns>The original enumerable.</returns>
    [Obsolete("Use certs.Export().AsPkcs7().ToFile(path) instead.")]
    public static IEnumerable<X509Certificate2> ExportAsPkcs7(this IEnumerable<X509Certificate2> enumerable, string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new BinaryWriter(stream);
        #pragma warning disable CS0618
        return enumerable.ExportAsPkcs7(writer);
        #pragma warning restore CS0618
    }


    /// <summary>
    /// Exports the certificates in PKCS#12 format to a file path.
    /// </summary>
    /// <remarks>Deprecated. Use <c>certs.Export().WithPassword(password).AsPkcs12().ToFile(path)</c> instead.</remarks>
    /// <param name="enumerable">The enumerable of certificates to export.</param>
    /// <param name="path">The file path to write to.</param>
    /// <param name="password">Optional password for the PKCS#12 file.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original enumerable.</returns>
    [Obsolete("Use certs.Export().WithPassword(password).AsPkcs12().ToFile(path) instead.")]
    public static IEnumerable<X509Certificate2> ExportAsPkcs12(this IEnumerable<X509Certificate2> enumerable, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new BinaryWriter(stream);
        #pragma warning disable CS0618
        return enumerable.ExportAsPkcs12(writer, password, include);
        #pragma warning restore CS0618
    }


    /// <summary>
    /// Exports the certificates in PEM format to a file path.
    /// </summary>
    /// <remarks>Deprecated. Use <c>certs.Export().AsPem().ToFile(path)</c> instead.</remarks>
    /// <param name="enumerable">The enumerable of certificates to export.</param>
    /// <param name="path">The file path to write to.</param>
    /// <param name="password">Optional password for encrypted private key export.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original enumerable.</returns>
    [Obsolete("Use certs.Export().AsPem().ToFile(path) instead.")]
    public static IEnumerable<X509Certificate2> ExportAsPem(this IEnumerable<X509Certificate2> enumerable, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        #pragma warning disable CS0618
        return enumerable.ExportAsPem(writer, password, include);
        #pragma warning restore CS0618
    }

    #endregion


    /// <summary>
    /// Exports the certificates in PEM format as a string.
    /// </summary>
    /// <remarks>Deprecated. Use <c>certs.Export().AsPem().ToPemString()</c> instead.</remarks>
    /// <param name="enumerable">The enumerable of certificates to export.</param>
    /// <param name="password">Optional password for encrypted private key export.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The PEM-encoded string.</returns>
    [Obsolete("Use certs.Export().AsPem().ToPemString() instead.")]
    public static string ToPemString(this IEnumerable<X509Certificate2> enumerable, string? password = null, ExportKeys include = ExportKeys.All)
    {
        var list = enumerable.FilterPrivateKeys(include).Reverse().ToList();
        if (list.Count == 0) {
            return String.Empty;
        }

        using var sw = new StringWriter();
        if (include != ExportKeys.None) {
            foreach (var cert in list.Where(x => x.HasPrivateKey)) {
                cert.GetPrivateKey().ExportAsPrivateKeyPem(sw, password);
                sw.Write('\n');
            }
        }
        sw.Write(PemEncoding.Write("CERTIFICATE", list.First().RawData));
        foreach (var cert in list.Skip(1)) {
            sw.Write('\n');
            sw.Write(PemEncoding.Write("CERTIFICATE", cert.RawData));
        }
        return sw.ToString();
    }


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this sequence.
    /// </summary>
    /// <param name="enumerable">The certificates to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing all certificates in the sequence.</returns>
    public static CertificateExportBuilder Export(this IEnumerable<X509Certificate2> enumerable)
        => new(enumerable);
}
