using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public static class X509Certificate2CollectionExtensions
{
    public static IEnumerable<X509Certificate2> ToEnumerable(this X509Certificate2Collection collection)
        => collection;


    /// <summary>
    /// Exports the certificate collection in PKCS#7 format to a <see cref="BinaryWriter"/>.
    /// </summary>
    /// <remarks>Deprecated. Use <c>collection.Export().AsPkcs7().ToStream(writer.BaseStream)</c> instead.</remarks>
    /// <param name="collection">The certificate collection to export.</param>
    /// <param name="writer">The binary writer to write to.</param>
    /// <returns>The original collection.</returns>
    [Obsolete("Use collection.Export().AsPkcs7().ToStream(writer.BaseStream) instead.")]
    public static X509Certificate2Collection ExportAsPkcs7(this X509Certificate2Collection collection, BinaryWriter writer)
    {
        #pragma warning disable CS0618
        collection.ToEnumerable().ExportAsPkcs7(writer);
        #pragma warning restore CS0618
        return collection;
    }


    /// <summary>
    /// Exports the certificate collection in PKCS#7 format to a file path.
    /// </summary>
    /// <remarks>Deprecated. Use <c>collection.Export().AsPkcs7().ToFile(path)</c> instead.</remarks>
    /// <param name="collection">The certificate collection to export.</param>
    /// <param name="path">The file path to write to.</param>
    /// <returns>The original collection.</returns>
    [Obsolete("Use collection.Export().AsPkcs7().ToFile(path) instead.")]
    public static X509Certificate2Collection ExportAsPkcs7(this X509Certificate2Collection collection, string path)
    {
        #pragma warning disable CS0618
        collection.ToEnumerable().ExportAsPkcs7(path);
        #pragma warning restore CS0618
        return collection;
    }


    /// <summary>
    /// Exports the certificate collection in PKCS#12 format to a <see cref="BinaryWriter"/>.
    /// </summary>
    /// <remarks>Deprecated. Use <c>collection.Export().WithPassword(password).AsPkcs12().ToStream(writer.BaseStream)</c> instead.</remarks>
    /// <param name="collection">The certificate collection to export.</param>
    /// <param name="writer">The binary writer to write to.</param>
    /// <param name="password">Optional password for the PKCS#12 file.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original collection.</returns>
    [Obsolete("Use collection.Export().WithPassword(password).AsPkcs12().ToStream(writer.BaseStream) instead.")]
    public static X509Certificate2Collection ExportAsPkcs12(this X509Certificate2Collection collection, BinaryWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        collection.ToEnumerable().ExportAsPkcs12(writer, password, include);
        #pragma warning restore CS0618
        return collection;
    }

    
    /// <summary>
    /// Exports the certificate collection in PKCS#12 format to a file path.
    /// </summary>
    /// <remarks>Deprecated. Use <c>collection.Export().WithPassword(password).AsPkcs12().ToFile(path)</c> instead.</remarks>
    /// <param name="collection">The certificate collection to export.</param>
    /// <param name="path">The file path to write to.</param>
    /// <param name="password">Optional password for the PKCS#12 file.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original collection.</returns>
    [Obsolete("Use collection.Export().WithPassword(password).AsPkcs12().ToFile(path) instead.")]
    public static X509Certificate2Collection ExportAsPkcs12(this X509Certificate2Collection collection, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        collection.ToEnumerable().ExportAsPkcs12(path, password, include);
        #pragma warning restore CS0618
        return collection;
    }


    /// <summary>
    /// Exports the certificate collection in PEM format to a <see cref="TextWriter"/>.
    /// </summary>
    /// <remarks>Deprecated. Use <c>collection.Export().AsPem().ToPemString()</c> and write the result to the TextWriter instead.</remarks>
    /// <param name="collection">The certificate collection to export.</param>
    /// <param name="writer">The text writer to write to.</param>
    /// <param name="password">Optional password for encrypted private key export.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original collection.</returns>
    [Obsolete("Use collection.Export().AsPem().ToPemString() and write the result to the TextWriter instead.")]
    public static X509Certificate2Collection ExportAsPem(this X509Certificate2Collection collection, TextWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        collection.ToEnumerable().ExportAsPem(writer, password, include);
        #pragma warning restore CS0618
        return collection;
    }

    
    /// <summary>
    /// Exports the certificate collection in PEM format to a file path.
    /// </summary>
    /// <remarks>Deprecated. Use <c>collection.Export().AsPem().ToFile(path)</c> instead.</remarks>
    /// <param name="collection">The certificate collection to export.</param>
    /// <param name="path">The file path to write to.</param>
    /// <param name="password">Optional password for encrypted private key export.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original collection.</returns>
    [Obsolete("Use collection.Export().AsPem().ToFile(path) instead.")]
    public static X509Certificate2Collection ExportAsPem(this X509Certificate2Collection collection, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        collection.ToEnumerable().ExportAsPem(path, password, include);
        #pragma warning restore CS0618
        return collection;
    }


    /// <summary>
    /// Exports the certificate collection in PEM format as a string.
    /// </summary>
    /// <remarks>Deprecated. Use <c>collection.Export().AsPem().ToPemString()</c> instead.</remarks>
    /// <param name="collection">The certificate collection to export.</param>
    /// <param name="password">Optional password for encrypted private key export.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The PEM-encoded string.</returns>
    [Obsolete("Use collection.Export().AsPem().ToPemString() instead.")]
    public static string ToPemString(this X509Certificate2Collection collection, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        return collection.ToEnumerable().ToPemString(password, include);
        #pragma warning restore CS0618
    }


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this collection.
    /// </summary>
    /// <param name="collection">The certificate collection to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing all certificates in the collection.</returns>
    public static CertificateExportBuilder Export(this X509Certificate2Collection collection)
        => new(collection.Cast<X509Certificate2>());
}
