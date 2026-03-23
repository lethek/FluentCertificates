using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public static class X509ChainExtensions
{
    public static IEnumerable<X509Certificate2> ToEnumerable(this X509Chain chain)
        => chain
            .ChainElements
            .Reverse()
            .Select(x => x.Certificate);


    public static X509Certificate2Collection ToCollection(this X509Chain chain, ExportKeys include = ExportKeys.All)
        => chain.ToEnumerable().FilterPrivateKeys(include).ToCollection();


    /// <summary>
    /// Exports the certificate chain in PKCS#7 format to a <see cref="BinaryWriter"/>.
    /// </summary>
    /// <remarks>Deprecated. Use <c>chain.Export().AsPkcs7().ToStream(writer.BaseStream)</c> instead.</remarks>
    /// <param name="chain">The certificate chain to export.</param>
    /// <param name="writer">The binary writer to write to.</param>
    /// <returns>The original chain.</returns>
    [Obsolete("Use chain.Export().AsPkcs7().ToStream(writer.BaseStream) instead.")]
    public static X509Chain ExportAsPkcs7(this X509Chain chain, BinaryWriter writer)
    {
        #pragma warning disable CS0618
        chain.ToEnumerable().ExportAsPkcs7(writer);
        #pragma warning restore CS0618
        return chain;
    }

    
    /// <summary>
    /// Exports the certificate chain in PKCS#7 format to a file path.
    /// </summary>
    /// <remarks>Deprecated. Use <c>chain.Export().AsPkcs7().ToFile(path)</c> instead.</remarks>
    /// <param name="chain">The certificate chain to export.</param>
    /// <param name="path">The file path to write to.</param>
    /// <returns>The original chain.</returns>
    [Obsolete("Use chain.Export().AsPkcs7().ToFile(path) instead.")]
    public static X509Chain ExportAsPkcs7(this X509Chain chain, string path)
    {
        #pragma warning disable CS0618
        chain.ToEnumerable().ExportAsPkcs7(path);
        #pragma warning restore CS0618
        return chain;
    }


    /// <summary>
    /// Exports the certificate chain in PKCS#12 format to a <see cref="BinaryWriter"/>.
    /// </summary>
    /// <remarks>Deprecated. Use <c>chain.Export().WithPassword(password).AsPkcs12().ToStream(writer.BaseStream)</c> instead.</remarks>
    /// <param name="chain">The certificate chain to export.</param>
    /// <param name="writer">The binary writer to write to.</param>
    /// <param name="password">Optional password for the PKCS#12 file.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original chain.</returns>
    [Obsolete("Use chain.Export().WithPassword(password).AsPkcs12().ToStream(writer.BaseStream) instead.")]
    public static X509Chain ExportAsPkcs12(this X509Chain chain, BinaryWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        chain.ToEnumerable().ExportAsPkcs12(writer, password, include);
        #pragma warning restore CS0618
        return chain;
    }

    
    /// <summary>
    /// Exports the certificate chain in PKCS#12 format to a file path.
    /// </summary>
    /// <remarks>Deprecated. Use <c>chain.Export().WithPassword(password).AsPkcs12().ToFile(path)</c> instead.</remarks>
    /// <param name="chain">The certificate chain to export.</param>
    /// <param name="path">The file path to write to.</param>
    /// <param name="password">Optional password for the PKCS#12 file.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original chain.</returns>
    [Obsolete("Use chain.Export().WithPassword(password).AsPkcs12().ToFile(path) instead.")]
    public static X509Chain ExportAsPkcs12(this X509Chain chain, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        chain.ToEnumerable().ExportAsPkcs12(path, password, include);
        #pragma warning restore CS0618
        return chain;
    }


    /// <summary>
    /// Exports the certificate chain in PEM format to a <see cref="TextWriter"/>.
    /// </summary>
    /// <remarks>Deprecated. Use <c>chain.Export().AsPem().ToPemString()</c> and write the result to the TextWriter instead.</remarks>
    /// <param name="chain">The certificate chain to export.</param>
    /// <param name="writer">The text writer to write to.</param>
    /// <param name="password">Optional password for encrypted private key export.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original chain.</returns>
    [Obsolete("Use chain.Export().AsPem().ToPemString() and write the result to the TextWriter instead.")]
    public static X509Chain ExportAsPem(this X509Chain chain, TextWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        chain.ToEnumerable().ExportAsPem(writer, password, include);
        #pragma warning restore CS0618
        return chain;
    }

    
    /// <summary>
    /// Exports the certificate chain in PEM format to a file path.
    /// </summary>
    /// <remarks>Deprecated. Use <c>chain.Export().AsPem().ToFile(path)</c> instead.</remarks>
    /// <param name="chain">The certificate chain to export.</param>
    /// <param name="path">The file path to write to.</param>
    /// <param name="password">Optional password for encrypted private key export.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The original chain.</returns>
    [Obsolete("Use chain.Export().AsPem().ToFile(path) instead.")]
    public static X509Chain ExportAsPem(this X509Chain chain, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        chain.ToEnumerable().ExportAsPem(path, password, include);
        #pragma warning restore CS0618
        return chain;
    }


    /// <summary>
    /// Exports the certificate chain in PEM format as a string.
    /// </summary>
    /// <remarks>Deprecated. Use <c>chain.Export().AsPem().ToPemString()</c> instead.</remarks>
    /// <param name="chain">The certificate chain to export.</param>
    /// <param name="password">Optional password for encrypted private key export.</param>
    /// <param name="include">Which key material to include in the export.</param>
    /// <returns>The PEM-encoded string.</returns>
    [Obsolete("Use chain.Export().AsPem().ToPemString() instead.")]
    public static string ToPemString(this X509Chain chain, string? password = null, ExportKeys include = ExportKeys.All)
    {
        #pragma warning disable CS0618
        return chain.ToEnumerable().ToPemString(password, include);
        #pragma warning restore CS0618
    }


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this chain.
    /// Certificates are added in root-first order (same as <see cref="ToEnumerable"/>).
    /// Use <see cref="CertificateExportBuilder.AsCert"/> to export the first certificate (the root);
    /// use <see cref="CertificateExportBuilder.AsPkcs12"/> etc. to export all chain certificates.
    /// </summary>
    /// <param name="chain">The certificate chain to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing the chain's certificates.</returns>
    public static CertificateExportBuilder Export(this X509Chain chain)
        => new(chain.ToEnumerable());
}