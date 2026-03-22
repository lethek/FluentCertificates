using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public static class X509Certificate2CollectionExtensions
{
    public static IEnumerable<X509Certificate2> ToEnumerable(this X509Certificate2Collection collection)
        => collection;


    public static X509Certificate2Collection ExportAsPkcs7(this X509Certificate2Collection collection, BinaryWriter writer)
    {
        collection.ToEnumerable().ExportAsPkcs7(writer);
        return collection;
    }


    public static X509Certificate2Collection ExportAsPkcs7(this X509Certificate2Collection collection, string path)
    {
        collection.ToEnumerable().ExportAsPkcs7(path);
        return collection;
    }


    public static X509Certificate2Collection ExportAsPkcs12(this X509Certificate2Collection collection, BinaryWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
    {
        collection.ToEnumerable().ExportAsPkcs12(writer, password, include);
        return collection;
    }

    
    public static X509Certificate2Collection ExportAsPkcs12(this X509Certificate2Collection collection, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        collection.ToEnumerable().ExportAsPkcs12(path, password, include);
        return collection;
    }


    public static X509Certificate2Collection ExportAsPem(this X509Certificate2Collection collection, TextWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
    {
        collection.ToEnumerable().ExportAsPem(writer, password, include);
        return collection;
    }

    
    public static X509Certificate2Collection ExportAsPem(this X509Certificate2Collection collection, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        collection.ToEnumerable().ExportAsPem(path, password, include);
        return collection;
    }


    public static string ToPemString(this X509Certificate2Collection collection, string? password = null, ExportKeys include = ExportKeys.All)
        => collection.ToEnumerable().ToPemString(password, include);


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with the certificates in this collection.
    /// </summary>
    /// <param name="collection">The certificate collection to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing all certificates in the collection.</returns>
    public static CertificateExportBuilder Export(this X509Certificate2Collection collection)
        => new(collection.Cast<X509Certificate2>());
}
