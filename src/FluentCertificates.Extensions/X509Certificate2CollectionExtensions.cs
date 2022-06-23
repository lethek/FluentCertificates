using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

[SuppressMessage("ReSharper", "PossibleMultipleEnumeration")]
public static class X509Certificate2CollectionExtensions
{
    public static IEnumerable<X509Certificate2> ToEnumerable(this X509Certificate2Collection collection)
        => collection
            .Cast<X509Certificate2>();


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
}
