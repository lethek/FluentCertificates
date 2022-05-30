using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Extensions;

public static class X509ChainExtensions
{
    public static X509Certificate2Collection ToCollection(this X509Chain chain, ExportKeys include = ExportKeys.All)
        => chain.ToEnumerable().FilterPrivateKeys(include).ToCollection();


    public static IEnumerable<X509Certificate2> ToEnumerable(this X509Chain chain)
        => chain
            .ChainElements
            .Cast<X509ChainElement>()
            .Select(x => x.Certificate);


    public static X509Chain ExportAsPkcs7(this X509Chain chain, string path)
    {
        chain.ToEnumerable().ExportAsPkcs7(path);
        return chain;
    }


    public static X509Chain ExportAsPkcs12(this X509Chain chain, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        chain.ToEnumerable().ExportAsPkcs12(path, password, include);
        return chain;
    }


    public static X509Chain ExportAsPem(this X509Chain chain, string path, ExportKeys include = ExportKeys.All)
    {
        chain.ToEnumerable().ExportAsPem(path, include);
        return chain;
    }


    public static string ToPemString(this X509Chain chain, ExportKeys include = ExportKeys.All)
        => chain.ToEnumerable().ToPemString(include);
}