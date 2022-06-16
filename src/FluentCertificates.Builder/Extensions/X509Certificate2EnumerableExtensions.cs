using System.Diagnostics.CodeAnalysis;
#if NET5_0_OR_GREATER
using System.Security.Cryptography;
#endif
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates.Extensions;

[SuppressMessage("ReSharper", "PossibleMultipleEnumeration")]
public static class X509Certificate2EnumerableExtensions
{
    public static X509Certificate2Collection ToCollection(this IEnumerable<X509Certificate2> enumerable)
        => new(enumerable.ToArray());


    public static IEnumerable<X509Certificate2> FilterPrivateKeys(this IEnumerable<X509Certificate2> enumerable, ExportKeys include)
        => include switch {
            ExportKeys.All => enumerable,
            ExportKeys.Leaf => enumerable.Select((x, i) => x.HasPrivateKey && i > 0 ? new X509Certificate2(x.RawData, "", X509KeyStorageFlags.Exportable) : x),
            ExportKeys.None => enumerable.Select(x => x.HasPrivateKey ? new X509Certificate2(x.RawData, "", X509KeyStorageFlags.Exportable) : x),
            _ => throw new ArgumentOutOfRangeException(nameof(include))
        };


    [SuppressMessage("ReSharper", "SuspiciousTypeConversion.Global")]
    public static IEnumerable<X509Certificate2> ExportAsPkcs7(this IEnumerable<X509Certificate2> enumerable, string path)
    {
        //In .NET 6 and up, X509Certificate2Collection implements IEnumerable<X509Certificate2>, so no need to allocate & copy
        var collection = enumerable is X509Certificate2Collection certCollection
            ? certCollection
            : enumerable.ToCollection();

        var data = collection
            .Export(X509ContentType.Pkcs7)
            ?? throw new ArgumentException("Nothing to export", nameof(enumerable));

        File.WriteAllBytes(path, data);
        return enumerable;
    }


    public static IEnumerable<X509Certificate2> ExportAsPkcs12(this IEnumerable<X509Certificate2> enumerable, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        var data = enumerable
            .FilterPrivateKeys(include)
            .ToCollection()
            .Export(X509ContentType.Pkcs12, password)
            ?? throw new ArgumentException("Nothing to export", nameof(enumerable));

        File.WriteAllBytes(path, data);
        return enumerable;
    }


    public static IEnumerable<X509Certificate2> ExportAsPem(this IEnumerable<X509Certificate2> enumerable, TextWriter writer, ExportKeys include = ExportKeys.All)
    {
        writer.Write(enumerable.ToPemString(include));
        return enumerable;
    }

    
    public static IEnumerable<X509Certificate2> ExportAsPem(this IEnumerable<X509Certificate2> enumerable, string path, ExportKeys include = ExportKeys.All)
    {
        File.WriteAllText(path, enumerable.ToPemString(include));
        return enumerable;
    }


    public static string ToPemString(this IEnumerable<X509Certificate2> enumerable, ExportKeys include = ExportKeys.All)
    {
        var list = enumerable.FilterPrivateKeys(include).ToList();
        using var sw = new StringWriter();
        foreach (var cert in list) {
            sw.Write(PemEncoding.Write("CERTIFICATE", cert.RawData));
            sw.Write('\n');
        }
        if (include != ExportKeys.None) {
            foreach (var cert in list.Where(x => x.HasPrivateKey)) {
                sw.Write(PemEncoding.Write("PRIVATE KEY", cert.GetPrivateKey().ExportPkcs8PrivateKey()));
                sw.Write('\n');
            }
        }
        return sw.ToString();
    }
}
