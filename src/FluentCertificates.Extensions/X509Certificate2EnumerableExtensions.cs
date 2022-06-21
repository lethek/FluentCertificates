using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

[SuppressMessage("ReSharper", "PossibleMultipleEnumeration")]
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
            ExportKeys.Leaf => enumerable.Reverse().Select((x, i) => x.HasPrivateKey && i > 0 ? new X509Certificate2(x.RawData, "", X509KeyStorageFlags.Exportable) : x).Reverse(),
            ExportKeys.None => enumerable.Select(x => x.HasPrivateKey ? new X509Certificate2(x.RawData, "", X509KeyStorageFlags.Exportable) : x),
            _ => throw new ArgumentOutOfRangeException(nameof(include))
        };


    #region Export to a Writer

    [SuppressMessage("ReSharper", "SuspiciousTypeConversion.Global")]
    public static IEnumerable<X509Certificate2> ExportAsPkcs7(this IEnumerable<X509Certificate2> enumerable, BinaryWriter writer)
    {
        //In .NET 6 and up, X509Certificate2Collection implements IEnumerable<X509Certificate2>, so no need to allocate & copy
        var collection = enumerable is X509Certificate2Collection certCollection
            ? certCollection
            : enumerable.ToCollection();

        var data = collection
                       .Export(X509ContentType.Pkcs7)
                   ?? throw new ArgumentException("Nothing to export", nameof(enumerable));

        writer.Write(data);
        return enumerable;
    }


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


    public static IEnumerable<X509Certificate2> ExportAsPem(this IEnumerable<X509Certificate2> enumerable, TextWriter writer, ExportKeys include = ExportKeys.All)
    {
        writer.Write(enumerable.ToPemString(include));
        return enumerable;
    }

    #endregion


    #region Export to a File

    [SuppressMessage("ReSharper", "SuspiciousTypeConversion.Global")]
    public static IEnumerable<X509Certificate2> ExportAsPkcs7(this IEnumerable<X509Certificate2> enumerable, string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new BinaryWriter(stream);
        return enumerable.ExportAsPkcs7(writer);
    }


    public static IEnumerable<X509Certificate2> ExportAsPkcs12(this IEnumerable<X509Certificate2> enumerable, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new BinaryWriter(stream);
        return enumerable.ExportAsPkcs12(writer, password, include);
    }


    public static IEnumerable<X509Certificate2> ExportAsPem(this IEnumerable<X509Certificate2> enumerable, string path, ExportKeys include = ExportKeys.All)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return enumerable.ExportAsPem(writer, include);
    }

    #endregion


    public static string ToPemString(this IEnumerable<X509Certificate2> enumerable, ExportKeys include = ExportKeys.All)
    {
        var list = enumerable.FilterPrivateKeys(include).Reverse().ToList();
        using var sw = new StringWriter();
        if (include != ExportKeys.None) {
            foreach (var cert in list.Where(x => x.HasPrivateKey)) {
                sw.Write(PemEncoding.Write("PRIVATE KEY", cert.GetPrivateKey().ExportPkcs8PrivateKey()));
                sw.Write('\n');
            }
        }
        foreach (var cert in list) {
            sw.Write(PemEncoding.Write("CERTIFICATE", cert.RawData));
            sw.Write('\n');
        }
        return sw.ToString();
    }
}
