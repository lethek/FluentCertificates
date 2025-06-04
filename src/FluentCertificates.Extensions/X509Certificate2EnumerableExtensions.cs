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
    public static IEnumerable<X509Certificate2> ExportAsPkcs7(this IEnumerable<X509Certificate2> enumerable, BinaryWriter writer)
    {
        //In .NET 6 and up, X509Certificate2Collection implements IEnumerable<X509Certificate2>, so no need to allocate & copy
        var collection = enumerable as X509Certificate2Collection ?? enumerable.ToCollection();

        var data = collection.Export(X509ContentType.Pkcs7)
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


    public static IEnumerable<X509Certificate2> ExportAsPem(this IEnumerable<X509Certificate2> enumerable, TextWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
    {
        writer.Write(enumerable.ToPemString(password, include));
        return enumerable;
    }

    #endregion


    #region Export to a File

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


    public static IEnumerable<X509Certificate2> ExportAsPem(this IEnumerable<X509Certificate2> enumerable, string path, string? password = null, ExportKeys include = ExportKeys.All)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return enumerable.ExportAsPem(writer, password, include);
    }

    #endregion


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
}
