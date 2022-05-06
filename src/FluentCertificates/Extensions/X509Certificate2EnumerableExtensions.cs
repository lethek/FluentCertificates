using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

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


    public static IEnumerable<X509Certificate2> ExportAsPem(this IEnumerable<X509Certificate2> enumerable, string path, ExportKeys include = ExportKeys.All)
    {
        File.WriteAllText(path, enumerable.ToPemString(include));
        return enumerable;
    }


    public static string ToPemString(this IEnumerable<X509Certificate2> enumerable, ExportKeys include = ExportKeys.All)
    {
        var list = enumerable.FilterPrivateKeys(include).ToList();
        using var sw = new StringWriter();
        var pem = new PemWriter(sw);
        foreach (var cert in list.Select(DotNetUtilities.FromX509Certificate)) {
            pem.WriteObject(cert);
        }
        if (include != ExportKeys.None) {
            foreach (var cert in list.Where(x => x.HasPrivateKey)) {
                pem.WriteObject(InternalTools.GetBouncyCastleRsaKeyPair(cert).Private);
            }
        }
        return sw.ToString();
    }
}
