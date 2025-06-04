using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

#pragma warning disable SYSLIB0057
internal static class CertTools
{
    /*
     * https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography/docs/X509CertificateLoader.SecurityDesign.md
     */
    
    internal static X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
#if NET9_0_OR_GREATER
        => X509CertificateLoader.LoadCertificate(data);
#else
        => new X509Certificate2(data);
#endif

    
    internal static X509Certificate2 LoadCertificateFromFile(string path)
#if NET9_0_OR_GREATER
        => X509CertificateLoader.LoadCertificateFromFile(path);
#else
        => new X509Certificate2(path);
#endif

    
    internal static X509Certificate2 LoadPkcs12(
        ReadOnlySpan<byte> data,
        string? password,
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
#if NET9_0_OR_GREATER
        => X509CertificateLoader.LoadPkcs12(data, password, keyStorageFlags, CustomLimits);
#else
        => new X509Certificate2(data, password, keyStorageFlags);
#endif

    
    internal static X509Certificate2 LoadPkcs12FromFile(
        string path,
        string? password,
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
#if NET9_0_OR_GREATER
        => X509CertificateLoader.LoadPkcs12FromFile(path, password, keyStorageFlags, CustomLimits);
#else
        => new X509Certificate2(path, password, keyStorageFlags);
#endif


#if NET9_0_OR_GREATER
    private static readonly Pkcs12LoaderLimits CustomLimits = new(Pkcs12LoaderLimits.Defaults) {
        PreserveCertificateAlias = true,
        PreserveUnknownAttributes = true,
    };
#endif
}
#pragma warning restore SYSLIB0057
