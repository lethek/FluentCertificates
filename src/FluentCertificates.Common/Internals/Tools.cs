using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

#pragma warning disable SYSLIB0057
internal static class Tools
{
    internal static X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
    {
// #if NET9_0_OR_GREATER
//         return X509CertificateLoader.LoadCertificate(data);
// #else
        return new X509Certificate2(data);
//#endif
    }

    
    internal static X509Certificate2 LoadCertificateFromFile(string path)
    {
// #if NET19_0_OR_GREATER
//         return X509CertificateLoader.LoadCertificateFromFile(path);
// #else
        return new X509Certificate2(path);
// #endif
    }

    
    internal static X509Certificate2 LoadPkcs12(
        ReadOnlySpan<byte> data,
        string? password,
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
    {
// #if NET9_0_OR_GREATER
//         return X509CertificateLoader.LoadPkcs12(data, password, keyStorageFlags);
// #else
        return new X509Certificate2(data, password, keyStorageFlags);
// #endif
    }

    
    internal static X509Certificate2 LoadPkcs12FromFile(
        string path,
        string? password,
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
    {
// #if NET9_0_OR_GREATER
//         return X509CertificateLoader.LoadPkcs12FromFile(path, password, keyStorageFlags);
// #else
        return new X509Certificate2(path, password, keyStorageFlags);
// #endif
    }
}
#pragma warning restore SYSLIB0057
