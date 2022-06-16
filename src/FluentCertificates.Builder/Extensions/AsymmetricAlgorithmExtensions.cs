using System.Security.Cryptography;

using FluentCertificates.Internals;

namespace FluentCertificates.Extensions;

public static class AsymmetricAlgorithmExtensions
{
    public static AsymmetricAlgorithm ExportAsPrivateKeyPem(this AsymmetricAlgorithm keys, TextWriter writer)
    {
        writer.Write(keys.ToPrivateKeyPemString());
        return keys;
    }

    
    public static AsymmetricAlgorithm ExportAsPrivateKeyPem(this AsymmetricAlgorithm keys, string path)
    {
        File.WriteAllText(path, keys.ToPrivateKeyPemString());
        return keys;
    }


    public static string ToPrivateKeyPemString(this AsymmetricAlgorithm keys)
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write("PRIVATE KEY", keys.ExportPkcs8PrivateKey()));
        sw.Write('\n');
        return sw.ToString();
    }


    public static AsymmetricAlgorithm ExportAsPublicKeyPem(this AsymmetricAlgorithm keys, TextWriter writer)
    {
        writer.Write(keys.ToPublicKeyPemString());
        return keys;
    }

    
    public static AsymmetricAlgorithm ExportAsPublicKeyPem(this AsymmetricAlgorithm keys, string path)
    {
        File.WriteAllText(path, keys.ToPublicKeyPemString());
        return keys;
    }

    
    public static string ToPublicKeyPemString(this AsymmetricAlgorithm keys)
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write("PUBLIC KEY", keys.ExportSubjectPublicKeyInfo()));
        sw.Write('\n');
        return sw.ToString();
    }
}