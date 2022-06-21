using System.Security.Cryptography;


namespace FluentCertificates;

public static class AsymmetricAlgorithmExtensions
{
    public static string ToPrivateKeyPemString(this AsymmetricAlgorithm keys, string? password = null)
    {
        using var sw = new StringWriter();
        sw.Write(
            String.IsNullOrEmpty(password)
                ? PemEncoding.Write("PRIVATE KEY", keys.ExportPkcs8PrivateKey())
                : PemEncoding.Write("ENCRYPTED PRIVATE KEY", keys.ExportEncryptedPkcs8PrivateKey(password, DefaultPbeParameters))
        );
        sw.Write('\n');
        return sw.ToString();
    }


    public static string ToPublicKeyPemString(this AsymmetricAlgorithm keys)
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write("PUBLIC KEY", keys.ExportSubjectPublicKeyInfo()));
        sw.Write('\n');
        return sw.ToString();
    }


    public static AsymmetricAlgorithm ExportAsPrivateKeyPem(this AsymmetricAlgorithm keys, TextWriter writer)
    {
        writer.Write(keys.ToPrivateKeyPemString());
        return keys;
    }


    public static AsymmetricAlgorithm ExportAsPublicKeyPem(this AsymmetricAlgorithm keys, TextWriter writer)
    {
        writer.Write(keys.ToPublicKeyPemString());
        return keys;
    }


    public static AsymmetricAlgorithm ExportAsPrivateKeyPem(this AsymmetricAlgorithm keys, string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return keys.ExportAsPrivateKeyPem(writer);
    }


    public static AsymmetricAlgorithm ExportAsPublicKeyPem(this AsymmetricAlgorithm keys, string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return keys.ExportAsPublicKeyPem(writer);
    }


    private static readonly PbeParameters DefaultPbeParameters = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);
}