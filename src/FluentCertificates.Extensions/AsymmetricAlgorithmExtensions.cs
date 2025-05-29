using System.Security.Cryptography;


namespace FluentCertificates;

/// <summary>
/// Provides extension methods for <see cref="AsymmetricAlgorithm"/> to export keys as PEM strings or files.
/// </summary>
public static class AsymmetricAlgorithmExtensions
{
    /// <summary>
    /// Exports the private key as a PEM-encoded string.
    /// Optionally encrypts the key with the specified password.
    /// </summary>
    /// <param name="keys">The <see cref="AsymmetricAlgorithm"/> instance.</param>
    /// <param name="password">The password to encrypt the private key, or null for no encryption.</param>
    /// <returns>A PEM-encoded string representing the private key.</returns>
    public static string ToPrivateKeyPemString(this AsymmetricAlgorithm keys, string? password = null)
    {
        using var sw = new StringWriter();
        sw.Write(
            String.IsNullOrEmpty(password)
                ? PemEncoding.Write("PRIVATE KEY", keys.ExportPkcs8PrivateKey())
                : PemEncoding.Write("ENCRYPTED PRIVATE KEY", keys.ExportEncryptedPkcs8PrivateKey(password, DefaultPbeParameters))
        );
        return sw.ToString();
    }


    /// <summary>
    /// Exports the public key as a PEM-encoded string.
    /// </summary>
    /// <param name="keys">The <see cref="AsymmetricAlgorithm"/> instance.</param>
    /// <returns>A PEM-encoded string representing the public key.</returns>
    public static string ToPublicKeyPemString(this AsymmetricAlgorithm keys)
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write("PUBLIC KEY", keys.ExportSubjectPublicKeyInfo()));
        return sw.ToString();
    }


    /// <summary>
    /// Exports the private key as PEM to the specified <see cref="TextWriter"/>.
    /// Optionally encrypts the key with the specified password.
    /// </summary>
    /// <param name="keys">The <see cref="AsymmetricAlgorithm"/> instance.</param>
    /// <param name="writer">The <see cref="TextWriter"/> to write the PEM to.</param>
    /// <param name="password">The password to encrypt the private key, or null for no encryption.</param>
    /// <returns>The original <see cref="AsymmetricAlgorithm"/> instance.</returns>
    public static AsymmetricAlgorithm ExportAsPrivateKeyPem(this AsymmetricAlgorithm keys, TextWriter writer, string? password = null)
    {
        writer.Write(keys.ToPrivateKeyPemString(password));
        return keys;
    }


    /// <summary>
    /// Exports the public key as PEM to the specified <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="keys">The <see cref="AsymmetricAlgorithm"/> instance.</param>
    /// <param name="writer">The <see cref="TextWriter"/> to write the PEM to.</param>
    /// <returns>The original <see cref="AsymmetricAlgorithm"/> instance.</returns>
    public static AsymmetricAlgorithm ExportAsPublicKeyPem(this AsymmetricAlgorithm keys, TextWriter writer)
    {
        writer.Write(keys.ToPublicKeyPemString());
        return keys;
    }


    /// <summary>
    /// Exports the private key as PEM to a file at the specified path.
    /// Optionally encrypts the key with the specified password.
    /// </summary>
    /// <param name="keys">The <see cref="AsymmetricAlgorithm"/> instance.</param>
    /// <param name="path">The file path to write the PEM to.</param>
    /// <param name="password">The password to encrypt the private key, or null for no encryption.</param>
    /// <returns>The original <see cref="AsymmetricAlgorithm"/> instance.</returns>
    public static AsymmetricAlgorithm ExportAsPrivateKeyPem(this AsymmetricAlgorithm keys, string path, string? password = null)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return keys.ExportAsPrivateKeyPem(writer, password);
    }


    /// <summary>
    /// Exports the public key as PEM to a file at the specified path.
    /// </summary>
    /// <param name="keys">The <see cref="AsymmetricAlgorithm"/> instance.</param>
    /// <param name="path">The file path to write the PEM to.</param>
    /// <returns>The original <see cref="AsymmetricAlgorithm"/> instance.</returns>
    public static AsymmetricAlgorithm ExportAsPublicKeyPem(this AsymmetricAlgorithm keys, string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return keys.ExportAsPublicKeyPem(writer);
    }


    /// <summary>
    /// The default parameters for password-based encryption (PBE) when exporting encrypted private keys.
    /// </summary>
    private static readonly PbeParameters DefaultPbeParameters = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);
}