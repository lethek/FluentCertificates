using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace FluentCertificates;

internal static class InternalTools
{
    internal static SecureRandom SecureRandom = new();


    internal static AsymmetricCipherKeyPair GetBouncyCastleRsaKeyPair(X509Certificate2 cert)
    {
        using var source = cert.GetRSAPrivateKey() ?? throw new KeyException("RSA private key expected but not found");
        using var rsa = RSA.Create();
        var pbeParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1);
        var pwd = (new byte[32]).AsSpan();
        SecureRandom.NextBytes(pwd);
        rsa.ImportEncryptedPkcs8PrivateKey(pwd, source.ExportEncryptedPkcs8PrivateKey(pwd, pbeParams), out _);
        pwd.Clear();
        return DotNetUtilities.GetRsaKeyPair(rsa);
    }
}