using System.Security.Cryptography;

namespace FluentCertificates.Internals;

internal class AsymmetricAlgorithmParameters
{
    public KeyAlgorithm Algorithm { get; private set; }
    public ECParameters ECParameters { get; private set; }
    public RSAParameters RSAParameters { get; private set; }
    public DSAParameters DSAParameters { get; private set; }


    public static AsymmetricAlgorithmParameters Create(KeyAlgorithm algorithm, int? keyLength = null)
    {
        using AsymmetricAlgorithm keys = algorithm switch {
            KeyAlgorithm.ECDsa => ECDsa.Create() ?? throw new NotSupportedException("Unsupported ECDSA algorithm"),
            KeyAlgorithm.RSA => RSA.Create(keyLength ?? 4096),
            KeyAlgorithm.DSA => DSA.Create(keyLength ?? 1024),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
        };
        return Create(keys);
    }


    public static AsymmetricAlgorithmParameters Create(AsymmetricAlgorithm keys)
        => keys switch {
            ECDsa ecdsa => new AsymmetricAlgorithmParameters { Algorithm = KeyAlgorithm.ECDsa, ECParameters = ecdsa.ExportParameters(true) },
            RSA rsa => new AsymmetricAlgorithmParameters { Algorithm = KeyAlgorithm.RSA, RSAParameters = rsa.ExportParameters(true) },
            DSA dsa => new AsymmetricAlgorithmParameters { Algorithm = KeyAlgorithm.DSA, DSAParameters = dsa.ExportParameters(true) },
            _ => throw new NotSupportedException($"Unsupported AsymmetricAlgorithm: {keys.GetType()}")
        };


    private AsymmetricAlgorithmParameters() { }


    public AsymmetricAlgorithm CreateKeyPair()
        => Algorithm switch {
            KeyAlgorithm.DSA => DSA.Create(DSAParameters),
            KeyAlgorithm.RSA => RSA.Create(RSAParameters),
            KeyAlgorithm.ECDsa => ECDsa.Create(ECParameters) ?? throw new NotSupportedException("Unsupported ECDSA algorithm"),
            _ => throw new ArgumentOutOfRangeException(nameof(Algorithm), Algorithm, null)
        };
}
