using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

/// <summary>Chooses the <see cref="X509SignatureGenerator"/> that signs with a given key.</summary>
internal static class SignatureGenerators
{
    /// <summary>The generator that signs with <paramref name="keys"/>, which stays owned by the caller.</summary>
    /// <exception cref="NotSupportedException">The key cannot sign, or is of an unsupported kind.</exception>
    public static X509SignatureGenerator GetForKey(CertificateKey keys, RSASignaturePadding rsaPadding)
    {
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
#pragma warning disable FLUENTCERT001
        if (keys.AsMLDsa is { } mldsa) {
            return X509SignatureGenerator.CreateForMLDsa(mldsa);
        }

        if (keys.AsSlhDsa is { } slhdsa) {
            return X509SignatureGenerator.CreateForSlhDsa(slhdsa);
        }

        if (keys.AsCompositeMLDsa is { } composite) {
            return X509SignatureGenerator.CreateForCompositeMLDsa(composite);
        }
#pragma warning restore FLUENTCERT001
#pragma warning restore SYSLIB5006
#endif

        return keys.AsAsymmetricAlgorithm switch {
#pragma warning disable CS0618 // Type or member is obsolete
            DSA dsa => new DSAX509SignatureGenerator(dsa),
#pragma warning restore CS0618 // Type or member is obsolete
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, rsaPadding),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            ECDiffieHellman => throw new NotSupportedException($"An {nameof(ECDiffieHellman)} key agrees on a shared secret and cannot sign"),
            _ => throw new NotSupportedException($"Unsupported algorithm: {keys.Family}")
        };
    }
}
