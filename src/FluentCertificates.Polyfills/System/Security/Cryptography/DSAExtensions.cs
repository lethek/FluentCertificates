#if NETSTANDARD
// ReSharper disable All

namespace System.Security.Cryptography;

public static class DSAExtensions
{
    public static bool VerifyData(this DSA key, byte[] data, byte[] signature, HashAlgorithmName hashAlgorithm, DSASignatureFormat signatureFormat)
    {
        var sig = key.ConvertSignatureToIeeeP1363(DSASignatureFormat.Rfc3279DerSequence, signature);

        //If the signature failed normalization to P1363, it obviously doesn't verify.
        if (sig == null) {
            return false;
        }

        return key.VerifyData(data, sig, hashAlgorithm);
    }


    public static bool VerifyData(this DSA key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, DSASignatureFormat signatureFormat)
    {
        var sig = key.ConvertSignatureToIeeeP1363(DSASignatureFormat.Rfc3279DerSequence, signature);

        //If the signature failed normalization to P1363, it obviously doesn't verify.
        if (sig == null) {
            return false;
        }

        return key.VerifyData(data, sig, hashAlgorithm);
    }

}

#endif
