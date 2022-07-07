#if !NET6_0_OR_GREATER

// ReSharper disable All

using System.Formats.Asn1;
using System.Runtime.Versioning;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography.X509Certificates;

public static class PublicKeyExtensions
{
    
    /// <summary>Gets the <see cref="T:System.Security.Cryptography.RSA" /> public key, or <see langword="null" /> if the key is not an RSA key.</summary>
    /// <exception cref="T:System.Security.Cryptography.CryptographicException">The key contents are corrupt or could not be read successfully.</exception>
    /// <returns>The public key, or <see langword="null" /> if the key is not an RSA key.</returns>
    public static RSA? GetRSAPublicKey(this PublicKey pk)
    {
        if (pk.Oid.Value != "1.2.840.113549.1.1.1") {
            return null;
        }

        var rsa = RSA.Create();
        try {
            rsa.ImportSubjectPublicKeyInfo(pk.ExportSubjectPublicKeyInfo(), out _);
            return rsa;
        } catch {
            rsa.Dispose();
            throw;
        }
    }
    

    /// <summary>Gets the <see cref="T:System.Security.Cryptography.DSA" /> public key, or <see langword="null" /> if the key is not an DSA key.</summary>
    /// <exception cref="T:System.Security.Cryptography.CryptographicException">The key contents are corrupt or could not be read successfully.</exception>
    /// <returns>The public key, or <see langword="null" /> if the key is not an DSA key.</returns>
    #if NET5_0_OR_GREATER
    [UnsupportedOSPlatform("ios")]
    [UnsupportedOSPlatform("tvos")]
    #endif
    public static DSA? GetDSAPublicKey(this PublicKey pk)
    {
        if (pk.Oid.Value != "1.2.840.10040.4.1") {
            return null;
        }

        var dsa = DSA.Create();
        try {
            dsa.ImportSubjectPublicKeyInfo(pk.ExportSubjectPublicKeyInfo(), out _);
            return dsa;
        } catch {
            dsa.Dispose();
            throw;
        }
    }


    /// <summary>Gets the <see cref="T:System.Security.Cryptography.ECDsa" /> public key, or <see langword="null" /> if the key is not an ECDsa key.</summary>
    /// <exception cref="T:System.Security.Cryptography.CryptographicException">The key contents are corrupt or could not be read successfully.</exception>
    /// <returns>The public key, or <see langword="null" /> if the key is not an ECDsa key.</returns>
    public static ECDsa? GetECDsaPublicKey(this PublicKey pk)
    {
        if (pk.Oid.Value != "1.2.840.10045.2.1") {
            return null;
        }

        var ecdsa = ECDsa.Create();
        try {
            ecdsa.ImportSubjectPublicKeyInfo(pk.ExportSubjectPublicKeyInfo(), out _);
            return ecdsa;
        } catch {
            ecdsa.Dispose();
            throw;
        }
    }


    /// <summary>Gets the <see cref="T:System.Security.Cryptography.ECDiffieHellman" /> public key, or <see langword="null" /> if the key is not an ECDiffieHellman key.</summary>
    /// <exception cref="T:System.Security.Cryptography.CryptographicException">The key contents are corrupt or could not be read successfully.</exception>
    /// <returns>The public key, or <see langword="null" /> if the key is not an ECDiffieHellman key.</returns>
    public static ECDiffieHellman? GetECDiffieHellmanPublicKey(this PublicKey pk)
    {
        if (pk.Oid.Value != "1.2.840.10045.2.1") {
            return null;
        }

        var ecdh = ECDiffieHellman.Create();
        try {
            ecdh.ImportSubjectPublicKeyInfo(pk.ExportSubjectPublicKeyInfo(), out _);
            return ecdh;
        } catch {
            ecdh.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Exports the current key in the X.509 SubjectPublicKeyInfo format.
    /// </summary>
    /// <returns>
    /// A byte array containing the X.509 SubjectPublicKeyInfo representation of this key.
    /// </returns>
    public static byte[] ExportSubjectPublicKeyInfo(this PublicKey pk)
        => EncodeSubjectPublicKeyInfo(pk).Encode();
    

    private static AsnWriter EncodeSubjectPublicKeyInfo(PublicKey pk)
    {
        SubjectPublicKeyInfoAsn spki = new SubjectPublicKeyInfoAsn {
            Algorithm = new AlgorithmIdentifierAsn {
                Algorithm = pk.Oid.Value ?? string.Empty,
                Parameters =  pk.EncodedParameters.RawData,
            },
            SubjectPublicKey = pk.EncodedKeyValue.RawData,
        };

        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
        spki.Encode(writer);
        return writer;
    }
}

#endif
