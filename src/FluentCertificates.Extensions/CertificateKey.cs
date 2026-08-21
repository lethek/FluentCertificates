using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// Holds a key belonging to a certificate, whether classical or post-quantum, and exposes what the library
/// needs from it without the caller having to know which kind it is.
/// </summary>
/// <remarks>
/// <para>
/// This type exists because .NET's post-quantum key types do not derive from
/// <see cref="AsymmetricAlgorithm"/> - they derive from <see cref="Object"/> and implement
/// <see cref="IDisposable"/>. Any signature typed as <see cref="AsymmetricAlgorithm"/> is therefore a wall
/// that ML-DSA and its relatives cannot pass, which is why <c>GetPrivateKey()</c> returns this instead.
/// </para>
/// <para>
/// A <see cref="CertificateKey"/> owns the key it wraps and disposes it. Where the library hands one back it
/// hands back a fresh instance each time, so dispose it when finished; disposing it does not affect the
/// certificate it came from or any other instance. Where the caller supplies one, the library never disposes
/// it - see the key-ownership rules in the project's AGENTS.md.
/// </para>
/// </remarks>
public sealed class CertificateKey : IDisposable
{
    /// <summary>Wraps a classical key.</summary>
    /// <param name="key">The key to wrap. This instance takes ownership of it.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="NotSupportedException">Thrown when the key's algorithm is not recognised.</exception>
    public CertificateKey(AsymmetricAlgorithm key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
        Family = key switch {
            System.Security.Cryptography.ECDsa => KeyAlgorithmFamily.ECDsa,
            System.Security.Cryptography.ECDiffieHellman => KeyAlgorithmFamily.ECDiffieHellman,
            System.Security.Cryptography.RSA => KeyAlgorithmFamily.Rsa,
#pragma warning disable CS0618 // Type or member is obsolete
            System.Security.Cryptography.DSA => KeyAlgorithmFamily.Dsa,
#pragma warning restore CS0618 // Type or member is obsolete
            _ => throw new NotSupportedException($"Unsupported {nameof(AsymmetricAlgorithm)}: {key.GetType()}")
        };
    }


    /// <summary>Gets the family of key this holds.</summary>
    public KeyAlgorithmFamily Family { get; }


    /// <summary>
    /// Gets whether this key can produce signatures. This is <see langword="false"/> for the key-agreement and
    /// key-encapsulation families, which have no signing operation at all.
    /// </summary>
    public bool CanSign
        => Family is not (KeyAlgorithmFamily.ECDiffieHellman or KeyAlgorithmFamily.MLKem);


    /// <summary>Gets whether this holds a post-quantum key.</summary>
    public bool IsPostQuantum
        => Family is KeyAlgorithmFamily.MLDsa or KeyAlgorithmFamily.SlhDsa
            or KeyAlgorithmFamily.CompositeMLDsa or KeyAlgorithmFamily.MLKem;


    /// <summary>
    /// Gets the wrapped key as an <see cref="AsymmetricAlgorithm"/>, or <see langword="null"/> if it is a
    /// post-quantum key, which does not derive from that type.
    /// </summary>
    /// <remarks>
    /// The returned instance belongs to this <see cref="CertificateKey"/>. Do not dispose it separately;
    /// dispose this instead.
    /// </remarks>
    public AsymmetricAlgorithm? AsAsymmetricAlgorithm => _key as AsymmetricAlgorithm;


    /// <summary>
    /// Exports the public key as a DER-encoded SubjectPublicKeyInfo structure.
    /// </summary>
    /// <exception cref="CryptographicException">Thrown when the key cannot be exported.</exception>
    public byte[] ExportSubjectPublicKeyInfo()
        => _key switch {
            AsymmetricAlgorithm key => key.ExportSubjectPublicKeyInfo(),
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
            MLDsa key => key.ExportSubjectPublicKeyInfo(),
#pragma warning restore SYSLIB5006
#endif
            _ => throw new NotSupportedException($"Cannot export a public key of type {_key.GetType()}")
        };


    /// <summary>
    /// Exports the private key as a DER-encoded PKCS#8 PrivateKeyInfo structure.
    /// </summary>
    /// <exception cref="CryptographicException">Thrown when the key cannot be exported.</exception>
    public byte[] ExportPkcs8PrivateKey()
        => _key switch {
            AsymmetricAlgorithm key => key.ExportPkcs8PrivateKey(),
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
            MLDsa key => key.ExportPkcs8PrivateKey(),
#pragma warning restore SYSLIB5006
#endif
            _ => throw new NotSupportedException($"Cannot export a private key of type {_key.GetType()}")
        };


    /// <summary>
    /// Exports the private key as an unencrypted PKCS#8 PEM string.
    /// </summary>
    /// <exception cref="CryptographicException">Thrown when the key cannot be exported.</exception>
    public string ExportPkcs8PrivateKeyPem()
        => _key switch {
            AsymmetricAlgorithm key => key.ExportPkcs8PrivateKeyPem(),
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
            MLDsa key => key.ExportPkcs8PrivateKeyPem(),
#pragma warning restore SYSLIB5006
#endif
            _ => throw new NotSupportedException($"Cannot export a private key of type {_key.GetType()}")
        };


    /// <summary>
    /// Exports the private key as an encrypted PKCS#8 PEM string.
    /// </summary>
    /// <param name="password">The password to encrypt with.</param>
    /// <param name="parameters">The encryption parameters.</param>
    /// <exception cref="CryptographicException">Thrown when the key cannot be exported.</exception>
    public string ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<char> password, PbeParameters parameters)
        => _key switch {
            AsymmetricAlgorithm key => key.ExportEncryptedPkcs8PrivateKeyPem(password, parameters),
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
            MLDsa key => key.ExportEncryptedPkcs8PrivateKeyPem(password, parameters),
#pragma warning restore SYSLIB5006
#endif
            _ => throw new NotSupportedException($"Cannot export a private key of type {_key.GetType()}")
        };


    /// <summary>
    /// Attaches this key to a certificate, returning a new certificate that carries it.
    /// </summary>
    /// <param name="cert">The certificate to attach the key to.</param>
    /// <returns>
    /// A new certificate holding the private key. The original is unaffected and remains the caller's to
    /// dispose.
    /// </returns>
    /// <exception cref="NotSupportedException">Thrown when the key's type cannot be attached.</exception>
    public X509Certificate2 CopyToCertificate(X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        return _key switch {
#pragma warning disable CS0618 // Type or member is obsolete
            System.Security.Cryptography.DSA dsa => cert.CopyWithPrivateKey(dsa),
#pragma warning restore CS0618 // Type or member is obsolete
            System.Security.Cryptography.RSA rsa => cert.CopyWithPrivateKey(rsa),
            System.Security.Cryptography.ECDsa ecdsa => cert.CopyWithPrivateKey(ecdsa),
            System.Security.Cryptography.ECDiffieHellman ecdh => cert.CopyWithPrivateKey(ecdh),
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
            MLDsa mldsa => cert.CopyWithPrivateKey(mldsa),
#pragma warning restore SYSLIB5006
#endif
            _ => throw new NotSupportedException($"Cannot attach a private key of type {_key.GetType()} to a certificate")
        };
    }


    /// <summary>Releases the wrapped key.</summary>
    public void Dispose()
    {
        if (_key is IDisposable disposable) {
            disposable.Dispose();
        }
    }


    /// <summary>Implicitly wraps a classical key.</summary>
    /// <param name="key">The key to wrap.</param>
    [return: NotNullIfNotNull(nameof(key))]
    public static implicit operator CertificateKey?(AsymmetricAlgorithm? key)
        => key == null ? null : new CertificateKey(key);


    private readonly object _key;

#if NET10_0_OR_GREATER
    /// <summary>Wraps an ML-DSA key.</summary>
    /// <param name="key">The key to wrap. This instance takes ownership of it.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <see langword="null"/>.</exception>
    [Experimental(Experiments.PostQuantumCryptography)]
#pragma warning disable SYSLIB5006
    public CertificateKey(MLDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
        Family = KeyAlgorithmFamily.MLDsa;
    }


    /// <summary>
    /// Gets the wrapped key as an <see cref="MLDsa"/>, or <see langword="null"/> if it is not one.
    /// </summary>
    /// <remarks>
    /// The returned instance belongs to this <see cref="CertificateKey"/>. Do not dispose it separately.
    /// </remarks>
    [Experimental(Experiments.PostQuantumCryptography)]
    public MLDsa? AsMLDsa => _key as MLDsa;


    /// <summary>Implicitly wraps an ML-DSA key.</summary>
    /// <param name="key">The key to wrap.</param>
    [Experimental(Experiments.PostQuantumCryptography)]
    [return: NotNullIfNotNull(nameof(key))]
    public static implicit operator CertificateKey?(MLDsa? key)
        => key == null ? null : new CertificateKey(key);
#pragma warning restore SYSLIB5006
#endif
}
