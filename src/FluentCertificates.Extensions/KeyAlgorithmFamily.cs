using System.Diagnostics.CodeAnalysis;


namespace FluentCertificates;

/// <summary>
/// Identifies the family a <see cref="KeyAlgorithm"/> belongs to.
/// </summary>
/// <remarks>
/// <para>
/// The family says what kind of key it is and therefore how it is generated, whether it can sign, and which
/// parameters are meaningful. <see cref="KeyAlgorithm"/> carries the parameters themselves.
/// </para>
/// <para>
/// The post-quantum members carry <c>[Experimental]</c> individually rather than the enum carrying it as a
/// whole, so that naming <see cref="Rsa"/> stays diagnostic-free while
/// <c>KeyAlgorithm.Default(KeyAlgorithmFamily.MLDsa)</c> reports FLUENTCERT001 like every other route into
/// the post-quantum surface.
/// </para>
/// </remarks>
public enum KeyAlgorithmFamily
{
    /// <summary>RSA (Rivest-Shamir-Adleman). Parameterised by key length.</summary>
    Rsa,

    /// <summary>DSA (Digital Signature Algorithm). Parameterised by key length.</summary>
    [Obsolete("DSA is deprecated for certificate use. Consider using ECDsa, RSA or ML-DSA instead.")]
    Dsa,

    /// <summary>ECDsa (Elliptic Curve Digital Signature Algorithm). Parameterised by curve.</summary>
    ECDsa,

    /// <summary>
    /// ECDH (Elliptic Curve Diffie-Hellman) key agreement. Parameterised by curve. Cannot sign.
    /// </summary>
    ECDiffieHellman,

    /// <summary>ML-DSA (FIPS 204), a lattice-based post-quantum signature algorithm.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    MLDsa,

    /// <summary>SLH-DSA (FIPS 205), a hash-based post-quantum signature algorithm.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    SlhDsa,

    /// <summary>Composite ML-DSA, pairing ML-DSA with a classical signature algorithm.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    CompositeMLDsa,

    /// <summary>ML-KEM (FIPS 203), a post-quantum key-encapsulation mechanism. Cannot sign.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    MLKem
}
