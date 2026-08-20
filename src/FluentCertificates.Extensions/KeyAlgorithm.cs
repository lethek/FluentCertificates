namespace FluentCertificates;

/// <summary>
/// Specifies the supported key algorithms for cryptographic operations.
/// </summary>
public enum KeyAlgorithm
{
    /// <summary>RSA (Rivest–Shamir–Adleman) algorithm.</summary>
    RSA,
    
    /// <summary>DSA (Digital Signature Algorithm).</summary>
    [Obsolete("DSA is deprecated for certificate use. Consider using ECDsa or RSA instead.")]
    DSA,

    /// <summary>ECDsa (Elliptic Curve Digital Signature Algorithm).</summary>
    ECDsa,

    /// <summary>
    /// ECDH (Elliptic Curve Diffie-Hellman) key agreement. An ECDH key cannot sign, so a certificate for
    /// one must be issued by a CA and cannot itself be a CA or a code-signing, OCSP-signing or
    /// time-stamping certificate.
    /// </summary>
    ECDiffieHellman
}