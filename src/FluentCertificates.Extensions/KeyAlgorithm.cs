namespace FluentCertificates;

/// <summary>
/// Specifies the supported key algorithms for cryptographic operations.
/// </summary>
public enum KeyAlgorithm
{
    /// <summary>RSA (Rivest–Shamir–Adleman) algorithm.</summary>
    RSA,
    
    /// <summary>DSA (Digital Signature Algorithm).</summary>
    [Obsolete] DSA,

    /// <summary>ECDsa (Elliptic Curve Digital Signature Algorithm).</summary>
    ECDsa
}