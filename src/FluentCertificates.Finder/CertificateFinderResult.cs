using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Represents the result of a certificate search, including the certificate and its source.
/// </summary>
public record CertificateFinderResult {
    /// <summary>
    /// Gets the certificate store from which the certificate was found, if applicable.
    /// </summary>
    public CertificateStore? Store { get; init; }
    
    
    /// <summary>
    /// Gets the directory from which the certificate was found, if applicable.
    /// </summary>    
    public CertificateDirectory? Directory { get; init; }
    
    
    /// <summary>
    /// Gets the found X.509 certificate.
    /// </summary>
    public required X509Certificate2 Certificate { get; init; }
}
