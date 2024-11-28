using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public record CertificateFinderResult {
    public CertificateStore? Store { get; init; }
    public CertificateDirectory? Directory { get; init; }
    public required X509Certificate2 Certificate { get; init; }
}
