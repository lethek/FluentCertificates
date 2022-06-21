using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Pkcs;


namespace FluentCertificates;

public static class CertificateRequestExtensions
{
    public static Pkcs10CertificationRequest ConvertToBouncyCastle(this CertificateRequest certRequest)
        => new(certRequest.CreateSigningRequest());
}
