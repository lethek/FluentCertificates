using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace FluentCertificates.Extensions;

public static class CertificateRequestExtensions
{
    public static CertificateRequest ExportAsPem(this CertificateRequest certRequest, string path)
    {
        File.WriteAllText(path, certRequest.ConvertToBouncyCastle().ToPemString());
        return certRequest;
    }


    public static string ToPemString(this CertificateRequest certRequest)
    {
        using var sw = new StringWriter();
        var pem = new PemWriter(sw);
        pem.WriteObject(certRequest.ConvertToBouncyCastle());
        return sw.ToString();
    }


    public static Pkcs10CertificationRequest ConvertToBouncyCastle(this CertificateRequest certRequest)
        => new(certRequest.CreateSigningRequest());
}
