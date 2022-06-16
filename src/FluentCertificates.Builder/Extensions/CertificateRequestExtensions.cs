using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using Org.BouncyCastle.Pkcs;

namespace FluentCertificates.Extensions;

public static class CertificateRequestExtensions
{
    public static CertificateRequest ExportAsPem(this CertificateRequest certRequest, string path)
    {
        File.WriteAllText(path, certRequest.ToPemString());
        return certRequest;
    }


    public static string ToPemString(this CertificateRequest certRequest)
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write("CERTIFICATE REQUEST", certRequest.CreateSigningRequest()));
        sw.Write('\n');
        return sw.ToString();
    }


    public static Pkcs10CertificationRequest ConvertToBouncyCastle(this CertificateRequest certRequest)
        => new(certRequest.CreateSigningRequest());
}
