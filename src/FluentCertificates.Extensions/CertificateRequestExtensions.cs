using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

public static class CertificateRequestExtensions
{
    public static CertificateRequest ExportAsPem(this CertificateRequest certRequest, TextWriter writer)
    {
        writer.Write(certRequest.ToPemString());
        return certRequest;
    }

    
    public static CertificateRequest ExportAsPem(this CertificateRequest certRequest, string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return certRequest.ExportAsPem(writer);
    }


    public static string ToPemString(this CertificateRequest certRequest)
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write("CERTIFICATE REQUEST", certRequest.CreateSigningRequest()));
        return sw.ToString();
    }
}
