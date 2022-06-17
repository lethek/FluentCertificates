using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace FluentCertificates.Extensions;

public static class Pkcs10CertificationRequestExtensions
{
    public static Pkcs10CertificationRequest ExportAsPem(this Pkcs10CertificationRequest csr, TextWriter writer)
    {
        writer.Write(csr.ToPemString());
        return csr;
    }

    
    public static Pkcs10CertificationRequest ExportAsPem(this Pkcs10CertificationRequest csr, string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return csr.ExportAsPem(writer);
    }


    public static string ToPemString(this Pkcs10CertificationRequest csr)
    {
        using var sw = new StringWriter();
        var pem = new PemWriter(sw);
        pem.WriteObject(csr);
        return sw.ToString();
    }
}
