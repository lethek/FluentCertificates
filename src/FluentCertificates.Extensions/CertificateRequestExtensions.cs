using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// Provides extension methods for <see cref="CertificateRequest"/> to export certificate requests as PEM or string.
/// </summary>
public static class CertificateRequestExtensions
{
    /// <summary>
    /// Exports the certificate request as PEM to the specified <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="certRequest">The certificate request to export.</param>
    /// <param name="writer">The <see cref="TextWriter"/> to write the PEM to.</param>
    /// <returns>The original <see cref="CertificateRequest"/> instance.</returns>
    public static CertificateRequest ExportAsPem(this CertificateRequest certRequest, TextWriter writer)
    {
        writer.Write(certRequest.ToPemString());
        return certRequest;
    }

    
    /// <summary>
    /// Exports the certificate request as PEM to a file at the specified path.
    /// </summary>
    /// <param name="certRequest">The certificate request to export.</param>
    /// <param name="path">The file path to write the PEM to.</param>
    /// <returns>The original <see cref="CertificateRequest"/> instance.</returns>
    public static CertificateRequest ExportAsPem(this CertificateRequest certRequest, string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return certRequest.ExportAsPem(writer);
    }


    /// <summary>
    /// Converts the certificate request to a PEM-encoded string.
    /// </summary>
    /// <param name="certRequest">The certificate request to convert.</param>
    /// <returns>A PEM-encoded string representing the certificate request.</returns>
    public static string ToPemString(this CertificateRequest certRequest)
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write("CERTIFICATE REQUEST", certRequest.CreateSigningRequest()));
        return sw.ToString();
    }
}
