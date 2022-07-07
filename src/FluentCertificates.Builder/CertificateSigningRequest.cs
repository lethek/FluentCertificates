using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

public record CertificateSigningRequest
{
    public CertificateRequest CertificateRequest { get; init; }
    public X509SignatureGenerator SignatureGenerator { get; init; }
    public byte[] RawData { get; init; }


    internal CertificateSigningRequest(CertificateRequest certificateRequest, X509SignatureGenerator signatureGenerator)
    {
        CertificateRequest = certificateRequest;
        SignatureGenerator = signatureGenerator;
        RawData = CertificateRequest.CreateSigningRequest(SignatureGenerator);
    }


    /// <summary>Creates an ASN.1 DER-encoded PKCS#10 CertificationRequest value representing the state of the current <see cref="P:CertificateRequest"/> property signed using the current <see cref="P:SignatureGenerator"/>.</summary>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The <see cref="P:System.Security.Cryptography.X509Certificates.CertificateRequest.HashAlgorithm" /> property value is not supported.</exception>
    /// <returns>A DER-encoded certificate signing request as a raw byte array.</returns>
    public byte[] GetRawData()
        => RawData;


    public byte[] GetRequestData()
        => throw new NotImplementedException();


    public byte[] GetSignatureData()
        => throw new NotImplementedException();


    public static SignatureAlgorithm GetSignatureAlgorithm()
        => throw new NotImplementedException();


    public CertificateSigningRequest ExportAsPem(TextWriter writer)
    {
        writer.Write(ToPemString());
        return this;
    }

    
    public CertificateSigningRequest ExportAsPem(string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return ExportAsPem(writer);
    }


    public string ToPemString()
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write("CERTIFICATE REQUEST", GetRawData()));
        return sw.ToString();
    }
}