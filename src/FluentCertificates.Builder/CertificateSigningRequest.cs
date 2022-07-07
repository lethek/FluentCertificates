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
    public ReadOnlyMemory<byte> GetRawData()
        => RawData;

    
    public ReadOnlyMemory<byte> GetRequestData()
        => new AsnReader(RawData, AsnEncodingRules.DER)
            .ReadSequence(Asn1Tag.Sequence)
            .ReadEncodedValue();


    public ReadOnlyMemory<byte> GetSignatureData()
    {
        var reader = new AsnReader(RawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
        reader.ReadSequence(Asn1Tag.Sequence); //Skip CertificationRequestInfo
        reader.ReadSequence(Asn1Tag.Sequence); //Skip Signature AlgorithmIdentifier
        return reader.ReadBitString(out _, Asn1Tag.PrimitiveBitString);
    }


    public SignatureAlgorithm GetSignatureAlgorithm()
    {
        var reader = new AsnReader(RawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
        reader.ReadSequence(Asn1Tag.Sequence); //Skip CertificationRequestInfo
        var algIdentifier = reader.ReadSequence(Asn1Tag.Sequence);
        var algorithm = algIdentifier.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
        if (algorithm == "1.2.840.113549.1.1.10") {
            var hashAlgorithm = algIdentifier
                .ReadSequence(Asn1Tag.Sequence)
                .ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0))
                .ReadSequence(Asn1Tag.Sequence)
                .ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
            return SignatureAlgorithm.ForRsaSsaPss(algorithm, hashAlgorithm);
        }
        return SignatureAlgorithm.FromOidValue(algorithm);
    }


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
        sw.Write(PemEncoding.Write("CERTIFICATE REQUEST", GetRawData().Span));
        return sw.ToString();
    }
}