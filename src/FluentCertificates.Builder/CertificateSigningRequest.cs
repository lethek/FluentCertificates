using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Represents a PKCS#10 certificate signing request (CSR), including the request data,
/// signature, and associated cryptographic information.
/// </summary>
public record CertificateSigningRequest
{
    /// <summary>
    /// Gets the underlying <see cref="CertificateRequest"/> used to generate the CSR.
    /// </summary>
    public CertificateRequest CertificateRequest { get; init; }
    
    /// <summary>
    /// Gets the <see cref="X509SignatureGenerator"/> used to sign the CSR.
    /// </summary>
    public X509SignatureGenerator SignatureGenerator { get; init; }
    
    /// <summary>
    /// Gets the raw DER-encoded CSR data.
    /// </summary>
    public byte[] RawData { get; init; }


    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningRequest"/> class
    /// using the specified certificate request and signature generator.
    /// </summary>
    /// <param name="certificateRequest">The certificate request to use.</param>
    /// <param name="signatureGenerator">The signature generator to use.</param>
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

    
    /// <summary>
    /// Gets the DER-encoded CertificationRequestInfo portion of the CSR.
    /// </summary>
    /// <returns>The encoded CertificationRequestInfo as a <see cref="ReadOnlyMemory{Byte}"/>.</returns>
    public ReadOnlyMemory<byte> GetRequestData()
        => new AsnReader(RawData, AsnEncodingRules.DER)
            .ReadSequence(Asn1Tag.Sequence)
            .ReadEncodedValue();


    /// <summary>
    /// Gets the signature portion of the CSR as a bit string.
    /// </summary>
    /// <returns>The signature data as a <see cref="ReadOnlyMemory{Byte}"/>.</returns>
    public ReadOnlyMemory<byte> GetSignatureData()
    {
        var reader = new AsnReader(RawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
        reader.ReadSequence(Asn1Tag.Sequence); //Skip CertificationRequestInfo
        reader.ReadSequence(Asn1Tag.Sequence); //Skip Signature AlgorithmIdentifier
        return reader.ReadBitString(out _, Asn1Tag.PrimitiveBitString);
    }


    /// <summary>
    /// Gets the signature algorithm used in the CSR.
    /// </summary>
    /// <returns>The <see cref="SignatureAlgorithm"/> used for signing.</returns>
    public SignatureAlgorithm GetSignatureAlgorithm()
    {
        var reader = new AsnReader(RawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
        reader.ReadSequence(Asn1Tag.Sequence); //Skip CertificationRequestInfo
        var algIdentifier = reader.ReadSequence(Asn1Tag.Sequence);
        var algorithm = algIdentifier.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
        if (algorithm == Oids.RsaPss) {
            var hashAlgorithm = algIdentifier
                .ReadSequence(Asn1Tag.Sequence)
                .ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0))
                .ReadSequence(Asn1Tag.Sequence)
                .ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
            return SignatureAlgorithm.ForRsaSsaPss(algorithm, hashAlgorithm);
        }
        return SignatureAlgorithm.FromOidValue(algorithm);
    }


    /// <summary>
    /// Exports the CSR as PEM-encoded text to the specified <see cref="TextWriter"/>.
    /// </summary>
    /// <param name="writer">The text writer to which the PEM will be written.</param>
    /// <returns>The current <see cref="CertificateSigningRequest"/> instance.</returns>
    public CertificateSigningRequest ExportAsPem(TextWriter writer)
    {
        writer.Write(ToPemString());
        return this;
    }

    
    /// <summary>
    /// Exports the CSR as PEM-encoded text to the specified file path.
    /// </summary>
    /// <param name="path">The file path to write the PEM to.</param>
    /// <returns>The current <see cref="CertificateSigningRequest"/> instance.</returns>
    public CertificateSigningRequest ExportAsPem(string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return ExportAsPem(writer);
    }


    /// <summary>
    /// Gets the PEM-encoded string representation of the CSR.
    /// </summary>
    /// <returns>The PEM-encoded CSR as a string.</returns>
    public string ToPemString()
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write("CERTIFICATE REQUEST", GetRawData().Span));
        return sw.ToString();
    }
}