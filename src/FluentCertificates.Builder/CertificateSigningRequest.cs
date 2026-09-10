using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

/// <summary>Represents a PKCS#10 certificate signing request (CSR).</summary>
public record CertificateSigningRequest
{
    /// <summary>Gets the <see cref="CertificateRequest"/> the CSR was generated from, or parsed into.</summary>
    public CertificateRequest CertificateRequest { get; }

    /// <summary>Gets the <see cref="X509SignatureGenerator"/> that signed the CSR, or <see langword="null"/>
    /// for a parsed CSR, which cannot be re-signed.</summary>
    public X509SignatureGenerator? SignatureGenerator { get; }

    /// <summary>Gets a fresh copy of the raw DER-encoded CSR data on each read.</summary>
    public byte[] RawData => _rawData.AsSpan().ToArray();

    /// <summary>Gets the raw DER-encoded CSR data as a read-only view, without copying it.</summary>
    public ReadOnlyMemory<byte> RawDataMemory => _rawData;


    /// <summary>Initializes a new instance from a certificate request and signature generator.</summary>
    /// <param name="certificateRequest">The certificate request to use.</param>
    /// <param name="signatureGenerator">The signature generator to use.</param>
    internal CertificateSigningRequest(CertificateRequest certificateRequest, X509SignatureGenerator signatureGenerator)
    {
        CertificateRequest = certificateRequest;
        SignatureGenerator = signatureGenerator;
        _rawData = certificateRequest.CreateSigningRequest(signatureGenerator);
    }


    /// <summary>Initializes a new instance from DER already parsed into a <see cref="CertificateRequest"/>.</summary>
    /// <param name="rawData">The DER-encoded CSR, taken as-is rather than copied.</param>
    /// <param name="certificateRequest">The certificate request parsed out of <paramref name="rawData"/>.</param>
    private CertificateSigningRequest(byte[] rawData, CertificateRequest certificateRequest)
    {
        CertificateRequest = certificateRequest;
        _rawData = rawData;
    }


    /// <summary>Parses a DER-encoded PKCS#10 certificate signing request.</summary>
    /// <remarks>
    /// The signature is verified unless <see cref="CertificateRequestLoadOptions.SkipSignatureValidation"/>
    /// is passed, and requested extensions are discarded unless
    /// <see cref="CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions"/> is. Treat any that are
    /// loaded as untrusted input.
    /// </remarks>
    /// <param name="der">The DER-encoded CSR, spanning one CSR and nothing else.</param>
    /// <param name="options">Options controlling what is loaded and what is verified.</param>
    /// <returns>A CSR with a <see langword="null"/> <see cref="SignatureGenerator"/>.</returns>
    /// <exception cref="CryptographicException">The data is not a well-formed CSR, or its signature does not verify.</exception>
    public static CertificateSigningRequest FromDer(ReadOnlySpan<byte> der, CertificateRequestLoadOptions options = CertificateRequestLoadOptions.Default)
    {
        var rawData = der.ToArray();
        var algorithm = TryReadSignatureAlgorithm(rawData);

        //The hash does not verify the signature: LoadSigningRequest only records it for a later Create call.
        //SHA-256 stands in where none can be read, because .NET 8 and 9 reject a nameless hash outright.
        var request = CertificateRequest.LoadSigningRequest(
            rawData,
            algorithm is null ? HashAlgorithmName.SHA256 : algorithm.HashAlgorithm ?? default,
            options,
            algorithm?.RSASignaturePadding
        );

        return new CertificateSigningRequest(rawData, request);
    }


    /// <summary>Reads the signature algorithm out of DER-encoded CSR data, or <see langword="null"/>.</summary>
    /// <remarks>
    /// This runs before anything has validated the data, and must not be what decides whether a CSR is
    /// acceptable. Anything it cannot make sense of falls through to <c>LoadSigningRequest</c> to reject.
    /// </remarks>
    /// <param name="rawData">The DER-encoded CSR, not yet known to be well-formed.</param>
    /// <returns>The <see cref="SignatureAlgorithm"/> the CSR is signed with, or <see langword="null"/>.</returns>
    private static SignatureAlgorithm? TryReadSignatureAlgorithm(ReadOnlyMemory<byte> rawData)
    {
        try {
            return ReadSignatureAlgorithm(rawData);
        } catch (AsnContentException) {
            return null;
        } catch (NotSupportedException) {
            return null;
        }
    }


    /// <summary>Parses the first <c>CERTIFICATE REQUEST</c> PEM block in the text, ignoring everything else.</summary>
    /// <inheritdoc cref="FromDer" path="/remarks"/>
    /// <param name="pem">The PEM-encoded text to search.</param>
    /// <param name="options">Options controlling what is loaded and what is verified.</param>
    /// <returns>A CSR with a <see langword="null"/> <see cref="SignatureGenerator"/>.</returns>
    /// <exception cref="ArgumentException">No <c>CERTIFICATE REQUEST</c> PEM block was found.</exception>
    /// <exception cref="CryptographicException">The data is not a well-formed CSR, or its signature does not verify.</exception>
    public static CertificateSigningRequest FromPem(ReadOnlySpan<char> pem, CertificateRequestLoadOptions options = CertificateRequestLoadOptions.Default)
    {
        var remaining = pem;
        while (PemEncoding.TryFind(remaining, out var fields)) {
            if (remaining[fields.Label].SequenceEqual(PemLabel)) {
                return FromDer(PemTools.DecodeBlock(remaining, fields), options);
            }
            remaining = remaining[fields.Location.End..];
        }

        throw new ArgumentException($"No {PemLabel} PEM block was found.", nameof(pem));
    }


    /// <summary>Gets the DER-encoded CertificationRequestInfo portion of the CSR.</summary>
    /// <returns>The encoded CertificationRequestInfo.</returns>
    public ReadOnlyMemory<byte> GetRequestData()
        => new AsnReader(RawDataMemory, AsnEncodingRules.DER)
            .ReadSequence(Asn1Tag.Sequence)
            .ReadEncodedValue();


    /// <summary>Gets the signature portion of the CSR as a bit string.</summary>
    /// <returns>The signature data.</returns>
    public ReadOnlyMemory<byte> GetSignatureData()
    {
        var reader = new AsnReader(RawDataMemory, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
        reader.ReadSequence(Asn1Tag.Sequence); //Skip CertificationRequestInfo
        reader.ReadSequence(Asn1Tag.Sequence); //Skip Signature AlgorithmIdentifier
        return reader.ReadBitString(out _, Asn1Tag.PrimitiveBitString);
    }


    /// <summary>Gets the signature algorithm used in the CSR.</summary>
    /// <returns>The <see cref="SignatureAlgorithm"/> used for signing.</returns>
    /// <exception cref="NotSupportedException">The CSR is signed with an algorithm this library does not model.</exception>
    public SignatureAlgorithm GetSignatureAlgorithm()
        => ReadSignatureAlgorithm(RawDataMemory);


    /// <summary>Reads the signature algorithm out of DER-encoded CSR data.</summary>
    /// <param name="rawData">The DER-encoded CSR.</param>
    /// <returns>The <see cref="SignatureAlgorithm"/> the CSR is signed with.</returns>
    private static SignatureAlgorithm ReadSignatureAlgorithm(ReadOnlyMemory<byte> rawData)
    {
        var reader = new AsnReader(rawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
        reader.ReadSequence(Asn1Tag.Sequence); //Skip CertificationRequestInfo
        var algIdentifier = reader.ReadSequence(Asn1Tag.Sequence);
        var algorithm = algIdentifier.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
        if (algorithm == Oids.RsaPss) {
            var hashAlgorithm = algIdentifier
                .ReadSequence(Asn1Tag.Sequence)
                .ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0))
                .ReadSequence(Asn1Tag.Sequence)
                .ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
            return SignatureAlgorithm.CreateForRsaSsaPss(algorithm, hashAlgorithm);
        }
        return SignatureAlgorithm.FromOidValue(algorithm);
    }


    /// <summary>Exports the CSR as PEM-encoded text to the specified <see cref="TextWriter"/>.</summary>
    /// <param name="writer">The text writer to which the PEM will be written.</param>
    /// <returns>This instance.</returns>
    public CertificateSigningRequest ExportAsPem(TextWriter writer)
    {
        writer.Write(ToPemString());
        return this;
    }

    
    /// <summary>Exports the CSR as PEM-encoded text to the specified file path.</summary>
    /// <param name="path">The file path to write the PEM to.</param>
    /// <returns>This instance.</returns>
    public CertificateSigningRequest ExportAsPem(string path)
    {
        using var stream = File.OpenWrite(path);
        using var writer = new StreamWriter(stream);
        return ExportAsPem(writer);
    }


    /// <summary>Gets the PEM-encoded string representation of the CSR.</summary>
    /// <returns>The PEM-encoded CSR.</returns>
    public string ToPemString()
    {
        using var sw = new StringWriter();
        sw.Write(PemEncoding.Write(PemLabel, RawDataMemory.Span));
        return sw.ToString();
    }


    private const string PemLabel = "CERTIFICATE REQUEST";

    private readonly byte[] _rawData;
}