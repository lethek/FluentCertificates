using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class CertificateSigningRequestTests
{
    [Test]
    public async Task RawData_ReturnsANewCopyEachTime()
    {
        var csr = BuildEcdsaRequest("CN=Raw Data Copy");

        var first = csr.RawData;
        var second = csr.RawData;

        await Assert.That(first).IsNotSameReferenceAs(second);
        await Assert.That(first).IsEquivalentTo(second, CollectionOrdering.Matching);
    }


    [Test]
    public async Task RawData_WritingIntoTheReturnedArray_ChangesNothing()
    {
        var csr = BuildEcdsaRequest("CN=Raw Data Immutable");

        var expected = csr.RawData;
        var algorithmBefore = csr.GetSignatureAlgorithm();

        var mine = csr.RawData;
        mine[0] ^= 0xFF;
        mine[^1] ^= 0xFF;

        await Assert.That(csr.RawData).IsEquivalentTo(expected, CollectionOrdering.Matching);
        await Assert.That(csr.RawDataMemory.ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
        await Assert.That(csr.GetSignatureAlgorithm()).IsEqualTo(algorithmBefore);
    }


    [Test]
    public async Task RawDataMemory_AgreesWithRawData()
    {
        var csr = BuildEcdsaRequest("CN=Raw Data Memory");

        await Assert.That(csr.RawDataMemory.ToArray()).IsEquivalentTo(csr.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task FromDer_RoundTripsABuiltRequest()
    {
        var csr = BuildEcdsaRequest("CN=Der Round Trip");

        var parsed = CertificateSigningRequest.FromDer(csr.RawData);

        await Assert.That(parsed.RawData).IsEquivalentTo(csr.RawData, CollectionOrdering.Matching);
        await Assert.That(parsed.CertificateRequest.SubjectName.Name).IsEqualTo(csr.CertificateRequest.SubjectName.Name);
        await Assert.That(parsed.GetSignatureAlgorithm()).IsEqualTo(csr.GetSignatureAlgorithm());
        await Assert.That(parsed.ToPemString()).IsEqualTo(csr.ToPemString());
    }


    [Test]
    public async Task FromDer_LeavesTheSignatureGeneratorNull()
    {
        var csr = BuildEcdsaRequest("CN=No Signature Generator");

        await Assert.That(csr.SignatureGenerator).IsNotNull();
        await Assert.That(CertificateSigningRequest.FromDer(csr.RawData).SignatureGenerator).IsNull();
    }


    [Test]
    public async Task FromDer_ReadsTheHashAlgorithmOutOfTheRequest()
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var csr = new CertificateBuilder()
            .SetSubject("CN=Hash From Der")
            .SetKeyPair(keys)
            .SetHashAlgorithm(HashAlgorithmName.SHA384)
            .CreateCertificateSigningRequest();

        //LoadSigningRequest takes any hash the caller offers without checking it against the request, so the
        //value has to come out of the DER for the parsed CertificateRequest to be able to sign anything
        var parsed = CertificateSigningRequest.FromDer(csr.RawData);

        await Assert.That(parsed.CertificateRequest.HashAlgorithm).IsEqualTo(HashAlgorithmName.SHA384);
    }


    [Test]
    public async Task FromDer_ReadsTheRsaPaddingOutOfTheRequest()
    {
        using var keys = RSA.Create(2048);
        var csr = new CertificateBuilder()
            .SetSubject("CN=Pss From Der")
            .SetKeyPair(keys)
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetRSASignaturePadding(RSASignaturePadding.Pss)
            .CreateCertificateSigningRequest();

        var parsed = CertificateSigningRequest.FromDer(csr.RawData);

        await Assert.That(parsed.GetSignatureAlgorithm().RSASignaturePadding).IsEqualTo(RSASignaturePadding.Pss);
        await Assert.That(parsed.CertificateRequest.HashAlgorithm).IsEqualTo(HashAlgorithmName.SHA256);

        //The padding is only observable once the parsed request signs something, since CertificateRequest
        //keeps it for that and exposes it nowhere
        using var issuerKeys = RSA.Create(2048);
        using var issuer = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Pss Issuing CA")
            .SetKeyPair(issuerKeys)
            .Create();

        using var issued = parsed.CertificateRequest.Create(issuer, issuer.NotBefore, issuer.NotAfter, new byte[] { 5 });

        await Assert.That(issued.SignatureAlgorithm.Value).IsEqualTo(Oids.RsaPss);
    }


    [Test]
    public async Task FromDer_WithATamperedSignature_Throws()
    {
        var csr = BuildEcdsaRequest("CN=Tampered Signature");

        var tampered = csr.RawData;
        tampered[^1] ^= 0xFF;

        await Assert.That(() => CertificateSigningRequest.FromDer(tampered)).Throws<CryptographicException>();
    }


    [Test]
    public async Task FromDer_WithATamperedSignatureAndValidationSkipped_Succeeds()
    {
        var csr = BuildEcdsaRequest("CN=Tampered But Skipped");

        var tampered = csr.RawData;
        tampered[^1] ^= 0xFF;

        var parsed = CertificateSigningRequest.FromDer(tampered, CertificateRequestLoadOptions.SkipSignatureValidation);

        await Assert.That(parsed.CertificateRequest.SubjectName.Name).IsEqualTo("CN=Tampered But Skipped");
    }


    [Test]
    public async Task FromDer_WithTrailingBytes_Throws()
    {
        var csr = BuildEcdsaRequest("CN=Trailing Bytes");

        var padded = csr.RawData.Concat(new byte[] { 0, 0, 0 }).ToArray();

        await Assert.That(() => CertificateSigningRequest.FromDer(padded)).Throws<CryptographicException>();
    }


    [Test]
    public async Task FromDer_DiscardsRequestedExtensionsUnlessAskedForThem()
    {
        var csr = BuildEcdsaRequest("CN=Requested Extensions");

        await Assert.That(csr.CertificateRequest.CertificateExtensions).IsNotEmpty();

        var safe = CertificateSigningRequest.FromDer(csr.RawData);
        await Assert.That(safe.CertificateRequest.CertificateExtensions).IsEmpty();

        var unsafeLoad = CertificateSigningRequest.FromDer(csr.RawData, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        await Assert.That(unsafeLoad.CertificateRequest.CertificateExtensions.Count).IsEqualTo(csr.CertificateRequest.CertificateExtensions.Count);
    }


    [Test]
    public async Task FromPem_RoundTripsABuiltRequest()
    {
        var csr = BuildEcdsaRequest("CN=Pem Round Trip");

        var parsed = CertificateSigningRequest.FromPem(csr.ToPemString());

        await Assert.That(parsed.RawData).IsEquivalentTo(csr.RawData, CollectionOrdering.Matching);
        await Assert.That(parsed.CertificateRequest.SubjectName.Name).IsEqualTo("CN=Pem Round Trip");
    }


    [Test]
    public async Task FromPem_SkipsSurroundingTextAndOtherLabels()
    {
        var csr = BuildEcdsaRequest("CN=Pem Among Others");
        using var cert = new CertificateBuilder().SetSubject("CN=Decoy").Create();

        var pem = "notes about the request\n"
            + new string(PemEncoding.Write("CERTIFICATE", cert.RawData)) + "\n"
            + csr.ToPemString() + "\n"
            + "trailing notes";

        var parsed = CertificateSigningRequest.FromPem(pem);

        await Assert.That(parsed.RawData).IsEquivalentTo(csr.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task FromPem_WithNoCertificateRequestBlock_Throws()
    {
        using var cert = new CertificateBuilder().SetSubject("CN=Not A Request").Create();
        var pem = new string(PemEncoding.Write("CERTIFICATE", cert.RawData));

        await Assert.That(() => CertificateSigningRequest.FromPem(pem)).Throws<ArgumentException>();
        await Assert.That(() => CertificateSigningRequest.FromPem("no pem here at all")).Throws<ArgumentException>();
    }


    [Test]
    public async Task FromDer_ParsedRequest_CanBeIssuedAsACertificate()
    {
        //CertificateRequest.Create signs with the issuer's key, which has to be the same algorithm as the request
        using var issuerKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuer = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Issuing CA")
            .SetKeyPair(issuerKeys)
            .SetValidity(TimeSpan.FromDays(2))
            .Create();

        var csr = BuildEcdsaRequest("CN=Issued From Parsed");

        var parsed = CertificateSigningRequest.FromDer(csr.RawData);
        using var issued = parsed.CertificateRequest.Create(
            issuer,
            issuer.NotBefore,
            issuer.NotAfter,
            new byte[] { 1, 2, 3, 4 }
        );

        await Assert.That(issued.Subject).IsEqualTo("CN=Issued From Parsed");
        await Assert.That(issued.Issuer).IsEqualTo("CN=Issuing CA");
    }


    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(8)]
    public async Task FromDer_WithMalformedData_ThrowsCryptographicException(int length)
    {
        //The signature algorithm is read out of the DER before anything has validated it, so malformed input
        //reaches an AsnReader first. AsnContentException does not derive from CryptographicException, so
        //letting it out would mean a caller guarding the documented exception still faults
        var malformed = Enumerable.Range(1, length).Select(x => (byte)x).ToArray();

        await Assert.That(() => CertificateSigningRequest.FromDer(malformed)).Throws<CryptographicException>();
    }


    [Test]
    public async Task FromDer_WithATruncatedRequest_ThrowsCryptographicException()
    {
        var csr = BuildEcdsaRequest("CN=Truncated");
        var truncated = csr.RawData.AsSpan(0, csr.RawData.Length / 2).ToArray();

        await Assert.That(() => CertificateSigningRequest.FromDer(truncated)).Throws<CryptographicException>();
    }


    [Test]
    public async Task FromPem_WithAnEmptyRequestBlock_ThrowsCryptographicException()
    {
        const string pem = "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----";

        await Assert.That(() => CertificateSigningRequest.FromPem(pem)).Throws<CryptographicException>();
    }


    [Test]
    public async Task FromPem_PassesOverABlockWhoseBodyIsNotBase64()
    {
        //PemEncoding does not recognise such a block as PEM at all, so it is not the "first" request block
        var csr = BuildEcdsaRequest("CN=After The Garbage");
        var pem = "-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----\n" + csr.ToPemString();

        var parsed = CertificateSigningRequest.FromPem(pem);

        await Assert.That(parsed.RawData).IsEquivalentTo(csr.RawData, CollectionOrdering.Matching);
        await Assert
            .That(() => CertificateSigningRequest.FromPem("-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----"))
            .Throws<ArgumentException>();
    }


    [Test]
    public async Task FromPem_TakesTheFirstRequestBlock()
    {
        var first = BuildEcdsaRequest("CN=First Request");
        var second = BuildEcdsaRequest("CN=Second Request");

        var parsed = CertificateSigningRequest.FromPem(first.ToPemString() + "\n" + second.ToPemString());

        await Assert.That(parsed.CertificateRequest.SubjectName.Name).IsEqualTo("CN=First Request");
    }


    [Test]
    public async Task FromDer_RoundTripsAnRsaPkcs1Request()
    {
        using var keys = RSA.Create(2048);
        var csr = new CertificateBuilder()
            .SetSubject("CN=Rsa Pkcs1 Round Trip")
            .SetKeyPair(keys)
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetRSASignaturePadding(RSASignaturePadding.Pkcs1)
            .CreateCertificateSigningRequest();

        var parsed = CertificateSigningRequest.FromDer(csr.RawData);

        await Assert.That(parsed.RawData).IsEquivalentTo(csr.RawData, CollectionOrdering.Matching);
        await Assert.That(parsed.GetSignatureAlgorithm()).IsEqualTo(SignatureAlgorithm.SHA256RSA);
        await Assert.That(parsed.CertificateRequest.HashAlgorithm).IsEqualTo(HashAlgorithmName.SHA256);
    }


    [Test]
    public async Task FromDer_WithASignatureAlgorithmThisLibraryDoesNotModel_StillParses()
    {
        //Nothing about reading the hash should decide whether a request is acceptable: that is the BCL's call
        var csr = BuildRsaRequest("CN=Unmodelled Signature");
        var spliced = SpliceSignatureOid(csr.RawData, Oids.RsaPkcs1Sha256, DsaWithSha3_256Oid);

        var parsed = CertificateSigningRequest.FromDer(spliced, CertificateRequestLoadOptions.SkipSignatureValidation);

        await Assert.That(parsed.CertificateRequest.SubjectName.Name).IsEqualTo("CN=Unmodelled Signature");
        await Assert.That(parsed.RawData).IsEquivalentTo(spliced, CollectionOrdering.Matching);

        //Reading it back is still unsupported; only the parse stopped depending on it
        await Assert.That(() => parsed.GetSignatureAlgorithm()).Throws<NotSupportedException>();
    }


    private static CertificateSigningRequest BuildEcdsaRequest(string subject)
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateBuilder()
            .SetSubject(subject)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();
    }


    private static CertificateSigningRequest BuildRsaRequest(string subject)
    {
        using var keys = RSA.Create(2048);
        return new CertificateBuilder()
            .SetSubject(subject)
            .SetKeyPair(keys)
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetRSASignaturePadding(RSASignaturePadding.Pkcs1)
            .CreateCertificateSigningRequest();
    }


    /// <summary>
    /// Rewrites the signature AlgorithmIdentifier's OID in place. Both OIDs encode to the same length, so
    /// every enclosing DER length stays correct and the request remains well-formed.
    /// </summary>
    private static byte[] SpliceSignatureOid(byte[] der, string fromOid, string toOid)
    {
        var from = EncodeOid(fromOid);
        var to = EncodeOid(toOid);
        if (from.Length != to.Length) {
            throw new InvalidOperationException($"{fromOid} and {toOid} must encode to the same length");
        }

        var at = der.AsSpan().IndexOf(from);
        if (at < 0) {
            throw new InvalidOperationException($"{fromOid} does not appear in the request");
        }

        var spliced = (byte[])der.Clone();
        to.CopyTo(spliced.AsSpan(at));
        return spliced;
    }


    private static byte[] EncodeOid(string oid)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(oid);
        return writer.Encode();
    }


    //id-dsa-with-sha3-256, which SignatureAlgorithm does not model, and which encodes to the same length as
    //the sha256WithRSAEncryption OID it replaces
    private const string DsaWithSha3_256Oid = "2.16.840.1.101.3.4.3.6";
}
