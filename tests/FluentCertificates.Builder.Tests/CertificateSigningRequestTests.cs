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


    private static CertificateSigningRequest BuildEcdsaRequest(string subject)
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateBuilder()
            .SetSubject(subject)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();
    }
}
