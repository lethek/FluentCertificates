using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

/// <summary>
/// Covers extensions whose value contradicts the builder's <see cref="CertificateUsage"/> profile. Unlike a
/// criticality violation, which is corrected, these are refused: the contradiction is in the value, and a
/// certificate either vouches for other certificates or identifies an endpoint.
/// </summary>
public class CertificateBuilderUsageAgreementTests
{
    [Test]
    [Arguments(CertificateUsage.Server)]
    [Arguments(CertificateUsage.Client)]
    [Arguments(CertificateUsage.SMime)]
    [Arguments(CertificateUsage.CodeSign)]
    [Arguments(CertificateUsage.OcspSigning)]
    [Arguments(CertificateUsage.TimeStamping)]
    public async Task Create_WithCertificateAuthorityBasicConstraintsOnAnEndEntityProfile_Throws(CertificateUsage usage)
    {
        //The attack this refusal exists for: a requester slips cA=TRUE past an accept predicate that
        //whitelists by OID, and walks away able to issue certificates for anyone. Correcting the criticality
        //cannot help, because a validator honours cA=TRUE whichever way the flag is set.
        var builder = new CertificateBuilder()
            .SetUsage(usage)
            .SetSubject("CN=Would Be A Ca")
            .AddExtension(new X509BasicConstraintsExtension(true, false, 0, critical: true));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("cA=TRUE");
    }


    [Test]
    public async Task Create_WithEndEntityBasicConstraintsOnTheCaProfile_Throws()
    {
        //The mirror case: a requester strips the authority the caller asked for, leaving a certificate whose
        //key usage still asserts keyCertSign but which no validator will accept as a CA
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Would Be Declawed")
            .AddExtension(new X509BasicConstraintsExtension(false, false, 0, critical: true));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("cA=FALSE");
    }


    [Test]
    public async Task Create_WithKeyCertSignOnAnEndEntityProfile_Throws()
    {
        //keyCertSign is what makes a certificate able to mint others, and the security review's exploit
        //carried it alongside cA=TRUE
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Would Sign Certificates")
            .AddExtension(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, critical: true));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains(nameof(CertificateUsage.Server));
    }


    [Test]
    public async Task Create_WithCrlSignOnAnEndEntityProfile_IsIssuedNormally()
    {
        //An indirect CRL issuer is conventionally an end-entity certificate asserting cRLSign and nothing
        //else, so refusing the flag outright would make that certificate inexpressible
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetSubject("CN=Crl Issuer")
            .AddExtension(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign, critical: true))
            .Create();

        var ext = new X509KeyUsageExtension(cert.Extensions.Single(x => x.Oid?.Value == Oids.KeyUsage), true);

        await Assert.That(ext.KeyUsages).IsEqualTo(X509KeyUsageFlags.CrlSign);
    }


    [Test]
    public async Task Create_WithAPathLengthButNotACertificateAuthority_Throws()
    {
        //RFC 5280 s4.2.1.9: a CA MUST NOT include pathLenConstraint unless cA is asserted. These bytes are
        //canonical DER for (cA=FALSE, pathLen=3) and round-trip cleanly, so only this rule catches them.
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Path Length Without Ca")
            .AddExtension(Retype(Oids.BasicConstraints2, [0x30, 0x03, 0x02, 0x01, 0x03]));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("s4.2.1.9");
    }


    [Test]
    public async Task Create_WithAPathLengthOnTheCaProfile_IsIssuedNormally()
    {
        //Pins that the rule is conditional on cA. Without this, refusing every path length would still pass
        //the case above.
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Bounded Ca")
            .AddExtension(new X509BasicConstraintsExtension(true, true, 3, critical: true))
            .Create();

        var ext = cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2);

        await Assert.That(new X509BasicConstraintsExtension(ext, ext.Critical).PathLengthConstraint).IsEqualTo(3);
    }


    [Test]
    public async Task Create_WithAnOrdinaryKeyUsageOnAnEndEntityProfile_IsIssuedNormally()
    {
        //Pins that only keyCertSign is refused. Without this, rejecting every hand-supplied key usage would
        //still pass the cases above.
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Ordinary Key Usage")
            .AddExtension(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true))
            .Create();

        var ext = new X509KeyUsageExtension(cert.Extensions.Single(x => x.Oid?.Value == Oids.KeyUsage), true);

        await Assert.That(ext.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign)).IsFalse();
        await Assert.That(ext.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)).IsTrue();
    }


    [Test]
    public async Task Create_WithCertificateAuthorityBasicConstraintsAndNoUsage_IsIssuedNormally()
    {
        //A caller assembling a certificate by hand has no profile to contradict, so nothing is checked.
        //Without this, refusing cA=TRUE unconditionally would still pass every case above.
        using var cert = new CertificateBuilder()
            .SetSubject("CN=Hand Built Ca")
            .AddExtension(new X509BasicConstraintsExtension(true, false, 0, critical: true))
            .Create();

        var ext = cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2);

        await Assert.That(new X509BasicConstraintsExtension(ext, ext.Critical).CertificateAuthority).IsTrue();
    }


    [Test]
    public async Task Create_WithTheCaProfilesOwnExtensions_IsIssuedNormally()
    {
        //The profile generates a cA=TRUE basic constraints and a keyCertSign key usage of its own, so a check
        //that read the wrong way round would break every CA certificate the library builds
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Ordinary Ca")
            .Create();

        var ext = cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2);

        await Assert.That(new X509BasicConstraintsExtension(ext, ext.Critical).CertificateAuthority).IsTrue();
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_CertificateAuthorityBasicConstraints_Throws()
    {
        //The route the security review exploited, end to end: a permissive predicate on a Server profile
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = BuildCa();

        var request = new CertificateRequest("CN=Smuggled Ca", requesterKeys, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, critical: false));
        var csr = CertificateSigningRequest.FromDer(request.CreateSigningRequest(), CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, _ => true);

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task CreateCertificateSigningRequest_WithCertificateAuthorityBasicConstraintsOnAnEndEntityProfile_Throws()
    {
        //CreateCertificateSigningRequest does not call Validate, so it needs its own coverage: the check runs
        //in CreateCertificateRequest, which every issuance path goes through
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Would Be A Ca Request")
            .SetKeyPair(keys)
            .AddExtension(new X509BasicConstraintsExtension(true, false, 0, critical: true));

        await Assert.That(() => builder.CreateCertificateSigningRequest()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task CreateCertificateSigningRequest_WithACriticalAuthorityInformationAccess_WritesItNonCritical()
    {
        //The criticality correction reaches the signed PKCS#10 too, not only an issued certificate
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var csr = new CertificateBuilder()
            .SetSubject("CN=Critical Aia Signing Request")
            .SetKeyPair(keys)
            .AddExtension(new X509AuthorityInformationAccessExtension(["http://ocsp.example.com/"], null, critical: true)) // DevSkim: ignore DS137138
            .CreateCertificateSigningRequest();

        var reloaded = CertificateSigningRequest.FromDer(csr.RawData, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var ext = reloaded.CertificateRequest.CertificateExtensions.Single(x => x.Oid?.Value == Oids.AuthorityInformationAccess);

        await Assert.That(ext.Critical).IsFalse();
    }


    [Test]
    public async Task Create_WithAKeyUsageThatDoesNotSignCertificatesOnTheCaProfile_Throws()
    {
        //The mirror of the keyCertSign refusal above. A CA certificate whose key usage does not assert
        //keyCertSign cannot sign what it was made to sign, and this is the same harm the cA=FALSE refusal
        //exists for, reached through the other extension.
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Would Not Sign")
            .AddExtension(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains(nameof(X509KeyUsageFlags.KeyCertSign));
    }


    [Test]
    [Arguments(Oids.BasicConstraints2, new byte[] { 0x30, 0x03, 0x01, 0x01, 0xFF, 0x05, 0x00 })] //cA=TRUE, then a trailing NULL
    [Arguments(Oids.KeyUsage, new byte[] { 0x03, 0x02, 0x01, 0x04, 0x00 })]                      //keyCertSign, then a trailing octet
    public async Task Create_WithATrailingDataValueOnAnEndEntityProfile_Throws(string oid, byte[] rawData)
    {
        //The bypass a security review demonstrated end to end: .NET's decoder rejects both of these, while
        //OpenSSL and Windows CryptoAPI read the well-formed part and honour cA=TRUE and Certificate Sign.
        //Treating "I cannot read it" as "it asserts nothing" issued a working certificate authority under an
        //end-entity profile and chained a forged leaf through it. What this builder cannot read, it refuses.
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Trailing Data")
            .AddExtension(Retype(oid, rawData));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("does not read back");
    }


    [Test]
    [Arguments(new byte[] { 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0xFF })]                   //pathLenConstraint = -1
    [Arguments(new byte[] { 0x30, 0x0A, 0x01, 0x01, 0xFF, 0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 })] //pathLenConstraint > Int32.MaxValue
    public async Task Create_WithAPathLengthDotNetCannotRepresent_ThrowsInvalidOperationException(byte[] rawData)
    {
        //The two fail in different halves of the round trip, which is the point of testing both: -1 decodes
        //and then trips the re-encoding constructor, which rejects a negative path length, while a value
        //above Int32.MaxValue throws at decode and never reaches the re-encode. Only the first exercises the
        //widened catch. Either way the refusal has to arrive as InvalidOperationException like every other
        //one, not as whatever the BCL happened to throw.
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Unrepresentable Path Length")
            .AddExtension(Retype(Oids.BasicConstraints2, rawData));

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_WithAnUndecodableKeyUsageAndNoUsage_IsIssuedUnchanged()
    {
        //The basic constraints twin of this is above; without both, the no-profile path is pinned for one
        //extension only
        var supplied = Retype(Oids.KeyUsage, [0x05, 0x00]);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Undecodable Key Usage No Profile")
            .AddExtension(supplied)
            .Create();

        await Assert.That(cert.Extensions.Single(x => x.Oid?.Value == Oids.KeyUsage).RawData)
            .IsEquivalentTo(supplied.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    [Arguments(Oids.BasicConstraints2, new byte[] { 0x05, 0x00 })]
    [Arguments(Oids.KeyUsage, new byte[] { 0x05, 0x00 })]
    public async Task Create_WithAnUndecodableValueOnAnEndEntityProfile_Throws(string oid, byte[] rawData)
    {
        //Same rule for a value with no well-formed part at all, so the refusal does not depend on the
        //attacker's encoding being nearly right
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Undecodable")
            .AddExtension(Retype(oid, rawData));

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_WithAnUndecodableBasicConstraintsAndNoUsage_IsIssuedUnchanged()
    {
        //Nothing is compared when there is no profile, so nothing is refused either: the extension goes out
        //as supplied, exactly as it did before any of these checks existed. Without this test, refusing an
        //undecodable value unconditionally would still pass every case above.
        var supplied = Retype(Oids.BasicConstraints2, [0x05, 0x00]);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Undecodable No Profile")
            .AddExtension(supplied)
            .Create();

        await Assert.That(cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2).RawData)
            .IsEquivalentTo(supplied.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithAnExplicitDefaultInBasicConstraints_Throws()
    {
        //DER omits a field at its default, so cA spelled out as FALSE re-encodes to different bytes. It
        //asserts nothing dangerous, but the builder cannot promise every validator reads it the way .NET
        //does, and RFC 5280 s4.1 requires DER in the first place.
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Explicit Default")
            .AddExtension(Retype(Oids.BasicConstraints2, [0x30, 0x03, 0x01, 0x01, 0x00]));

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_WithACanonicalBasicConstraintsOnAnEndEntityProfile_IsIssuedNormally()
    {
        //Pins that the round trip accepts what it should. Without this, refusing every basic constraints
        //extension would still pass every refusal case above.
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Canonical Basic Constraints")
            .AddExtension(new X509BasicConstraintsExtension(false, false, 0, critical: true))
            .Create();

        var ext = cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2);

        await Assert.That(new X509BasicConstraintsExtension(ext, ext.Critical).CertificateAuthority).IsFalse();
    }


    [Test]
    public async Task Create_WithASubjectMatchingTheIssuers_Throws()
    {
        //RFC 5280 s6.3.3 accepts a revocation list from any certificate whose subject matches the target
        //certificate's issuer and whose key usage asserts cRLSign, without requiring cA=TRUE. So a leaf under
        //the CA's own name can revoke everything that CA ever issued; OpenSSL and Java PKIX both honour it.
        using var ca = BuildCa();

        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetIssuer(ca)
            .SetSubject(ca.SubjectName);

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("issuer's own name");
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithASubjectMatchingTheIssuers_Throws()
    {
        //The route that matters: the subject comes off the request unchallenged, so the requester chooses it
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = BuildCa();

        var request = new CertificateRequest(ca.SubjectName, requesterKeys, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign, critical: true));
        var csr = CertificateSigningRequest.FromDer(request.CreateSigningRequest(), CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, _ => true);

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    [Arguments(UniversalTagNumber.PrintableString)] //the CA's own common name is a UTF8String
    [Arguments(UniversalTagNumber.BMPString)]
    public async Task Create_WithASubjectMatchingTheIssuersUnderAnotherStringEncoding_Throws(UniversalTagNumber encoding)
    {
        //RFC 5280 s7.1 has relying parties compare names canonically, and OpenSSL and Java both disregard
        //which ASN.1 string type carried the characters. Comparing the encoded bytes would let the same name
        //through under any encoding the requester picked, which is what this test caught.
        using var ca = BuildCa();

        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetIssuer(ca)
            .SetSubject(x => x.Set(Oids.CommonNameOid, encoding, CaCommonName));

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    [Arguments("issuing ca")]      //case-folded
    [Arguments("ISSUING CA")]
    [Arguments("Issuing   CA")]    //whitespace collapsed
    [Arguments("  Issuing CA  ")]
    public async Task Create_WithASubjectMatchingTheIssuersButForCaseOrSpacing_Throws(string commonName)
    {
        //Canonical name comparison folds case and collapses whitespace, so neither is a way past the check
        using var ca = BuildCa();

        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetIssuer(ca)
            .SetSubject(x => x.SetCommonName(commonName));

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_WithASubjectMerelyResemblingTheIssuers_IsIssuedNormally()
    {
        //Pins that the comparison is not so loose that any similar name collides. Without this, an
        //implementation refusing every subject would still pass every case above.
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetIssuer(ca)
            .SetSubject(x => x.SetCommonName(CaCommonName + " Subordinate"))
            .Create();

        await Assert.That(cert.SubjectName.Name).Contains("Subordinate");
    }


    [Test]
    public async Task Create_WithASubjectMatchingTheIssuersAndNoUsage_IsIssuedNormally()
    {
        //A builder with no Usage makes none of these refusals, as UseCertificateSigningRequest's remarks and
        //the README both warn. Without this test, extending the check to an unconfigured builder would pass
        //the whole suite, so the documented behaviour would not actually be pinned anywhere.
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetIssuer(ca)
            .SetSubject(ca.SubjectName)
            .Create();

        await Assert.That(cert.SubjectName.RawData).IsEquivalentTo(ca.SubjectName.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithASubjectMatchingTheIssuersOnTheCaProfile_IsIssuedNormally()
    {
        //A self-issued CA certificate is ordinary key rollover, so the CA profile is exempt. Without this,
        //refusing every name collision would still pass the cases above.
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetIssuer(ca)
            .SetSubject(ca.SubjectName)
            .Create();

        await Assert.That(cert.SubjectName.RawData).IsEquivalentTo(ca.SubjectName.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_SelfSignedWithAnEndEntityProfile_IsIssuedNormally()
    {
        //A self-signed certificate is its own issuer, so the collision is unavoidable and means nothing.
        //Without this, comparing against the subject rather than the issuer would break the commonest thing
        //this library does.
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=localhost")
            .Create();

        await Assert.That(cert.SubjectName.Name).IsEqualTo(cert.IssuerName.Name);
    }


    private const string CaCommonName = "Issuing CA";


    //A plain X509Extension does not replace the profile's generated extension of the same OID -- the set
    //matches on runtime type too -- so both would reach CertificateRequest and it would throw before any of
    //this was reached. CopyFrom gives the right runtime type carrying the bytes under test.
    private static X509Extension Retype(string oid, byte[] rawData)
    {
        X509Extension typed = oid == Oids.BasicConstraints2
            ? new X509BasicConstraintsExtension()
            : new X509KeyUsageExtension();
        typed.CopyFrom(new X509Extension(oid, rawData, critical: false));
        return typed;
    }


    private static X509Certificate2 BuildCa()
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            //SetCommonName writes a UTF8String, so the encoding tests below have something to differ from
            .SetSubject(x => x.SetCommonName(CaCommonName))
            .SetKeyPair(keys)
            .SetValidity(TimeSpan.FromDays(2))
            .Create();
    }
}
