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
    public async Task Create_WithAPathLengthButNotACertificateAuthority_IsIssuedNormally()
    {
        //RFC 5280 s4.2.1.9 says a CA MUST NOT include pathLenConstraint unless cA is asserted, but the
        //field is inert on an end-entity certificate and conforming to that profile is the caller's to
        //decide. These bytes are canonical DER for (cA=FALSE, pathLen=3) and go out as supplied.
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Path Length Without Ca")
            .AddExtension(new X509Extension(Oids.BasicConstraints2, [0x30, 0x03, 0x02, 0x01, 0x03], critical: false))
            .Create();

        var ext = cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2);

        await Assert.That(ext.RawData).IsEquivalentTo(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x03 });
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
        //The bypass a security review demonstrated end to end: OpenSSL and Windows CryptoAPI read the
        //well-formed part of both of these and honour cA=TRUE and Certificate Sign. Treating "I cannot read
        //it" as "it asserts nothing" issued a working certificate authority under an end-entity profile and
        //chained a forged leaf through it.
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Trailing Data")
            .AddExtension(new X509Extension(oid, rawData, critical: false));

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_WithAValueHidingASecondAssertionAfterIt_Throws()
    {
        //The sharp end of the same bypass, and the reason the extent is measured rather than left to the
        //decoder: an empty SEQUENCE reads as cA=FALSE, which agrees with the Server profile, so the check
        //above sees nothing wrong and only the trailing bytes carry cA=TRUE for a reader that skips the
        //SEQUENCE length. .NET 10 refuses these bytes itself; .NET 8 and 9 decode them and report cA=FALSE.
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Hidden Assertion")
            .AddExtension(new X509Extension(Oids.BasicConstraints2, [0x30, 0x00, 0x01, 0x01, 0xFF], critical: false));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("cannot be read");
    }


    [Test]
    public async Task Create_WithAKeyUsageHidingASecondAssertionAfterIt_Throws()
    {
        //The key usage twin, and it needs its own case: an empty bit string asserts no usages at all, which
        //an end-entity profile is content with, so the trailing bytes asserting keyCertSign are again what
        //only the extent measurement catches. .NET 8 and 9 read the first value and report no usages.
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Hidden Key Usage")
            .AddExtension(new X509Extension(Oids.KeyUsage, [0x03, 0x01, 0x00, 0x03, 0x02, 0x01, 0x04], critical: true));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("cannot be read");
    }


    [Test]
    public async Task Create_WithANegativePathLength_IsIssuedUnchanged()
    {
        //It decodes, and what it decodes to agrees with the profile: cA=TRUE. Whether a path length below
        //zero is one this authority should sign is the caller's policy, and the bytes go out as written.
        //A pathLenConstraint too large for an Int32 is deliberately not tested alongside it: on net8 and
        //net9 the BCL decodes basic constraints through the platform, so Windows refuses those bytes while
        //Linux reads them as pathLen=0. Only cA is consulted here and the value is emitted as supplied, so
        //the misreading reaches no decision, but the outcome is the platform's and not this library's.
        var supplied = new X509Extension(Oids.BasicConstraints2, [0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0xFF], critical: false);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Negative Path Length")
            .AddExtension(supplied)
            .Create();

        await Assert.That(cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2).RawData)
            .IsEquivalentTo(supplied.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithAnUndecodableKeyUsageAndNoUsage_IsIssuedUnchanged()
    {
        //The basic constraints twin of this is above; without both, the no-profile path is pinned for one
        //extension only
        var supplied = new X509Extension(Oids.KeyUsage, [0x05, 0x00], critical: false);

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
            .AddExtension(new X509Extension(oid, rawData, critical: false));

        await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_WithAnUndecodableBasicConstraintsAndNoUsage_IsIssuedUnchanged()
    {
        //Nothing is compared when there is no profile, so nothing is refused either: the extension goes out
        //as supplied, exactly as it did before any of these checks existed. Without this test, refusing an
        //undecodable value unconditionally would still pass every case above.
        var supplied = new X509Extension(Oids.BasicConstraints2, [0x05, 0x00], critical: false);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Undecodable No Profile")
            .AddExtension(supplied)
            .Create();

        await Assert.That(cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2).RawData)
            .IsEquivalentTo(supplied.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithAnExplicitDefaultInBasicConstraints_IsIssuedUnchanged()
    {
        //DER omits a field at its default, so cA spelled out as FALSE re-encodes to different bytes. Real
        //certificates carry it and every reader takes it for FALSE, which is what the Server profile wants,
        //so the spelling is no reason to refuse the caller's own bytes.
        var supplied = new X509Extension(Oids.BasicConstraints2, [0x30, 0x03, 0x01, 0x01, 0x00], critical: false);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Explicit Default")
            .AddExtension(supplied)
            .Create();

        await Assert.That(cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2).RawData)
            .IsEquivalentTo(supplied.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithABerBooleanInBasicConstraints_IsIssuedUnchanged()
    {
        //DER spells TRUE as 0xFF, BER as any non-zero octet. Both say cA=TRUE to every reader, so the
        //spelling is no reason to refuse a value that agrees with the CA profile.
        var supplied = new X509Extension(Oids.BasicConstraints2, [0x30, 0x03, 0x01, 0x01, 0x01], critical: false);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Ber Boolean")
            .AddExtension(supplied)
            .Create();

        await Assert.That(cert.Extensions.Single(x => x.Oid?.Value == Oids.BasicConstraints2).RawData)
            .IsEquivalentTo(supplied.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithANonMinimalKeyUsageBitString_IsIssuedUnchanged()
    {
        //The key usage twin: a bit string carrying a spare zero byte decodes to DigitalSignature for every
        //reader, and re-encodes shorter. Without this the same rule is pinned for one extension only.
        var supplied = new X509Extension(Oids.KeyUsage, [0x03, 0x03, 0x07, 0x80, 0x00], critical: true);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Non Minimal Key Usage")
            .AddExtension(supplied)
            .Create();

        await Assert.That(cert.Extensions.Single(x => x.Oid?.Value == Oids.KeyUsage).RawData)
            .IsEquivalentTo(supplied.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithACanonicalBasicConstraintsOnAnEndEntityProfile_IsIssuedNormally()
    {
        //Pins that the check accepts what it should. Without this, refusing every basic constraints
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
    public async Task Create_WithASignatureGeneratorAndNoIssuer_ThrowsWhenTheKeyIsNotTheSubjectsOwn()
    {
        //With no Issuer the certificate is written self-issued, which is only what it says when the signing
        //key is the subject's own. A generator holding the CA's key mints a certificate under whatever name
        //the requester chose,
        //signed by the CA: Java's CertPathBuilder selects it as a CRL issuer by the CRL's AKID, accepts it as
        //an end-entity certificate whose signature verifies against the anchor, and reports a third party
        //REVOKED. Verified on JDK 21; with this certificate absent the same run reports only
        //UNDETERMINED_REVOCATION_STATUS, so it is this certificate being trusted and not the real CA.
        using var caKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName(CaCommonName))
            .SetKeyPair(caKeys)
            .SetValidity(TimeSpan.FromDays(2))
            .Create();

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(ca.SubjectName, requesterKeys, HashAlgorithmName.SHA256);
        var csr = CertificateSigningRequest.FromDer(request.CreateSigningRequest());

        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetSignatureGenerator(X509SignatureGenerator.CreateForECDsa(caKeys))
            .UseCertificateSigningRequest(csr);

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("signed by a key that is not its own");
    }


    [Test]
    public async Task Create_WithASignatureGeneratorOverItsOwnKey_IsIssuedNormally()
    {
        //The legitimate reason to supply a generator with no issuer: the subject's own key lives somewhere
        //that will not export it. That certificate really is self-signed, so nothing is refused.
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetSubject(x => x.SetCommonName("Self Signed Leaf"))
            .SetKeyPair(keys)
            .SetSignatureGenerator(X509SignatureGenerator.CreateForECDsa(keys))
            .SetValidity(TimeSpan.FromDays(1))
            .Create();

        await Assert.That(cert.SubjectName.Name).Contains("Self Signed Leaf");
    }


    [Test]
    public async Task Create_WithASignatureGeneratorAndNoIssuer_ThrowsUnderTheCaProfileToo()
    {
        //The CA profile is no exemption from the rule above. Here the certificate certifies the requester's
        //key under the signing authority's own name with cA=TRUE and keyCertSign, which is a certificate
        //authority impersonated outright rather than the rollover the profile exists to allow.
        using var caKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName(CaCommonName))
            .SetKeyPair(caKeys)
            .SetValidity(TimeSpan.FromDays(2))
            .Create();

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(ca.SubjectName, requesterKeys, HashAlgorithmName.SHA256);
        var csr = CertificateSigningRequest.FromDer(request.CreateSigningRequest());

        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSignatureGenerator(X509SignatureGenerator.CreateForECDsa(caKeys))
            .UseCertificateSigningRequest(csr);

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("signed by a key that is not its own");
    }


    [Test]
    public async Task Create_WithACaSelfSignedOverItsOwnKey_IsIssuedNormally()
    {
        //Pins that the rule above turns on whose key signs, not on the CA profile. Without this, refusing
        //every generator under that profile would still pass the case above.
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Self Signed Root"))
            .SetKeyPair(keys)
            .SetSignatureGenerator(X509SignatureGenerator.CreateForECDsa(keys))
            .SetValidity(TimeSpan.FromDays(1))
            .Create();

        await Assert.That(cert.SubjectName.Name).Contains("Self Signed Root");
    }


    [Test]
    public async Task Create_WithACaRolloverUnderTheIssuersOwnName_IsIssuedNormally()
    {
        //Rollover is the ordinary reason a certificate carries its issuer's own subject, and nothing refuses
        //it: with no SignatureGenerator the issuer's own private key signs, which is what the check asks for.
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetIssuer(ca)
            .SetSubject(x => x.SetCommonName(CaCommonName))
            .SetValidity(TimeSpan.FromDays(1))
            .Create();

        await Assert.That(cert.SubjectName.Name).Contains(CaCommonName);
    }


    [Test]
    public async Task Create_WithACaRolloverSignedByAForeignKey_Throws()
    {
        //The CA profile's rollover exemption above only accepts a same-named issuer when the certificate is
        //genuinely signed by that issuer. Naming a real, trusted root as Issuer while actually signing with
        //an unrelated key mints a certificate that looks like the root's own successor to any relying party
        //doing the RFC 5280 s6.3.3 name match -- the same impersonation the no-Issuer case above refuses,
        //just reached by borrowing the issuer's name instead of leaving Issuer unset.
        using var ca = BuildCa();

        using var attackerKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetIssuer(ca)
            .SetSubject(x => x.SetCommonName(CaCommonName))
            .SetSignatureGenerator(X509SignatureGenerator.CreateForECDsa(attackerKeys))
            .SetPublicKey(new PublicKey(attackerKeys));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("signed by a key that is not the issuer's own");
    }


    [Test]
    public async Task Create_WithAGenuineCaRolloverSignedByTheIssuersOwnKey_IsIssuedNormally()
    {
        //Pins that the rule above turns on whose key actually signs, not on merely supplying a
        //SignatureGenerator: genuine rollover through a generator that really is the issuer's own key, such
        //as one backed by an HSM, must still be issued.
        using var caKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName(CaCommonName))
            .SetKeyPair(caKeys)
            .SetValidity(TimeSpan.FromDays(2))
            .Create();

        using var newKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetIssuer(ca)
            .SetSubject(x => x.SetCommonName(CaCommonName))
            .SetKeyPair(newKeys)
            .SetSignatureGenerator(X509SignatureGenerator.CreateForECDsa(caKeys))
            .SetValidity(TimeSpan.FromDays(1))
            .Create();

        await Assert.That(cert.SubjectName.Name).Contains(CaCommonName);
    }


    [Test]
    public async Task Create_WithAnOcspSigningPurposeUnderAnEndEntityProfile_IsIssuedNormally()
    {
        //RFC 6960 s4.2.2.2 delegates OCSP for the whole CA to any certificate the CA issued directly that
        //carries this purpose, so accepting one onto an endpoint profile is a consequential decision. It is
        //the caller's decision: which extended key usage purposes a requester may have is their policy, and
        //the accept predicate is where they apply it.
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(
                RequestFor("totally-ordinary.example.net", Oids.OcspSigningPurpose),
                x => x.Oid?.Value == Oids.EnhancedKeyUsage)
            .Create();

        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();

        await Assert.That(eku.EnhancedKeyUsages.Cast<Oid>().Select(x => x.Value)).Contains(Oids.OcspSigningPurpose);
    }


    [Test]
    public async Task Create_WithAnOcspSigningProfileAndThatPurpose_IsIssuedNormally()
    {
        //The profile named for this purpose carries it too, since which purposes a requester may have is the
        //caller's policy either way
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.OcspSigning)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(
                RequestFor("ocsp.example.net", Oids.OcspSigningPurpose),
                x => x.Oid?.Value == Oids.EnhancedKeyUsage)
            .Create();

        await Assert.That(cert.SubjectName.Name).Contains("ocsp.example.net");
    }


    [Test]
    public async Task Create_WithAnOrdinaryPurposeUnderAnEndEntityProfile_IsIssuedNormally()
    {
        //Refining the profile's own extended key usage is the ordinary reason to supply one
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(
                RequestFor("ordinary.example.net", Oids.ServerAuthPurpose, Oids.ClientAuthPurpose),
                x => x.Oid?.Value == Oids.EnhancedKeyUsage)
            .Create();

        await Assert.That(cert.SubjectName.Name).Contains("ordinary.example.net");
    }


    [Test]
    [Arguments(CertificateUsage.Server)]
    [Arguments(CertificateUsage.Client)]
    public async Task Create_WithNameConstraintsOnAnEndEntityProfile_IsIssuedNormally(CertificateUsage usage)
    {
        //RFC 5280 s4.2.1.10 restricts this extension to a CA certificate, but which extensions a profile
        //permits is the caller's policy. The criticality that same section requires is still applied.
        using var cert = new CertificateBuilder()
            .SetUsage(usage)
            .SetSubject("CN=Would Constrain Names")
            .AddExtension(new X509NameConstraintExtension(null, null))
            .Create();

        await Assert.That(cert.Extensions[Oids.NameConstraints]!.Critical).IsTrue();
    }


    [Test]
    [Arguments(Oids.CertPolicyConstraints)]     //s4.2.1.11
    [Arguments(Oids.InhibitAnyPolicyExtension)] //s4.2.1.14
    public async Task Create_WithAPolicyConstraintExtensionOnAnEndEntityProfile_IsIssuedNormally(string oid)
    {
        //Both sections restrict these to a CA certificate, and both are certificate policy machinery, which
        //the caller's policy governs rather than this library. The criticality those sections require is
        //still applied. The value is opaque here, since only the refusal is under test.
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Would Constrain Policies")
            .AddExtension(new X509Extension(oid, [0x30, 0x00], critical: false))
            .Create();

        await Assert.That(cert.Extensions[oid]!.Critical).IsTrue();
    }


    [Test]
    public async Task Create_WithAnOcspSigningProfileAndNoOcspPurpose_IsIssuedNormally()
    {
        //The converse of the two tests above: the profile named for OCSP does not oblige a requester to ask
        //for that purpose. Which purposes an accepted extended key usage must carry is the caller's policy,
        //and the accept predicate is where they apply it.
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.OcspSigning)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(
                RequestFor("not-really-ocsp.example.net", Oids.ServerAuthPurpose),
                x => x.Oid?.Value == Oids.EnhancedKeyUsage)
            .Create();

        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();

        await Assert.That(eku.EnhancedKeyUsages.Cast<Oid>().Select(x => x.Value)).DoesNotContain(Oids.OcspSigningPurpose);
    }


    [Test]
    public async Task Create_WithNameConstraintsOnTheCaProfile_IsIssuedNormally()
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=May Constrain Names")
            .AddExtension(new X509NameConstraintExtension(null, null))
            .Create();

        await Assert.That(cert.Extensions[Oids.NameConstraints]).IsNotNull();
    }


    [Test]
    public async Task Create_WithASubjectAlternativeNameCarryingNoEntries_IsIssuedNormally()
    {
        //RFC 5280 s4.2.1.6 says the sequence MUST contain at least one entry if present. An empty one
        //asserts nothing to any validator, and conforming to that profile is the caller's to decide.
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Empty San")
            .AddExtension(new X509Extension(Oids.SubjectAltName, [0x30, 0x00], critical: false))
            .Create();

        await Assert.That(cert.Extensions[Oids.SubjectAltName]!.RawData).IsEquivalentTo(new byte[] { 0x30, 0x00 });
    }


    [Test]
    public async Task Create_WithAnOrdinarySubjectAlternativeName_IsIssuedNormally()
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Named San")
            .SetSubjectAlternativeNames(x => x.AddDnsName("named.example.com"))
            .Create();

        await Assert.That(cert.Extensions[Oids.SubjectAltName]).IsNotNull();
    }


    private static CertificateSigningRequest RequestFor(string commonName, params string[] purposes)
    {
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var purposeOids = new OidCollection();
        foreach (var purpose in purposes) {
            purposeOids.Add(new Oid(purpose));
        }

        var request = new CertificateRequest($"CN={commonName}", requesterKeys, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(purposeOids, false));

        return CertificateSigningRequest.FromDer(request.CreateSigningRequest(), CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
    }


    [Test]
    public async Task Create_WithASubjectMatchingTheIssuersAndNoUsage_IsIssuedNormally()
    {
        //A builder with no Usage makes none of these refusals, as UseCertificateSigningRequest's remarks and
        //the README both warn. The same arrangement under a Usage is refused by
        //Create_WithACaRolloverSignedByAForeignKey_Throws.
        using var ca = BuildCa();

        using var attackerKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var cert = new CertificateBuilder()
            .SetIssuer(ca)
            .SetSubject(ca.SubjectName)
            .SetSignatureGenerator(X509SignatureGenerator.CreateForECDsa(attackerKeys))
            .SetPublicKey(new PublicKey(attackerKeys))
            .Create();

        await Assert.That(cert.SubjectName.RawData).IsEquivalentTo(ca.SubjectName.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithASubjectMatchingTheIssuersOnTheCaProfile_IsIssuedNormally()
    {
        //A self-issued CA certificate is ordinary key rollover. Whether a subject may bear its issuer's name
        //is the caller's to judge; only the signing key behind that name is checked.
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetIssuer(ca)
            .SetSubject(ca.SubjectName)
            .Create();

        await Assert.That(cert.SubjectName.RawData).IsEquivalentTo(ca.SubjectName.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    [Arguments(CertificateUsage.Server)]
    [Arguments(CertificateUsage.Client)]
    public async Task Create_WithASubjectMatchingTheIssuersOnAnEndEntityProfile_IsIssuedNormally(CertificateUsage usage)
    {
        //An end-entity certificate under its issuer's own name is how an indirect CRL issuer is conventionally
        //made, and RFC 5280 s6.3.3 has a relying party match that name to decide whose revocation lists it
        //will accept. Whether a subject is entitled to the name is the caller's to judge, so only the signing
        //key behind it is checked, exactly as on the CA profile above.
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetUsage(usage)
            .SetIssuer(ca)
            .SetSubject(ca.SubjectName)
            .Create();

        await Assert.That(cert.SubjectName.RawData).IsEquivalentTo(ca.SubjectName.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_SelfSignedWithAnEndEntityProfile_IsIssuedNormally()
    {
        //A self-signed certificate is its own issuer, the commonest thing this library does
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=localhost")
            .Create();

        await Assert.That(cert.SubjectName.Name).IsEqualTo(cert.IssuerName.Name);
    }


    private const string CaCommonName = "Issuing CA";


    private static X509Certificate2 BuildCa()
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName(CaCommonName))
            .SetKeyPair(keys)
            .SetValidity(TimeSpan.FromDays(2))
            .Create();
    }
}
