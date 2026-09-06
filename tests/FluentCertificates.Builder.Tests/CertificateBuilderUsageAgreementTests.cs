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
    [Arguments(X509KeyUsageFlags.KeyCertSign)]
    [Arguments(X509KeyUsageFlags.CrlSign)]
    public async Task Create_WithACaOnlyKeyUsageOnAnEndEntityProfile_Throws(X509KeyUsageFlags flag)
    {
        //Both flags exist only for a certificate authority, and the reviewer's exploit carried them alongside
        //cA=TRUE
        var builder = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Would Sign Certificates")
            .AddExtension(new X509KeyUsageExtension(flag | X509KeyUsageFlags.DigitalSignature, critical: true));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains(nameof(CertificateUsage.Server));
    }


    [Test]
    public async Task Create_WithAnOrdinaryKeyUsageOnAnEndEntityProfile_IsIssuedNormally()
    {
        //Pins that only the two CA flags are refused. Without this, rejecting every hand-supplied key usage
        //would still pass the cases above.
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
    public async Task Create_WithAMalformedKeyUsageValueOnAnEndEntityProfile_IsIssuedUnchanged()
    {
        //A value that will not decode asserts no flag this builder can read, so it claims none of the ones
        //reserved to a CA and is issued as supplied, exactly as it was before the check existed.
        //CopyFrom rather than a plain X509Extension so the supplied extension replaces the Server profile's
        //generated key usage: the extension set matches on runtime type as well as OID.
        var supplied = new X509KeyUsageExtension();
        supplied.CopyFrom(new X509Extension(Oids.KeyUsage, [0x05, 0x00], critical: false));

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject("CN=Malformed Key Usage")
            .AddExtension(supplied)
            .Create();

        await Assert.That(cert.Extensions.Single(x => x.Oid?.Value == Oids.KeyUsage).RawData)
            .IsEquivalentTo(supplied.RawData, TUnit.Assertions.Enums.CollectionOrdering.Matching);
    }


    private static X509Certificate2 BuildCa()
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Issuing CA")
            .SetKeyPair(keys)
            .SetValidity(TimeSpan.FromDays(2))
            .Create();
    }
}
