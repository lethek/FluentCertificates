using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using TUnit.Assertions.Enums;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

/// <summary>
/// Covers the criticality RFC 5280 requires of particular extensions. Each rule is a MUST about the flag
/// beside the extension rather than the value inside it, so an extension breaking one is issued with the
/// required flag and its value untouched. Assertions read the issued certificate rather than the builder.
/// </summary>
public class CertificateBuilderCriticalityConformanceTests
{
    [Test]
    public async Task Create_WithACriticalAuthorityKeyIdentifier_IssuesItNonCritical()
    {
        //RFC 5280 s4.2.1.1: conforming CAs MUST mark this extension as non-critical
        using var ca = BuildCa();
        var supplied = new X509Extension(Oids.AuthorityKeyIdentifier, new X509AuthorityKeyIdentifierExtension(ca, false).RawData, critical: true);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Critical Aki")
            .SetIssuer(ca)
            .AddExtension(supplied)
            .Create();

        var ext = FindExtension(cert, Oids.AuthorityKeyIdentifier);

        await Assert.That(ext.Critical).IsFalse();
        await Assert.That(ext.RawData).IsEquivalentTo(supplied.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithACriticalSubjectKeyIdentifier_IssuesItNonCriticalKeepingItsValue()
    {
        //RFC 5280 s4.2.1.2: conforming CAs MUST mark this extension as non-critical. The supplied identifier
        //is deliberately not the one the builder would compute, so an implementation that regenerated the
        //extension instead of correcting the flag would fail this.
        var supplied = new X509SubjectKeyIdentifierExtension("0102030405060708090A", critical: true);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Critical Ski")
            .AddExtension(supplied)
            .Create();

        var ext = FindExtension(cert, Oids.SubjectKeyIdentifier);

        await Assert.That(ext.Critical).IsFalse();
        await Assert.That(ext.RawData).IsEquivalentTo(supplied.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithACriticalSubjectInformationAccess_IssuesItNonCritical()
    {
        //RFC 5280 s4.2.2.2: conforming CAs MUST mark this extension as non-critical. It has no BCL type, so
        //it arrives as a plain X509Extension and shares SubjectInfoAccessSyntax with the AIA extension.
        var supplied = new X509Extension(Oids.SubjectInformationAccess, new X509AuthorityInformationAccessExtension([CaIssuersUri], null).RawData, critical: true);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Critical Sia")
            .AddExtension(supplied)
            .Create();

        var ext = FindExtension(cert, Oids.SubjectInformationAccess);

        await Assert.That(ext.Critical).IsFalse();
        await Assert.That(ext.RawData).IsEquivalentTo(supplied.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithACriticalFreshestCrl_IssuesItNonCritical()
    {
        //RFC 5280 s4.2.1.15: conforming CAs MUST mark this extension as non-critical. It has no BCL type
        //either, and shares CRLDistributionPoints' syntax.
        var supplied = new X509Extension(Oids.FreshestCrl, CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([CrlUri]).RawData, critical: true);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Critical Freshest Crl")
            .AddExtension(supplied)
            .Create();

        var ext = FindExtension(cert, Oids.FreshestCrl);

        await Assert.That(ext.Critical).IsFalse();
        await Assert.That(ext.RawData).IsEquivalentTo(supplied.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithANonCriticalCertificateAuthorityBasicConstraints_IssuesItCritical()
    {
        //RFC 5280 s4.2.1.9: basic constraints MUST be critical in a CA certificate. No Usage profile is set,
        //so nothing contradicts the extension and only its criticality is at stake.
        using var cert = new CertificateBuilder()
            .SetSubject("CN=Hand Built Ca")
            .AddExtension(new X509BasicConstraintsExtension(true, false, 0, critical: false))
            .Create();

        var ext = FindExtension(cert, Oids.BasicConstraints2);

        await Assert.That(ext.Critical).IsTrue();
        await Assert.That(new X509BasicConstraintsExtension(ext, ext.Critical).CertificateAuthority).IsTrue();
    }


    [Test]
    public async Task Create_WithAMalformedBasicConstraintsValue_IssuesItUnchanged()
    {
        //Reading the cA bit means decoding the requester's DER, and a value that will not decode has no bit
        //to read. Refusing it here would be a new failure for input the builder issued verbatim before the
        //criticality rules existed, so no rule applies and it goes out as supplied.
        var supplied = new X509Extension(Oids.BasicConstraints2, [0x05, 0x00], critical: false);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Malformed Basic Constraints")
            .AddExtension(supplied)
            .Create();

        var ext = FindExtension(cert, Oids.BasicConstraints2);

        await Assert.That(ext.Critical).IsFalse();
        await Assert.That(ext.RawData).IsEquivalentTo(supplied.RawData, CollectionOrdering.Matching);
    }


    [Test]
    [Arguments(Oids.NameConstraints)]           //s4.2.1.10
    [Arguments(Oids.CertPolicyConstraints)]     //s4.2.1.11
    [Arguments(Oids.InhibitAnyPolicyExtension)] //s4.2.1.14
    public async Task Create_WithANonCriticalConstraintExtension_IssuesItCritical(string oid)
    {
        //Each of those sections says conforming CAs MUST mark the extension critical. A non-critical one is
        //worse than useless: a relying party that does not implement the extension ignores the restriction
        //rather than refusing the certificate it restricts. The value is opaque here, since only the flag is
        //under test.
        var supplied = new X509Extension(oid, [0x30, 0x00], critical: false);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Non Critical Constraint")
            .AddExtension(supplied)
            .Create();

        var ext = FindExtension(cert, oid);

        await Assert.That(ext.Critical).IsTrue();
        await Assert.That(ext.RawData).IsEquivalentTo(supplied.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithACriticalSubjectDirectoryAttributes_IssuesItNonCritical()
    {
        //RFC 5280 s4.2.1.8: conforming CAs MUST mark this extension as non-critical. Marked critical it makes
        //the certificate unusable, since s4.2 has every conforming client reject an unrecognised critical
        //extension.
        var supplied = new X509Extension(Oids.SubjectDirectoryAttributes, [0x30, 0x00], critical: true);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Critical Subject Directory Attributes")
            .AddExtension(supplied)
            .Create();

        await Assert.That(FindExtension(cert, Oids.SubjectDirectoryAttributes).Critical).IsFalse();
    }


    [Test]
    public async Task Create_WithAnIssuer_IssuesTheIssuersAuthorityKeyIdentifierNonCritical()
    {
        //The issuer's own AKI is added straight to the request rather than through the extension set, so it
        //is the one extension that could drift out of conformance without any other test noticing
        using var ca = BuildCa();

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Issued Normally")
            .SetIssuer(ca)
            .Create();

        await Assert.That(FindExtension(cert, Oids.AuthorityKeyIdentifier).Critical).IsFalse();
    }


    [Test]
    public async Task Create_WithANonCriticalEndEntityBasicConstraints_LeavesItNonCritical()
    {
        //RFC 5280 s4.2.1.9 says nothing either way for an end-entity certificate, so cA=FALSE keeps the
        //criticality it was given. Without this test, marking every basic constraints extension critical
        //would still pass the CA case above.
        using var cert = new CertificateBuilder()
            .SetSubject("CN=End Entity")
            .AddExtension(new X509BasicConstraintsExtension(false, false, 0, critical: false))
            .Create();

        var ext = FindExtension(cert, Oids.BasicConstraints2);

        await Assert.That(ext.Critical).IsFalse();
    }


    [Test]
    public async Task Create_WithAnEmptySubjectAndANonCriticalSubjectAltName_IssuesItCritical()
    {
        //RFC 5280 s4.2.1.6: the subject alternative name MUST be critical when the subject is empty, because
        //it is then the only name the certificate carries
        using var ca = BuildCa();
        var supplied = new X509SubjectAlternativeNameExtension(BuildSan("empty.example.com").RawData, critical: false);

        using var cert = new CertificateBuilder()
            .SetIssuer(ca)
            .AddExtension(supplied)
            .Create();

        var ext = FindExtension(cert, Oids.SubjectAltName);

        await Assert.That(ext.Critical).IsTrue();
        await Assert.That(ext.RawData).IsEquivalentTo(supplied.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_WithASubjectAndANonCriticalSubjectAltName_LeavesItNonCritical()
    {
        //The rule is conditional on the subject being empty; without this test, marking every subject
        //alternative name critical would still pass the empty-subject case above
        using var cert = new CertificateBuilder()
            .SetSubject("CN=Named")
            .AddExtension(new X509SubjectAlternativeNameExtension(BuildSan("named.example.com").RawData, critical: false))
            .Create();

        await Assert.That(FindExtension(cert, Oids.SubjectAltName).Critical).IsFalse();
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_ACriticalAuthorityKeyIdentifier_IsIssuedNonCritical()
    {
        //The route the work item found: a requester marks the extension critical, the CA's accept predicate
        //whitelists it by OID without inspecting Critical, and the certificate goes out non-conformant
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = BuildCa();

        var request = new CertificateRequest("CN=Critical Aki From Csr", requesterKeys, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509Extension(Oids.AuthorityKeyIdentifier, new X509AuthorityKeyIdentifierExtension(ca, false).RawData, critical: true));
        var csr = CertificateSigningRequest.FromDer(request.CreateSigningRequest(), CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        using var cert = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, _ => true)
            .Create();

        await Assert.That(CountExtensions(cert, Oids.AuthorityKeyIdentifier)).IsEqualTo(1);
        await Assert.That(FindExtension(cert, Oids.AuthorityKeyIdentifier).Critical).IsFalse();
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_ACriticalAuthorityInformationAccess_IsIssuedNonCritical()
    {
        //RFC 5280 s4.2.2.1, reached through the CSR route rather than AddExtension
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = BuildCa();

        var request = new CertificateRequest("CN=Critical Aia From Csr", requesterKeys, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([OcspUri], null, critical: true));
        var csr = CertificateSigningRequest.FromDer(request.CreateSigningRequest(), CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        using var cert = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, _ => true)
            .Create();

        await Assert.That(FindExtension(cert, Oids.AuthorityInformationAccess).Critical).IsFalse();
    }


    [Test]
    public async Task CreateCertificateRequest_WithACriticalAuthorityInformationAccess_WritesItNonCritical()
    {
        //Create() reaches the correction through CreateCertificateRequest(), but this route is public in its
        //own right and a signing request is a certificate's first draft
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var request = new CertificateBuilder()
            .SetSubject("CN=Critical Aia Request")
            .SetKeyPair(keys)
            .AddExtension(new X509AuthorityInformationAccessExtension([OcspUri], null, critical: true))
            .CreateCertificateRequest();

        var ext = request.CertificateExtensions.Single(x => x.Oid?.Value == Oids.AuthorityInformationAccess);

        await Assert.That(ext.Critical).IsFalse();
    }


    [Test]
    public async Task AddExtension_WithACriticalAuthorityInformationAccess_LeavesExtensionsReportingWhatItWasGiven()
    {
        //The correction lands on what is issued, not on the builder, so Extensions stays a faithful record of
        //what the caller handed over
        var builder = new CertificateBuilder()
            .SetSubject("CN=Unrepaired Builder")
            .AddExtension(new X509AuthorityInformationAccessExtension([OcspUri], null, critical: true));

        await Assert.That(builder.Extensions.Single(x => x.Oid?.Value == Oids.AuthorityInformationAccess).Critical).IsTrue();
    }


    private const string OcspUri = "http://ocsp.example.com/"; // DevSkim: ignore DS137138
    private const string CaIssuersUri = "http://pki.example.com/issuer.cer"; // DevSkim: ignore DS137138
    private const string CrlUri = "http://crl.example.com/root.crl"; // DevSkim: ignore DS137138


    private static X509Extension FindExtension(X509Certificate2 cert, string oid)
        => cert.Extensions.Single(x => x.Oid?.Value == oid);


    private static int CountExtensions(X509Certificate2 cert, string oid)
        => cert.Extensions.Count(x => x.Oid?.Value == oid);


    private static X509Extension BuildSan(string dnsName)
    {
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dnsName);
        return san.Build();
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
