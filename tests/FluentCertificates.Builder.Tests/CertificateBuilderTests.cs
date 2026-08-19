using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

public class CertificateBuilderTests
{
    [Test]
    public async Task Build_Certificate_HasPrivateKey()
    {
        using var cert1 = new CertificateBuilder().Create();
        await Assert.That(cert1.HasPrivateKey).IsTrue();

        using var cert2 = new CertificateBuilder().SetKeyStorageFlags(X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable).Create();
        await Assert.That(cert2.HasPrivateKey).IsTrue();
    }


    [Test]
    public async Task Build_Certificate_WithSubject()
    {
        const string testName = nameof(Build_Certificate_WithSubject);
        const string expected = $"CN={testName}";

        //Test several different, equivalent ways of setting the Subject

        using var cert1 = new CertificateBuilder().SetSubject(b => b.SetCommonName(testName)).Create();
        await Assert.That(cert1.Subject).IsEqualTo(expected);

        using var cert2 = new CertificateBuilder().SetSubject(new X500NameBuilder().SetCommonName(testName)).Create();
        await Assert.That(cert2.Subject).IsEqualTo(expected);

        using var cert3 = new CertificateBuilder().SetSubject(new X500DistinguishedName(expected)).Create();
        await Assert.That(cert3.Subject).IsEqualTo(expected);

        using var cert5 = new CertificateBuilder().SetSubject(expected).Create();
        await Assert.That(cert5.Subject).IsEqualTo(expected);

        using var cert6 = new CertificateBuilder {Subject = new X500NameBuilder(expected)}.Create();
        await Assert.That(cert6.Subject).IsEqualTo(expected);
    }


    [Test]
    public async Task Build_Certificate_WithRSAKeys()
    {
        using var keys = RSA.Create();
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Create();
        await Assert.That(cert1.GetKeyAlgorithm()).IsEqualTo(PkcsObjectIdentifiers.RsaEncryption.Id);

        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.RSA).Create();
        await Assert.That(cert2.GetKeyAlgorithm()).IsEqualTo(PkcsObjectIdentifiers.RsaEncryption.Id);
    }


    [Test]
    public async Task Build_Certificate_WithECDsaKeys()
    {
        using var keys = ECDsa.Create();
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Create();
        await Assert.That(cert1.GetKeyAlgorithm()).IsEqualTo(X9ObjectIdentifiers.IdECPublicKey.Id);

        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.ECDsa).Create();
        await Assert.That(cert2.GetKeyAlgorithm()).IsEqualTo(X9ObjectIdentifiers.IdECPublicKey.Id);
    }


    [Test]
    public async Task Build_Certificate_WithDSAKeys()
    {
        using var keys = DSA.Create(1024);
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Create();
        await Assert.That(cert1.GetKeyAlgorithm()).IsEqualTo(X9ObjectIdentifiers.IdDsa.Id);

#pragma warning disable CS0612 // Type or member is obsolete
        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.DSA).Create();
#pragma warning restore CS0612 // Type or member is obsolete
        await Assert.That(cert2.GetKeyAlgorithm()).IsEqualTo(X9ObjectIdentifiers.IdDsa.Id);
    }


    [Test]
    public async Task Build_RSACertificate_WithECDsaIssuer()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(now.AddHours(1))
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa)
            .Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(rootCA)
            .SetKeyAlgorithm(KeyAlgorithm.RSA)
            .Create();

        await Assert.That(cert.IsIssuedBy(rootCA, true)).IsTrue();
    }


    [Test]
    public async Task Build_ECDsaCertificate_WithRSAIssuer()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(now.AddHours(1))
            .SetKeyAlgorithm(KeyAlgorithm.RSA)
            .Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(rootCA)
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa)
            .Create();

        await Assert.That(cert.IsIssuedBy(rootCA, true)).IsTrue();
    }


    [Test]
    [SupportedOS(SupportedOS.Windows)]
    public async Task Build_CertificateOnWindows_WithFriendlyName()
    {
        const string friendlyName = "A FriendlyName can be set on Windows";

        using var cert1 = new CertificateBuilder().SetFriendlyName(friendlyName).Create();
        await Assert.That(cert1.FriendlyName).IsEqualTo(friendlyName);

        using var cert2 = new CertificateBuilder().SetFriendlyName(friendlyName).SetKeyStorageFlags(X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable).Create();
        await Assert.That(cert2.FriendlyName).IsEqualTo(friendlyName);
    }


    [Test]
    public async Task Build_InvalidKeyLength_ThrowsException()
    {
        await Assert.That(() => {
            using var cert = new CertificateBuilder().SetKeyLength(10).Create();
        }).Throws<Exception>();

        await Assert.That(() => {
            using var cert = new CertificateBuilder().SetKeyLength(0).Create();
        }).ThrowsExactly<ArgumentException>();

        await Assert.That(() => {
            using var cert = new CertificateBuilder().SetKeyLength(-1024).Create();
        }).ThrowsExactly<ArgumentException>();
    }


    [Test]
    public async Task Build_MinimalCertificate_IsValid()
    {
        using var cert = new CertificateBuilder().Create();

        await Assert.That(cert.Subject).IsEmpty();
        await Assert.That(cert.SerialNumberBytes.Length).IsEqualTo(18);
        await Assert.That(cert.IsValidNow()).IsTrue();
    }


    [Test]
    public async Task Build_RootCA_IsSelfSigned()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .Create();

        await Assert.That(rootCa.Extensions.OfType<X509BasicConstraintsExtension>()).Contains(x => x.CertificateAuthority);
        await Assert.That(rootCa.IsSelfSigned()).IsTrue();
    }


    [Test]
    public async Task Build_SubordinateCA_IsSignedByRoot()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(now.AddHours(1))
            .Create();

        using var subCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Subordinate CA Test"))
            .SetNotAfter(now.AddMinutes(1))
            .SetIssuer(rootCa)
            .Create();

        await Assert.That(rootCa.Extensions.OfType<X509BasicConstraintsExtension>()).Contains(x => x.CertificateAuthority);
        await Assert.That(subCa.IsIssuedBy(rootCa, true)).IsTrue();
    }


    [Test]
    public async Task Build_WebCertificate_IsValid()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(7))
            .Create();

        using var subCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Intermediate CA Test"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(6))
            .SetIssuer(rootCa)
            .Create();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetFriendlyName("FluentCertificates Server Test")
            .SetSubjectAlternativeNames(x => x.AddDnsNames("*.fake.domain", "fake.domain", "another.domain"))
            .SetSubject(x => x.SetCommonName("*.fake.domain"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .SetIssuer(subCa)
            .Create();

        await Assert.That(cert.IsValidNow()).IsTrue();
        await Assert.That(rootCa.IsIssuedBy(rootCa, true)).IsTrue();
        await Assert.That(subCa.IsIssuedBy(rootCa, true)).IsTrue();
        await Assert.That(cert.IsIssuedBy(subCa, true)).IsTrue();

        //Assert correct DNS names in the SAN
        var ext = cert.Extensions[X509Extensions.SubjectAlternativeName.Id];
        var san = EnumerateNamesFromSan(ext!).Where(x => x.TagNo == Org.BouncyCastle.Asn1.X509.GeneralName.DnsName).ToList();
        await Assert.That(san).Contains(x => x.Name.ToString() == "*.fake.domain");
        await Assert.That(san).Contains(x => x.Name.ToString() == "fake.domain");
        await Assert.That(san).Contains(x => x.Name.ToString() == "another.domain");
    }


    [Test]
    public async Task Build_CertificateSigningRequest_WithRSAKeys()
    {
        using var keys = RSA.Create();

        var csr = new CertificateBuilder()
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        await Assert.That(csr.GetRawData().IsEmpty).IsFalse();

        var cr = csr.CertificateRequest;
        var algorithm = csr.GetSignatureAlgorithm();
        var cri = csr.GetRequestData().ToArray();
        var sig = csr.GetSignatureData().ToArray();

        await Assert.That(algorithm).IsEqualTo(SignatureAlgorithm.SHA256RSA);
        await Assert.That(cr.PublicKey.GetRSAPublicKey()!.VerifyData(cri, sig, algorithm.HashAlgorithm, algorithm.RSASignaturePadding!)).IsTrue();
    }


    [Test]
    public async Task Build_CertificateSigningRequest_WithDSAKeys()
    {
        using var keys = DSA.Create();

        var csr = new CertificateBuilder()
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        await Assert.That(csr.GetRawData().IsEmpty).IsFalse();

        var cr = csr.CertificateRequest;
        var algorithm = csr.GetSignatureAlgorithm();
        var cri = csr.GetRequestData().ToArray();
        var sig = csr.GetSignatureData().ToArray();

#pragma warning disable CS0618 // Type or member is obsolete
        await Assert.That(algorithm).IsEqualTo(SignatureAlgorithm.SHA256DSA);
#pragma warning restore CS0618 // Type or member is obsolete
        await Assert.That(cr.PublicKey.GetDSAPublicKey()!.VerifyData(cri, sig, algorithm.HashAlgorithm, DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
    }


    [Test]
    public async Task Build_CertificateSigningRequest_WithECDsaKeys()
    {
        using var keys = ECDsa.Create();

        var csr = new CertificateBuilder()
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        await Assert.That(csr.GetRawData().IsEmpty).IsFalse();

        var cr = csr.CertificateRequest;
        var algorithm = csr.GetSignatureAlgorithm();
        var cri = csr.GetRequestData().ToArray();
        var sig = csr.GetSignatureData().ToArray();

        await Assert.That(algorithm).IsEqualTo(SignatureAlgorithm.SHA256ECDSA);
        await Assert.That(cr.PublicKey.GetECDsaPublicKey()!.VerifyData(cri, sig, algorithm.HashAlgorithm, DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
    }


    private static IEnumerable<Org.BouncyCastle.Asn1.X509.GeneralName> EnumerateNamesFromSan(X509Extension extension)
        => Asn1Sequence
            .GetInstance(extension.ConvertToBouncyCastle().GetParsedValue())
            .Select(Org.BouncyCastle.Asn1.X509.GeneralName.GetInstance);
}
