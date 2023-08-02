using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;

using Xunit.Abstractions;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

public class CertificateBuilderTests
{
    public CertificateBuilderTests(ITestOutputHelper outputHelper)
        => OutputHelper = outputHelper;


    [Fact]
    public void Build_Certificate_HasPrivateKey()
    {
        using var cert = new CertificateBuilder().Create();
        Assert.True(cert.HasPrivateKey);
    }


    [Fact]
    public void Build_Certificate_WithSubject()
    {
        const string testName = nameof(Build_Certificate_WithSubject);
        const string expected = $"CN={testName}";

        //Test several different, equivalent ways of setting the Subject

        using var cert1 = new CertificateBuilder().SetSubject(b => b.SetCommonName(testName)).Create();
        Assert.Equal(expected, cert1.Subject);

        using var cert2 = new CertificateBuilder().SetSubject(new X500NameBuilder().SetCommonName(testName)).Create();
        Assert.Equal(expected, cert2.Subject);

        using var cert3 = new CertificateBuilder().SetSubject(new X500DistinguishedName(expected)).Create();
        Assert.Equal(expected, cert3.Subject);

        using var cert4 = new CertificateBuilder().SetSubject(new X509Name(expected)).Create();
        Assert.Equal(expected, cert4.Subject);

        using var cert5 = new CertificateBuilder().SetSubject(expected).Create();
        Assert.Equal(expected, cert5.Subject);

        using var cert6 = new CertificateBuilder {Subject = new X500NameBuilder(expected)}.Create();
        Assert.Equal(expected, cert6.Subject);
    }


    [Fact]
    public void Build_Certificate_WithRSAKeys()
    {
        using var keys = RSA.Create();
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Create();
        Assert.Equal(PkcsObjectIdentifiers.RsaEncryption.Id, cert1.GetKeyAlgorithm());

        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.RSA).Create();
        Assert.Equal(PkcsObjectIdentifiers.RsaEncryption.Id, cert2.GetKeyAlgorithm());
    }


    [Fact]
    public void Build_Certificate_WithECDsaKeys()
    {
        using var keys = ECDsa.Create();
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Create();
        Assert.Equal(X9ObjectIdentifiers.IdECPublicKey.Id, cert1.GetKeyAlgorithm());

        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.ECDsa).Create();
        Assert.Equal(X9ObjectIdentifiers.IdECPublicKey.Id, cert2.GetKeyAlgorithm());
    }


    [Fact]
    public void Build_Certificate_WithDSAKeys()
    {
        using var keys = DSA.Create(1024);
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Create();
        Assert.Equal(X9ObjectIdentifiers.IdDsa.Id, cert1.GetKeyAlgorithm());

        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.DSA).Create();
        Assert.Equal(X9ObjectIdentifiers.IdDsa.Id, cert2.GetKeyAlgorithm());
    }


    [Fact]
    public void Build_RSACertificate_WithECDsaIssuer()
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

        Assert.True(cert.IsIssuedBy(rootCA, true));
    }


    [Fact]
    public void Build_ECDsaCertificate_WithRSAIssuer()
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

        Assert.True(cert.IsIssuedBy(rootCA, true));
    }


    [SkippableFact]
    public void Build_CertificateOnWindows_WithFriendlyName()
    {
        Skip.IfNot(Tools.IsWindows);

        const string friendlyName = "A FriendlyName can be set on Windows";
        using var cert = new CertificateBuilder().SetFriendlyName(friendlyName).Create();
        Assert.Equal(friendlyName, cert.FriendlyName);
    }


    [Fact]
    public void Build_InvalidKeyLength_ThrowsException()
    {
        Assert.ThrowsAny<Exception>(() => {
            using var cert = new CertificateBuilder().SetKeyLength(10).Create();
        });
        Assert.Throws<ArgumentException>(() => {
            using var cert = new CertificateBuilder().SetKeyLength(0).Create();
        });
        Assert.Throws<ArgumentException>(() => {
            using var cert = new CertificateBuilder().SetKeyLength(-1024).Create();
        });
    }


    [Fact]
    public void Build_MinimalCertificate_IsValid()
    {
        using var cert = new CertificateBuilder().Create();

        Assert.NotNull(cert);
        Assert.True(cert.IsValidNow());
    }


    [Fact]
    public void Build_RootCA_IsSelfSigned()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .Create();

        Assert.Contains(rootCa.Extensions.OfType<X509BasicConstraintsExtension>(), x => x.CertificateAuthority);
        Assert.True(rootCa.IsSelfSigned());
    }


    [Fact]
    public void Build_SubordinateCA_IsSignedByRoot()
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

        Assert.Contains(rootCa.Extensions.OfType<X509BasicConstraintsExtension>(), x => x.CertificateAuthority);
        Assert.True(subCa.IsIssuedBy(rootCa, true));
    }


    [Fact]
    public void Build_WebCertificate_IsValid()
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
            .SetDnsNames("*.fake.domain", "fake.domain", "another.domain")
            .SetSubject(x => x.SetCommonName("*.fake.domain"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .SetIssuer(subCa)
            .Create();

        Assert.True(cert.IsValidNow());
        Assert.True(rootCa.IsIssuedBy(rootCa, true));
        Assert.True(subCa.IsIssuedBy(rootCa, true));
        Assert.True(cert.IsIssuedBy(subCa, true));

        //Assert correct DNS names in the SAN
        var ext = cert.Extensions[X509Extensions.SubjectAlternativeName.Id];
        var san = EnumerateNamesFromSAN(ext!).Where(x => x.TagNo == GeneralName.DnsName).ToList();
        Assert.Contains(san, x => x.Name.ToString() == "*.fake.domain");
        Assert.Contains(san, x => x.Name.ToString() == "fake.domain");
        Assert.Contains(san, x => x.Name.ToString() == "another.domain");
    }


    [Fact]
    public void Build_CertificateSigningRequest_WithRSAKeys()
    {
        using var keys = RSA.Create();

        var csr = new CertificateBuilder()
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        Assert.False(csr.GetRawData().IsEmpty);
        
        var cr = csr.CertificateRequest;
        var algorithm = csr.GetSignatureAlgorithm();
        var cri = csr.GetRequestData().Span;
        var sig = csr.GetSignatureData().Span;

        Assert.Equal(SignatureAlgorithm.SHA256RSA, algorithm);
        Assert.True(cr.PublicKey.GetRSAPublicKey()!.VerifyData(cri, sig, algorithm.HashAlgorithm, algorithm.RSASignaturePadding!));
    }


    [Fact]
    public void Build_CertificateSigningRequest_WithDSAKeys()
    {
        using var keys = DSA.Create();

        var csr = new CertificateBuilder()
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        Assert.False(csr.GetRawData().IsEmpty);

        var cr = csr.CertificateRequest;
        var algorithm = csr.GetSignatureAlgorithm();
        var cri = csr.GetRequestData().Span;
        var sig = csr.GetSignatureData().Span;
        
        Assert.Equal(SignatureAlgorithm.SHA256DSA, algorithm);
        Assert.True(cr.PublicKey.GetDSAPublicKey()!.VerifyData(cri, sig, algorithm.HashAlgorithm, DSASignatureFormat.Rfc3279DerSequence));
    }


    [Fact]
    public void Build_CertificateSigningRequest_WithECDsaKeys()
    {
        using var keys = ECDsa.Create();

        var csr = new CertificateBuilder()
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        Assert.False(csr.GetRawData().IsEmpty);

        var cr = csr.CertificateRequest;
        var algorithm = csr.GetSignatureAlgorithm();
        var cri = csr.GetRequestData().Span;
        var sig = csr.GetSignatureData().Span;

        Assert.Equal(SignatureAlgorithm.SHA256ECDSA, algorithm);
        Assert.True(cr.PublicKey.GetECDsaPublicKey()!.VerifyData(cri, sig, algorithm.HashAlgorithm, DSASignatureFormat.Rfc3279DerSequence));
    }


    private readonly ITestOutputHelper OutputHelper;


    private static IEnumerable<GeneralName> EnumerateNamesFromSAN(X509Extension extension)
        => Asn1Sequence
            .GetInstance(extension.ConvertToBouncyCastle().GetParsedValue())
            .Cast<Asn1Encodable>()
            .Select(GeneralName.GetInstance);
}