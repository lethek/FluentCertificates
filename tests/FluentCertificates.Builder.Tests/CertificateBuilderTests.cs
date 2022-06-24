using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;

using Xunit;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

public class CertificateBuilderTests
{
    [Fact]
    public void Build_NewCertificate_HasPrivateKey()
    {
        using var cert = new CertificateBuilder().Build();
        Assert.True(cert.HasPrivateKey);
    }


    [Fact]
    public void Build_NewCertificate_WithSubject()
    {
        const string testName = nameof(Build_NewCertificate_WithSubject);
        const string expected = $"CN={testName}";

        //Test several different, equivalent ways of setting the Subject

        using var cert1 = new CertificateBuilder().SetSubject(b => b.SetCommonName(testName)).Build();
        Assert.Equal(expected, cert1.Subject);

        using var cert2 = new CertificateBuilder().SetSubject(new X500NameBuilder().SetCommonName(testName)).Build();
        Assert.Equal(expected, cert2.Subject);

        using var cert3 = new CertificateBuilder().SetSubject(new X500DistinguishedName(expected)).Build();
        Assert.Equal(expected, cert3.Subject);

        using var cert4 = new CertificateBuilder().SetSubject(new X509Name(expected)).Build();
        Assert.Equal(expected, cert4.Subject);

        using var cert5 = new CertificateBuilder().SetSubject(expected).Build();
        Assert.Equal(expected, cert5.Subject);

        using var cert6 = new CertificateBuilder {Subject = new X500NameBuilder(expected)}.Build();
        Assert.Equal(expected, cert6.Subject);
    }


    [Fact]
    public void Build_NewCertificate_WithRSAKeys()
    {
        using var keys = RSA.Create();
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Build();
        Assert.Equal(PkcsObjectIdentifiers.RsaEncryption.Id, cert1.GetKeyAlgorithm());

        using var cert2 = new CertificateBuilder().GenerateKeyPair(KeyAlgorithm.RSA).Build();
        Assert.Equal(PkcsObjectIdentifiers.RsaEncryption.Id, cert2.GetKeyAlgorithm());
    }


    [Fact]
    public void Build_NewCertificate_WithECDsaKeys()
    {
        using var keys = ECDsa.Create();
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Build();
        Assert.Equal(X9ObjectIdentifiers.IdECPublicKey.Id, cert1.GetKeyAlgorithm());

        using var cert2 = new CertificateBuilder().GenerateKeyPair(KeyAlgorithm.ECDsa).Build();
        Assert.Equal(X9ObjectIdentifiers.IdECPublicKey.Id, cert2.GetKeyAlgorithm());
    }


    [Fact]
    public void Build_NewCertificate_WithDSAKeys()
    {
        using var keys = DSA.Create(1024);
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Build();
        Assert.Equal(X9ObjectIdentifiers.IdDsa.Id, cert1.GetKeyAlgorithm());

        using var cert2 = new CertificateBuilder().GenerateKeyPair(KeyAlgorithm.DSA).Build();
        Assert.Equal(X9ObjectIdentifiers.IdDsa.Id, cert2.GetKeyAlgorithm());
    }


    [Fact]
    public void Build_NewRSACertificate_WithECDsaIssuer()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(now.AddHours(1))
            .GenerateKeyPair(KeyAlgorithm.ECDsa)
            .Build();

        using var cert = new CertificateBuilder()
            .SetIssuer(rootCA)
            .GenerateKeyPair(KeyAlgorithm.RSA)
            .Build();

        Assert.True(cert.IsIssuedBy(rootCA, true));
    }


    [Fact]
    public void Build_NewECDsaCertificate_WithRSAIssuer()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(now.AddHours(1))
            .GenerateKeyPair(KeyAlgorithm.RSA)
            .Build();

        using var cert = new CertificateBuilder()
            .SetIssuer(rootCA)
            .GenerateKeyPair(KeyAlgorithm.ECDsa)
            .Build();

        Assert.True(cert.IsIssuedBy(rootCA, true));
    }


    [SkippableFact]
    public void Build_CertificateOnWindows_WithFriendlyName()
    {
        Skip.IfNot(Tools.IsWindows);

        const string friendlyName = "A FriendlyName can be set on Windows";
        using var cert = new CertificateBuilder().SetFriendlyName(friendlyName).Build();
        Assert.Equal(friendlyName, cert.FriendlyName);
    }


    [Fact]
    public void Build_InvalidKeyLength_ThrowsException()
    {
        Assert.ThrowsAny<Exception>(() => {
            using var cert = new CertificateBuilder().SetKeyLength(10).Build();
        });
        Assert.Throws<ArgumentException>(() => {
            using var cert = new CertificateBuilder().SetKeyLength(0).Build();
        });
        Assert.Throws<ArgumentException>(() => {
            using var cert = new CertificateBuilder().SetKeyLength(-1024).Build();
        });
    }


    [Fact]
    public void Build_MinimalCertificate_IsValid()
    {
        using var cert = new CertificateBuilder().Build();

        Assert.NotNull(cert);
        Assert.True(cert.IsValidNow());
    }


    [Fact]
    public void Build_RootCA_IsSelfSigned()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .Build();

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
            .Build();

        using var subCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Subordinate CA Test"))
            .SetNotAfter(now.AddMinutes(1))
            .SetIssuer(rootCa)
            .Build();

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
            .Build();

        using var subCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Intermediate CA Test"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(6))
            .SetIssuer(rootCa)
            .Build();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetFriendlyName("FluentCertificates Server Test")
            .SetDnsNames("*.fake.domain", "fake.domain", "another.domain")
            .SetSubject(x => x.SetCommonName("*.fake.domain"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .SetIssuer(subCa)
            .Build();

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


    private static IEnumerable<GeneralName> EnumerateNamesFromSAN(X509Extension extension)
        => Asn1Sequence
            .GetInstance(extension.ConvertToBouncyCastle().GetParsedValue())
            .Cast<Asn1Encodable>()
            .Select(GeneralName.GetInstance);
}