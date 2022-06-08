using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Extensions;
using FluentCertificates.Internals;
using FluentCertificates.Tests.Fixtures;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;

using Xunit;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace FluentCertificates.Tests;

public class CertificateBuilderTests : IClassFixture<CertificateTestingFixture>
{
    public CertificateBuilderTests(CertificateTestingFixture fixture)
        => Fixture = fixture;


    [Fact]
    public void Build_NewCertificate_HasPrivateKey()
    {
        var cert = new CertificateBuilder().Build();
        Assert.True(cert.HasPrivateKey);
    }


    [Fact]
    public void Build_NewCertificate_WithRSAKeys()
    {
        var keys = RSA.Create();
        var cert = new CertificateBuilder().SetKeyPair(keys).Build();
        Assert.Equal(PkcsObjectIdentifiers.RsaEncryption.Id, cert.GetKeyAlgorithm());
    }


    [Fact]
    public void Build_NewCertificate_WithECDsaKeys()
    {
        var keys = ECDsa.Create();
        var cert = new CertificateBuilder().SetKeyPair(keys).Build();
        Assert.Equal(X9ObjectIdentifiers.IdECPublicKey.Id, cert.GetKeyAlgorithm());
    }


    [Fact]
    public void Build_NewCertificate_WithDSAKeys()
    {
        //NOTE: FluentCertificates does not currently support creating DSA certificates on .NET 5 or earlier
        
        #if NET6_0_OR_GREATER
        var cert = new CertificateBuilder().GenerateKeyPair(KeyAlgorithm.DSA).Build();
        Assert.Equal(X9ObjectIdentifiers.IdDsa.Id, cert.GetKeyAlgorithm());
        #else
        Assert.Throws<NotImplementedException>(() => CertificateBuilder.Create().GenerateKeyPair(KeyAlgorithm.DSA).Build());
        #endif
    }


    [Fact]
    public void Build_NewRSACertificate_WithECDsaIssuer()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(new X509NameBuilder().SetCommonName("Test Root CA"))
            .SetNotAfter(now.AddHours(1))
            .GenerateKeyPair(KeyAlgorithm.ECDsa)
            .Build();

        using var cert = new CertificateBuilder()
            .SetIssuer(rootCA)
            .GenerateKeyPair(KeyAlgorithm.RSA)
            .Build();

        Assert.True(cert.IsIssuedBy(rootCA));
        Assert.True(cert.VerifyIssuer(rootCA));
    }


    [Fact]
    public void Build_NewECDsaCertificate_WithRSAIssuer()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(new X509NameBuilder().SetCommonName("Test Root CA"))
            .SetNotAfter(now.AddHours(1))
            .GenerateKeyPair(KeyAlgorithm.RSA)
            .Build();

        using var cert = new CertificateBuilder()
            .SetIssuer(rootCA)
            .GenerateKeyPair(KeyAlgorithm.ECDsa)
            .Build();

        Assert.True(cert.IsIssuedBy(rootCA));
        Assert.True(cert.VerifyIssuer(rootCA));
    }


    [SkippableFact]
    public void Build_CertificateOnWindows_WithFriendlyName()
    {
        Skip.IfNot(Tools.IsWindows);

        const string friendlyName = "A FriendlyName can be set on Windows";
        var cert = new CertificateBuilder().SetFriendlyName(friendlyName).Build();
        Assert.Equal(friendlyName, cert.FriendlyName);
    }


    [Fact]
    public void Build_InvalidKeyLength_ThrowsException()
    {
        Assert.ThrowsAny<Exception>(() => new CertificateBuilder().SetKeyLength(10).Build());
        Assert.Throws<ArgumentException>(() => new CertificateBuilder().SetKeyLength(0).Build());
        Assert.Throws<ArgumentException>(() => new CertificateBuilder().SetKeyLength(-1024).Build());
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
        using var rootCert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(new X509NameBuilder().SetCommonName("Test Root CA"))
            .Build();

        Assert.Contains(rootCert.Extensions.OfType<X509BasicConstraintsExtension>(), x => x.CertificateAuthority);
        Assert.True(rootCert.IsSelfSigned());
    }


    [Fact]
    public void Build_SubordinateCA_IsSignedByRoot()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(new X509NameBuilder().SetCommonName("Test Root CA"))
            .SetNotAfter(now.AddHours(1))
            .Build();

        using var subCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(new X509NameBuilder().SetCommonName("Test Subordinate CA 1"))
            .SetNotAfter(now.AddMinutes(1))
            .SetIssuer(rootCA)
            .Build();

        Assert.Contains(rootCA.Extensions.OfType<X509BasicConstraintsExtension>(), x => x.CertificateAuthority);
        Assert.True(subCA.IsIssuedBy(rootCA));
        Assert.True(subCA.VerifyIssuer(rootCA));
    }

    
    [Fact]
    public void Build_WebCertificate_IsValid()
    {
        var issuer = Fixture.IntermediateCA;

        var cert = CertificateBuilder.Create()
            .SetUsage(CertificateUsage.Server)
            .SetFriendlyName("FluentCertificates Test Server")
            .SetDnsNames("*.fake.domain", "fake.domain", "another.domain")
            .SetSubject(new X509NameBuilder().SetCommonName("*.fake.domain"))
            .SetIssuer(issuer)
            .Build();

        Assert.True(cert.IsValidNow());
        Assert.True(cert.VerifyIssuer(issuer));

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


    private CertificateTestingFixture Fixture { get; }
}