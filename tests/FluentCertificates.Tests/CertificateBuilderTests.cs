using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Extensions;
using FluentCertificates.Internals;
using FluentCertificates.Tests.Fixtures;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

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