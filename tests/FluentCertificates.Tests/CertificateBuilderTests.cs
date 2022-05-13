using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Extensions;

using Xunit;

namespace FluentCertificates.Tests;

public class CertificateBuilderTests
{
    [Fact]
    public void Build_InvalidKeyLength_ThrowsException()
    {
        Assert.ThrowsAny<Exception>(() => new CertificateBuilder().SetKeyLength(10).Build());
        Assert.Throws<ArgumentException>(nameof(CertificateBuilder.KeyLength), () => new CertificateBuilder().SetKeyLength(0).Build());
        Assert.Throws<ArgumentException>(nameof(CertificateBuilder.KeyLength), () => new CertificateBuilder().SetKeyLength(-1024).Build());
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
        Assert.Equal(rootCert.SubjectName.RawData, rootCert.IssuerName.RawData);
    }


    [Fact]
    public void Build_SubordinateCA_IsSignedByRoot()
    {
        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(new X509NameBuilder().SetCommonName("Test Root CA"))
            .Build();

        using var subCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(new X509NameBuilder().SetCommonName("Test Subordinate CA 1"))
            .SetIssuer(rootCA)
            .Build();

        Assert.Contains(rootCA.Extensions.OfType<X509BasicConstraintsExtension>(), x => x.CertificateAuthority);
        Assert.Equal(rootCA.SubjectName.RawData, subCA.IssuerName.RawData);
        Assert.True(subCA.VerifyIssuerSignature(rootCA));
    }
}