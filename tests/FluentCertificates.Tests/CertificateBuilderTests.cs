using System;

using FluentCertificates.Extensions;

using Xunit;

namespace FluentCertificates.Tests;

public class CertificateBuilderTests
{
    [Fact]
    public void Minimal_Build_Returns_Certificate()
    {
        using var cert = new CertificateBuilder().Build();
        Assert.NotNull(cert);
    }


    [Fact]
    public void Build_Requires_Positive_KeyLength()
    {
        Assert.Throws<ArgumentException>(nameof(CertificateBuilder.KeyLength), () => new CertificateBuilder().SetKeyLength(0).Build());
        Assert.Throws<ArgumentException>(nameof(CertificateBuilder.KeyLength), () => new CertificateBuilder().SetKeyLength(-1024).Build());
    }
}