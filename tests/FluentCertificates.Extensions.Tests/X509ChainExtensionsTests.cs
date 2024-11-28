namespace FluentCertificates;

public class X509ChainExtensionsTests
{
    [Fact]
    public void ToEnumerable_ReversesChainOrder_PutsLeafCertLast()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(3))
            .SetSubject("CN=RootCA")
            .Create();

        using var subCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(2))
            .SetIssuer(rootCa)
            .SetSubject("CN=SubCA")
            .Create();

        using var cert = new CertificateBuilder()
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .SetIssuer(subCa)
            .SetSubject("CN=Leaf")
            .Create();

        using var chain = cert.BuildChain([subCa, rootCa], true);

        var expected = new[] { rootCa, subCa, cert };

        Assert.Equal(expected, chain.ToEnumerable());
        Assert.Equal(expected, chain.ToCollection().ToEnumerable());
    }
}