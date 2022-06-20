using System;

using Xunit;


namespace FluentCertificates.Extensions;

public class X509ChainExtensionsTests
{
    [Fact]
    public void ToEnumerable_ReversesChainOrder_PutsLeafCertLast()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(3))
            .SetSubject("CN=RootCA")
            .Build();

        using var subCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(2))
            .SetIssuer(rootCa)
            .SetSubject("CN=SubCA")
            .Build();

        using var cert = new CertificateBuilder()
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .SetIssuer(subCa)
            .SetSubject("CN=Leaf")
            .Build();

        using var chain = cert.BuildChain(new[] { subCa, rootCa }, true);

        var expected = new[] { rootCa, subCa, cert };

        Assert.Equal(expected, chain.ToEnumerable());
        Assert.Equal(expected, chain.ToCollection().ToEnumerable());
    }
}