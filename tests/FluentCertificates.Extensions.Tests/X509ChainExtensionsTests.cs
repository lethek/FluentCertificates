using System.Security.Cryptography.X509Certificates;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class X509ChainExtensionsTests
{
    [Test]
    public async Task ToEnumerable_ReversesChainOrder_PutsLeafCertLast()
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

        var chainResult = cert.BuildChain([subCa, rootCa], true);
        using var chain = chainResult.Chain;

        var expected = new[] { rootCa, subCa, cert };

        //TUnit's IsEquivalentTo compares members structurally by default, which trips over the
        //differing native Handle of each X509Certificate2; compare by value instead.
        var comparer = EqualityComparer<X509Certificate2>.Default;

        await Assert.That(chainResult.Verified).IsTrue();
        await Assert.That(chain.ToEnumerable()).IsEquivalentTo(expected, comparer, CollectionOrdering.Matching);
        await Assert.That(chain.ToCollection().ToEnumerable()).IsEquivalentTo(expected, comparer, CollectionOrdering.Matching);
    }
}
