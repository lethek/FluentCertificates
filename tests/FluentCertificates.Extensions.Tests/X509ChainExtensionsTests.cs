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


    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task BuildChain_PlacesExtraCertsAccordingToCustomRootTrust(bool customRootTrust)
    {
        using var rootCa = BuildRootCa();
        using var cert = BuildLeaf(rootCa);

        var (_, chain) = cert.BuildChain([rootCa], customRootTrust);
        using var _chain = chain;

        var comparer = EqualityComparer<X509Certificate2>.Default;
        var expectedTrustMode = customRootTrust ? X509ChainTrustMode.CustomRootTrust : X509ChainTrustMode.System;
        var populated = customRootTrust ? chain.ChainPolicy.CustomTrustStore : chain.ChainPolicy.ExtraStore;
        var empty = customRootTrust ? chain.ChainPolicy.ExtraStore : chain.ChainPolicy.CustomTrustStore;

        await Assert.That(chain.ChainPolicy.TrustMode).IsEqualTo(expectedTrustMode);
        await Assert.That(populated).IsEquivalentTo(new[] { rootCa }, comparer);
        await Assert.That(empty).IsEmpty();

        //Revocation is off by default on both overloads, so a chain build never reaches the network
        await Assert.That(chain.ChainPolicy.RevocationMode).IsEqualTo(X509RevocationMode.NoCheck);
    }


    [Test]
    public async Task BuildChain_WithPolicyAction_CanEstablishCustomRootTrust()
    {
        using var rootCa = BuildRootCa();
        using var cert = BuildLeaf(rootCa);

        //A self-signed root is not in the machine's trust store, so this only verifies if the policy says so
        var (unTrusted, chain1) = cert.BuildChain(_ => { });
        using var _chain1 = chain1;

        var (trusted, chain2) = cert.BuildChain(policy => {
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            policy.CustomTrustStore.Add(rootCa);
        });
        using var _chain2 = chain2;

        await Assert.That(unTrusted).IsFalse();
        await Assert.That(trusted).IsTrue();
    }


    [Test]
    public async Task BuildChain_WithPolicyAction_DefaultsToNoRevocationButLetsTheActionOverrideIt()
    {
        using var rootCa = BuildRootCa();
        using var cert = BuildLeaf(rootCa);

        X509RevocationMode observed = default;
        var (_, chain) = cert.BuildChain(policy => {
            observed = policy.RevocationMode;
            policy.RevocationMode = X509RevocationMode.Offline;
        });
        using var _chain = chain;

        //The action sees NoCheck rather than the framework's Online default, and its own change sticks
        await Assert.That(observed).IsEqualTo(X509RevocationMode.NoCheck);
        await Assert.That(chain.ChainPolicy.RevocationMode).IsEqualTo(X509RevocationMode.Offline);
    }


    [Test]
    public async Task BuildChain_WithNullPolicyAction_Throws()
    {
        using var cert = BuildRootCa();

        await Assert
            .That(() => cert.BuildChain((Action<X509ChainPolicy>)null!))
            .ThrowsExactly<ArgumentNullException>();
    }


    [Test]
    public async Task BuildChain_WithNoArguments_StillResolvesToTheExtraCertsOverload()
    {
        //Guards against the policy overload making the parameterless call ambiguous
        using var cert = BuildRootCa();

        var (_, chain) = cert.BuildChain();
        using var _chain = chain;

        await Assert.That(chain.ChainPolicy.TrustMode).IsEqualTo(X509ChainTrustMode.System);
        await Assert.That(chain.ChainPolicy.ExtraStore).IsEmpty();
    }


    private static X509Certificate2 BuildRootCa()
        => new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(3))
            .SetSubject("CN=RootCA")
            .Create();


    private static X509Certificate2 BuildLeaf(X509Certificate2 issuer)
        => new CertificateBuilder()
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .SetIssuer(issuer)
            .SetSubject("CN=Leaf")
            .Create();
}
