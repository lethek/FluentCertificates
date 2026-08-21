using System.Security.Cryptography.X509Certificates;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class X509ChainExtensionsTests
{
    [Test]
    public async Task ToEnumerable_KeepsChainOrder_PutsLeafCertFirst()
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

        using var chainResult = cert.BuildChain().TrustRoot(subCa, rootCa).Create();
        var chain = chainResult.Chain;

        var expected = new[] { cert, subCa, rootCa };

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

        var builder = cert.BuildChain();
        builder = customRootTrust ? builder.TrustRoot(rootCa) : builder.AddCertificates(rootCa);
        using var result = builder.Create();
        var chain = result.Chain;

        var comparer = EqualityComparer<X509Certificate2>.Default;
        var expectedTrustMode = customRootTrust ? X509ChainTrustMode.CustomRootTrust : X509ChainTrustMode.System;
        var populated = customRootTrust ? chain.ChainPolicy.CustomTrustStore : chain.ChainPolicy.ExtraStore;
        var empty = customRootTrust ? chain.ChainPolicy.ExtraStore : chain.ChainPolicy.CustomTrustStore;

        await Assert.That(chain.ChainPolicy.TrustMode).IsEqualTo(expectedTrustMode);
        await Assert.That(populated).IsEquivalentTo([rootCa], comparer);
        await Assert.That(empty).IsEmpty();

        //Revocation is off by default, so a chain build never reaches the network
        await Assert.That(chain.ChainPolicy.RevocationMode).IsEqualTo(X509RevocationMode.NoCheck);
    }


    [Test]
    public async Task BuildChain_WithPolicyAction_CanEstablishCustomRootTrust()
    {
        using var rootCa = BuildRootCa();
        using var cert = BuildLeaf(rootCa);

        //A self-signed root is not in the machine's trust store, so this only verifies if the policy says so
        using var unTrusted = cert.BuildChain().Create();

        using var trusted = cert.BuildChain()
            .WithPolicy(policy => {
                policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                policy.CustomTrustStore.Add(rootCa);
            })
            .Create();

        await Assert.That(unTrusted.Verified).IsFalse();
        await Assert.That(trusted.Verified).IsTrue();
    }


    [Test]
    public async Task BuildChain_WithPolicyAction_DefaultsToNoRevocationButLetsTheActionOverrideIt()
    {
        using var rootCa = BuildRootCa();
        using var cert = BuildLeaf(rootCa);

        X509RevocationMode observed = default;
        using var result = cert.BuildChain()
            .WithPolicy(policy => {
                observed = policy.RevocationMode;
                policy.RevocationMode = X509RevocationMode.Offline;
            })
            .Create();

        //The action sees NoCheck rather than the framework's Online default, and its own change sticks
        await Assert.That(observed).IsEqualTo(X509RevocationMode.NoCheck);
        await Assert.That(result.Chain.ChainPolicy.RevocationMode).IsEqualTo(X509RevocationMode.Offline);
    }


    [Test]
    public async Task BuildChain_WithNullCertificate_Throws()
        => await Assert
            .That(() => X509Certificate2Extensions.BuildChain(null!))
            .ThrowsExactly<ArgumentNullException>();


    [Test]
    public async Task BuildChain_ReturnsBuilderForTheCertificate()
    {
        using var cert = BuildRootCa();

        var builder = cert.BuildChain();

        await Assert.That(builder.Certificate).IsSameReferenceAs(cert);
        await Assert.That(builder.TrustedRoots).IsEmpty();
        await Assert.That(builder.ExtraCertificates).IsEmpty();

        //An unconfigured builder must seed neither store
        using var result = builder.Create();
        await Assert.That(result.Chain.ChainPolicy.TrustMode).IsEqualTo(X509ChainTrustMode.System);
        await Assert.That(result.Chain.ChainPolicy.ExtraStore.Count).IsEqualTo(0);
    }


    [Test]
    public async Task IsIssuedBy_VerifiesRepeatedly_AndLeavesBothCertificatesUsable()
    {
        using var rootCa = BuildRootCa();
        using var cert = BuildLeaf(rootCa);

        //Signature verification extracts and releases the issuer's public key on every call
        await Assert.That(cert.IsIssuedBy(rootCa, true)).IsTrue();
        await Assert.That(cert.IsIssuedBy(rootCa, true)).IsTrue();
        await Assert.That(cert.IsIssuedBy(rootCa, true)).IsTrue();

        using var rootKey = rootCa.GetPrivateKey();
        await Assert.That(rootKey.ExportSubjectPublicKeyInfo()).IsEquivalentTo(rootCa.PublicKey.ExportSubjectPublicKeyInfo());
    }


    [Test]
    public async Task ExportPem_WithPrivateKey_IsRepeatableAndLeavesTheCertificateUsable()
    {
        using var cert = BuildRootCa();

        //The PEM exporter extracts and releases a private key per certificate it writes
        var first = cert.Export().WithPrivateKey().AsPem().ToPemString();
        var second = cert.Export().WithPrivateKey().AsPem().ToPemString();

        await Assert.That(first).IsEqualTo(second);
        await Assert.That(first).Contains("PRIVATE KEY");

        using var key = cert.GetPrivateKey();
        await Assert.That(key.ExportSubjectPublicKeyInfo()).IsEquivalentTo(cert.PublicKey.ExportSubjectPublicKeyInfo());
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
