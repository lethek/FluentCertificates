using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public class X509ChainBuilderTests
{
    private static X509Certificate2 BuildRootCa(int daysValid = 3)
        => new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(daysValid))
            .SetSubject("CN=RootCA")
            .Create();

    private static X509Certificate2 BuildIntermediate(X509Certificate2 issuer, int daysValid = 2)
        => new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(daysValid))
            .SetIssuer(issuer)
            .SetSubject("CN=SubCA")
            .Create();

    private static X509Certificate2 BuildLeaf(X509Certificate2 issuer, int daysValid = 1)
        => new CertificateBuilder()
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(daysValid))
            .SetIssuer(issuer)
            .SetSubject("CN=Leaf")
            .Create();


    [Test]
    public async Task Create_WithTrustedRootAndIntermediate_Verifies()
    {
        using var root = BuildRootCa();
        using var mid = BuildIntermediate(root);
        using var leaf = BuildLeaf(mid);

        using var result = new X509ChainBuilder(leaf).TrustRoot(root).AddCertificates(mid).Create();

        await Assert.That(result.Verified).IsTrue();
        await Assert.That(result.Chain.ChainElements.Count).IsEqualTo(3);
    }


    [Test]
    public async Task TrustRoot_SetsCustomRootTrustAndPopulatesCustomTrustStore()
    {
        using var root = BuildRootCa();
        using var leaf = BuildLeaf(root);

        using var result = new X509ChainBuilder(leaf).TrustRoot(root).Create();

        await Assert.That(result.Chain.ChainPolicy.TrustMode).IsEqualTo(X509ChainTrustMode.CustomRootTrust);
        await Assert.That(result.Chain.ChainPolicy.CustomTrustStore.Contains(root)).IsTrue();
    }


    [Test]
    public async Task TrustRoot_NeverCalled_UsesSystemTrust()
    {
        using var root = BuildRootCa();
        using var leaf = BuildLeaf(root);

        using var result = new X509ChainBuilder(leaf).AddCertificates(root).Create();

        await Assert.That(result.Chain.ChainPolicy.TrustMode).IsEqualTo(X509ChainTrustMode.System);
        //A private root is not in the system store, so this must not verify
        await Assert.That(result.Verified).IsFalse();
    }


    [Test]
    public async Task AddCertificates_PopulatesExtraStore()
    {
        using var root = BuildRootCa();
        using var mid = BuildIntermediate(root);
        using var leaf = BuildLeaf(mid);

        using var result = new X509ChainBuilder(leaf).TrustRoot(root).AddCertificates(mid).Create();

        await Assert.That(result.Chain.ChainPolicy.ExtraStore.Contains(mid)).IsTrue();
    }


    [Test]
    public async Task Create_MissingIntermediate_ReportsPartialChainWithoutThrowing()
    {
        using var root = BuildRootCa();
        using var mid = BuildIntermediate(root);
        using var leaf = BuildLeaf(mid);

        //mid is deliberately absent
        using var result = new X509ChainBuilder(leaf).TrustRoot(root).Create();

        await Assert.That(result.Verified).IsFalse();
        await Assert.That(result.ChainStatus.Select(x => x.Status)).Contains(X509ChainStatusFlags.PartialChain);
    }


    [Test]
    public async Task EnsureVerified_OnFailure_ThrowsNamingTheStatus()
    {
        using var root = BuildRootCa();
        using var mid = BuildIntermediate(root);
        using var leaf = BuildLeaf(mid);

        using var result = new X509ChainBuilder(leaf).TrustRoot(root).Create();

        var ex = await Assert.That(() => result.EnsureVerified()).Throws<CryptographicException>();
        await Assert.That(ex!.Message).Contains("PartialChain");
    }


    [Test]
    public async Task EnsureVerified_OnSuccess_ReturnsSameInstance()
    {
        using var root = BuildRootCa();
        using var leaf = BuildLeaf(root);

        using var result = new X509ChainBuilder(leaf).TrustRoot(root).Create();

        await Assert.That(result.EnsureVerified()).IsSameReferenceAs(result);
    }


    [Test]
    public async Task Builder_IsImmutable()
    {
        using var root = BuildRootCa();
        using var leaf = BuildLeaf(root);

        var builder = new X509ChainBuilder(leaf);
        var withRoot = builder.TrustRoot(root);

        await Assert.That(ReferenceEquals(builder, withRoot)).IsFalse();
        await Assert.That(builder.TrustedRoots).IsEmpty();
        await Assert.That(withRoot.TrustedRoots).HasCount().EqualTo(1);
    }


    [Test]
    public async Task Create_DefaultsToNoRevocationCheck()
    {
        using var root = BuildRootCa();
        using var leaf = BuildLeaf(root);

        using var result = new X509ChainBuilder(leaf).TrustRoot(root).Create();

        await Assert.That(result.Chain.ChainPolicy.RevocationMode).IsEqualTo(X509RevocationMode.NoCheck);
    }


    private static X509Certificate2 BuildExpiredIntermediate(X509Certificate2 issuer)
        => new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetNotBefore(DateTimeOffset.UtcNow.AddDays(-10))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(-1))
            .SetIssuer(issuer)
            .SetSubject("CN=ExpiredSubCA")
            .Create();


    [Test]
    public async Task Create_ExpiredIntermediate_FailsByDefault()
    {
        using var root = BuildRootCa();
        using var mid = BuildExpiredIntermediate(root);
        using var leaf = BuildLeaf(mid);

        using var result = new X509ChainBuilder(leaf).TrustRoot(root).AddCertificates(mid).Create();

        await Assert.That(result.Verified).IsFalse();
        var allStatuses = result.Chain.ChainElements
            .SelectMany(x => x.ChainElementStatus)
            .Concat(result.ChainStatus)
            .Select(x => x.Status);
        await Assert.That(allStatuses).Contains(X509ChainStatusFlags.NotTimeValid);
    }


    [Test]
    public async Task Create_ExpiredIntermediate_PassesWithAllowInvalidTime()
    {
        using var root = BuildRootCa();
        using var mid = BuildExpiredIntermediate(root);
        using var leaf = BuildLeaf(mid);

        using var result = new X509ChainBuilder(leaf)
            .TrustRoot(root)
            .AddCertificates(mid)
            .AllowInvalidTime()
            .Create();

        await Assert.That(result.Verified).IsTrue();
    }


    [Test]
    public async Task WithPolicy_RunsAfterBuilderSettingsAndWins()
    {
        using var root = BuildRootCa();
        using var mid = BuildExpiredIntermediate(root);
        using var leaf = BuildLeaf(mid);

        //AllowInvalidTime() would let this verify; the policy action undoes it, so it must run last
        using var result = new X509ChainBuilder(leaf)
            .TrustRoot(root)
            .AddCertificates(mid)
            .AllowInvalidTime()
            .WithPolicy(policy => policy.VerificationFlags = X509VerificationFlags.NoFlag)
            .Create();

        await Assert.That(result.Chain.ChainPolicy.VerificationFlags).IsEqualTo(X509VerificationFlags.NoFlag);
        await Assert.That(result.Verified).IsFalse();
    }


    [Test]
    public async Task WithPolicy_MultipleCalls_RunInOrder()
    {
        using var root = BuildRootCa();
        using var leaf = BuildLeaf(root);

        var order = new List<int>();
        using var result = new X509ChainBuilder(leaf)
            .TrustRoot(root)
            .WithPolicy(_ => order.Add(1))
            .WithPolicy(_ => order.Add(2))
            .Create();

        await Assert.That(order).IsEquivalentTo([1, 2]);
    }


    [Test]
    public async Task WithPolicy_Null_Throws()
    {
        using var root = BuildRootCa();
        using var leaf = BuildLeaf(root);

        await Assert.That(() => new X509ChainBuilder(leaf).WithPolicy(null!)).Throws<ArgumentNullException>();
    }
}
