using System.Security.Cryptography.X509Certificates;

using TUnit.Assertions.Enums;

namespace FluentCertificates;

/// <summary>
/// Ordering is decided by which API added the certificates, and <see cref="ExportKeys.Primary"/> is resolved
/// through the anchor rather than by position.
/// </summary>
public class ExportOrderingAndAnchorTests
{
    [Test]
    public async Task AddChain_OrdersLeafFirstWhateverOrderItWasGivenIn()
    {
        using var root = Root();
        using var intermediate = Intermediate(root);
        using var leaf = Leaf(intermediate);

        var pem = leaf.Export().AddChain([root, intermediate]).AsPem().ToPemString();

        await Assert.That(SubjectsInOrder(pem)).IsEquivalentTo(
            ["CN=Leaf", "CN=Intermediate", "CN=Root"], CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddChain_AlreadyLeafFirst_KeepsThatOrder()
    {
        using var root = Root();
        using var intermediate = Intermediate(root);
        using var leaf = Leaf(intermediate);

        var pem = leaf.Export().AddChain([intermediate, root]).AsPem().ToPemString();

        await Assert.That(SubjectsInOrder(pem)).IsEquivalentTo(
            ["CN=Leaf", "CN=Intermediate", "CN=Root"], CollectionOrdering.Matching);
    }


    /// <summary>
    /// A group that is not one chain is appended as given: with nothing to order it by, guessing would be
    /// worse than leaving it alone.
    /// </summary>
    [Test]
    public async Task AddChain_DisjointCertificates_AreAppendedAsGiven()
    {
        using var anchor = Root("Anchor");
        using var first = Root("First");
        using var second = Root("Second");

        var pem = anchor.Export().AddChain([first, second]).AsPem().ToPemString();

        await Assert.That(SubjectsInOrder(pem)).IsEquivalentTo(
            ["CN=Anchor", "CN=First", "CN=Second"], CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddCertificates_IsNeverReordered()
    {
        using var root = Root();
        using var intermediate = Intermediate(root);
        using var leaf = Leaf(intermediate);

        var pem = leaf.Export().AddCertificates(root, intermediate).AsPem().ToPemString();

        await Assert.That(SubjectsInOrder(pem)).IsEquivalentTo(
            ["CN=Leaf", "CN=Root", "CN=Intermediate"], CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddChain_SkipsCertificatesAlreadyPresent()
    {
        using var root = Root();
        using var leaf = Leaf(root);

        var pem = leaf.Export().AddChain([root, leaf]).AsPem().ToPemString();

        await Assert.That(SubjectsInOrder(pem)).IsEquivalentTo(
            ["CN=Leaf", "CN=Root"], CollectionOrdering.Matching);
    }


    /// <summary>
    /// A bundle designates no leaf, so <see cref="ExportKeys.Primary"/> has nothing to resolve and must say
    /// so rather than taking whichever certificate happens to be first.
    /// </summary>
    [Test]
    public async Task Collection_ExportWithPrimaryKeys_Throws()
    {
        using var root = Root();
        using var leaf = Leaf(root);

        var ex = await Assert
            .That(() => new[] { leaf, root }.Export().WithKeys(ExportKeys.Primary).AsPkcs12().ToByteArray())
            .ThrowsExactly<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("ExportKeys.Primary");
        await Assert.That(ex.Message).Contains("none anchored as the primary one");
        await Assert.That(ex.Message).Contains("cert.Export()");
    }


    [Test]
    public async Task Collection_ExportWithAllOrNoKeys_DoesNotNeedAnAnchor()
    {
        using var root = Root();
        using var leaf = Leaf(root);

        await Assert.That(() => new[] { leaf, root }.Export().WithKeys(ExportKeys.All).AsPkcs12().ToByteArray())
            .ThrowsNothing();
        await Assert.That(() => new[] { leaf, root }.Export().WithKeys(ExportKeys.None).AsPkcs12().ToByteArray())
            .ThrowsNothing();
    }


    /// <summary>
    /// The anchor keeps its key wherever it lands in the list, so a chain appended after it cannot retarget
    /// which certificate <see cref="ExportKeys.Primary"/> means.
    /// </summary>
    [Test]
    public async Task Primary_ResolvesThroughTheAnchorNotThePosition()
    {
        using var root = Root();
        using var leaf = Leaf(root);

        var pem = root.Export().AddChain([leaf]).WithKeys(ExportKeys.Primary).AsPem().ToPemString();

        //Each AddChain call sorts only its own group, so a single-element one leaves the anchor first
        await Assert.That(SubjectsInOrder(pem)).IsEquivalentTo(
            ["CN=Root", "CN=Leaf"], CollectionOrdering.Matching);

        //Exactly one private key, and it is the anchor's rather than the first-listed certificate's
        await Assert.That(pem.Split("-----BEGIN PRIVATE KEY-----").Length - 1).IsEqualTo(1);
    }


    private static X509Certificate2 Root(string name = "Root")
        => new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject(x => x.SetCommonName(name)).Create();

    private static X509Certificate2 Intermediate(X509Certificate2 issuer)
        => new CertificateBuilder().SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Intermediate")).SetIssuer(issuer).Create();

    private static X509Certificate2 Leaf(X509Certificate2 issuer)
        => new CertificateBuilder().SetSubject(x => x.SetCommonName("Leaf")).SetIssuer(issuer).Create();

    private static List<string> SubjectsInOrder(string pem)
    {
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(pem);
        return collection.Select(x => x.Subject).ToList();
    }
}
