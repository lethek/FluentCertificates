using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

/// <summary>
/// <see cref="X509Certificate2EnumerableExtensions.FilterPrivateKeys(IEnumerable{X509Certificate2},ExportKeys)"/>
/// has no anchor to consult, so <see cref="ExportKeys.Primary"/> means the first certificate in the sequence.
/// </summary>
public class X509Certificate2EnumerableExtensionsTests
{
    [Test]
    public async Task FilterPrivateKeys_All_KeepsEveryKeyAndEveryInstance()
    {
        using var first = WithKey("First");
        using var second = WithKey("Second");

        var filtered = new[] { first, second }.FilterPrivateKeys(ExportKeys.All).ToList();

        await Assert.That(filtered[0]).IsSameReferenceAs(first);
        await Assert.That(filtered[1]).IsSameReferenceAs(second);
        await Assert.That(filtered.All(x => x.HasPrivateKey)).IsTrue();
    }


    [Test]
    public async Task FilterPrivateKeys_None_StripsEveryKey()
    {
        using var first = WithKey("First");
        using var second = WithKey("Second");

        var filtered = new[] { first, second }.FilterPrivateKeys(ExportKeys.None).ToList();

        await Assert.That(filtered.Any(x => x.HasPrivateKey)).IsFalse();
        await Assert.That(filtered[0].Thumbprint).IsEqualTo(first.Thumbprint);
        await Assert.That(filtered[1].Thumbprint).IsEqualTo(second.Thumbprint);

        //The originals are untouched: stripping produces a copy rather than mutating the input
        await Assert.That(first.HasPrivateKey).IsTrue();
    }


    [Test]
    public async Task FilterPrivateKeys_Primary_KeepsOnlyTheFirstCertificatesKey()
    {
        using var first = WithKey("First");
        using var second = WithKey("Second");
        using var third = WithKey("Third");

        var filtered = new[] { first, second, third }.FilterPrivateKeys(ExportKeys.Primary).ToList();

        await Assert.That(filtered[0].HasPrivateKey).IsTrue();
        await Assert.That(filtered[0]).IsSameReferenceAs(first);
        await Assert.That(filtered[1].HasPrivateKey).IsFalse();
        await Assert.That(filtered[2].HasPrivateKey).IsFalse();
        await Assert.That(filtered[1].Thumbprint).IsEqualTo(second.Thumbprint);
    }


    /// <summary>
    /// A certificate that has no private key is passed through as the caller's own instance, whatever its
    /// position: there is nothing to strip, so no copy is made.
    /// </summary>
    [Test]
    public async Task FilterPrivateKeys_Primary_PassesKeylessCertificatesThroughUnchanged()
    {
        using var first = WithKey("First");
        using var keyless = WithoutKey("Keyless");

        var filtered = new[] { first, keyless }.FilterPrivateKeys(ExportKeys.Primary).ToList();

        await Assert.That(filtered[1]).IsSameReferenceAs(keyless);
    }


    [Test]
    public async Task FilterPrivateKeys_Primary_FirstCertificateWithoutKey_LeavesLaterKeysStripped()
    {
        using var keyless = WithoutKey("Keyless");
        using var second = WithKey("Second");

        var filtered = new[] { keyless, second }.FilterPrivateKeys(ExportKeys.Primary).ToList();

        await Assert.That(filtered[0]).IsSameReferenceAs(keyless);
        await Assert.That(filtered[1].HasPrivateKey).IsFalse();
    }


    [Test]
    public async Task FilterPrivateKeys_UndefinedValue_Throws()
    {
        using var cert = WithKey("Only");

        await Assert.That(() => new[] { cert }.FilterPrivateKeys((ExportKeys)999).ToList())
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }


    private static X509Certificate2 WithKey(string name)
        => new CertificateBuilder().SetSubject(x => x.SetCommonName(name)).Create();

    private static X509Certificate2 WithoutKey(string name)
    {
        using var withKey = WithKey(name);
        return CertTools.LoadCertificate(withKey.RawDataMemory.Span);
    }
}
