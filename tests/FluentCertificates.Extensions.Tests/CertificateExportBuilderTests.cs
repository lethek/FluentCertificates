using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class CertificateExportBuilderTests
{
    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pkcs12_RoundTrip(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var bytes = cert.Export().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        await Assert.That(loaded.Thumbprint).IsEqualTo(cert.Thumbprint);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pkcs12_WithPrivateKey_IncludesKey(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        await Assert.That(cert.HasPrivateKey).IsTrue();

        var bytes = cert.Export().WithPrivateKey().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        await Assert.That(loaded.HasPrivateKey).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pkcs12_WithoutPrivateKeys_StripsKey(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        await Assert.That(cert.HasPrivateKey).IsTrue();

        var bytes = cert.Export().WithoutPrivateKeys().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        await Assert.That(loaded.HasPrivateKey).IsFalse();
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pem_ToPemString_ContainsCertBlock(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var result = cert.Export().WithoutPrivateKeys().AsPem().ToPemString();

        await Assert.That(result).Contains("-----BEGIN CERTIFICATE-----");
        await Assert.That(result).Contains("-----END CERTIFICATE-----");
        await Assert.That(result).DoesNotContain("PRIVATE KEY");

        using var parsed = X509Certificate2.CreateFromPem(result);
        await Assert.That(parsed.RawData).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
        await Assert.That(parsed.HasPrivateKey).IsFalse();
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pem_WithPrivateKey_ContainsKeyAndCertBlocks(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var result = cert.Export().WithPrivateKey().AsPem().ToPemString();

        await Assert.That(
                result.Contains("-----BEGIN PRIVATE KEY-----") || result.Contains("-----BEGIN EC PRIVATE KEY-----"))
            .IsTrue()
            .Because("a PRIVATE KEY block is expected in the PEM output");
        await Assert.That(result).Contains("-----BEGIN CERTIFICATE-----");

        using var parsed = X509Certificate2.CreateFromPem(result, result);
        await Assert.That(parsed.RawData).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
        await Assert.That(parsed.Thumbprint).IsEqualTo(cert.Thumbprint);
        await Assert.That(parsed.HasPrivateKey).IsTrue();
        await Assert.That(SignedByPrivateKeyVerifiesAgainst(parsed, cert, algorithm))
            .IsTrue()
            .Because("the exported private key must pair with the exported certificate's public key");
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Cert_ToByteArray_MatchesRawData(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var result = cert.Export().AsCert().ToByteArray();
        await Assert.That(result).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pkcs7_ToByteArray_RoundTrips(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var bytes = cert.Export().AsPkcs7().ToByteArray();

        var coll = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        coll.Import(bytes);
#pragma warning restore SYSLIB0057
        await Assert.That(coll).HasSingleItem();
        await Assert.That(coll[0].Thumbprint).IsEqualTo(cert.Thumbprint);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Chain_Pkcs12_ContainsAllCerts(KeyAlgorithm algorithm)
    {
        using var rootCert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetUsage(CertificateUsage.CA)
            .Create();
        using var leafCert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetIssuer(rootCert)
            .Create();

        var certs = new[] { leafCert, rootCert };
        var bytes = certs.Export().AsPkcs12().ToByteArray();

        var loaded = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        loaded.Import(bytes);
#pragma warning restore SYSLIB0057

        var thumbprints = loaded.Cast<X509Certificate2>().Select(c => c.Thumbprint).ToHashSet();
        await Assert.That(thumbprints).Contains(leafCert.Thumbprint);
        await Assert.That(thumbprints).Contains(rootCert.Thumbprint);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_WithChain_DeduplicatesByThumbprint(KeyAlgorithm algorithm)
    {
        using var rootCert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetUsage(CertificateUsage.CA)
            .Create();
        using var leafCert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetIssuer(rootCert)
            .Create();

        // leafCert already in the initial list; WithChain adds leafCert again + rootCert
        var bytes = leafCert.Export()
            .WithChain([leafCert, rootCert])
            .AsPkcs12()
            .ToByteArray();

        var loaded = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        loaded.Import(bytes);
#pragma warning restore SYSLIB0057
        await Assert.That(loaded.Count).IsEqualTo(2);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_ToFile_WritesCorrectContent(KeyAlgorithm algorithm)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
        try {
            using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
            cert.Export().AsCert().ToFile(path);
            await Assert.That(File.ReadAllBytes(path)).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
        } finally {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_ToFile_ReturnsThis_EnablesChaining(KeyAlgorithm algorithm)
    {
        var path1 = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
        var path2 = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
        try {
            using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
            cert.Export().AsCert().ToFile(path1).ToFile(path2);
            await Assert.That(File.ReadAllBytes(path1)).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
            await Assert.That(File.ReadAllBytes(path2)).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
        } finally {
            if (File.Exists(path1)) File.Delete(path1);
            if (File.Exists(path2)) File.Delete(path2);
        }
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_ToStream_WritesBytes(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var ms = new MemoryStream();
        cert.Export().AsCert().ToStream(ms);
        await Assert.That(ms.ToArray()).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Collection_EntryPoint_Works(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var coll = new X509Certificate2Collection(new[] { cert, cert2 });
        var pem = coll.Export().WithoutPrivateKeys().AsPem().ToPemString();

        var parsed = new X509Certificate2Collection();
        parsed.ImportFromPem(pem);
        try {
            //PEM output is leaf-first: the last certificate in the source collection is treated as the leaf
            await Assert.That(parsed.Count).IsEqualTo(2);
            await Assert.That(parsed[0].RawData).IsEquivalentTo(cert2.RawData, CollectionOrdering.Matching);
            await Assert.That(parsed[1].RawData).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
        } finally {
            foreach (var c in parsed) c.Dispose();
        }
    }


    private static bool SignedByPrivateKeyVerifiesAgainst(X509Certificate2 signer, X509Certificate2 verifier, KeyAlgorithm algorithm)
    {
        var data = "FluentCertificates"u8.ToArray();
        switch (algorithm) {
            case KeyAlgorithm.ECDsa: {
                using var priv = signer.GetECDsaPrivateKey()!;
                using var pub = verifier.GetECDsaPublicKey()!;
                return pub.VerifyData(data, priv.SignData(data, HashAlgorithmName.SHA256), HashAlgorithmName.SHA256);
            }
            case KeyAlgorithm.RSA: {
                using var priv = signer.GetRSAPrivateKey()!;
                using var pub = verifier.GetRSAPublicKey()!;
                var sig = priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return pub.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null);
        }
    }


    public static IEnumerable<KeyAlgorithm> KeyAlgorithmsTestData()
    {
        yield return KeyAlgorithm.ECDsa;
        yield return KeyAlgorithm.RSA;
    }
}
