using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

public class CertificateExportBuilderTests
{
    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_Pkcs12_RoundTrip(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var bytes = cert.Export().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        Assert.Equal(cert.Thumbprint, loaded.Thumbprint);
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_Pkcs12_WithPrivateKey_IncludesKey(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        Assert.True(cert.HasPrivateKey);

        var bytes = cert.Export().WithPrivateKey().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        Assert.True(loaded.HasPrivateKey);
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_Pkcs12_WithoutPrivateKeys_StripsKey(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        Assert.True(cert.HasPrivateKey);

        var bytes = cert.Export().WithoutPrivateKeys().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        Assert.False(loaded.HasPrivateKey);
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_Pem_ToPemString_ContainsCertBlock(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var result = cert.Export().WithoutPrivateKeys().AsPem().ToPemString();

        Assert.Contains("-----BEGIN CERTIFICATE-----", result);
        Assert.Contains("-----END CERTIFICATE-----", result);
        Assert.DoesNotContain("PRIVATE KEY", result);
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_Pem_WithPrivateKey_ContainsKeyAndCertBlocks(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var result = cert.Export().WithPrivateKey().AsPem().ToPemString();

        Assert.True(
            result.Contains("-----BEGIN PRIVATE KEY-----") || result.Contains("-----BEGIN EC PRIVATE KEY-----"),
            "Expected a PRIVATE KEY block in PEM output");
        Assert.Contains("-----BEGIN CERTIFICATE-----", result);
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_Cert_ToByteArray_MatchesRawData(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var result = cert.Export().AsCert().ToByteArray();
        Assert.Equal(cert.RawData, result);
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_Pkcs7_ToByteArray_RoundTrips(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var bytes = cert.Export().AsPkcs7().ToByteArray();

        var coll = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        coll.Import(bytes);
#pragma warning restore SYSLIB0057
        var single = Assert.Single(coll);
        Assert.Equal(cert.Thumbprint, single.Thumbprint);
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_Chain_Pkcs12_ContainsAllCerts(KeyAlgorithm algorithm)
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
        Assert.Contains(leafCert.Thumbprint, thumbprints);
        Assert.Contains(rootCert.Thumbprint, thumbprints);
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_WithChain_DeduplicatesByThumbprint(KeyAlgorithm algorithm)
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
            .WithChain(new[] { leafCert, rootCert })
            .AsPkcs12()
            .ToByteArray();

        var loaded = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        loaded.Import(bytes);
#pragma warning restore SYSLIB0057
        Assert.Equal(2, loaded.Count);
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_ToFile_WritesCorrectContent(KeyAlgorithm algorithm)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
        try {
            using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
            cert.Export().AsCert().ToFile(path);
            Assert.Equal(cert.RawData, File.ReadAllBytes(path));
        } finally {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_ToFile_ReturnsThis_EnablesChaining(KeyAlgorithm algorithm)
    {
        var path1 = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
        var path2 = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
        try {
            using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
            cert.Export().AsCert().ToFile(path1).ToFile(path2);
            Assert.Equal(cert.RawData, File.ReadAllBytes(path1));
            Assert.Equal(cert.RawData, File.ReadAllBytes(path2));
        } finally {
            if (File.Exists(path1)) File.Delete(path1);
            if (File.Exists(path2)) File.Delete(path2);
        }
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_ToStream_WritesBytes(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var ms = new MemoryStream();
        cert.Export().AsCert().ToStream(ms);
        Assert.Equal(cert.RawData, ms.ToArray());
    }

    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportBuilder_Collection_EntryPoint_Works(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var coll = new X509Certificate2Collection(cert);
        var pem = coll.Export().WithoutPrivateKeys().AsPem().ToPemString();
        Assert.Contains("-----BEGIN CERTIFICATE-----", pem);
    }


    public static TheoryData<KeyAlgorithm> KeyAlgorithmsTestData => new()
    {
        KeyAlgorithm.ECDsa,
        KeyAlgorithm.RSA
    };
}
