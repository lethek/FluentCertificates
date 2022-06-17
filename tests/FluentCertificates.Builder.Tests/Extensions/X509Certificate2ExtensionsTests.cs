using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using Xunit;


namespace FluentCertificates.Extensions;

public class X509Certificate2ExtensionsTests
{
    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportAsCert_ToWriter_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().GenerateKeyPair(alg).Build();
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream)) {
            expected.ExportAsCert(writer);
        }

        using var actual = new X509Certificate2(stream.ToArray());

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportAsCert_ToFile_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().GenerateKeyPair(alg).Build();
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "crt");
        expected.ExportAsCert(tmpFile);

        using var actual = new X509Certificate2(tmpFile);
        File.Delete(tmpFile);

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportAsPkcs7_ToWriter_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().GenerateKeyPair(alg).Build();
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream)) {
            expected.ExportAsPkcs7(writer);
        }

        var cms = new SignedCms();
        cms.Decode(stream.ToArray());
        using var actual = cms.Certificates[0];

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportAsPkcs7_ToFile_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().GenerateKeyPair(alg).Build();
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "p7b");
        expected.ExportAsPkcs7(tmpFile);

        var cms = new SignedCms();
        cms.Decode(File.ReadAllBytes(tmpFile));
        File.Delete(tmpFile);
        using var actual = cms.Certificates[0];

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportAsPkcs12_ToWriter_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().GenerateKeyPair(alg).Build();
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream)) {
            expected.ExportAsPkcs12(writer);
        }

        using var actual = new X509Certificate2(stream.ToArray());

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.True(actual.HasPrivateKey, "Loaded X509Certificate2 should have a private key attached");
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportAsPkcs12_ToFile_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().GenerateKeyPair(alg).Build();
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "pfx");
        expected.ExportAsPkcs12(tmpFile);

        using var actual = new X509Certificate2(tmpFile);
        File.Delete(tmpFile);

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.True(actual.HasPrivateKey, "Loaded X509Certificate2 should have a private key attached");
    }


    [Theory]
    [InlineData(KeyAlgorithm.ECDsa, ExportKeys.None)]
    [InlineData(KeyAlgorithm.RSA, ExportKeys.None)]
    [InlineData(KeyAlgorithm.ECDsa, ExportKeys.Leaf)]
    [InlineData(KeyAlgorithm.RSA, ExportKeys.Leaf)]
    [InlineData(KeyAlgorithm.ECDsa, ExportKeys.All)]
    [InlineData(KeyAlgorithm.RSA, ExportKeys.All)]
    public void ExportAsPkcs12_ToFileWithPassword_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include)
    {
        using var expected = new CertificateBuilder().GenerateKeyPair(KeyAlgorithm.ECDsa).Build();
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "pfx");
        expected.ExportAsPkcs12(tmpFile, TestPassword, include);

        using var actual = new X509Certificate2(tmpFile, TestPassword);
        File.Delete(tmpFile);

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");

        if (include == ExportKeys.None) {
            Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
        } else {
            Assert.True(actual.HasPrivateKey, "Loaded X509Certificate2 should have a private key attached");
        }
    }


    public static IEnumerable<object[]> KeyAlgorithmsTestData => new[] {
        new object[] {KeyAlgorithm.ECDsa}, new object[] {KeyAlgorithm.RSA},
    };


    private const string TestPassword = "nHLYyNcicPsEaV7T";
}