using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using Xunit;


namespace FluentCertificates.Extensions;

public class X509Certificate2ExtensionsTests
{
    [Fact]
    public void ExportAsCert_ToWriter_RawDataIsEqual()
    {
        using var expected = new CertificateBuilder().Build();
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream)) {
            expected.ExportAsCert(writer);
        }

        using var actual = new X509Certificate2(stream.ToArray());

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
    }


    [Fact]
    public void ExportAsCert_ToFile_RawDataIsEqual()
    {
        using var expected = new CertificateBuilder().Build();
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "crt");
        expected.ExportAsCert(tmpFile);

        using var actual = new X509Certificate2(tmpFile);
        File.Delete(tmpFile);

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
    }


    [Fact]
    public void ExportAsPkcs7_ToWriter_RawDataIsEqual()
    {
        using var expected = new CertificateBuilder().Build();
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


    [Fact]
    public void ExportAsPkcs7_ToFile_RawDataIsEqual()
    {
        using var expected = new CertificateBuilder().Build();
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


    [Fact]
    public void ExportAsPkcs12_ToWriter_RawDataIsEqual()
    {
        using var expected = new CertificateBuilder().Build();
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream)) {
            expected.ExportAsPkcs12(writer);
        }

        using var actual = new X509Certificate2(stream.ToArray());

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.True(actual.HasPrivateKey, "Loaded X509Certificate2 should have a private key attached");
    }


    [Fact]
    public void ExportAsPkcs12_ToFile_RawDataIsEqual()
    {
        using var expected = new CertificateBuilder().Build();
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "pfx");
        expected.ExportAsPkcs12(tmpFile);

        using var actual = new X509Certificate2(tmpFile);
        File.Delete(tmpFile);

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.True(actual.HasPrivateKey, "Loaded X509Certificate2 should have a private key attached");
    }
}