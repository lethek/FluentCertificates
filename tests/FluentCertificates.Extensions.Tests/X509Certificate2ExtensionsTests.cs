using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace FluentCertificates;

public class X509Certificate2ExtensionsTests
{
    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void Certificate_IssuedBy_VerifiesIssuerSignature(KeyAlgorithm alg)
    {
        var builder = new CertificateBuilder().SetSubject("CN=Test Issuer");
        using var faker = builder.SetKeyAlgorithm(alg).Create();
        using var issuer = builder.SetKeyAlgorithm(alg).Create();

        using var cert = new CertificateBuilder().SetIssuer(issuer).Create();

        //The fake issuer has the same subject-name as the real issuer
        Assert.True(cert.IsIssuedBy(faker, verifySignature: false));

        //Signature verification against the fake issuer fails
        Assert.False(cert.IsIssuedBy(faker, verifySignature: true));

        //Signature verification against the real issuer succeeds
        Assert.True(cert.IsIssuedBy(issuer, true));
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsAndExportKeysTestData))]
    public void ExportAsPem_ToWriter_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include, string password)
    {
        using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

        using var stream = new MemoryStream();
        using (var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true)) {
            expected.ExportAsPem(writer, password, include);
        }
        var parser = new X509CertificateParser();
        var bcCert = parser.ReadCertificate(stream.ToArray());
        using var actual = new X509Certificate2(bcCert.GetEncoded());
        //TODO: load the private key if one was in the export

        stream.Position = 0;
        using var streamReader = new StreamReader(stream, Encoding.ASCII);
        var pemReader = new PemReader(streamReader);

        //Check structure of the PEM file
        if (include != ExportKeys.None) {
            Assert.Equal(password != null ? "ENCRYPTED PRIVATE KEY" : "PRIVATE KEY", pemReader.ReadPemObject().Type);
        }
        Assert.Equal("CERTIFICATE", pemReader.ReadPemObject().Type);
        Assert.Null(pemReader.ReadPemObject());

        //Check the read certificate
        Assert.Equal(expected.RawData, bcCert.GetEncoded());
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsAndExportKeysTestData))]
    public void ExportAsPem_ToFile_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include, string password)
    {
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "pem");
        try {
            using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

            expected.ExportAsPem(tmpFile, password, include);
            var parser = new X509CertificateParser();
            var bcCert = parser.ReadCertificate(File.ReadAllBytes(tmpFile));
            using var actual = new X509Certificate2(bcCert.GetEncoded());
            //TODO: load the private key if one was in the export

            using var streamReader = new StreamReader(tmpFile, Encoding.ASCII);
            var pemReader = new PemReader(streamReader);

            //Check structure of the PEM file
            if (include != ExportKeys.None) {
                Assert.Equal(password != null ? "ENCRYPTED PRIVATE KEY" : "PRIVATE KEY", pemReader.ReadPemObject().Type);
            }
            Assert.Equal("CERTIFICATE", pemReader.ReadPemObject().Type);
            Assert.Null(pemReader.ReadPemObject());

            //Check the read certificate
            Assert.Equal(expected.RawData, actual.RawData);
            Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
            Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
        } finally {
            File.Delete(tmpFile);
        }
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportAsCert_ToWriter_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

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
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "crt");
        try {
            using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

            expected.ExportAsCert(tmpFile);
            using var actual = new X509Certificate2(tmpFile);

            Assert.Equal(expected.RawData, actual.RawData);
            Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
            Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
        } finally {
            File.Delete(tmpFile);
        }
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsTestData))]
    public void ExportAsPkcs7_ToWriter_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

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
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "p7b");
        try {
            using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

            expected.ExportAsPkcs7(tmpFile);
            var cms = new SignedCms();
            cms.Decode(File.ReadAllBytes(tmpFile));
            using var actual = cms.Certificates[0];

            Assert.Equal(expected.RawData, actual.RawData);
            Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
            Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
        } finally {
            File.Delete(tmpFile);
        }
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsAndExportKeysTestData))]
    public void ExportAsPkcs12_ToWriter_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include, string password)
    {
        using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream)) {
            expected.ExportAsPkcs12(writer, password, include);
        }
        using var actual = new X509Certificate2(stream.ToArray(), password);

        Assert.Equal(expected.RawData, actual.RawData);
        Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");
        if (include == ExportKeys.None) {
            Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
        } else {
            Assert.True(actual.HasPrivateKey, "Loaded X509Certificate2 should have a private key attached");
        }
    }


    [Theory]
    [MemberData(nameof(KeyAlgorithmsAndExportKeysTestData))]
    public void ExportAsPkcs12_ToFile_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include, string password)
    {
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "pfx");
        try {
            using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

            expected.ExportAsPkcs12(tmpFile, password, include);
            using var actual = new X509Certificate2(tmpFile, password);

            Assert.Equal(expected.RawData, actual.RawData);
            Assert.True(expected.HasPrivateKey, "Original X509Certificate2 should have a private key attached");

            if (include == ExportKeys.None) {
                Assert.False(actual.HasPrivateKey, "Loaded X509Certificate2 should not have a private key attached");
            } else {
                Assert.True(actual.HasPrivateKey, "Loaded X509Certificate2 should have a private key attached");
            }
        } finally {
            File.Delete(tmpFile);
        }
    }


    public static IEnumerable<object[]> KeyAlgorithmsTestData => new[] {
        new object[] { KeyAlgorithm.ECDsa },
        new object[] { KeyAlgorithm.RSA },
    };


    public static IEnumerable<object[]> KeyAlgorithmsAndExportKeysTestData => new[] {
        new object[] { KeyAlgorithm.ECDsa, ExportKeys.None, TestPassword },
        new object[] { KeyAlgorithm.ECDsa, ExportKeys.Leaf, TestPassword },
        new object[] { KeyAlgorithm.ECDsa, ExportKeys.All, TestPassword },
        new object[] { KeyAlgorithm.ECDsa, ExportKeys.None, null! },
        new object[] { KeyAlgorithm.ECDsa, ExportKeys.Leaf, null! },
        new object[] { KeyAlgorithm.ECDsa, ExportKeys.All, null! },
        new object[] { KeyAlgorithm.RSA, ExportKeys.None, TestPassword },
        new object[] { KeyAlgorithm.RSA, ExportKeys.Leaf, TestPassword },
        new object[] { KeyAlgorithm.RSA, ExportKeys.All, TestPassword },
        new object[] { KeyAlgorithm.RSA, ExportKeys.None, null! },
        new object[] { KeyAlgorithm.RSA, ExportKeys.Leaf, null! },
        new object[] { KeyAlgorithm.RSA, ExportKeys.All, null! }
    };


    private const string TestPassword = "nHLYyNcicPsEaV7T";
}