using System.Security.Cryptography.Pkcs;
using System.Text;

using FluentCertificates.Internals;

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class X509Certificate2ExtensionsTests
{
    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task Certificate_IssuedBy_VerifiesIssuerSignature(KeyAlgorithm alg)
    {
        var builder = new CertificateBuilder().SetSubject("CN=Test Issuer");
        using var faker = builder.SetKeyAlgorithm(alg).Create();
        using var issuer = builder.SetKeyAlgorithm(alg).Create();

        using var cert = new CertificateBuilder().SetIssuer(issuer).Create();

        //The fake issuer has the same subject-name as the real issuer
        await Assert.That(cert.IsIssuedBy(faker, verifySignature: false)).IsTrue();

        //Signature verification against the fake issuer fails
        await Assert.That(cert.IsIssuedBy(faker, verifySignature: true)).IsFalse();

        //Signature verification against the real issuer succeeds
        await Assert.That(cert.IsIssuedBy(issuer, true)).IsTrue();
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsAndExportKeysTestData))]
    public async Task ExportAsPem_ToWriter_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include, string? password)
    {
        using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

        using var stream = new MemoryStream();
        using (var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true)) {
            writer.Write(expected.Export().WithPassword(password).WithKeys(include).AsPem().ToPemString());
        }

        var parser = new X509CertificateParser();
        var bcCert = parser.ReadCertificate(stream.ToArray());
        using var actual = CertTools.LoadCertificate(bcCert.GetEncoded());
        //TODO: load the private key if one was in the export

        stream.Position = 0;
        using var streamReader = new StreamReader(stream, Encoding.ASCII);
        var pemReader = new PemReader(streamReader);

        //Check structure of the PEM file
        if (include != ExportKeys.None) {
            await Assert.That(pemReader.ReadPemObject().Type)
                .IsEqualTo(password != null ? "ENCRYPTED PRIVATE KEY" : "PRIVATE KEY");
        }

        await Assert.That(pemReader.ReadPemObject().Type).IsEqualTo("CERTIFICATE");
        await Assert.That(pemReader.ReadPemObject()).IsNull();

        //Check the read certificate
        await Assert.That(bcCert.GetEncoded()).IsEquivalentTo(expected.RawData, CollectionOrdering.Matching);
        await Assert.That(expected.HasPrivateKey).IsTrue()
            .Because("the original X509Certificate2 should have a private key attached");
        await Assert.That(actual.HasPrivateKey).IsFalse()
            .Because("the loaded X509Certificate2 should not have a private key attached");
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsAndExportKeysTestData))]
    public async Task ExportAsPem_ToFile_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include, string? password)
    {
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "pem");
        try {
            using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

            expected.Export().WithPassword(password).WithKeys(include).AsPem().ToFile(tmpFile);
            var parser = new X509CertificateParser();
            var bcCert = parser.ReadCertificate(File.ReadAllBytes(tmpFile));
            using var actual = CertTools.LoadCertificate(bcCert.GetEncoded());
            //TODO: load the private key if one was in the export

            using var streamReader = new StreamReader(tmpFile, Encoding.ASCII);
            var pemReader = new PemReader(streamReader);

            //Check structure of the PEM file
            if (include != ExportKeys.None) {
                await Assert.That(pemReader.ReadPemObject().Type)
                    .IsEqualTo(password != null ? "ENCRYPTED PRIVATE KEY" : "PRIVATE KEY");
            }

            await Assert.That(pemReader.ReadPemObject().Type).IsEqualTo("CERTIFICATE");
            await Assert.That(pemReader.ReadPemObject()).IsNull();

            //Check the read certificate
            await Assert.That(actual.RawData).IsEquivalentTo(expected.RawData, CollectionOrdering.Matching);
            await Assert.That(expected.HasPrivateKey).IsTrue()
                .Because("the original X509Certificate2 should have a private key attached");
            await Assert.That(actual.HasPrivateKey).IsFalse()
                .Because("the loaded X509Certificate2 should not have a private key attached");
        } finally {
            File.Delete(tmpFile);
        }
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportAsCert_ToWriter_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream)) {
            expected.Export().AsCert().ToStream(writer.BaseStream);
        }

        using var actual = CertTools.LoadCertificate(stream.ToArray());

        await Assert.That(actual.RawData).IsEquivalentTo(expected.RawData, CollectionOrdering.Matching);
        await Assert.That(expected.HasPrivateKey).IsTrue()
            .Because("the original X509Certificate2 should have a private key attached");
        await Assert.That(actual.HasPrivateKey).IsFalse()
            .Because("the loaded X509Certificate2 should not have a private key attached");
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportAsCert_ToFile_RawDataIsEqual(KeyAlgorithm alg)
    {
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "crt");
        try {
            using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

            expected.Export().AsCert().ToFile(tmpFile);
            using var actual = CertTools.LoadCertificateFromFile(tmpFile);

            await Assert.That(actual.RawData).IsEquivalentTo(expected.RawData, CollectionOrdering.Matching);
            await Assert.That(expected.HasPrivateKey).IsTrue()
                .Because("the original X509Certificate2 should have a private key attached");
            await Assert.That(actual.HasPrivateKey).IsFalse()
                .Because("the loaded X509Certificate2 should not have a private key attached");
        } finally {
            File.Delete(tmpFile);
        }
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportAsPkcs7_ToWriter_RawDataIsEqual(KeyAlgorithm alg)
    {
        using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream)) {
            expected.Export().AsPkcs7().ToStream(writer.BaseStream);
        }

        var cms = new SignedCms();
        cms.Decode(stream.ToArray());
        using var actual = cms.Certificates[0];

        await Assert.That(actual.RawData).IsEquivalentTo(expected.RawData, CollectionOrdering.Matching);
        await Assert.That(expected.HasPrivateKey).IsTrue()
            .Because("the original X509Certificate2 should have a private key attached");
        await Assert.That(actual.HasPrivateKey).IsFalse()
            .Because("the loaded X509Certificate2 should not have a private key attached");
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportAsPkcs7_ToFile_RawDataIsEqual(KeyAlgorithm alg)
    {
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "p7b");
        try {
            using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

            expected.Export().AsPkcs7().ToFile(tmpFile);
            var cms = new SignedCms();
            cms.Decode(File.ReadAllBytes(tmpFile));
            using var actual = cms.Certificates[0];

            await Assert.That(actual.RawData).IsEquivalentTo(expected.RawData, CollectionOrdering.Matching);
            await Assert.That(expected.HasPrivateKey).IsTrue()
                .Because("the original X509Certificate2 should have a private key attached");
            await Assert.That(actual.HasPrivateKey).IsFalse()
                .Because("the loaded X509Certificate2 should not have a private key attached");
        } finally {
            File.Delete(tmpFile);
        }
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsAndExportKeysTestData))]
    public async Task ExportAsPkcs12_ToWriter_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include, string? password)
    {
        using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream)) {
            expected.Export().WithKeys(include).WithPassword(password).AsPkcs12().ToStream(writer.BaseStream);
        }

        using var actual = CertTools.LoadPkcs12(stream.ToArray(), password);

        await Assert.That(actual.RawData).IsEquivalentTo(expected.RawData, CollectionOrdering.Matching);
        await Assert.That(expected.HasPrivateKey).IsTrue()
            .Because("the original X509Certificate2 should have a private key attached");
        if (include == ExportKeys.None) {
            await Assert.That(actual.HasPrivateKey).IsFalse()
                .Because("the loaded X509Certificate2 should not have a private key attached");
        } else {
            await Assert.That(actual.HasPrivateKey).IsTrue()
                .Because("the loaded X509Certificate2 should have a private key attached");
        }
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsAndExportKeysTestData))]
    public async Task ExportAsPkcs12_ToFile_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include, string? password)
    {
        var tmpFile = Path.ChangeExtension(Path.GetTempFileName(), "pfx");
        try {
            using var expected = new CertificateBuilder().SetKeyAlgorithm(alg).Create();

            expected.Export().WithKeys(include).WithPassword(password).AsPkcs12().ToFile(tmpFile);
            using var actual = CertTools.LoadPkcs12FromFile(tmpFile, password);

            await Assert.That(actual.RawData).IsEquivalentTo(expected.RawData, CollectionOrdering.Matching);
            await Assert.That(expected.HasPrivateKey).IsTrue()
                .Because("the original X509Certificate2 should have a private key attached");
            if (include == ExportKeys.None) {
                await Assert.That(actual.HasPrivateKey).IsFalse()
                    .Because("the loaded X509Certificate2 should not have a private key attached");
            } else {
                await Assert.That(actual.HasPrivateKey).IsTrue()
                    .Because("the loaded X509Certificate2 should have a private key attached");
            }
        } finally {
            File.Delete(tmpFile);
        }
    }


    public static IEnumerable<KeyAlgorithm> KeyAlgorithmsTestData()
    {
        yield return KeyAlgorithm.ECDsa;
        yield return KeyAlgorithm.RSA;
    }


    [Test]
    public async Task IsValidAt_InsideAndOutsideTheValidityWindow()
    {
        var from = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var to = new DateTimeOffset(2030, 12, 31, 0, 0, 0, TimeSpan.Zero);

        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("Validity Test"))
            .SetNotBefore(from)
            .SetNotAfter(to)
            .Create();

        await Assert.That(cert.IsValidAt(from.UtcDateTime.AddDays(30))).IsTrue();
        await Assert.That(cert.IsValidAt(from.UtcDateTime.AddSeconds(-1))).IsFalse();
        await Assert.That(cert.IsValidAt(to.UtcDateTime.AddSeconds(1))).IsFalse();

        //Both bounds are inclusive
        await Assert.That(cert.IsValidAt(from.UtcDateTime)).IsTrue();
        await Assert.That(cert.IsValidAt(to.UtcDateTime)).IsTrue();
    }


    [Test]
    public async Task IsValidNow_ReflectsTheCurrentValidityWindow()
    {
        var now = DateTimeOffset.UtcNow;

        using var current = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("Current"))
            .SetNotBefore(now.AddHours(-1))
            .SetNotAfter(now.AddHours(1))
            .Create();

        using var expired = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("Expired"))
            .SetNotBefore(now.AddHours(-2))
            .SetNotAfter(now.AddHours(-1))
            .Create();

        using var notYetValid = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("Future"))
            .SetNotBefore(now.AddHours(1))
            .SetNotAfter(now.AddHours(2))
            .Create();

        await Assert.That(current.IsValidNow()).IsTrue();
        await Assert.That(expired.IsValidNow()).IsFalse();
        await Assert.That(notYetValid.IsValidNow()).IsFalse();
    }


    [Test]
    public async Task IsValidAt_LocalDateTime_IsComparedAgainstUtcBounds()
    {
        var now = DateTimeOffset.UtcNow;

        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("Kind Test"))
            .SetNotBefore(now.AddMinutes(-5))
            .SetNotAfter(now.AddMinutes(5))
            .Create();

        //IsValidAt converts the certificate's bounds to UTC but uses atTime as given, so the
        //result depends on the DateTimeKind of the argument. A UTC instant is correct; the
        //identical moment expressed as local time is compared against UTC bounds unconverted.
        await Assert.That(cert.IsValidAt(DateTime.UtcNow)).IsTrue();

        var offset = TimeZoneInfo.Local.GetUtcOffset(DateTime.UtcNow);
        if (offset != TimeSpan.Zero) {
            await Assert
                .That(cert.IsValidAt(DateTime.Now))
                .IsFalse()
                .Because("the local wall-clock value is compared against UTC bounds without conversion");
        }
    }


    public static IEnumerable<(KeyAlgorithm, ExportKeys, string?)> KeyAlgorithmsAndExportKeysTestData()
    {
        yield return (KeyAlgorithm.ECDsa, ExportKeys.None, TestPassword);
        yield return (KeyAlgorithm.ECDsa, ExportKeys.Leaf, TestPassword);
        yield return (KeyAlgorithm.ECDsa, ExportKeys.All, TestPassword);
        yield return (KeyAlgorithm.ECDsa, ExportKeys.None, null);
        yield return (KeyAlgorithm.ECDsa, ExportKeys.Leaf, null);
        yield return (KeyAlgorithm.ECDsa, ExportKeys.All, null);
        yield return (KeyAlgorithm.RSA, ExportKeys.None, TestPassword);
        yield return (KeyAlgorithm.RSA, ExportKeys.Leaf, TestPassword);
        yield return (KeyAlgorithm.RSA, ExportKeys.All, TestPassword);
        yield return (KeyAlgorithm.RSA, ExportKeys.None, null);
        yield return (KeyAlgorithm.RSA, ExportKeys.Leaf, null);
        yield return (KeyAlgorithm.RSA, ExportKeys.All, null);
    }


    private const string TestPassword = "nHLYyNcicPsEaV7T";
}
