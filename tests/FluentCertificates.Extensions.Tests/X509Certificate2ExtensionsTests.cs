using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
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


    /// <summary>
    /// DSA has its own arm in the verifier, and the certificates it signs are the only ones that reach it.
    /// </summary>
    [Test]
    [SupportedOSPlatform("Windows")]
    [SupportedOSPlatform("Linux")]
    public async Task Certificate_IssuedByADSAIssuer_VerifiesIssuerSignature()
    {
        #pragma warning disable CS0618 // Type or member is obsolete
        var builder = new CertificateBuilder().SetSubject("CN=DSA Issuer").SetKeyAlgorithm(KeyAlgorithm.DSA());
        #pragma warning restore CS0618 // Type or member is obsolete

        using var faker = builder.Create();
        using var issuer = builder.Create();

        using var cert = new CertificateBuilder().SetIssuer(issuer).Create();

        await Assert.That(cert.IsIssuedBy(faker, verifySignature: false)).IsTrue();
        await Assert.That(cert.IsIssuedBy(faker, verifySignature: true)).IsFalse();
        await Assert.That(cert.IsIssuedBy(issuer, true)).IsTrue();
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsAndExportKeysTestData))]
    public async Task ExportAsPem_ToWriter_RawDataIsEqual(KeyAlgorithm alg, ExportKeys include, string? password)
    {
        using var expected = new CertificateBuilder().SetSubject("CN=Test").SetKeyAlgorithm(alg).Create();

        var pem = expected.Export().WithPassword(password).WithKeys(include).AsPem().ToPemString();

        using var stream = new MemoryStream();
        using (var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true)) {
            writer.Write(pem);
        }

        var parser = new X509CertificateParser();
        var bcCert = parser.ReadCertificate(stream.ToArray());
        using var actual = CertTools.LoadCertificate(bcCert.GetEncoded());

        await AssertExportedKeyBelongsToTheCertificate(pem, include, password, expected);

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
            using var expected = new CertificateBuilder().SetSubject("CN=Test").SetKeyAlgorithm(alg).Create();

            expected.Export().WithPassword(password).WithKeys(include).AsPem().ToFile(tmpFile);
            var parser = new X509CertificateParser();
            var bcCert = parser.ReadCertificate(File.ReadAllBytes(tmpFile));
            using var actual = CertTools.LoadCertificate(bcCert.GetEncoded());

            await AssertExportedKeyBelongsToTheCertificate(
                File.ReadAllText(tmpFile), include, password, expected);

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


    /// <summary>
    /// A PEM export that was asked for a key has to carry that certificate's own private half, readable
    /// with the password it was given. The block's presence and label say neither.
    /// </summary>
    private static async Task AssertExportedKeyBelongsToTheCertificate(
        string pem, ExportKeys include, string? password, X509Certificate2 expected)
    {
        if (include == ExportKeys.None) {
            await Assert.That(pem).DoesNotContain("PRIVATE KEY");
            return;
        }

        using var withKey = password != null
            ? X509Certificate2.CreateFromEncryptedPem(pem, pem, password)
            : X509Certificate2.CreateFromPem(pem, pem);

        await Assert.That(withKey.HasPrivateKey).IsTrue();
        await Assert.That(withKey.Thumbprint).IsEqualTo(expected.Thumbprint);
    }


    public static IEnumerable<KeyAlgorithm> KeyAlgorithmsTestData()
    {
        yield return KeyAlgorithm.ECDsa();
        yield return KeyAlgorithm.RSA();
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

        await Assert.That(cert.IsValidAt(from.AddDays(30))).IsTrue();
        await Assert.That(cert.IsValidAt(from.AddSeconds(-1))).IsFalse();
        await Assert.That(cert.IsValidAt(to.AddSeconds(1))).IsFalse();

        //Both bounds are inclusive
        await Assert.That(cert.IsValidAt(from)).IsTrue();
        await Assert.That(cert.IsValidAt(to)).IsTrue();

    }


    [Test]
    public async Task IsValidAt_SameInstantInDifferentOffsets_GivesTheSameAnswer()
    {
        //A window narrow enough that mistaking the offset for part of the value crosses a bound
        var instant = new DateTimeOffset(2030, 6, 1, 12, 0, 0, TimeSpan.Zero);

        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("Offset Test"))
            .SetNotBefore(instant.AddMinutes(-5))
            .SetNotAfter(instant.AddMinutes(5))
            .Create();

        await Assert.That(cert.IsValidAt(instant)).IsTrue();
        await Assert.That(cert.IsValidAt(instant.ToOffset(TimeSpan.FromHours(10)))).IsTrue();
        await Assert.That(cert.IsValidAt(instant.ToOffset(TimeSpan.FromHours(-8)))).IsTrue();

        //Shifting the instant itself, rather than its representation, does leave the window
        await Assert.That(cert.IsValidAt(instant.AddHours(10))).IsFalse();
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


    public static IEnumerable<(KeyAlgorithm, ExportKeys, string?)> KeyAlgorithmsAndExportKeysTestData()
    {
        yield return (KeyAlgorithm.ECDsa(), ExportKeys.None, TestPassword);
        yield return (KeyAlgorithm.ECDsa(), ExportKeys.Primary, TestPassword);
        yield return (KeyAlgorithm.ECDsa(), ExportKeys.All, TestPassword);
        yield return (KeyAlgorithm.ECDsa(), ExportKeys.None, null);
        yield return (KeyAlgorithm.ECDsa(), ExportKeys.Primary, null);
        yield return (KeyAlgorithm.ECDsa(), ExportKeys.All, null);
        yield return (KeyAlgorithm.RSA(), ExportKeys.None, TestPassword);
        yield return (KeyAlgorithm.RSA(), ExportKeys.Primary, TestPassword);
        yield return (KeyAlgorithm.RSA(), ExportKeys.All, TestPassword);
        yield return (KeyAlgorithm.RSA(), ExportKeys.None, null);
        yield return (KeyAlgorithm.RSA(), ExportKeys.Primary, null);
        yield return (KeyAlgorithm.RSA(), ExportKeys.All, null);
    }


    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task CanSign_WithAWorkingSigningKey_IsTrue(KeyAlgorithm alg)
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(alg)
            .SetSubject("CN=Signer")
            .Create();

        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.CanSign()).IsTrue();
    }


    [Test]
    [SupportedOSPlatform("Windows")]
    [SupportedOSPlatform("Linux")]
    public async Task CanSign_WithADSAKey_IsTrue()
    {
        //DSA signs, however deprecated it is for certificate use
        #pragma warning disable CS0618 // Type or member is obsolete
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.DSA())
            .SetSubject("CN=DSA Signer")
            .Create();
        #pragma warning restore CS0618 // Type or member is obsolete

        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.CanSign()).IsTrue();
    }


    [Test]
    public async Task CanSign_WithoutAPrivateKey_IsFalseAndDoesNotThrow()
    {
        using var signer = new CertificateBuilder().SetSubject("CN=Signer").Create();
        using var keyless = CertTools.LoadCertificate(signer.RawData);

        await Assert.That(keyless.HasPrivateKey).IsFalse();
        await Assert.That(keyless.CanSign()).IsFalse();
    }


    [Test]
    public async Task CanSign_WithAnECDiffieHellmanCertificate_FollowsTheKeyThePlatformHandsBack()
    {
        using var issuer = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=ECDH Issuer")
            .Create();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.SMime)
            .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman())
            .SetSubject("CN=ECDH Subject")
            .SetIssuer(issuer)
            .Create();

        await Assert.That(cert.HasPrivateKey).IsTrue();

        //Whether an EC key was meant for agreement or signing lives in KeyAlgorithm and the KeyUsage
        //bits, never in the key, so CanSign can only report what the platform will hand back
        using var key = cert.GetPrivateKey();
        await Assert.That(cert.CanSign()).IsEqualTo(key.AsAsymmetricAlgorithm is not ECDiffieHellman);

        if (key.AsAsymmetricAlgorithm is ECDsa ecdsa) {
            //Windows takes this branch, and the true answer is not a lie: the key really does sign
            await Assert
                .That(() => ecdsa.SignData(new byte[] { 1, 2, 3 }, HashAlgorithmName.SHA256))
                .ThrowsNothing();
        }
    }


    [Test]
    public async Task CanSign_WithANullCertificate_Throws()
        => await Assert
            .That(() => X509Certificate2Extensions.CanSign(null!))
            .ThrowsExactly<ArgumentNullException>();


    [Test]
    //A key association that outlives its container is a CERT_KEY_PROV_INFO behaviour
    [SupportedOSPlatform("Windows")]
    public async Task CanSign_WhenTheKeyContainerIsDeleted_IsFalseWhileHasPrivateKeyStaysTrue()
    {
        var keyName = NewTestKeyName();
        CreatePersistedRsaKey(keyName, CngExportPolicies.AllowPlaintextExport);
        try {
            using var cert = BuildCertWithPersistedKey(keyName, "CN=Dangling Key");

            await Assert.That(cert.HasPrivateKey).IsTrue();
            await Assert.That(cert.CanSign()).IsTrue()
                .Because("the key container still exists at this point");

            DeletePersistedKey(keyName);

            //The certificate still names a container that no longer exists, which is the state
            //certutil reports as "Missing stored keyset"
            await Assert.That(cert.HasPrivateKey).IsTrue()
                .Because("the association is metadata on the certificate and outlives the key itself");
            await Assert.That(cert.CanSign()).IsFalse();

        } finally {
            DeletePersistedKey(keyName);
        }
    }


    [Test]
    //CNG export policies are a Windows key-storage concept
    [SupportedOSPlatform("Windows")]
    public async Task CanSign_WithANonExportableKey_IsTrueEvenThoughItsMaterialIsWalledOff()
    {
        var keyName = NewTestKeyName();
        CreatePersistedRsaKey(keyName, CngExportPolicies.None);
        try {
            using var cert = BuildCertWithPersistedKey(keyName, "CN=Non Exportable");

            //Signing goes through the key's handle; only the key material is unreachable. Never
            //implement CanSign in terms of exportability.
            await Assert.That(cert.CanSign()).IsTrue();

            using var key = cert.GetPrivateKey();
            await Assert.That(() => key.ExportPkcs8PrivateKey()).Throws<CryptographicException>();

        } finally {
            DeletePersistedKey(keyName);
        }
    }


    private static string NewTestKeyName()
        => $"FluentCertificates.Tests.{Guid.NewGuid():N}";


    [SupportedOSPlatform("Windows")]
    private static void CreatePersistedRsaKey(string name, CngExportPolicies exportPolicy)
    {
        using var key = CngKey.Create(CngAlgorithm.Rsa, name, new CngKeyCreationParameters {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            ExportPolicy = exportPolicy
        });
    }


    [SupportedOSPlatform("Windows")]
    private static X509Certificate2 BuildCertWithPersistedKey(string keyName, string subject)
    {
        //A persisted key makes CopyWithPrivateKey record the container name on the certificate, rather
        //than attaching an ephemeral key that would disappear along with this instance
        using var key = CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        using var rsa = new RSACng(key);
        return new CertificateBuilder().SetSubject(subject).SetKeyPair(rsa).Create();
    }


    [SupportedOSPlatform("Windows")]
    private static void DeletePersistedKey(string name)
    {
        if (!CngKey.Exists(name, CngProvider.MicrosoftSoftwareKeyStorageProvider)) {
            return;
        }
        using var key = CngKey.Open(name, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        key.Delete();
    }


    private const string TestPassword = "nHLYyNcicPsEaV7T";
}
