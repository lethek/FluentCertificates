using System.Security.Cryptography;

namespace FluentCertificates;

public class AsymmetricAlgorithmExtensionsTests
{
    [Test]
    public async Task ToPrivateKeyPemString_NoPassword_WritesUnencryptedPkcs8()
    {
        using var key = ECDsa.Create();

        var pem = key.ToPrivateKeyPemString();

        await Assert.That(pem).Contains("-----BEGIN PRIVATE KEY-----");
        await Assert.That(pem).Contains("-----END PRIVATE KEY-----");
        await Assert.That(pem).DoesNotContain("ENCRYPTED");

        //Round-trips: the PEM really carries this key's private half
        using var reloaded = ECDsa.Create();
        reloaded.ImportFromPem(pem);
        await Assert.That(reloaded.ExportPkcs8PrivateKey()).IsEquivalentTo(key.ExportPkcs8PrivateKey());
    }


    [Test]
    [Arguments("")]
    [Arguments(null)]
    public async Task ToPrivateKeyPemString_EmptyOrNullPassword_IsNotEncrypted(string? password)
    {
        using var key = ECDsa.Create();

        await Assert.That(key.ToPrivateKeyPemString(password)).Contains("-----BEGIN PRIVATE KEY-----");
    }


    [Test]
    public async Task ToPrivateKeyPemString_WithPassword_WritesEncryptedPkcs8()
    {
        using var key = ECDsa.Create();

        var pem = key.ToPrivateKeyPemString("s3cret");

        await Assert.That(pem).Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");
        await Assert.That(pem).Contains("-----END ENCRYPTED PRIVATE KEY-----");

        using var reloaded = ECDsa.Create();
        reloaded.ImportFromEncryptedPem(pem, "s3cret");
        await Assert.That(reloaded.ExportPkcs8PrivateKey()).IsEquivalentTo(key.ExportPkcs8PrivateKey());

        //The wrong password must not open it
        using var wrong = ECDsa.Create();
        await Assert.That(() => wrong.ImportFromEncryptedPem(pem, "wrong")).ThrowsException();
    }


    [Test]
    public async Task ToPublicKeyPemString_WritesSubjectPublicKeyInfo()
    {
        using var key = ECDsa.Create();

        var pem = key.ToPublicKeyPemString();

        await Assert.That(pem).Contains("-----BEGIN PUBLIC KEY-----");
        await Assert.That(pem).DoesNotContain("PRIVATE");

        using var reloaded = ECDsa.Create();
        reloaded.ImportFromPem(pem);
        await Assert.That(reloaded.ExportSubjectPublicKeyInfo()).IsEquivalentTo(key.ExportSubjectPublicKeyInfo());
    }


    [Test]
    public async Task ExportAsPem_ToWriter_WritesAndReturnsTheSameKey()
    {
        using var key = ECDsa.Create();
        using var privateWriter = new StringWriter();
        using var publicWriter = new StringWriter();

        var returnedPrivate = key.ExportAsPrivateKeyPem(privateWriter);
        var returnedPublic = key.ExportAsPublicKeyPem(publicWriter);

        await Assert.That(privateWriter.ToString()).IsEqualTo(key.ToPrivateKeyPemString());
        await Assert.That(publicWriter.ToString()).IsEqualTo(key.ToPublicKeyPemString());
        await Assert.That(returnedPrivate).IsSameReferenceAs(key);
        await Assert.That(returnedPublic).IsSameReferenceAs(key);
    }


    [Test]
    public async Task ExportAsPrivateKeyPem_ToWriterWithPassword_IsEncrypted()
    {
        using var key = ECDsa.Create();
        using var writer = new StringWriter();

        key.ExportAsPrivateKeyPem(writer, "s3cret");

        await Assert.That(writer.ToString()).Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");
    }


    [Test]
    public async Task ExportAsPem_ToFile_WritesAndReturnsTheSameKey()
    {
        using var key = ECDsa.Create();
        var dir = CreateTempDirectory();
        try {
            var privatePath = Path.Combine(dir, "key.pem");
            var publicPath = Path.Combine(dir, "key.pub.pem");

            var returnedPrivate = key.ExportAsPrivateKeyPem(privatePath);
            var returnedPublic = key.ExportAsPublicKeyPem(publicPath);

            await Assert.That(File.ReadAllText(privatePath)).IsEqualTo(key.ToPrivateKeyPemString());
            await Assert.That(File.ReadAllText(publicPath)).IsEqualTo(key.ToPublicKeyPemString());
            await Assert.That(returnedPrivate).IsSameReferenceAs(key);
            await Assert.That(returnedPublic).IsSameReferenceAs(key);
        } finally {
            Directory.Delete(dir, true);
        }
    }


    [Test]
    public async Task ExportAsPrivateKeyPem_ToFileWithPassword_IsEncrypted()
    {
        using var key = ECDsa.Create();
        var dir = CreateTempDirectory();
        try {
            var path = Path.Combine(dir, "key.pem");

            key.ExportAsPrivateKeyPem(path, "s3cret");

            await Assert.That(File.ReadAllText(path)).Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");
        } finally {
            Directory.Delete(dir, true);
        }
    }


    [Test]
    public async Task ToPrivateKeyPemString_RsaKey_RoundTrips()
    {
        using var key = RSA.Create(2048);

        using var reloaded = RSA.Create();
        reloaded.ImportFromPem(key.ToPrivateKeyPemString());

        await Assert.That(reloaded.ExportPkcs8PrivateKey()).IsEquivalentTo(key.ExportPkcs8PrivateKey());
    }


    private static string CreateTempDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fluentcerts-keys-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
