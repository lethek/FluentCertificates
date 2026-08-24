using System.Security;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

/// <summary>
/// The exporter's guards and its <see cref="SecureString"/> password path, which the format-focused tests
/// in <see cref="CertificateExportBuilderTests"/> do not reach.
/// </summary>
public class CertificateExporterGuardTests
{
    [Test]
    public async Task Export_NoCertificates_Throws()
    {
        var ex = await Assert.That(() => Array.Empty<X509Certificate2>().Export().AsPem().ToPemString())
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("No certificates to export");
    }


    /// <summary>
    /// <c>Certificates</c> is publicly settable, so a <c>with</c> expression can leave the anchor pointing at
    /// a certificate the export no longer contains. That has to be refused rather than silently ignored.
    /// </summary>
    [Test]
    public async Task Export_AnchorNotAmongCertificates_Throws()
    {
        using var anchor = new CertificateBuilder().SetSubject(x => x.SetCommonName("Anchor")).Create();
        using var other = new CertificateBuilder().SetSubject(x => x.SetCommonName("Other")).Create();

        var dangling = anchor.Export() with { Certificates = [other] };

        var ex = await Assert.That(() => dangling.AsPem().ToPemString()).ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("anchor certificate is not among the certificates");
    }


    [Test]
    public async Task WithPassword_SecureString_ProducesAPkcs12ThatOpensWithThatPassword()
    {
        using var cert = new CertificateBuilder().SetSubject(x => x.SetCommonName("Secure")).Create();
        using var secure = ToSecureString("s3cret");

        var bytes = cert.Export().WithPrivateKey().WithPassword(secure).AsPkcs12().ToByteArray();

        using var loaded = CertTools.LoadPkcs12(bytes, "s3cret");
        await Assert.That(loaded.Thumbprint).IsEqualTo(cert.Thumbprint);
        await Assert.That(loaded.HasPrivateKey).IsTrue();
    }


    [Test]
    public async Task WithPassword_SecureString_ThenWithoutPassword_ClearsIt()
    {
        using var cert = new CertificateBuilder().SetSubject(x => x.SetCommonName("Secure")).Create();
        using var secure = ToSecureString("s3cret");

        var bytes = cert.Export().WithPassword(secure).WithoutPassword().AsPkcs12().ToByteArray();

        using var loaded = CertTools.LoadPkcs12(bytes, null);
        await Assert.That(loaded.Thumbprint).IsEqualTo(cert.Thumbprint);
    }


    /// <summary>
    /// The last <c>WithPassword</c> wins: each overload clears the other kind.
    /// </summary>
    [Test]
    public async Task WithPassword_StringAfterSecureString_ReplacesIt()
    {
        using var cert = new CertificateBuilder().SetSubject(x => x.SetCommonName("Secure")).Create();
        using var secure = ToSecureString("first");

        var builder = cert.Export().WithPassword(secure).WithPassword("second");

        await Assert.That(builder.SecurePassword).IsNull();
        await Assert.That(builder.Password).IsEqualTo("second");

        using var loaded = CertTools.LoadPkcs12(builder.AsPkcs12().ToByteArray(), "second");
        await Assert.That(loaded.Thumbprint).IsEqualTo(cert.Thumbprint);
    }


    [Test]
    public async Task WithPassword_SecureStringAfterString_ReplacesIt()
    {
        using var cert = new CertificateBuilder().SetSubject(x => x.SetCommonName("Secure")).Create();
        using var secure = ToSecureString("second");

        var builder = cert.Export().WithPassword("first").WithPassword(secure);

        await Assert.That(builder.Password).IsNull();

        //The SecureString that survived has to be the second one, not merely some SecureString
        using var loaded = CertTools.LoadPkcs12(builder.AsPkcs12().ToByteArray(), "second");
        await Assert.That(loaded.Thumbprint).IsEqualTo(cert.Thumbprint);
    }


    [Test]
    public async Task SecureString_PemExport_IsEncryptedWithThatPassword()
    {
        using var cert = new CertificateBuilder().SetSubject(x => x.SetCommonName("Secure")).Create();
        using var secure = ToSecureString("s3cret");

        var pem = cert.Export().WithPrivateKey().WithPassword(secure).AsPem().ToPemString();

        await Assert.That(pem).Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");
        await Assert.That(pem).Contains("-----BEGIN CERTIFICATE-----");

        //The header only says something encrypted it. Opening it is what proves the SecureString's
        //characters reached the exporter rather than some other password.
        using var reloaded = X509Certificate2.CreateFromEncryptedPem(pem, pem, "s3cret");
        await Assert.That(reloaded.Thumbprint).IsEqualTo(cert.Thumbprint);
        await Assert.That(reloaded.HasPrivateKey).IsTrue();

        await Assert
            .That(() => {
                using var wrong = X509Certificate2.CreateFromEncryptedPem(pem, pem, "wrong");
            })
            .ThrowsException();
    }


    private static SecureString ToSecureString(string value)
    {
        var secure = new SecureString();
        foreach (var c in value) {
            secure.AppendChar(c);
        }
        secure.MakeReadOnly();
        return secure;
    }
}
