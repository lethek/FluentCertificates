using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// The export builder works on certificates, so a CSR keeps its own PEM helpers. They are the only way to
/// get a PKCS#10 request out of this library.
/// </summary>
public class CertificateRequestExtensionsTests
{
    [Test]
    public async Task ToPemString_WritesACertificateRequestBlock()
    {
        using var key = ECDsa.Create();
        var request = NewRequest(key);

        var pem = request.ToPemString();

        await Assert.That(pem).Contains("-----BEGIN CERTIFICATE REQUEST-----");
        await Assert.That(pem).Contains("-----END CERTIFICATE REQUEST-----");
        await Assert.That(pem).DoesNotContain("PRIVATE");
    }


    [Test]
    public async Task ExportAsPem_ToWriter_WritesAndReturnsTheSameRequest()
    {
        using var key = ECDsa.Create();
        var request = NewRequest(key);
        using var writer = new StringWriter();

        var returned = request.ExportAsPem(writer);

        await Assert.That(writer.ToString()).Contains("-----BEGIN CERTIFICATE REQUEST-----");
        await Assert.That(returned).IsSameReferenceAs(request);
    }


    [Test]
    public async Task ExportAsPem_ToFile_WritesAndReturnsTheSameRequest()
    {
        using var key = ECDsa.Create();
        var request = NewRequest(key);
        var dir = Path.Combine(Path.GetTempPath(), "fluentcerts-csr-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try {
            var path = Path.Combine(dir, "request.pem");

            var returned = request.ExportAsPem(path);

            await Assert.That(File.ReadAllText(path)).Contains("-----BEGIN CERTIFICATE REQUEST-----");
            await Assert.That(returned).IsSameReferenceAs(request);
        } finally {
            Directory.Delete(dir, true);
        }
    }


    /// <summary>
    /// The PEM body must be the request's own DER, not merely a well-formed block. RSA rather than
    /// ECDSA because a PKCS#1 v1.5 signature is deterministic, so two encodings compare equal.
    /// </summary>
    [Test]
    public async Task ToPemString_CarriesTheRequestsOwnEncoding()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=CSR Test"), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var pem = request.ToPemString();
        var der = Convert.FromBase64String(
            String.Concat(pem.Split('\n').Where(x => !x.StartsWith("-----")).Select(x => x.Trim())));

        await Assert.That(der).IsEquivalentTo(request.CreateSigningRequest());
    }


    private static CertificateRequest NewRequest(ECDsa key)
        => new(new X500DistinguishedName("CN=CSR Test"), key, HashAlgorithmName.SHA256);
}
