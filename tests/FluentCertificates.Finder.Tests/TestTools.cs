using System.IO.Abstractions.TestingHelpers;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FluentCertificates;

public static class TestTools
{
    internal static CertificateFinderResult LoadCertificateFinderResultMock(MockFileSystem fs, string path)
        => new() { Certificate = LoadCertificateMock(fs, path) };


    internal static X509Certificate2 LoadCertificateMock(MockFileSystem fs, string path)
    {
        var file = fs.GetFile(path);
        var pem = Encoding.UTF8.GetString(file.Contents);
        return X509Certificate2.CreateFromPem(pem);
    }

    
    internal static X509Certificate2 LoadCertificateResource(string fileName)
    {
        var resourceName = $"{ResourcePrefix}.{fileName}";
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
        if (stream is null) {
            throw new InvalidOperationException($"Could not load resource {resourceName}");
        }
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var pem = reader.ReadToEnd();
        return X509Certificate2.CreateFromPem(pem);
    }


    internal static MockFileSystem CreateMockFileSystemWithCerts()
    {
        const string certsDir = "/certs";
        var fs = new MockFileSystem(new MockFileSystemOptions { CreateDefaultTempDir = false });
        fs.AddFilesFromEmbeddedNamespace(certsDir, Assembly.GetExecutingAssembly(), ResourcePrefix);
        return fs;
    }

    
    private const string ResourcePrefix = "FluentCertificates.TestData";
}
