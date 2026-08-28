using System.IO.Abstractions.TestingHelpers;
using System.Security.Cryptography.X509Certificates;
using System.Text;

// TUnit's implicit `using static TUnit.Core.HookType` makes the bare name `Assembly` ambiguous
using Assembly = System.Reflection.Assembly;

namespace FluentCertificates;

public static class TestTools
{
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
