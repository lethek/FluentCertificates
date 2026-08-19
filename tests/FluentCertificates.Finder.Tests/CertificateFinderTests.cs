using System.IO.Abstractions.TestingHelpers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class CertificateFinderTests
{
    [Test]
    public async Task AddStores_WithEmptyArray_AddsNoSources()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var result = finder.AddStores(Array.Empty<X509Store>());

        await Assert.That(result.Sources).IsEmpty();
    }


    [Test]
    public async Task AddDirectories_WithEmptyEnumerable_AddsNoSources()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var result = finder.AddDirectories(Enumerable.Empty<string>());

        await Assert.That(result.Sources).IsEmpty();
    }


    [Test]
    public async Task ClearSources_ReturnsNewInstanceWithNoSources()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var cleared = finder.ClearSources();

        await Assert.That(cleared).IsNotNull();
        await Assert.That(cleared).IsNotSameReferenceAs(finder);
        await Assert.That(cleared.Sources).IsEmpty();
    }


    [Test]
    public async Task AddStore_WithValidX509Store_AddsStoreToFinder()
    {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var finder = new CertificateFinder(MockFileSystem).AddStore(store);

        await Assert
            .That(StoresOf(finder))
            .IsEquivalentTo(new[] { ("My", StoreLocation.CurrentUser) }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddStore_WithNameAndLocation_AddsStoreToFinder()
    {
        var finder = new CertificateFinder(MockFileSystem).AddStore(StoreName.My, StoreLocation.LocalMachine);

        await Assert
            .That(StoresOf(finder))
            .IsEquivalentTo(new[] { ("My", StoreLocation.LocalMachine) }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddStores_WithMultipleStores_AddsAllStores()
    {
        var store1 = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var store2 = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        var finder = new CertificateFinder(MockFileSystem).AddStores(store1, store2);

        await Assert
            .That(StoresOf(finder))
            .IsEquivalentTo(new[] {
                ("My", StoreLocation.CurrentUser),
                ("Root", StoreLocation.LocalMachine)
            }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddDirectory_WithValidPath_AddsDirectorySource()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/certs");

        await Assert
            .That(DirectoryPathsOf(finder))
            .IsEquivalentTo(new[] { "/certs" }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddDirectory_WithNonExistentPath_DoesNotThrow()
    {
        var finder = new CertificateFinder(MockFileSystem);

        await Assert.That(() => finder.AddDirectory("/nonexistent")).ThrowsNothing();
    }


    [Test]
    public async Task AddDirectories_WithMultiplePaths_AddsAllDirectories()
    {
        var dirs = new[] { "/certs", "/backup/certs" };
        var finder = new CertificateFinder(MockFileSystem).AddDirectories(dirs);

        await Assert.That(DirectoryPathsOf(finder)).IsEquivalentTo(dirs, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddCustomSource_WithEmptyList_AddsCustomSource()
    {
        var customSource = new List<CertificateFinderResult>();
        var finder = new CertificateFinder(MockFileSystem).AddCustomSource(customSource);

        await Assert.That(finder.Sources).HasSingleItem();
        await Assert.That(finder.Sources[0]).IsSameReferenceAs(customSource);
    }


    [Test]
    public async Task AddCommonStores_AddsExpectedStores()
    {
        var finder = new CertificateFinder(MockFileSystem).AddCommonStores();

        await Assert
            .That(StoresOf(finder))
            .IsEquivalentTo(new[] {
                ("My", StoreLocation.CurrentUser),
                ("CA", StoreLocation.CurrentUser),
                ("Root", StoreLocation.CurrentUser),
                ("My", StoreLocation.LocalMachine),
                ("CA", StoreLocation.LocalMachine),
                ("Root", StoreLocation.LocalMachine),
                ("WebHosting", StoreLocation.LocalMachine)
            }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task EnumerateCertificates_WithValidPath_ReturnsExpectedResults()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/certs");
        var results = finder.ToList();

        await Assert.That(results.Count).IsEqualTo(2);
        await Assert.That(results).All(r => r.Certificate != null);
        await Assert.That(results).All(r => r.Directory != null);
    }


    [Test]
    public async Task EnumerateCertificates_WithNonExistentPath_ThrowsDirectoryNotFoundException()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/nonexistent");

        await Assert.That(() => finder.ToList()).ThrowsExactly<DirectoryNotFoundException>();
    }


    [Test]
    public async Task EnumerateCertificates_FromEmptyFinder_ReturnsEmpty()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var results = finder.ToList();

        await Assert.That(results).IsEmpty();
    }


    [Test]
    public async Task EnumerateCertificates_FromCustomSource_ReturnsAllResults()
    {
        var certResult1 = TestTools.LoadCertificateFinderResultMock(MockFileSystem, "/certs/ecdsa-no-key.pem");
        var certResult2 = TestTools.LoadCertificateFinderResultMock(MockFileSystem, "/certs/ecdsa-with-key.pem");
        var customSource = new[] { certResult1, certResult2 };

        var finder = new CertificateFinder(MockFileSystem).AddCustomSource(customSource);
        var results = finder.ToList();

        await Assert.That(results.Count).IsEqualTo(2);
        await Assert.That(results).Contains(certResult1);
        await Assert.That(results).Contains(certResult2);
    }


    [Test]
    public async Task Where_FiltersToMatchingCertificates()
    {
        using var match = CreateSelfSignedCertificate("Match");
        using var other1 = CreateSelfSignedCertificate("Other1");
        using var other2 = CreateSelfSignedCertificate("Other2");

        var finder = new CertificateFinder(MockFileSystem)
            .AddCustomSource([
                new CertificateFinderResult { Certificate = other1 },
                new CertificateFinderResult { Certificate = match },
                new CertificateFinderResult { Certificate = other2 }
            ]);

        var results = finder.Where(r => r.Certificate.Subject.Contains("CN=Match")).ToList();

        await Assert.That(results.Count).IsEqualTo(1);
        await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(match.Thumbprint);
    }


    [Test]
    public async Task EnumerateCertificates_DirectoryWithMixedFiles_ReturnsOnlyCertificates()
    {
        using var cert = CreateSelfSignedCertificate("Mixed");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/mixed/notes.txt", new MockFileData("this is not a certificate"));
        fs.AddFile("/mixed/image.png", new MockFileData(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }));
        fs.AddFile("/mixed/cert.pem", new MockFileData(cert.ExportCertificatePem()));

        var finder = new CertificateFinder(fs).AddDirectory("/mixed");
        var results = finder.ToList();

        await Assert.That(results.Count).IsEqualTo(1);
        await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);
    }


    [Test]
    public async Task EnumerateCertificates_MalformedPemFile_IsSkippedWithoutThrowing()
    {
        using var cert = CreateSelfSignedCertificate("Valid");
        var fs = CreateEmptyMockFileSystem();
        const string truncatedPem = """
            -----BEGIN CERTIFICATE-----
            MIIBwTCCASKgAwIBAgISTVgI
            """;
        fs.AddFile("/malformed/truncated.pem", new MockFileData(truncatedPem));
        fs.AddFile("/malformed/garbage.pem", new MockFileData("not base64 at all"));
        fs.AddFile("/malformed/empty.pem", new MockFileData(String.Empty));
        fs.AddFile("/malformed/valid.pem", new MockFileData(cert.ExportCertificatePem()));

        var finder = new CertificateFinder(fs).AddDirectory("/malformed");

        //Unreadable certificate files are skipped rather than throwing, so a bad file
        //in a directory does not hide the good ones alongside it
        await Assert.That(() => finder.ToList()).ThrowsNothing();

        var results = finder.ToList();
        await Assert.That(results.Count).IsEqualTo(1);
        await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);
    }


    [Test]
    public async Task EnumerateCertificates_UppercaseFileExtension_IsSkipped()
    {
        using var cert = CreateSelfSignedCertificate("Uppercase");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/case/cert.PEM", new MockFileData(cert.ExportCertificatePem()));

        var finder = new CertificateFinder(fs).AddDirectory("/case");

        //Documents current behaviour: the supported-extension check is case-sensitive, so
        //an otherwise valid certificate with an uppercase extension is not found
        await Assert.That(finder.ToList()).IsEmpty();
    }


    [Test]
    public async Task ClearSources_AfterAddCommonStores_IsEmpty()
    {
        var finder = new CertificateFinder(MockFileSystem).AddCommonStores();
        await Assert.That(finder.Sources).IsNotEmpty();

        var cleared = finder.ClearSources();

        await Assert.That(cleared.Sources).IsEmpty();
        await Assert.That(cleared.ToList()).IsEmpty();
    }


    private static X509Certificate2 CreateSelfSignedCertificate(string commonName)
    {
        using var key = ECDsa.Create();
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
    }


    private static MockFileSystem CreateEmptyMockFileSystem()
        => new(new MockFileSystemOptions { CreateDefaultTempDir = false });


    private static List<(string Name, StoreLocation Location)> StoresOf(CertificateFinder finder)
        => finder.Sources
            .Cast<CertificateStoreEnumerable>()
            .Select(x => (x.Store.Name, x.Store.Location))
            .ToList();


    private static List<string> DirectoryPathsOf(CertificateFinder finder)
        => finder.Sources
            .Cast<CertificateDirectoryEnumerable>()
            .Select(x => x.Directory.Path)
            .ToList();


    private static readonly MockFileSystem MockFileSystem = TestTools.CreateMockFileSystemWithCerts();
}
