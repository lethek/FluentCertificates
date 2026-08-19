using System.IO.Abstractions.TestingHelpers;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public class CertificateFinderTests
{
    [Test]
    public async Task AddStores_WithEmptyArray_DoesNotThrowAndReturnsNewInstance()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var result = finder.AddStores(Array.Empty<X509Store>());

        await Assert.That(result).IsNotNull();
        await Assert.That(result).IsNotSameReferenceAs(finder);
    }


    [Test]
    public async Task AddDirectories_WithEmptyEnumerable_ReturnsNewInstance()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var result = finder.AddDirectories(Enumerable.Empty<string>());

        await Assert.That(result).IsNotNull();
        await Assert.That(result).IsNotSameReferenceAs(finder);
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
    public async Task AddCommonStores_AddsExpectedNumberOfSources()
    {
        var finder = new CertificateFinder(MockFileSystem).AddCommonStores();

        await Assert.That(finder.Sources.Count).IsEqualTo(7);
    }


    [Test]
    public async Task AddStore_WithValidX509Store_AddsStoreToFinder()
    {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var finder = new CertificateFinder(MockFileSystem).AddStore(store);

        await Assert.That(finder.Sources).HasSingleItem();
    }


    [Test]
    public async Task AddStore_WithNameAndLocation_AddsStoreToFinder()
    {
        var finder = new CertificateFinder(MockFileSystem).AddStore(StoreName.My, StoreLocation.LocalMachine);

        await Assert.That(finder.Sources).HasSingleItem();
    }


    [Test]
    public async Task AddStores_WithMultipleStores_AddsAllStores()
    {
        var store1 = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var store2 = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        var finder = new CertificateFinder(MockFileSystem).AddStores(store1, store2);

        await Assert.That(finder.Sources.Count).IsEqualTo(2);
    }


    [Test]
    public async Task AddDirectory_WithValidPath_AddsDirectorySource()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory(@"/certs");

        await Assert.That(finder.Sources).HasSingleItem();
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

        await Assert.That(finder.Sources.Count).IsEqualTo(2);
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

        await Assert.That(finder.Sources.Count).IsEqualTo(7);
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


    private static readonly MockFileSystem MockFileSystem = TestTools.CreateMockFileSystemWithCerts();
}
