using System.IO.Abstractions.TestingHelpers;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

public class CertificateFinderTests
{
    [Fact]
    public void AddStores_WithEmptyArray_DoesNotThrowAndReturnsNewInstance()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var result = finder.AddStores(Array.Empty<X509Store>());

        Assert.NotNull(result);
        Assert.NotSame(finder, result);
    }

    
    [Fact]
    public void AddDirectories_WithEmptyEnumerable_ReturnsNewInstance()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var result = finder.AddDirectories(Enumerable.Empty<string>());

        Assert.NotNull(result);
        Assert.NotSame(finder, result);
    }

    
    [Fact]
    public void ClearSources_ReturnsNewInstanceWithNoSources()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var cleared = finder.ClearSources();

        Assert.NotNull(cleared);
        Assert.NotSame(finder, cleared);
        Assert.Empty(cleared.Sources);
    }

    
    [Fact]
    public void AddCommonStores_AddsExpectedNumberOfSources()
    {
        var finder = new CertificateFinder(MockFileSystem).AddCommonStores();

        Assert.Equal(7, finder.Sources.Count);
    }


    [Fact]
    public void AddStore_WithValidX509Store_AddsStoreToFinder()
    {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var finder = new CertificateFinder(MockFileSystem).AddStore(store);

        Assert.Single(finder.Sources);
    }

    
    [Fact]
    public void AddStore_WithNameAndLocation_AddsStoreToFinder()
    {
        var finder = new CertificateFinder(MockFileSystem).AddStore(StoreName.My, StoreLocation.LocalMachine);

        Assert.Single(finder.Sources);
    }

    
    [Fact]
    public void AddStores_WithMultipleStores_AddsAllStores()
    {
        var store1 = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var store2 = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        var finder = new CertificateFinder(MockFileSystem).AddStores(store1, store2);

        Assert.Equal(2, finder.Sources.Count);
    }

    
    [Fact]
    public void AddDirectory_WithValidPath_AddsDirectorySource()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory(@"/certs");

        Assert.Single(finder.Sources);
    }

    
    [Fact]
    public void AddDirectory_WithNonExistentPath_DoesNotThrow()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var ex = Record.Exception(() => finder.AddDirectory("/nonexistent"));

        Assert.Null(ex);
    }

    
    [Fact]
    public void AddDirectories_WithMultiplePaths_AddsAllDirectories()
    {
        var dirs = new[] { "/certs", "/backup/certs" };
        var finder = new CertificateFinder(MockFileSystem).AddDirectories(dirs);

        Assert.Equal(2, finder.Sources.Count);
    }


    [Fact]
    public void AddCustomSource_WithEmptyList_AddsCustomSource()
    {
        var customSource = new List<CertificateFinderResult>();
        var finder = new CertificateFinder(MockFileSystem).AddCustomSource(customSource);
        
        Assert.Single(finder.Sources);
        Assert.Collection(finder.Sources, x => customSource.Equals(x));
    }


    [Fact]
    public void AddCommonStores_AddsExpectedStores()
    {
        var finder = new CertificateFinder(MockFileSystem).AddCommonStores();

        Assert.Equal(7, finder.Sources.Count);
    }


    [Fact]
    public void EnumerateCertificates_WithValidPath_ReturnsExpectedResults()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/certs");
        var results = finder.ToList();

        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.NotNull(r.Certificate));
        Assert.All(results, r => Assert.NotNull(r.Directory));
    }

    
    [Fact]
    public void EnumerateCertificates_WithNonExistentPath_ThrowsDirectoryNotFoundException()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/nonexistent");
        var ex = Record.Exception(() => finder.ToList());

        Assert.IsType<DirectoryNotFoundException>(ex);
    }
    
    
    [Fact]
    public void EnumerateCertificates_FromEmptyFinder_ReturnsEmpty()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var results = finder.ToList();

        Assert.Empty(results);
    }

    
    [Fact]
    public void EnumerateCertificates_FromCustomSource_ReturnsAllResults()
    {
        var certResult1 = TestTools.LoadCertificateFinderResultMock(MockFileSystem, "/certs/ecdsa-no-key.pem");
        var certResult2 = TestTools.LoadCertificateFinderResultMock(MockFileSystem, "/certs/ecdsa-with-key.pem");
        var customSource = new[] { certResult1, certResult2 };

        var finder = new CertificateFinder(MockFileSystem).AddCustomSource(customSource);
        var results = finder.ToList();

        Assert.Equal(2, results.Count);
        Assert.Contains(certResult1, results);
        Assert.Contains(certResult2, results);
    }    

  
    private static readonly MockFileSystem MockFileSystem = TestTools.CreateMockFileSystemWithCerts();
}
