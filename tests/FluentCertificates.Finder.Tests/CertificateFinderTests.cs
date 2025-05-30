using System.IO.Abstractions.TestingHelpers;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Finder.Tests;

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
    public void ClearStores_OnEmptyFinder_ReturnsNewInstanceWithNoStores()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var cleared = finder.ClearStores();
        Assert.NotNull(cleared);
        Assert.NotSame(finder, cleared);
        Assert.Empty(cleared.Stores);
    }

    
    [Fact]
    public void AddCommonStores_AddsExpectedNumberOfStores()
    {
        var finder = new CertificateFinder(MockFileSystem).AddCommonStores();
        Assert.Equal(7, finder.Stores.Count);
    }


    [Fact]
    public void AddStore_WithValidX509Store_AddsStoreToFinder()
    {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var finder = new CertificateFinder(MockFileSystem).AddStore(store);

        Assert.Single(finder.Stores);
    }

    
    [Fact]
    public void AddStore_WithNameAndLocation_AddsStoreToFinder()
    {
        var finder = new CertificateFinder(MockFileSystem).AddStore(StoreName.My, StoreLocation.LocalMachine);

        Assert.Single(finder.Stores);
    }

    
    [Fact]
    public void AddStores_WithMultipleStores_AddsAllStores()
    {
        var store1 = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var store2 = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        var finder = new CertificateFinder(MockFileSystem).AddStores(store1, store2);

        Assert.Equal(2, finder.Stores.Count);
    }

    
    [Fact]
    public void AddDirectory_WithValidPath_AddsDirectorySource()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory(@"/certs");

        Assert.Single(finder.Stores);
    }

    
    [Fact]
    public void AddDirectories_WithMultiplePaths_AddsAllDirectories()
    {
        var dirs = new[] { "/certs", "/backup/certs" };
        var finder = new CertificateFinder(MockFileSystem).AddDirectories(dirs);

        Assert.Equal(2, finder.Stores.Count);
    }

    
    [Fact]
    public void AddCustomSource_WithValidSource_AddsCustomSource()
    {
        var customSource = new List<CertificateFinderResult>();
        var finder = new CertificateFinder(MockFileSystem).AddCustomSource(customSource);
        
        Assert.Single(finder.Stores);
        Assert.Collection(finder.Stores, x => customSource.Equals(x));
    }

    
    [Fact]
    public void ClearStores_RemovesAllStores()
    {
        var finder = new CertificateFinder(MockFileSystem)
            .AddStore(StoreName.My, StoreLocation.CurrentUser)
            .ClearStores();

        Assert.Empty(finder);
    }

    
    [Fact]
    public void AddCommonStores_AddsExpectedStores()
    {
        var finder = new CertificateFinder(MockFileSystem).AddCommonStores();

        Assert.Equal(7, finder.Stores.Count);
    }

    
    [Fact]
    public void AddDirectory_WithNonExistentPath_DoesNotThrow()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var ex = Record.Exception(() => finder.AddDirectory("/nonexistent"));

        Assert.Null(ex);
    }

    
    [Fact]
    public void AddCustomSources_WithEmptyEnumerable_DoesNotThrow()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var ex = Record.Exception(() => finder.AddCustomSources(Enumerable.Empty<IEnumerable<CertificateFinderResult>>()));

        Assert.Null(ex);
    }


    private static readonly MockFileSystem MockFileSystem = CreateMockFileSystemWithCerts();


    private static MockFileSystem CreateMockFileSystemWithCerts() 
    {
        const string certsDir = "/certs";

        var fs = new MockFileSystem();
        fs.AddDirectory(certsDir);

        // Add some mock certificate files
        fs.AddFile(fs.Path.Combine(certsDir, "ecdsa-no-key.pem"), new MockFileData(ReadResource("ecdsa-no-key.pem")));
        fs.AddFile(fs.Path.Combine(certsDir, "ecdsa-with-key.pem"), new MockFileData(ReadResource("ecdsa-with-key.pem")));
        
        return fs;
    }
    
    
    private static byte[] ReadResource(string fileName)
    {
        var resourceName = $"{ResourcePrefix}.{fileName}";
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
        if (stream is null) {
            throw new InvalidOperationException($"Could not load resource {resourceName}");
        }
        using var memoryStream = new MemoryStream();
        stream.CopyTo(memoryStream);
        return memoryStream.ToArray();
    }


    const string ResourcePrefix = "FluentCertificates.TestData";
}
