using System.IO.Abstractions.TestingHelpers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
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
    public async Task ClearSources_LeavesTheOriginalFinderIntact()
    {
        var finder = new CertificateFinder(MockFileSystem).AddStore(StoreName.My, StoreLocation.CurrentUser);

        var cleared = finder.ClearSources();

        //Clearing produces a new finder rather than emptying this one, so the original still has its store
        await Assert.That(cleared.Sources).IsEmpty();
        await Assert
            .That(StoresOf(finder))
            .IsEquivalentTo([("My", StoreLocation.CurrentUser)], CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddStore_WithValidX509Store_AddsStoreToFinder()
    {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var finder = new CertificateFinder(MockFileSystem).AddStore(store);

        await Assert
            .That(StoresOf(finder))
            .IsEquivalentTo([("My", StoreLocation.CurrentUser)], CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddStore_WithNameAndLocation_AddsStoreToFinder()
    {
        var finder = new CertificateFinder(MockFileSystem).AddStore(StoreName.My, StoreLocation.LocalMachine);

        await Assert
            .That(StoresOf(finder))
            .IsEquivalentTo([("My", StoreLocation.LocalMachine)], CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddStores_WithMultipleStores_AddsAllStores()
    {
        var store1 = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        var store2 = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        var finder = new CertificateFinder(MockFileSystem).AddStores(store1, store2);

        await Assert
            .That(StoresOf(finder))
            .IsEquivalentTo([
                ("My", StoreLocation.CurrentUser),
                ("Root", StoreLocation.LocalMachine)
            ], CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddDirectory_WithValidPath_AddsDirectorySource()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/certs");

        await Assert
            .That(DirectoryPathsOf(finder))
            .IsEquivalentTo(["/certs"], CollectionOrdering.Matching);
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
            .IsEquivalentTo([
                ("My", StoreLocation.CurrentUser),
                ("CA", StoreLocation.CurrentUser),
                ("Root", StoreLocation.CurrentUser),
                ("My", StoreLocation.LocalMachine),
                ("CA", StoreLocation.LocalMachine),
                ("Root", StoreLocation.LocalMachine),
                ("WebHosting", StoreLocation.LocalMachine)
            ], CollectionOrdering.Matching);
    }


    [Test]
    public async Task EnumerateCertificates_WithValidPath_ReturnsExpectedResults()
    {
        using var expectedNoKey = TestTools.LoadCertificateResource("ecdsa-no-key.pem");
        using var expectedWithKey = TestTools.LoadCertificateResource("ecdsa-with-key.pem");

        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/certs");
        var results = finder.ToList();

        //Both files in the directory, identified rather than merely counted
        await Assert
            .That(results.Select(r => r.Certificate.Thumbprint))
            .IsEquivalentTo([expectedNoKey.Thumbprint, expectedWithKey.Thumbprint], CollectionOrdering.Any);

        //Directory is nullable and records where each result came from, so it has to be the one searched
        await Assert.That(results.Select(r => r.Directory!.Path).Distinct()).IsEquivalentTo(["/certs"]);
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
        fs.AddFile("/mixed/image.png", new MockFileData([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]));
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
    [Arguments("cert.PEM")]
    [Arguments("cert.Pem")]
    [Arguments("cert.pem")]
    public async Task EnumerateCertificates_ExtensionCaseIsIgnored(string fileName)
    {
        using var cert = CreateSelfSignedCertificate("AnyCase");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile($"/case/{fileName}", new MockFileData(cert.ExportCertificatePem()));

        var finder = new CertificateFinder(fs).AddDirectory("/case");
        var results = finder.ToList();

        await Assert.That(results.Count).IsEqualTo(1);
        await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);
    }


    [Test]
    public async Task EnumerateCertificates_UnsupportedExtension_IsStillSkipped()
    {
        using var cert = CreateSelfSignedCertificate("Unsupported");
        var fs = CreateEmptyMockFileSystem();

        //Valid certificate content, but an extension the finder does not claim to support
        fs.AddFile("/unsupported/cert.txt", new MockFileData(cert.ExportCertificatePem()));
        fs.AddFile("/unsupported/cert.PEMX", new MockFileData(cert.ExportCertificatePem()));

        var finder = new CertificateFinder(fs).AddDirectory("/unsupported");

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


    [Test]
    [Arguments(StoreName.AddressBook, "AddressBook")]
    [Arguments(StoreName.AuthRoot, "AuthRoot")]
    [Arguments(StoreName.CertificateAuthority, "CA")]
    [Arguments(StoreName.Disallowed, "Disallowed")]
    [Arguments(StoreName.My, "My")]
    [Arguments(StoreName.Root, "Root")]
    [Arguments(StoreName.TrustedPeople, "TrustedPeople")]
    [Arguments(StoreName.TrustedPublisher, "TrustedPublisher")]
    public async Task AddStore_MapsStoreNameToStoreString(StoreName name, string expected)
    {
        //CertificateAuthority maps to "CA": the enum name and the store name deliberately differ
        var finder = new CertificateFinder(MockFileSystem).AddStore(name, StoreLocation.CurrentUser);

        await Assert
            .That(StoresOf(finder))
            .IsEquivalentTo([(expected, StoreLocation.CurrentUser)], CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddStore_UnsupportedStoreName_Throws()
    {
        var ex = await Assert
            .That(() => new CertificateFinder(MockFileSystem).AddStore((StoreName)999, StoreLocation.CurrentUser))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("Unsupported StoreName value: 999");
        await Assert.That(ex.ParamName).IsEqualTo("name");
    }


    [Test]
    [Arguments(StoreName.AddressBook, "AddressBook")]
    [Arguments(StoreName.AuthRoot, "AuthRoot")]
    [Arguments(StoreName.CertificateAuthority, "CA")]
    [Arguments(StoreName.Disallowed, "Disallowed")]
    [Arguments(StoreName.My, "My")]
    [Arguments(StoreName.Root, "Root")]
    [Arguments(StoreName.TrustedPeople, "TrustedPeople")]
    [Arguments(StoreName.TrustedPublisher, "TrustedPublisher")]
    public async Task CertificateStore_MapsStoreNameToItsSystemName(StoreName name, string expected)
    {
        //CertificateAuthority is the one whose system name differs from its enum name
        var store = new CertificateStore(name, StoreLocation.CurrentUser);

        await Assert.That(store.Name).IsEqualTo(expected);
        await Assert.That(store.Location).IsEqualTo(StoreLocation.CurrentUser);
    }


    /// <summary>
    /// A store that does not exist yields no results rather than throwing, and is not created by being
    /// searched: the finder opens read-only and existing-only.
    /// </summary>
    [Test]
    public async Task EnumerateCertificates_StoreDoesNotExist_ReturnsEmpty()
    {
        var name = "FluentCertificatesMissing" + Guid.NewGuid().ToString("N")[..8];

        var results = new CertificateFinder().AddStore(name, StoreLocation.CurrentUser).ToList();

        await Assert.That(results).IsEmpty();
    }


    /// <summary>
    /// Recursion is opt-in: the default enumerates the top directory alone, so a certificate one level down
    /// is found only when the caller asks for it.
    /// </summary>
    [Test]
    [Arguments(false, 1)]
    [Arguments(true, 2)]
    public async Task EnumerateCertificates_Recurse_ControlsWhetherSubdirectoriesAreSearched(bool recurse, int expected)
    {
        using var top = CreateSelfSignedCertificate("Top");
        using var nested = CreateSelfSignedCertificate("Nested");
        var dir = CreateRealTempDirectory();
        try {
            var sub = Path.Combine(dir, "sub");
            Directory.CreateDirectory(sub);
            File.WriteAllText(Path.Combine(dir, "top.pem"), top.ExportCertificatePem());
            File.WriteAllText(Path.Combine(sub, "nested.pem"), nested.ExportCertificatePem());

            var results = new CertificateFinder().AddDirectory(dir, recurse).ToList();

            await Assert.That(results.Count).IsEqualTo(expected);
            await Assert.That(results.Select(x => x.Certificate.Thumbprint)).Contains(top.Thumbprint);
        } finally {
            Directory.Delete(dir, true);
        }
    }


    /// <summary>
    /// The params overload of <see cref="CertificateFinder.AddDirectories(string[])"/> does not recurse,
    /// which is why the recursing form is a separate overload.
    /// </summary>
    [Test]
    public async Task EnumerateCertificates_AddDirectoriesParams_DoesNotRecurse()
    {
        using var top = CreateSelfSignedCertificate("Top");
        using var nested = CreateSelfSignedCertificate("Nested");
        var dir = CreateRealTempDirectory();
        try {
            var sub = Path.Combine(dir, "sub");
            Directory.CreateDirectory(sub);
            File.WriteAllText(Path.Combine(dir, "top.pem"), top.ExportCertificatePem());
            File.WriteAllText(Path.Combine(sub, "nested.pem"), nested.ExportCertificatePem());

            var results = new CertificateFinder().AddDirectories(dir).ToList();

            await Assert.That(results.Count).IsEqualTo(1);
            await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(top.Thumbprint);
        } finally {
            Directory.Delete(dir, true);
        }
    }


    /// <summary>
    /// The enumeration pattern matches every file and filters by extension afterwards, so a certificate whose
    /// name has no extension-like prefix is still seen.
    /// </summary>
    [Test]
    public async Task EnumerateCertificates_FindsFilesWhateverTheirName()
    {
        using var cert = CreateSelfSignedCertificate("Odd");
        var dir = CreateRealTempDirectory();
        try {
            File.WriteAllText(Path.Combine(dir, ".hidden.pem"), cert.ExportCertificatePem());

            var results = new CertificateFinder().AddDirectory(dir).ToList();

            await Assert.That(results.Count).IsEqualTo(1);
        } finally {
            Directory.Delete(dir, true);
        }
    }


    [Test]
    [Arguments("cert.pem", "pem")]
    [Arguments("cert.ca-bundle", "pem")]
    [Arguments("cert.crt", "der")]
    [Arguments("cert.cer", "der")]
    [Arguments("cert.der", "der")]
    [Arguments("cert.pfx", "pkcs12")]
    [Arguments("cert.p12", "pkcs12")]
    [Arguments("cert.p7b", "pkcs7")]
    [Arguments("cert.p7c", "pkcs7")]
    public async Task EnumerateCertificates_EachSupportedExtension_IsLoaded(string fileName, string format)
    {
        using var cert = CreateSelfSignedCertificate("Formats");
        var dir = CreateRealTempDirectory();
        try {
            var path = Path.Combine(dir, fileName);
            switch (format) {
                case "pem": File.WriteAllText(path, cert.ExportCertificatePem()); break;
                case "der": File.WriteAllBytes(path, cert.RawData); break;
                case "pkcs12": File.WriteAllBytes(path, cert.Export(X509ContentType.Pkcs12)!); break;
                case "pkcs7": File.WriteAllBytes(path, BuildPkcs7(cert)); break;
                default: throw new ArgumentOutOfRangeException(nameof(format), format, null);
            }

            var results = new CertificateFinder().AddDirectory(dir).ToList();

            await Assert.That(results.Count).IsEqualTo(1);
            await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);
        } finally {
            Directory.Delete(dir, true);
        }
    }


    private static byte[] BuildPkcs7(X509Certificate2 cert)
    {
        var cms = new SignedCms(new ContentInfo([0]), false);
        cms.ComputeSignature(new CmsSigner(cert));
        return cms.Encode();
    }


    private static string CreateRealTempDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fluentcerts-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
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
        => [
            .. finder.Sources
                .Cast<CertificateStoreEnumerable>()
                .Select(x => (x.Store.Name, x.Store.Location))
        ];


    private static List<string> DirectoryPathsOf(CertificateFinder finder)
        => [
            .. finder.Sources
                .Cast<CertificateDirectoryEnumerable>()
                .Select(x => x.Directory.Path)
        ];


    private static readonly MockFileSystem MockFileSystem = TestTools.CreateMockFileSystemWithCerts();
}
