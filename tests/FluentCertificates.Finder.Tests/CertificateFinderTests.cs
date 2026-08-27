using System.IO.Abstractions;
using System.IO.Abstractions.TestingHelpers;
using System.Linq.Expressions;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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
    public async Task AddStores_WithNameAndLocationPairs_AddsAllStores()
    {
        (string, StoreLocation)[] expected = [("My", StoreLocation.CurrentUser), ("Root", StoreLocation.LocalMachine)];

        var fromParams = new CertificateFinder(MockFileSystem)
            .AddStores(("My", StoreLocation.CurrentUser), ("Root", StoreLocation.LocalMachine));

        var fromEnumerable = new CertificateFinder(MockFileSystem)
            .AddStores(new List<(string, StoreLocation)> { ("My", StoreLocation.CurrentUser), ("Root", StoreLocation.LocalMachine) });

        await Assert.That(StoresOf(fromParams)).IsEquivalentTo(expected, CollectionOrdering.Matching);
        await Assert.That(StoresOf(fromEnumerable)).IsEquivalentTo(expected, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddStores_WithStoreNameAndLocationPairs_AddsAllStores()
    {
        (string, StoreLocation)[] expected = [("My", StoreLocation.CurrentUser), ("Root", StoreLocation.LocalMachine)];

        var fromParams = new CertificateFinder(MockFileSystem)
            .AddStores((StoreName.My, StoreLocation.CurrentUser), (StoreName.Root, StoreLocation.LocalMachine));

        var fromEnumerable = new CertificateFinder(MockFileSystem)
            .AddStores(new List<(StoreName, StoreLocation)> { (StoreName.My, StoreLocation.CurrentUser), (StoreName.Root, StoreLocation.LocalMachine) });

        await Assert.That(StoresOf(fromParams)).IsEquivalentTo(expected, CollectionOrdering.Matching);
        await Assert.That(StoresOf(fromEnumerable)).IsEquivalentTo(expected, CollectionOrdering.Matching);
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

        //The result records where it came from, so the source has to be the directory searched
        await Assert
            .That(results.Select(r => ((CertificateDirectory)r.Source).Path).Distinct())
            .IsEquivalentTo(["/certs"]);
    }


    [Test]
    public async Task EnumerateCertificates_WithTheSameDirectoryAddedTwice_ReturnsEachCertificateOnce()
    {
        using var expectedNoKey = TestTools.LoadCertificateResource("ecdsa-no-key.pem");
        using var expectedWithKey = TestTools.LoadCertificateResource("ecdsa-with-key.pem");

        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/certs").AddDirectory("/certs");

        //Both additions are kept, so the caller still sees what they asked for
        await Assert.That(finder.Sources.Count).IsEqualTo(2);

        //...but the sources compare equal, so the directory is read once
        await Assert
            .That(finder.ToList().Select(r => r.Certificate.Thumbprint))
            .IsEquivalentTo([expectedNoKey.Thumbprint, expectedWithKey.Thumbprint], CollectionOrdering.Any);
    }


    /// <summary>
    /// Results are not deduplicated, so a file two sources both reach is reported by each of them. Where a
    /// certificate was found is part of the answer, and the caller who wants them collapsed can say so
    /// with <c>DistinctBy</c>.
    /// </summary>
    [Test]
    public async Task EnumerateCertificates_OverlappingDirectoryRoots_ReportTheSharedFileOncePerSource()
    {
        var fs = CreateEmptyMockFileSystem();
        using var top = CreateSelfSignedCertificate("Top");
        using var nested = CreateSelfSignedCertificate("Nested");
        fs.AddFile("/tree/top.cer", new MockFileData(top.RawData));
        fs.AddFile("/tree/sub/nested.cer", new MockFileData(nested.RawData));

        //Same path, different recursion: two distinct sources, and /tree/top.cer is found by both
        var finder = new CertificateFinder(fs).AddDirectory("/tree").AddDirectory("/tree", recurse: true);
        var results = finder.ToList();

        await Assert.That(finder.Sources.Count).IsEqualTo(2);
        await Assert
            .That(results.Select(r => r.Certificate.Thumbprint))
            .IsEquivalentTo([top.Thumbprint, top.Thumbprint, nested.Thumbprint], CollectionOrdering.Any);

        //Both copies name the same file, which is what a caller would deduplicate on
        await Assert
            .That(results.Where(r => r.Certificate.Thumbprint == top.Thumbprint).Select(r => r.Location).Distinct())
            .HasSingleItem();
    }


    /// <summary>
    /// <see cref="CertificateFinder.Last"/> searches sources newest-first and stops at the first holding a
    /// match, so it must agree with reading everything forwards and taking the final result. This is the
    /// test that keeps the short-circuit honest.
    /// </summary>
    [Test]
    public async Task Last_AgreesWithEnumeratingForwards()
    {
        using var a = CreateSelfSignedCertificate("A");
        using var b = CreateSelfSignedCertificate("B");
        using var c = CreateSelfSignedCertificate("C");
        var first = new StubSource("Stub", "one", a, b) { Descending = true };
        var second = new StubSource("Stub", "two", c) { Descending = true };
        var finder = new CertificateFinder().AddSources(first, second);

        //Matching everything: the last result overall
        await Assert
            .That(finder.Last(x => true).Certificate.Thumbprint)
            .IsEqualTo(finder.Where(x => true).ToList().Last().Certificate.Thumbprint);

        //A predicate the newest source cannot satisfy, so it has to fall back to the older one
        Expression<Func<CertificateFinderResult, bool>> notC = x => x.Certificate.Subject != "CN=C";
        await Assert
            .That(finder.Last(notC).Certificate.Thumbprint)
            .IsEqualTo(finder.Where(notC).ToList().Last().Certificate.Thumbprint);
        await Assert.That(finder.Last(notC).Certificate.Thumbprint).IsEqualTo(b.Thumbprint);
    }


    [Test]
    public async Task Last_StopsAtTheNewestSourceHoldingAMatch()
    {
        using var a = CreateSelfSignedCertificate("A");
        using var c = CreateSelfSignedCertificate("C");
        var first = new StubSource("Stub", "one", a) { Descending = true };
        var second = new StubSource("Stub", "two", c) { Descending = true };

        var found = new CertificateFinder().AddSources(first, second).Last(x => true);

        await Assert.That(found.Certificate.Thumbprint).IsEqualTo(c.Thumbprint);
        await Assert.That(second.Calls).IsEquivalentTo(["descending"], CollectionOrdering.Matching);

        //The older source was never touched, which is the whole point of searching backwards
        await Assert.That(first.Calls).IsEmpty();
    }


    /// <summary>
    /// A source that cannot go backwards is read forwards and the last match kept, which is cheaper than
    /// making it buffer its whole output to reverse itself.
    /// </summary>
    [Test]
    public async Task Last_ForwardOnlySource_IsReadForwards()
    {
        using var a = CreateSelfSignedCertificate("A");
        using var b = CreateSelfSignedCertificate("B");
        var source = new StubSource("Stub", "one", a, b) { Descending = false };

        var found = new CertificateFinder().AddSource(source).Last(x => true);

        await Assert.That(found.Certificate.Thumbprint).IsEqualTo(b.Thumbprint);
        await Assert.That(source.Calls).IsEquivalentTo(["forward"], CollectionOrdering.Matching);
    }


    /// <summary>
    /// A source claiming <see cref="AbstractCertificateSource.CanEnumerateDescending"/> must yield the
    /// true reverse of its forward pass, or <see cref="CertificateFinder.Last"/> silently disagrees with
    /// enumerating the finder. Asserted for the two sources that read from outside the process.
    /// </summary>
    [Test]
    public async Task FindDescending_YieldsTheExactReverseOfFind()
    {
        var fs = CreateEmptyMockFileSystem();
        using var one = CreateSelfSignedCertificate("One");
        using var two = CreateSelfSignedCertificate("Two");
        using var three = CreateSelfSignedCertificate("Three");
        fs.AddFile("/rev/a.cer", new MockFileData(one.RawData));
        fs.AddFile("/rev/b.cer", new MockFileData(two.RawData));
        fs.AddFile("/rev/c.cer", new MockFileData(three.RawData));

        var directory = new CertificateDirectory("/rev", false, fs);
        var forwards = directory.Find(CertificateFilter.Empty).Select(x => x.Certificate.Thumbprint).ToList();
        var backwards = directory.FindDescending(CertificateFilter.Empty).Select(x => x.Certificate.Thumbprint).ToList();

        await Assert.That(forwards.Count).IsEqualTo(3);
        await Assert.That(backwards).IsEquivalentTo(Enumerable.Reverse(forwards), CollectionOrdering.Matching);

        var custom = new CustomCertificateSource([one, two, three]);
        await Assert
            .That(custom.FindDescending(CertificateFilter.Empty).Select(x => x.Certificate.Thumbprint))
            .IsEquivalentTo([three.Thumbprint, two.Thumbprint, one.Thumbprint], CollectionOrdering.Matching);
    }


    [Test]
    public async Task FindDescending_OnASourceThatCannot_Throws()
    {
        using var a = CreateSelfSignedCertificate("A");
        var source = new StubSource("Stub", "one", a) { Descending = false };

        await Assert
            .That(() => source.FindDescending(CertificateFilter.Empty).ToList())
            .ThrowsExactly<NotSupportedException>();
    }


    /// <summary>
    /// The counterpart to the directory case: the same certificate in two different stores is two results,
    /// because where a certificate lives is part of what the caller asked.
    /// </summary>
    [Test]
    public async Task EnumerateCertificates_SameCertificateInTwoStores_IsReportedTwice()
    {
        using var cert = CreateSelfSignedCertificate("InBoth");
        var finder = new CertificateFinder()
            .AddSource(new StubSource("Store", "CurrentUser\\My", cert))
            .AddSource(new StubSource("Store", "LocalMachine\\My", cert));

        var results = finder.ToList();

        await Assert.That(results.Count).IsEqualTo(2);
        await Assert
            .That(results.Select(r => r.Location))
            .IsEquivalentTo(["CurrentUser\\My", "LocalMachine\\My"], CollectionOrdering.Any);
    }


    [Test]
    public async Task EnumerateCertificates_FromEmptyFinder_ReturnsEmpty()
    {
        var finder = new CertificateFinder(MockFileSystem);
        var results = finder.ToList();

        await Assert.That(results).IsEmpty();
    }


    [Test]
    public async Task AddCustomSource_SearchesTheSuppliedCertificates()
    {
        using var first = CreateSelfSignedCertificate("First");
        using var second = CreateSelfSignedCertificate("Second");

        var finder = new CertificateFinder(MockFileSystem).AddCustomSource(first, second);

        await Assert.That(finder.Sources).HasSingleItem();
        await Assert
            .That(finder.Select(x => x.Certificate.Thumbprint))
            .IsEquivalentTo([first.Thumbprint, second.Thumbprint], CollectionOrdering.Matching);
    }


    /// <summary>
    /// A custom source holds the caller's own certificates, so one the filter rejects must survive: the
    /// finder never disposes something it did not create.
    /// </summary>
    [Test]
    public async Task AddCustomSource_RejectedCertificate_IsNotDisposed()
    {
        using var match = CreateSelfSignedCertificate("Keep");
        using var reject = CreateSelfSignedCertificate("Reject");

        var results = new CertificateFinder(MockFileSystem)
            .AddCustomSource(match, reject)
            .Where(x => x.Certificate.Subject == "CN=Keep")
            .ToList();

        await Assert.That(results).HasSingleItem();
        await Assert.That(() => reject.Subject).ThrowsNothing();
    }


    /// <summary>
    /// <c>Where</c> is an instance method taking an expression tree, so it wins over
    /// <see cref="Enumerable.Where{T}(IEnumerable{T},Func{T,bool})"/> and the predicate reaches the source
    /// rather than being applied after collation.
    /// </summary>
    [Test]
    public async Task Where_HandsThePredicateToEverySource()
    {
        using var cert = CreateSelfSignedCertificate("Spy");
        var a = new StubSource("Stub", "a", cert);
        var b = new StubSource("Stub", "b", cert);

        _ = new CertificateFinder().AddSources(a, b).Where(x => x.Location == "a").ToList();

        await Assert.That(a.ReceivedPredicateCounts).IsEquivalentTo([1], CollectionOrdering.Matching);
        await Assert.That(b.ReceivedPredicateCounts).IsEquivalentTo([1], CollectionOrdering.Matching);
    }


    [Test]
    public async Task Where_CalledTwice_CombinesBothPredicates()
    {
        using var cert = CreateSelfSignedCertificate("Chained");
        var source = new StubSource("Stub", "a", cert);

        var results = new CertificateFinder()
            .AddSource(source)
            .Where(x => x.Location == "a")
            .Where(x => x.Certificate.Subject == "CN=Nope")
            .ToList();

        await Assert.That(source.ReceivedPredicateCounts).IsEquivalentTo([2], CollectionOrdering.Matching);
        await Assert.That(results).IsEmpty();
    }


    /// <summary>
    /// Query syntax lowers to the same instance method, so it pushes the predicate down too.
    /// </summary>
    [Test]
    public async Task Where_InQuerySyntax_AlsoReachesTheSource()
    {
        using var cert = CreateSelfSignedCertificate("Query");
        var source = new StubSource("Stub", "a", cert);
        var finder = new CertificateFinder().AddSource(source);

        var results = (from x in finder where x.Location == "a" select x.Certificate.Thumbprint).ToList();

        await Assert.That(source.ReceivedPredicateCounts).IsEquivalentTo([1], CollectionOrdering.Matching);
        await Assert.That(results).IsEquivalentTo([cert.Thumbprint], CollectionOrdering.Matching);
    }


    /// <summary>
    /// The predicate-taking terminals shadow their <see cref="Enumerable"/> counterparts for the same
    /// reason <see cref="CertificateFinder.Where"/> does, so the predicate reaches the source instead of
    /// filtering after collation. A stub receiving zero predicates would mean the extension method won.
    /// </summary>
    [Test]
    public async Task PredicateOverloads_HandThePredicateToTheSource()
    {
        using var cert = CreateSelfSignedCertificate("Overloads");

        await AssertPushesDown(cert, f => f.Any(x => x.Location == "a"));
        await AssertPushesDown(cert, f => f.First(x => x.Location == "a"));
        await AssertPushesDown(cert, f => f.FirstOrDefault(x => x.Location == "a"));
        await AssertPushesDown(cert, f => f.Last(x => x.Location == "a"));
        await AssertPushesDown(cert, f => f.LastOrDefault(x => x.Location == "a"));
        await AssertPushesDown(cert, f => f.Single(x => x.Location == "a"));
        await AssertPushesDown(cert, f => f.SingleOrDefault(x => x.Location == "a"));
        await AssertPushesDown(cert, f => f.Count(x => x.Location == "a"));
    }


    [Test]
    public async Task PredicateOverloads_ReturnTheSameAnswersAsLinq()
    {
        using var match = CreateSelfSignedCertificate("Match");
        using var other = CreateSelfSignedCertificate("Other");

        var finder = new CertificateFinder(MockFileSystem).AddCustomSource(match, other);
        var matches = (Expression<Func<CertificateFinderResult, bool>>)(x => x.Certificate.Subject == "CN=Match");
        Expression<Func<CertificateFinderResult, bool>> nothing = x => x.Certificate.Subject == "CN=Absent";

        await Assert.That(finder.Any(matches)).IsTrue();
        await Assert.That(finder.Any(nothing)).IsFalse();
        await Assert.That(finder.Count(matches)).IsEqualTo(1);
        await Assert.That(finder.Count(nothing)).IsEqualTo(0);
        await Assert.That(finder.First(matches).Certificate.Thumbprint).IsEqualTo(match.Thumbprint);
        await Assert.That(finder.FirstOrDefault(nothing)).IsNull();
        await Assert.That(finder.Last(matches).Certificate.Thumbprint).IsEqualTo(match.Thumbprint);
        await Assert.That(finder.LastOrDefault(nothing)).IsNull();
        await Assert.That(finder.Single(matches).Certificate.Thumbprint).IsEqualTo(match.Thumbprint);
        await Assert.That(finder.SingleOrDefault(nothing)).IsNull();

        await Assert.That(() => finder.First(nothing)).ThrowsExactly<InvalidOperationException>();
        await Assert.That(() => finder.Single(x => true)).ThrowsExactly<InvalidOperationException>();
    }


    [Test]
    public async Task Where_FiltersToMatchingCertificates()
    {
        using var match = CreateSelfSignedCertificate("Match");
        using var other1 = CreateSelfSignedCertificate("Other1");
        using var other2 = CreateSelfSignedCertificate("Other2");

        var finder = new CertificateFinder(MockFileSystem).AddCustomSource(other1, match, other2);

        var results = finder.Where(r => r.Certificate.Subject.Contains("CN=Match")).ToList();

        await Assert.That(results.Count).IsEqualTo(1);
        await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(match.Thumbprint);
    }


    /// <summary>
    /// A source that materialised a certificate and then rejected it must release it: nothing else can,
    /// since the caller never sees it. Captured through the predicate, which is the only place every
    /// candidate is visible from outside.
    /// </summary>
    [Test]
    [NotInParallel]
    public async Task Where_RejectedCertificatesFromAnOwningSource_AreDisposed()
    {
        using var keep = CreateSelfSignedCertificate("Keep");
        using var drop = CreateSelfSignedCertificate("Drop");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/own/keep.cer", new MockFileData(keep.RawData));
        fs.AddFile("/own/drop.cer", new MockFileData(drop.RawData));

        Captured.Clear();
        var results = new CertificateFinder(fs)
            .AddDirectory("/own")
            .Where(x => Capture(x.Certificate).Subject == "CN=Keep")
            .ToList();

        await Assert.That(results).HasSingleItem();
        await Assert.That(Captured.Count).IsEqualTo(2);

        //Identified by reference, not by thumbprint: reading a property off the disposed one is the assertion
        var rejected = Captured.Single(x => !ReferenceEquals(x, results[0].Certificate));
        await Assert.That(() => rejected.Subject).ThrowsExactly<CryptographicException>();

        //...and the one that matched is still usable
        await Assert.That(() => results[0].Certificate.Subject).ThrowsNothing();
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


    /// <summary>
    /// Deduplication of sources rests on them comparing by value, so a store named twice is one source
    /// however it was named, and a different store or location is a different one.
    /// </summary>
    [Test]
    public async Task StoreSources_CompareByTheStoreTheyName()
    {
        var byName = new CertificateStore("My", StoreLocation.CurrentUser);
        var byEnum = new CertificateStore(StoreName.My, StoreLocation.CurrentUser);
        var elsewhere = new CertificateStore(StoreName.My, StoreLocation.LocalMachine);
        var other = new CertificateStore(StoreName.Root, StoreLocation.CurrentUser);

        await Assert.That(byName).IsEqualTo(byEnum);
        await Assert.That(byName).IsNotEqualTo(elsewhere);
        await Assert.That(byName).IsNotEqualTo(other);
    }


    /// <summary>
    /// The same, for directories: the path and the recursion setting both count, since searching a tree is
    /// not the same search as searching its top level.
    /// </summary>
    [Test]
    public async Task DirectorySources_CompareByPathAndRecursion()
    {
        var fs = CreateEmptyMockFileSystem();
        var top = new CertificateDirectory("/certs", false, fs);
        var same = new CertificateDirectory("/certs", false, fs);
        var deep = new CertificateDirectory("/certs", true, fs);
        var other = new CertificateDirectory("/elsewhere", false, fs);

        await Assert.That(top).IsEqualTo(same);
        await Assert.That(top).IsNotEqualTo(deep);
        await Assert.That(top).IsNotEqualTo(other);
    }


    /// <summary>
    /// A store and a directory are never the same source, whatever else they carry.
    /// </summary>
    [Test]
    public async Task SourcesOfDifferentKinds_AreNeverEqual()
    {
        AbstractCertificateSource store = new CertificateStore("My", StoreLocation.CurrentUser);
        AbstractCertificateSource dir = new CertificateDirectory("/certs", false, CreateEmptyMockFileSystem());

        await Assert.That(store).IsNotEqualTo(dir);
        await Assert.That(store.Kind).IsEqualTo("Store");
        await Assert.That(dir.Kind).IsEqualTo("Directory");
    }


    [Test]
    public async Task EnumerateCertificates_WithNonExistentPath_ThrowsDirectoryNotFoundException()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/nonexistent");

        await Assert.That(() => finder.ToList()).ThrowsExactly<DirectoryNotFoundException>();
    }


    /// <summary>
    /// A store that does not exist yields no results rather than throwing, and is not created by being
    /// searched: the source opens read-only and existing-only.
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
            File.WriteAllBytes(Path.Combine(dir, fileName), CertificateFileBytes(cert, format));

            var results = new CertificateFinder().AddDirectory(dir).ToList();

            await Assert.That(results.Count).IsEqualTo(1);
            await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);
        } finally {
            Directory.Delete(dir, true);
        }
    }


    /// <summary>
    /// Every format has to be read through the <see cref="IFileSystem"/> the source was given. A loader
    /// taking a path goes to the real disk whatever that file system is, so on any other one it finds
    /// nothing, and the loader's catch turns the resulting <see cref="FileNotFoundException"/> into a
    /// silently skipped file rather than an error. The real-directory test above cannot see that, because
    /// there the two file systems are the same one.
    /// </summary>
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
    public async Task EnumerateCertificates_EachSupportedExtension_IsReadThroughTheGivenFileSystem(
        string fileName, string format)
    {
        using var cert = CreateSelfSignedCertificate("MockFormats");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile($"/formats/{fileName}", new MockFileData(CertificateFileBytes(cert, format)));

        var results = new CertificateFinder(fs).AddDirectory("/formats").ToList();

        await Assert.That(results.Count).IsEqualTo(1);
        await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);
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
    /// Runs <paramref name="use"/> against a finder holding one stub source, and asserts the stub was
    /// handed exactly one predicate.
    /// </summary>
    private static async Task AssertPushesDown(X509Certificate2 cert, Func<CertificateFinder, object?> use)
    {
        var source = new StubSource("Stub", "a", cert);

        _ = use(new CertificateFinder().AddSource(source));

        await Assert.That(source.ReceivedPredicateCounts).IsEquivalentTo([1], CollectionOrdering.Matching);
    }


    /// <summary>
    /// Captures every candidate the filter sees. Used from inside an expression tree, which cannot hold a
    /// statement body, so the capture has to be a method call.
    /// </summary>
    private static X509Certificate2 Capture(X509Certificate2 certificate)
    {
        lock (Captured) {
            Captured.Add(certificate);
        }
        return certificate;
    }


    private static readonly List<X509Certificate2> Captured = [];


    /// <summary>
    /// A source with a fixed kind and location, for exercising collation and predicate hand-off without a
    /// real store or directory behind it.
    /// </summary>
    private sealed record StubSource(string SourceKind, string At, params X509Certificate2[] Certificates)
        : AbstractCertificateSource
    {
        public override string Kind => SourceKind;

        //Never disposes: the certificates belong to the test
        public override bool OwnsCertificates => false;

        /// <summary>Whether this stub claims it can enumerate backwards.</summary>
        public bool Descending { get; init; }

        public override bool CanEnumerateDescending => Descending;

        public List<int> ReceivedPredicateCounts { get; } = [];

        /// <summary>Records which direction the source was read in, and whether it was read at all.</summary>
        public List<string> Calls { get; } = [];

        protected override IEnumerable<CertificateFinderResult> Enumerate(CertificateFilter filter)
        {
            ReceivedPredicateCounts.Add(filter.Expressions.Count);
            Calls.Add("forward");
            return Results(Certificates);
        }

        protected override IEnumerable<CertificateFinderResult> EnumerateDescending(CertificateFilter filter)
        {
            ReceivedPredicateCounts.Add(filter.Expressions.Count);
            Calls.Add("descending");
            //Enumerable.Reverse explicitly: on an array the bare call binds to the void span overload
            return Results(Enumerable.Reverse(Certificates));
        }

        private IEnumerable<CertificateFinderResult> Results(IEnumerable<X509Certificate2> certificates)
            => certificates.Select(cert => new CertificateFinderResult {
                Source = this,
                Location = At,
                Certificate = cert
            });
    }


    private static byte[] CertificateFileBytes(X509Certificate2 cert, string format)
        => format switch {
            "pem" => Encoding.ASCII.GetBytes(cert.ExportCertificatePem()),
            "der" => cert.RawData,
            "pkcs12" => cert.Export(X509ContentType.Pkcs12)!,
            "pkcs7" => BuildPkcs7(cert),
            _ => throw new ArgumentOutOfRangeException(nameof(format), format, null)
        };


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
        => [.. finder.Sources.Cast<CertificateStore>().Select(x => (x.Name, x.Location))];


    private static List<string> DirectoryPathsOf(CertificateFinder finder)
        => [.. finder.Sources.Cast<CertificateDirectory>().Select(x => x.Path)];


    private static readonly MockFileSystem MockFileSystem = TestTools.CreateMockFileSystemWithCerts();
}
