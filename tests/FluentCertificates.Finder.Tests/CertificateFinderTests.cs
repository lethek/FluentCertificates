using System.Collections;
using System.IO.Abstractions;
using System.IO.Abstractions.TestingHelpers;
using System.Linq.Expressions;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
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


    /// <summary>
    /// Sources are records, so a source equal to one that was added removes it. The caller does not have
    /// to have kept the instance they added.
    /// </summary>
    [Test]
    public async Task RemoveSource_MatchesBySourceValue_AndLeavesTheOriginalFinderIntact()
    {
        var finder = new CertificateFinder(MockFileSystem)
            .AddStore(StoreName.My, StoreLocation.CurrentUser)
            .AddStore(StoreName.Root, StoreLocation.CurrentUser);

        var narrowed = finder.RemoveSource(new CertificateStoreSource("My", StoreLocation.CurrentUser));

        await Assert
            .That(StoresOf(narrowed))
            .IsEquivalentTo([("Root", StoreLocation.CurrentUser)], CollectionOrdering.Matching);

        //Removing produces a new finder rather than editing this one
        await Assert.That(finder.Sources.Count).IsEqualTo(2);
    }


    /// <summary>
    /// A duplicate is searched no differently from the original, so one call takes both off rather than
    /// leaving the caller to count how many times they added it.
    /// </summary>
    [Test]
    public async Task RemoveSource_WithTheSameSourceAddedTwice_RemovesBoth()
    {
        var finder = new CertificateFinder(MockFileSystem).AddDirectory("/certs").AddDirectory("/certs");

        var narrowed = finder.RemoveSource(new CertificateDirectorySource("/certs", false, MockFileSystem));

        await Assert.That(narrowed.Sources).IsEmpty();
    }


    [Test]
    public async Task RemoveSource_WithASourceThatWasNeverAdded_ChangesNothing()
    {
        var finder = new CertificateFinder(MockFileSystem).AddStore(StoreName.My, StoreLocation.CurrentUser);

        var narrowed = finder.RemoveSource(new CertificateStoreSource("Root", StoreLocation.LocalMachine));

        await Assert
            .That(StoresOf(narrowed))
            .IsEquivalentTo([("My", StoreLocation.CurrentUser)], CollectionOrdering.Matching);
    }


    [Test]
    public async Task RemoveSources_WithSeveralSources_RemovesEachOfThem()
    {
        var finder = new CertificateFinder(MockFileSystem)
            .AddStore(StoreName.My, StoreLocation.CurrentUser)
            .AddStore(StoreName.Root, StoreLocation.CurrentUser)
            .AddStore(StoreName.CertificateAuthority, StoreLocation.CurrentUser);

        var narrowed = finder.RemoveSources(
            new CertificateStoreSource("My", StoreLocation.CurrentUser),
            new CertificateStoreSource("CA", StoreLocation.CurrentUser)
        );

        await Assert
            .That(StoresOf(narrowed))
            .IsEquivalentTo([("Root", StoreLocation.CurrentUser)], CollectionOrdering.Matching);
    }


    [Test]
    public async Task RemoveSources_WithAPredicate_RemovesEveryMatch()
    {
        var finder = new CertificateFinder(MockFileSystem)
            .AddStore(StoreName.My, StoreLocation.CurrentUser)
            .AddDirectory("/certs")
            .AddDirectory("/other");

        var narrowed = finder.RemoveSources(x => x.Kind == "Directory");

        await Assert
            .That(StoresOf(narrowed))
            .IsEquivalentTo([("My", StoreLocation.CurrentUser)], CollectionOrdering.Matching);
    }


    /// <summary>
    /// Removing a source stops it being searched, not merely listed.
    /// </summary>
    [Test]
    public async Task EnumerateCertificates_AfterRemovingADirectory_SkipsIt()
    {
        using var kept = CreateSelfSignedCertificate("Kept");
        using var dropped = CreateSelfSignedCertificate("Dropped");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/kept/kept.cer", new MockFileData(kept.RawData));
        fs.AddFile("/dropped/dropped.cer", new MockFileData(dropped.RawData));

        var results = new CertificateFinder(fs)
            .AddDirectory("/kept")
            .AddDirectory("/dropped")
            .RemoveSource(new CertificateDirectorySource("/dropped", false, fs))
            .ToList();

        await Assert.That(results.Select(x => x.Certificate.Thumbprint)).IsEquivalentTo([kept.Thumbprint]);
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
            .That(results.Select(r => ((CertificateDirectorySource)r.Source).Path).Distinct())
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
    /// A source implementing <c>EnumerateDescending</c> must yield the
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

        var directory = new CertificateDirectorySource("/rev", false, fs);
        var forwards = directory.Find(CertificateFilter.Empty).Select(x => x.Certificate.Thumbprint).ToList();
        var backwards = directory.FindDescending(CertificateFilter.Empty)!.Select(x => x.Certificate.Thumbprint).ToList();

        await Assert.That(forwards.Count).IsEqualTo(3);
        await Assert.That(backwards).IsEquivalentTo(Enumerable.Reverse(forwards), CollectionOrdering.Matching);

        var custom = new CertificateCollectionSource([one, two, three]);
        await Assert
            .That(custom.FindDescending(CertificateFilter.Empty)!.Select(x => x.Certificate.Thumbprint))
            .IsEquivalentTo([three.Thumbprint, two.Thumbprint, one.Thumbprint], CollectionOrdering.Matching);
    }


    [Test]
    public async Task FindDescending_OnASourceThatCannot_ReturnsNull()
    {
        using var a = CreateSelfSignedCertificate("A");
        var source = new StubSource("Stub", "one", a) { Descending = false };

        await Assert.That(source.FindDescending(CertificateFilter.Empty)).IsNull();
    }


    /// <summary>
    /// A source inherits "cannot go backwards" and a throwing <c>EnumerateDescending</c>, so an
    /// implementer opts in rather than having to opt out.
    /// </summary>
    [Test]
    public async Task AbstractCertificateSource_DefaultsToForwardOnly()
    {
        using var a = CreateSelfSignedCertificate("A");
        var source = new MinimalSource(a);

        await Assert.That(source.FindDescending(CertificateFilter.Empty)).IsNull();

        //Reached through the finder it is simply read forwards instead
        await Assert
            .That(new CertificateFinder().AddSource(source).Last(x => true).Certificate.Thumbprint)
            .IsEqualTo(a.Thumbprint);

        //...and it inherits ownership, so a result its filter rejects is disposed. Asserted last, since
        //it destroys the certificate this source hands out
        await Assert.That(source.Find(CertificateFilter.Empty.Add(x => false)).ToList()).IsEmpty();
        await Assert.That(() => a.Subject).ThrowsExactly<CryptographicException>();
    }


    /// <summary>
    /// Reading a real store: the only place the store source's own output is exercised, so it covers both
    /// the <see cref="CertificateFinderResult.Location"/> format and that descending is the exact reverse.
    /// Skipped rather than silently passing when the store holds nothing.
    /// </summary>
    [Test]
    public async Task CertificateStoreSource_ReadsARealStore()
    {
        var store = new CertificateStoreSource(StoreName.Root, StoreLocation.CurrentUser);
        var forwards = store.Find(CertificateFilter.Empty).ToList();
        try {
            Skip.Unless(forwards.Count > 0, "CurrentUser\\Root holds no certificates on this machine");

            await Assert.That(store.Kind).IsEqualTo("Store");
            await Assert.That(forwards.Select(x => x.Location).Distinct()).IsEquivalentTo(["CurrentUser\\Root"]);
            await Assert.That(forwards.All(x => ReferenceEquals(x.Source, store))).IsTrue();

            //A store is already materialised, so it can be read backwards
            var backwards = store.FindDescending(CertificateFilter.Empty)!.ToList();
            try {
                await Assert
                    .That(backwards.Select(x => x.Certificate.Thumbprint))
                    .IsEquivalentTo(Enumerable.Reverse(forwards.Select(x => x.Certificate.Thumbprint).ToList()),
                        CollectionOrdering.Matching);
            } finally {
                backwards.ForEach(x => x.Certificate.Dispose());
            }
        } finally {
            forwards.ForEach(x => x.Certificate.Dispose());
        }
    }


    /// <summary>
    /// Reading a forward-only source for its last match materialises every earlier match too. Those are
    /// unreachable the moment the next one supersedes them, so an owning source's copies are released.
    /// </summary>
    [Test]
    [NotInParallel]
    public async Task Last_ForwardOnlyOwningSource_DisposesTheMatchesItPassesOver()
    {
        //Deliberately not disposed by the test: the point is that Last does it
        var first = CreateSelfSignedCertificate("First");
        var second = CreateSelfSignedCertificate("Second");
        var source = new StubSource("Stub", "one", first, second) { Descending = false, Owns = true };

        var found = new CertificateFinder().AddSource(source).Last(x => true);

        await Assert.That(found.Certificate.Thumbprint).IsEqualTo(second.Thumbprint);
        await Assert.That(() => first.Subject).ThrowsExactly<CryptographicException>();
        await Assert.That(() => second.Subject).ThrowsNothing();

        second.Dispose();
    }


    [Test]
    public async Task CertificateFilter_TracksWhetherItHasPredicates()
    {
        await Assert.That(CertificateFilter.Empty.IsEmpty).IsTrue();
        await Assert.That(CertificateFilter.Empty.Predicates).IsEmpty();

        var one = CertificateFilter.Empty.Add(x => x.Location == "a");

        await Assert.That(one.IsEmpty).IsFalse();
        await Assert.That(one.Predicates.Length).IsEqualTo(1);

        //Immutable, so adding leaves the original alone
        await Assert.That(CertificateFilter.Empty.IsEmpty).IsTrue();
    }


    [Test]
    public async Task CertificateFinderPredicate_CarriesBothTheTreeAndTheCompiledForm()
    {
        Expression<Func<CertificateFinderResult, bool>> expression = x => x.Location == "a";
        var predicate = new CertificateFinderPredicate(expression);

        await Assert.That(predicate.Expression).IsSameReferenceAs(expression);

        using var cert = CreateSelfSignedCertificate("Predicate");
        var source = new StubSource("Stub", "a", cert);
        var matching = new CertificateFinderResult { Source = source, Location = "a", Certificate = cert };
        var other = matching with { Location = "b" };

        await Assert.That(predicate.Compiled(matching)).IsTrue();
        await Assert.That(predicate.Compiled(other)).IsFalse();
    }


    [Test]
    public async Task CertificateFilter_AcceptsAnAlreadyCompiledPredicate()
    {
        var predicate = new CertificateFinderPredicate(x => x.Location == "a");
        var filter = CertificateFilter.Empty.Add(predicate);

        //Added as-is, so the delegate the caller paid to compile is the one the filter runs
        await Assert.That(filter.Predicates.Single()).IsSameReferenceAs(predicate);

        using var cert = CreateSelfSignedCertificate("Compiled");
        var source = new StubSource("Stub", "a", cert);

        await Assert.That(filter.Matches(new CertificateFinderResult { Source = source, Location = "a", Certificate = cert })).IsTrue();
        await Assert.That(filter.Matches(new CertificateFinderResult { Source = source, Location = "b", Certificate = cert })).IsFalse();
    }


    [Test]
    public async Task CertificateCollectionSource_ReportsItsKindAndLeavesTheCallersCertificates()
    {
        using var cert = CreateSelfSignedCertificate("Custom");
        var source = new CertificateCollectionSource([cert]);

        await Assert.That(source.Kind).IsEqualTo("Collection");
        await Assert.That(source.FindDescending(CertificateFilter.Empty)).IsNotNull();

        //A supplied certificate has no location of its own, so its thumbprint stands in
        await Assert
            .That(source.Find(CertificateFilter.Empty).Single().Location)
            .IsEqualTo(cert.Thumbprint);
    }


    [Test]
    public async Task NullArguments_AreRejected()
    {
        using var cert = CreateSelfSignedCertificate("Null");
        var source = new StubSource("Stub", "one", cert);

        await Assert.That(() => new CertificateFinder().Where(null!)).ThrowsExactly<ArgumentNullException>();
        await Assert.That(() => new CertificateFinder().All(null!)).ThrowsExactly<ArgumentNullException>();
        await Assert.That(() => CertificateFilter.Empty.Add((Expression<Func<CertificateFinderResult, bool>>)null!)).ThrowsExactly<ArgumentNullException>();
        await Assert.That(() => CertificateFilter.Empty.Add((CertificateFinderPredicate)null!)).ThrowsExactly<ArgumentNullException>();
        await Assert.That(() => new CertificateFinderPredicate(null!)).ThrowsExactly<ArgumentNullException>();
        await Assert.That(() => source.Find(null!)).ThrowsExactly<ArgumentNullException>();
        await Assert.That(() => source.FindDescending(null!)).ThrowsExactly<ArgumentNullException>();
    }


    [Test]
    public async Task NonGenericEnumeration_YieldsTheSameResults()
    {
        using var cert = CreateSelfSignedCertificate("NonGeneric");
        IEnumerable finder = new CertificateFinder().AddCertificates(cert);

        //Taken off the interface directly: Cast<T> would notice the generic interface and short-circuit
        var enumerator = finder.GetEnumerator();
        var results = new List<CertificateFinderResult>();
        while (enumerator.MoveNext()) {
            results.Add((CertificateFinderResult)enumerator.Current!);
        }

        await Assert.That(results).HasSingleItem();
        await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);
    }


    /// <summary>
    /// A source that cannot go backwards is read forwards for its last match, rather than the finder
    /// giving up. One member decides it, so a source cannot claim the capability without implementing it.
    /// </summary>
    [Test]
    public async Task FindLast_FallsBackToAForwardScan()
    {
        using var first = CreateSelfSignedCertificate("First");
        using var second = CreateSelfSignedCertificate("Second");
        var source = new StubSource("Stub", "one", first, second) { Descending = false };

        await Assert.That(source.FindLast(CertificateFilter.Empty)!.Certificate.Thumbprint).IsEqualTo(second.Thumbprint);
        await Assert.That(source.Calls).IsEquivalentTo(["forward"], CollectionOrdering.Matching);

        await Assert.That(source.FindLast(CertificateFilter.Empty.Add(x => false))).IsNull();
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
    public async Task AddCertificates_SearchesTheSuppliedCertificates()
    {
        using var first = CreateSelfSignedCertificate("First");
        using var second = CreateSelfSignedCertificate("Second");

        var finder = new CertificateFinder(MockFileSystem).AddCertificates(first, second);

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
    public async Task AddCertificates_RejectedCertificate_IsNotDisposed()
    {
        using var match = CreateSelfSignedCertificate("Keep");
        using var reject = CreateSelfSignedCertificate("Reject");

        var results = new CertificateFinder(MockFileSystem)
            .AddCertificates(match, reject)
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
        await AssertPushesDown(cert, f => f.All(x => x.Location == "a"));
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

        var finder = new CertificateFinder(MockFileSystem).AddCertificates(match, other);
        var matches = (Expression<Func<CertificateFinderResult, bool>>)(x => x.Certificate.Subject == "CN=Match");
        Expression<Func<CertificateFinderResult, bool>> nothing = x => x.Certificate.Subject == "CN=Absent";

        await Assert.That(finder.Any(matches)).IsTrue();
        await Assert.That(finder.Any(nothing)).IsFalse();
        await Assert.That(finder.All(matches)).IsFalse();
        await Assert.That(finder.All(x => x.Certificate.Subject.StartsWith("CN="))).IsTrue();
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


    /// <summary>
    /// <see cref="CertificateFinder.All"/> hands the sources the negation of the caller's predicate, since
    /// a counter-example is what a source can look for and stop at. Answering with the predicate as written
    /// inverts the result whenever every certificate matches.
    /// </summary>
    [Test]
    public async Task All_AsksTheSourcesForACounterExample()
    {
        using var every = CreateSelfSignedCertificate("Every");
        using var odd = CreateSelfSignedCertificate("Odd");

        var finder = new CertificateFinder().AddCertificates(every, odd);

        await Assert.That(finder.All(x => x.Certificate.Subject.StartsWith("CN="))).IsTrue();
        await Assert.That(finder.All(x => x.Certificate.Subject == "CN=Every")).IsFalse();

        //Vacuously true over no certificates, as Enumerable.All is over an empty sequence
        await Assert.That(new CertificateFinder().All(x => false)).IsTrue();
    }


    [Test]
    public async Task Where_FiltersToMatchingCertificates()
    {
        using var match = CreateSelfSignedCertificate("Match");
        using var other1 = CreateSelfSignedCertificate("Other1");
        using var other2 = CreateSelfSignedCertificate("Other2");

        var finder = new CertificateFinder(MockFileSystem).AddCertificates(other1, match, other2);

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
        //A malformed PEM block is simply not found, whereas a binary format has to fail while parsing
        fs.AddFile("/malformed/garbage.der", new MockFileData([0x30, 0x82, 0x01, 0x02, 0xFF, 0xFF, 0xFF]));
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
        var byName = new CertificateStoreSource("My", StoreLocation.CurrentUser);
        var byEnum = new CertificateStoreSource(StoreName.My, StoreLocation.CurrentUser);
        var elsewhere = new CertificateStoreSource(StoreName.My, StoreLocation.LocalMachine);
        var other = new CertificateStoreSource(StoreName.Root, StoreLocation.CurrentUser);

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
        var top = new CertificateDirectorySource("/certs", false, fs);
        var same = new CertificateDirectorySource("/certs", false, fs);
        var deep = new CertificateDirectorySource("/certs", true, fs);
        var other = new CertificateDirectorySource("/elsewhere", false, fs);

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
        AbstractCertificateSource store = new CertificateStoreSource("My", StoreLocation.CurrentUser);
        AbstractCertificateSource dir = new CertificateDirectorySource("/certs", false, CreateEmptyMockFileSystem());

        await Assert.That(store).IsNotEqualTo(dir);
        await Assert.That(store.Kind).IsEqualTo("Store");
        await Assert.That(dir.Kind).IsEqualTo("Directory");
    }


    /// <summary>
    /// A directory that is not there yields no results rather than throwing, so a source that is missing
    /// fails the same way whether it is a directory or a store. Throwing would be worse than empty here:
    /// it happens part-way through enumeration, after earlier sources have already yielded.
    /// </summary>
    [Test]
    public async Task EnumerateCertificates_DirectoryDoesNotExist_ReturnsEmptyAndDoesNotHideOtherSources()
    {
        using var cert = CreateSelfSignedCertificate("Present");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/present/cert.cer", new MockFileData(cert.RawData));

        var finder = new CertificateFinder(fs).AddDirectory("/present").AddDirectory("/nonexistent");

        await Assert.That(finder.ToList().Select(x => x.Certificate.Thumbprint)).IsEquivalentTo([cert.Thumbprint]);
    }


    /// <summary>
    /// A recursive scan skips a subdirectory it cannot open rather than abandoning the whole scan. The
    /// <see cref="SearchOption"/> overload of <c>EnumerateFiles</c> does abandon it, which is why this
    /// source asks for <c>IgnoreInaccessible</c> instead.
    /// </summary>
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task EnumerateCertificates_UnreadableSubdirectory_IsSkippedAndTheRestAreReturned()
    {
        using var cert = CreateSelfSignedCertificate("Readable");
        using var dir = new TempDirectory();
        File.WriteAllText(Path.Combine(dir.Path, "readable.pem"), cert.ExportCertificatePem());

        var locked = Path.Combine(dir.Path, "locked");
        Directory.CreateDirectory(locked);
        using var unlock = DenyDirectoryAccess(locked);

        var results = new CertificateFinder().AddDirectory(dir.Path, recurse: true).ToList();

        await Assert.That(results.Select(x => x.Certificate.Thumbprint)).IsEquivalentTo([cert.Thumbprint]);
    }


    /// <summary>
    /// Skipping a file that will not parse is the right behaviour, but a search that skipped forty of them
    /// otherwise looks like one that found nothing. The handler is what makes the difference visible.
    /// </summary>
    [Test]
    public async Task OnLoadFailure_ReportsEveryFileTheSourceSkipped()
    {
        using var cert = CreateSelfSignedCertificate("Good");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/reported/good.pem", new MockFileData(cert.ExportCertificatePem()));
        fs.AddFile("/reported/bad.der", new MockFileData([0x30, 0x82, 0x01, 0x02, 0xFF, 0xFF, 0xFF]));
        fs.AddFile("/reported/worse.p7b", new MockFileData("not a PKCS#7 blob at all"));

        var skipped = new List<(string Path, Exception Exception)>();
        var results = new CertificateFinder(fs)
            .AddSource(new CertificateDirectorySource("/reported", false, fs) {
                OnLoadFailure = (path, ex) => skipped.Add((path, ex))
            })
            .ToList();

        //The good file is still returned: reporting a failure does not stop the search
        await Assert.That(results.Select(x => x.Certificate.Thumbprint)).IsEquivalentTo([cert.Thumbprint]);

        await Assert
            .That(skipped.Select(x => fs.Path.GetFileName(x.Path)))
            .IsEquivalentTo(["bad.der", "worse.p7b"], CollectionOrdering.Any);
        await Assert.That(skipped.All(x => x.Exception is not null)).IsTrue();
    }


    /// <summary>
    /// A directory that is not there is skipped like an unreadable file is, and is reported the same way,
    /// so making it silent does not make it invisible.
    /// </summary>
    [Test]
    public async Task OnLoadFailure_ReportsADirectoryThatIsNotThere()
    {
        var fs = CreateEmptyMockFileSystem();
        var skipped = new List<(string Path, Exception Exception)>();

        var results = new CertificateFinder(fs)
            .AddSource(new CertificateDirectorySource("/nonexistent", false, fs) {
                OnLoadFailure = (path, ex) => skipped.Add((path, ex))
            })
            .ToList();

        await Assert.That(results).IsEmpty();
        await Assert.That(skipped.Select(x => x.Path)).IsEquivalentTo(["/nonexistent"]);
        await Assert.That(skipped[0].Exception).IsTypeOf<DirectoryNotFoundException>();
    }


    /// <summary>
    /// A directory the process cannot open is treated like one that is not there, rather than throwing
    /// part-way through the search. <c>IgnoreInaccessible</c> covers the root of a scan as well as the
    /// subdirectories below it.
    /// </summary>
    [Test]
    [SupportedOSPlatform("windows")]
    public async Task EnumerateCertificates_UnreadableDirectory_ReturnsEmpty()
    {
        using var cert = CreateSelfSignedCertificate("Unreachable");
        using var dir = new TempDirectory();
        File.WriteAllText(Path.Combine(dir.Path, "cert.pem"), cert.ExportCertificatePem());
        using var unlock = DenyDirectoryAccess(dir.Path);

        var finder = new CertificateFinder().AddDirectory(dir.Path);

        await Assert.That(finder.ToList()).IsEmpty();
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
        using var dir = new TempDirectory();
        var sub = Path.Combine(dir.Path, "sub");
        Directory.CreateDirectory(sub);
        File.WriteAllText(Path.Combine(dir.Path, "top.pem"), top.ExportCertificatePem());
        File.WriteAllText(Path.Combine(sub, "nested.pem"), nested.ExportCertificatePem());

        var results = new CertificateFinder().AddDirectory(dir.Path, recurse).ToList();

        await Assert.That(results.Count).IsEqualTo(expected);
        await Assert.That(results.Select(x => x.Certificate.Thumbprint)).Contains(top.Thumbprint);
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
        using var dir = new TempDirectory();
        var sub = Path.Combine(dir.Path, "sub");
        Directory.CreateDirectory(sub);
        File.WriteAllText(Path.Combine(dir.Path, "top.pem"), top.ExportCertificatePem());
        File.WriteAllText(Path.Combine(sub, "nested.pem"), nested.ExportCertificatePem());

        var results = new CertificateFinder().AddDirectories(dir.Path).ToList();

        await Assert.That(results.Count).IsEqualTo(1);
        await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(top.Thumbprint);
    }


    /// <summary>
    /// The enumeration pattern matches every file and filters by extension afterwards, so a certificate whose
    /// name has no extension-like prefix is still seen.
    /// </summary>
    [Test]
    public async Task EnumerateCertificates_FindsFilesWhateverTheirName()
    {
        using var cert = CreateSelfSignedCertificate("Odd");
        using var dir = new TempDirectory();
        File.WriteAllText(Path.Combine(dir.Path, ".hidden.pem"), cert.ExportCertificatePem());

        var results = new CertificateFinder().AddDirectory(dir.Path).ToList();

        await Assert.That(results.Count).IsEqualTo(1);
    }


    [Test]
    [MethodDataSource(nameof(SupportedFormats))]
    public async Task EnumerateCertificates_EachSupportedExtension_IsLoaded(string fileName, string format)
    {
        using var cert = CreateSelfSignedCertificate("Formats");
        using var dir = new TempDirectory();
        File.WriteAllBytes(Path.Combine(dir.Path, fileName), CertificateFileBytes(cert, format));

        var results = new CertificateFinder().AddDirectory(dir.Path).ToList();

        await Assert.That(results.Count).IsEqualTo(1);
        await Assert.That(results[0].Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);
    }


    /// <summary>
    /// Every format has to be read through the <see cref="IFileSystem"/> the source was given. A loader
    /// taking a path goes to the real disk whatever that file system is, so on any other one it finds
    /// nothing, and the loader's catch turns the resulting <see cref="FileNotFoundException"/> into a
    /// silently skipped file rather than an error. The real-directory test above cannot see that, because
    /// there the two file systems are the same one.
    /// </summary>
    [Test]
    [MethodDataSource(nameof(SupportedFormats))]
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
    [MethodDataSource(nameof(StoreNames))]
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
    [MethodDataSource(nameof(StoreNames))]
    public async Task CertificateStoreSource_MapsStoreNameToItsSystemName(StoreName name, string expected)
    {
        //CertificateAuthority is the one whose system name differs from its enum name
        var store = new CertificateStoreSource(name, StoreLocation.CurrentUser);

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
    /// Overrides nothing but <c>Enumerate</c>, so it exercises what a minimal third-party source inherits.
    /// </summary>
    private sealed record MinimalSource(X509Certificate2 Certificate) : AbstractCertificateSource
    {
        public override string Kind => "Minimal";

        protected override IEnumerable<CertificateFinderResult> Enumerate(CertificateFilter filter)
            => SelectResults([Certificate], _ => "only");
    }


    /// <summary>
    /// A source with a fixed kind and location, for exercising collation and predicate hand-off without a
    /// real store or directory behind it.
    /// </summary>
    private sealed record StubSource(string SourceKind, string At, params X509Certificate2[] Certificates)
        : AbstractCertificateSource
    {
        public override string Kind => SourceKind;

        /// <summary>Whether this stub can enumerate backwards.</summary>
        public bool Descending { get; init; }

        /// <summary>Whether this stub treats the certificates as its own to dispose.</summary>
        public bool Owns { get; init; }

        public List<int> ReceivedPredicateCounts { get; } = [];

        /// <summary>Records which direction the source was read in, and whether it was read at all.</summary>
        public List<string> Calls { get; } = [];

        protected override IEnumerable<CertificateFinderResult> Enumerate(CertificateFilter filter)
        {
            ReceivedPredicateCounts.Add(filter.Predicates.Length);
            Calls.Add("forward");
            return SelectResults(Certificates, _ => At);
        }

        protected override IEnumerable<CertificateFinderResult>? EnumerateDescending(CertificateFilter filter)
        {
            if (!Descending) {
                return null;
            }
            ReceivedPredicateCounts.Add(filter.Predicates.Length);
            Calls.Add("descending");
            //Enumerable.Reverse explicitly: on an array the bare call binds to the void span overload
            return SelectResults(Enumerable.Reverse(Certificates), _ => At);
        }

        //Defaults to leaving them alone: the certificates belong to the test unless Owns says otherwise
        public override void Release(CertificateFinderResult result)
        {
            if (Owns) {
                base.Release(result);
            }
        }
    }


    /// <summary>Every file extension the finder claims to support, with the format to write it in.</summary>
    public static IEnumerable<(string FileName, string Format)> SupportedFormats()
    {
        yield return ("cert.pem", "pem");
        yield return ("cert.ca-bundle", "pem");
        yield return ("cert.crt", "der");
        yield return ("cert.cer", "der");
        yield return ("cert.der", "der");
        yield return ("cert.pfx", "pkcs12");
        yield return ("cert.p12", "pkcs12");
        yield return ("cert.p7b", "pkcs7");
        yield return ("cert.p7c", "pkcs7");
    }


    /// <summary>Every <see cref="StoreName"/>, with the system store name it maps to.</summary>
    public static IEnumerable<(StoreName Name, string Expected)> StoreNames()
    {
        yield return (StoreName.AddressBook, "AddressBook");
        yield return (StoreName.AuthRoot, "AuthRoot");
        yield return (StoreName.CertificateAuthority, "CA");
        yield return (StoreName.Disallowed, "Disallowed");
        yield return (StoreName.My, "My");
        yield return (StoreName.Root, "Root");
        yield return (StoreName.TrustedPeople, "TrustedPeople");
        yield return (StoreName.TrustedPublisher, "TrustedPublisher");
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


    /// <summary>A real directory on disk, removed with everything in it when the test scope ends.</summary>
    /// <summary>
    /// A PEM file holds any number of certificates, and a `.ca-bundle` is a bundle by definition, so
    /// reading only the first silently loses the rest.
    /// </summary>
    [Test]
    [Arguments(".pem")]
    [Arguments(".ca-bundle")]
    public async Task EnumerateCertificates_PemHoldingSeveralCertificates_ReturnsEachOfThem(string extension)
    {
        using var first = CreateSelfSignedCertificate("Bundled One");
        using var second = CreateSelfSignedCertificate("Bundled Two");

        var fs = CreateEmptyMockFileSystem();
        fs.AddFile($"/bundle/chain{extension}", new MockFileData(first.ExportCertificatePem() + "\n" + second.ExportCertificatePem()));

        var results = new CertificateFinder(fs).AddDirectory("/bundle").ToList();

        await Assert
            .That(results.Select(r => r.Certificate.Thumbprint))
            .IsEquivalentTo([first.Thumbprint, second.Thumbprint], CollectionOrdering.Any);

        foreach (var result in results) {
            result.Certificate.Dispose();
        }
    }


    /// <summary>
    /// A leaf-plus-issuer PKCS#12 is the common case. Loading a single certificate from it also made the
    /// answer depend on export order, since the loader picked whichever the file happened to lead with.
    /// </summary>
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task EnumerateCertificates_Pkcs12HoldingAChain_ReturnsEachCertificate(bool issuerFirst)
    {
        using var issuer = CreateSelfSignedCertificate("Pkcs12 Issuer");
        using var leaf = CreateSelfSignedCertificate("Pkcs12 Leaf");
        X509Certificate2[] ordered = issuerFirst ? [issuer, leaf] : [leaf, issuer];
        var pkcs12 = new X509Certificate2Collection(ordered).Export(X509ContentType.Pkcs12)!;

        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/p12/chain.pfx", new MockFileData(pkcs12));

        var results = new CertificateFinder(fs).AddDirectory("/p12").ToList();

        await Assert
            .That(results.Select(r => r.Certificate.Thumbprint))
            .IsEquivalentTo([issuer.Thumbprint, leaf.Thumbprint], CollectionOrdering.Any);

        foreach (var result in results) {
            result.Certificate.Dispose();
        }
    }


    [Test]
    public async Task EnumerateCertificates_SearchPattern_ReadsOnlyTheFilesThatMatch()
    {
        using var root = CreateSelfSignedCertificate("Root");
        using var server = CreateSelfSignedCertificate("Server");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/pki/ca-root.pem", new MockFileData(root.ExportCertificatePem()));
        fs.AddFile("/pki/server.pem", new MockFileData(server.ExportCertificatePem()));

        var results = new CertificateFinder(fs).AddDirectory("/pki", searchPattern: "ca-*.pem").ToList();

        await Assert.That(results.Select(x => x.Certificate.Thumbprint)).IsEquivalentTo([root.Thumbprint]);
    }


    /// <summary>
    /// The pattern decides what is read, not what is kept: a file it excludes is never opened or parsed,
    /// which is the whole point of filtering on the name. An unparseable file proves it, since reading one
    /// would report through <see cref="CertificateDirectorySource.OnLoadFailure"/>.
    /// </summary>
    [Test]
    public async Task EnumerateCertificates_SearchPattern_SkipsExcludedFilesWithoutParsingThem()
    {
        using var cert = CreateSelfSignedCertificate("Wanted");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/pki/ca-root.pem", new MockFileData(cert.ExportCertificatePem()));
        fs.AddFile("/pki/junk.der", new MockFileData([0x30, 0x82, 0x01, 0x02, 0xFF, 0xFF, 0xFF]));

        var skipped = new List<string>();
        var results = new CertificateFinder(fs)
            .AddSource(new CertificateDirectorySource("/pki", false, fs) {
                SearchPattern = "ca-*",
                OnLoadFailure = (path, _) => skipped.Add(path)
            })
            .ToList();

        await Assert.That(results.Select(x => x.Certificate.Thumbprint)).IsEquivalentTo([cert.Thumbprint]);
        await Assert.That(skipped).IsEmpty();
    }


    [Test]
    [Arguments("cert.pfx")]
    [Arguments("cert.p12")]
    public async Task EnumerateCertificates_PasswordProtectedPkcs12_IsReadWithTheDirectoryPassword(string fileName)
    {
        const string password = "correct horse battery staple";
        using var cert = CreateSelfSignedCertificate("Protected");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile($"/protected/{fileName}", new MockFileData(cert.Export(X509ContentType.Pkcs12, password)));

        var results = new CertificateFinder(fs).AddDirectory("/protected", password: password).ToList();

        await Assert.That(results.Select(r => r.Certificate.Thumbprint)).IsEquivalentTo([cert.Thumbprint]);

        foreach (var result in results) {
            result.Certificate.Dispose();
        }
    }


    /// <summary>
    /// A wrong or absent password must not look the same as a directory holding no certificates, which is
    /// what the handler is for.
    /// </summary>
    [Test]
    [Arguments(null)]
    [Arguments("wrong password")]
    public async Task EnumerateCertificates_PasswordProtectedPkcs12_WithTheWrongPassword_IsSkippedAndReported(string? password)
    {
        using var cert = CreateSelfSignedCertificate("Protected");
        var fs = CreateEmptyMockFileSystem();
        fs.AddFile("/protected/cert.pfx", new MockFileData(cert.Export(X509ContentType.Pkcs12, "the real one")));

        var skipped = new List<string>();
        var results = new CertificateFinder(fs)
            .AddSource(new CertificateDirectorySource("/protected", false, fs) {
                Password = password,
                OnLoadFailure = (path, _) => skipped.Add(path)
            })
            .ToList();

        await Assert.That(results).IsEmpty();
        await Assert.That(skipped.Select(fs.Path.GetFileName)).IsEquivalentTo(["cert.pfx"]);
    }


    /// <summary>
    /// A <see cref="CertificateFinderResult"/> carries the source it came from, so printing a result would
    /// otherwise print the directory's password with it.
    /// </summary>
    [Test]
    public async Task ToString_OfADirectorySource_RedactsThePassword()
    {
        var fs = CreateEmptyMockFileSystem();
        var source = new CertificateDirectorySource("/protected", false, fs) { Password = "hunter2" };

        var printed = source.ToString();

        await Assert.That(printed).DoesNotContain("hunter2");
        await Assert.That(printed).Contains("Password = ***");
        await Assert.That(printed).Contains("Path = /protected");
        await Assert.That(printed).Contains("SearchPattern = *");

        //A source with no password says so rather than hiding that too
        await Assert.That((source with { Password = null }).ToString()).Contains("Password = null");
    }


    /// <summary>
    /// A terminal answering with a bool or a count never hands the caller the certificates it matched, so
    /// nothing else can release them. <see cref="CertificateFinder.First"/> and friends are excluded: the
    /// match they stop on becomes the caller's.
    /// </summary>
    [Test]
    public async Task PredicateOverloads_ReleaseTheMatchesTheyDoNotReturn()
    {
        await AssertReleasesMatches(f => f.Any(x => true), expectedProduced: 1);
        await AssertReleasesMatches(f => f.All(x => false), expectedProduced: 1);
        await AssertReleasesMatches(f => f.Count(x => true), expectedProduced: 3);
        await AssertReleasesMatches(
            f => {
                try {
                    return f.Single(x => true);
                } catch (InvalidOperationException) {
                    return null;
                }
            },
            expectedProduced: 2
        );
    }


    /// <summary>
    /// Runs <paramref name="use"/> against a source that owns three certificates, and asserts every
    /// certificate the source produced was disposed rather than abandoned.
    /// </summary>
    private static async Task AssertReleasesMatches(Func<CertificateFinder, object?> use, int expectedProduced)
    {
        var certificates = new[] { "One", "Two", "Three" }.Select(CreateSelfSignedCertificate).ToArray();
        var source = new StubSource("Stub", "a", certificates) { Owns = true };

        _ = use(new CertificateFinder().AddSource(source));

        //Only the certificates actually reached are produced: the rest are never materialised
        var produced = certificates.Take(expectedProduced).ToArray();
        foreach (var certificate in produced) {
            await Assert.That(() => certificate.Subject).ThrowsExactly<CryptographicException>();
        }

        foreach (var certificate in certificates.Skip(expectedProduced)) {
            certificate.Dispose();
        }
    }


    /// <summary>
    /// Denies the current user access to <paramref name="path"/> until the returned handle is disposed.
    /// A deny rule beats the allow rules the directory inherits, so this works whether or not the test
    /// process is elevated.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static IDisposable DenyDirectoryAccess(string path)
    {
        var info = new DirectoryInfo(path);
        var rule = new FileSystemAccessRule(
            WindowsIdentity.GetCurrent().User!,
            FileSystemRights.ListDirectory | FileSystemRights.ReadData,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Deny
        );

        var security = info.GetAccessControl();
        security.AddAccessRule(rule);
        info.SetAccessControl(security);

        return new Restore(() => {
            var reverting = info.GetAccessControl();
            reverting.RemoveAccessRule(rule);
            info.SetAccessControl(reverting);
        });
    }


    private sealed class Restore(Action undo) : IDisposable
    {
        public void Dispose()
            => undo();
    }


    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; } =
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "fluentcerts-" + Guid.NewGuid().ToString("N"));

        public TempDirectory()
            => Directory.CreateDirectory(Path);

        public void Dispose()
            => Directory.Delete(Path, true);
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
        => [.. finder.Sources.Cast<CertificateStoreSource>().Select(x => (x.Name, x.Location))];


    private static List<string> DirectoryPathsOf(CertificateFinder finder)
        => [.. finder.Sources.Cast<CertificateDirectorySource>().Select(x => x.Path)];


    private static readonly MockFileSystem MockFileSystem = TestTools.CreateMockFileSystemWithCerts();
}
