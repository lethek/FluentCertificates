# AGENTS.md

## Project overview

FluentCertificates is a .NET library for working with X.509 certificates using an immutable fluent builder pattern. It's published as multiple NuGet packages and covers certificate creation, finding, querying and export.

**Important:** The API is under initial development (v0.x.y) and may include breaking changes between minor versions.

## Build system

Plain `dotnet` CLI. There is no build-system wrapper; CI in `.github/workflows/dotnet.yml` calls
`dotnet` directly.

Versioning is supplied by GitVersion, which runs as a GitHub Action step in CI (`gittools/actions`,
`versionSpec: 6.x`, configured by `GitVersion.yml`) and passes the result to `dotnet build`/`dotnet pack`
via `-p:` properties. A local `dotnet build` with no properties produces a default version; that is
expected and only CI-produced packages carry real version numbers.

Releases are cut with the `/release` skill (`.claude/skills/release/SKILL.md`): it sizes the SemVer bump
from the diff, promotes the changelog and tags, stopping before the push that publishes to nuget.org.

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Add an entry under
`## [Unreleased]` for anything that reaches consumers, grouped under `### Added` / `### Changed` /
`### Deprecated` / `### Removed` / `### Fixed` / `### Security`. One terse line per change. Repo-only
changes (tests, CI, docs for agents) get no entry.

### Common build commands

```bash
# Build
dotnet build

# Run all tests
dotnet test

# Run tests for a specific project (note: --project, not a bare path)
dotnet test --project tests/FluentCertificates.Builder.Tests/FluentCertificates.Builder.Tests.csproj

# Run a single target framework
dotnet test -f net9.0 --project tests/FluentCertificates.Builder.Tests/FluentCertificates.Builder.Tests.csproj

# Run a single test by name. `--filter` does NOT work under Microsoft.Testing.Platform;
# pass TUnit's tree-node filter after `--` instead. Scope it to the owning project: a project
# that matches zero tests is reported as a failure, so a solution-wide filter looks like it failed.
dotnet test --project tests/FluentCertificates.Builder.Tests/FluentCertificates.Builder.Tests.csproj -- --treenode-filter "/*/*/*/TestMethodName*"

# Run tests with coverage (Microsoft.Testing.Extensions.CodeCoverage, referenced transitively by TUnit)
dotnet test --coverage --coverage-output-format cobertura --results-directory ./coverage

# Create NuGet packages
dotnet pack -c Release -p:PackageOutputPath="$PWD/artifacts/"
```

### Mutation testing

`stryker-config.json` drives Stryker.NET: the MTP runner, `perTestInIsolation` coverage, net9.0, and
`DSAX509SignatureGenerator` excluded (a legacy compatibility shim there is no value in testing).

Set **`FLUENTCERT_MUTATION_TESTING=true`** for the run. It is the only thing that relaxes `FLUENTCERT001`
to a warning in `FluentCertificates.Builder`, which Stryker needs because its mutated compilation drops the
`#pragma` trivia around the post-quantum call sites when it rolls a mutant back, leaving the diagnostic as
an error that no mutant can build through. Every ordinary build leaves the gate closed, so the pragmas in
`CertificateBuilder.cs` remain the real suppression. Never make that `NoWarn` unconditional.

Two limits are the tool's, not the tests':

- **Static mutants cannot be killed.** The MTP runner reuses one test host across mutants, so a mutated
  `static` initialiser only takes effect when it lands in a fresh one. At `--concurrency 1` every static
  mutant is a false survivor; above that they flip at random between runs. Judge those files on the
  non-static mutants alone.
- **Timeouts count as kills and track machine load.** The headline score swings a couple of points between
  identical runs. Compare killed counts across runs rather than the percentage.

A survivor is worth reading before it is dismissed: the ones in `KeyAlgorithm.CurveKey` turned out to be
hiding a `NullReferenceException` and a real equality collision. Where one genuinely cannot be killed, say
so in a comment at the site rather than adding an ignore to the config.

## Architecture

### Package structure

The solution is organized into five NuGet packages. Every project under `src/` is published; there are no internal-only projects.

1. **FluentCertificates** (meta-package)
   - Top-level package that imports Builder, Extensions, and Finder
   - Location: `src/FluentCertificates/`

2. **FluentCertificates.Builder**
   - Core certificate building functionality via `CertificateBuilder`
   - Subject name building via `X500NameBuilder`
   - Subject Alternative Names via `GeneralNameListBuilder`
   - Certificate Signing Request (CSR) support
   - Location: `src/FluentCertificates.Builder/`
   - Depends on: FluentCertificates.Extensions

3. **FluentCertificates.Extensions**
   - Extension methods for X509Certificate2, X509Chain, X509Certificate2Collection
   - Export methods (PEM, PKCS7, PKCS12, CER)
   - Certificate validation and verification helpers
   - AsymmetricAlgorithm and CertificateRequest extensions
   - Location: `src/FluentCertificates.Extensions/`
   - Depends on: FluentCertificates.Common

4. **FluentCertificates.Finder**
   - Certificate discovery via `CertificateFinder` (implements IQueryable)
   - Searches X509Store instances and file system directories
   - LINQ support for flexible querying
   - Location: `src/FluentCertificates.Finder/`
   - Depends on: FluentCertificates.Common

5. **FluentCertificates.Common**
   - Shared internal utilities and OID constants
   - Location: `src/FluentCertificates.Common/`
   - Not typically referenced directly by consumers

### BouncyCastle

**BouncyCastle is not a dependency of any shipped package.** Nothing under `src/` references
`Org.BouncyCastle`, and nothing should.

Some tests use BouncyCastle as a tool, to construct inputs and to pick apart output for assertions.
Those projects take their own `BouncyCastle.Cryptography` package reference, and the two conversion
helpers they need (`X509Name.ConvertToDotNet()`, `X509Extension.ConvertToBouncyCastle()`) live in
`tests/FluentCertificates.Builder.Tests/BouncyCastleTestExtensions.cs`.

### Key design patterns

**Immutable fluent builder pattern:**
All builder classes (CertificateBuilder, X500NameBuilder, GeneralNameListBuilder, CertificateFinder) are immutable C# records. Each builder method returns a new instance rather than mutating state.

Example:
```csharp
var builder = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetSubject(b => b.SetCommonName("example.com"));
// 'builder' is unchanged, methods return new instances
```

**Fluent export builder:**
Export is reached through an `Export()` extension method on `X509Certificate2`, `X509Certificate2Collection`,
`X509Chain` and `IEnumerable<X509Certificate2>`, which returns a `CertificateExportBuilder`. Configure with
`With*`, choose a format with `As*`, then terminate with `To*`:

```csharp
cert.Export().WithPrivateKey().AsPem().ToPemString();
cert.Export().WithPassword(pw).AsPkcs12().ToFile(path);
```

`Export()` is the only export API for certificates. `CertificateRequest.ExportAsPem()` / `ToPemString()`
(in `CertificateRequestExtensions`) and the `AsymmetricAlgorithm.ExportAs*Pem()` methods have no builder
equivalent and are not deprecated: the export builder works on certificates, not CSRs or bare keys.

### Target frameworks

- All five library projects under `src/`: net8.0, net9.0 and net10.0
- Test projects: net8.0, net9.0 and net10.0
- `tests/FluentCertificates.TestSupport`: net8.0 alone, which all three consume. It references
  `FluentCertificates.Extensions`, so its capability checks compile against the net8.0 build but run
  against whichever build the consuming test project deployed

Some dependencies use conditional package references based on target framework (see .csproj files).

### Test framework

- **TUnit**, running on Microsoft.Testing.Platform (see `global.json`)
- `[Test]` for test methods, `[Arguments]` for inline cases, `[MethodDataSource]` for generated cases
- Assertions are async: `await Assert.That(actual).IsEqualTo(expected)`. Every test method returns `Task`
- TUnit parallelises tests by default, including methods within the same class; add `[NotInParallel]` where that isn't safe
- An OS-specific test declares its platforms with the BCL's `[SupportedOSPlatform]` /
  `[UnsupportedOSPlatform]` and nothing else: they satisfy CA1416, and `SkipUnsupportedOSPlatformAttribute`
  reads them back to skip the test elsewhere. Each test project applies that attribute at assembly level
  through an `<AssemblyAttribute>` item in its `.csproj`, so tests never mention it. Precedence rules are
  in its XML docs, and `SkipUnsupportedOSPlatformAttributeTests` guards it

TUnit gotchas:
- TUnit's implicit global usings make the bare name `Assembly` ambiguous with `System.Reflection.Assembly`; alias it
- `IsEquivalentTo` compares members structurally by reflection, not via `Equals`. For types like `X509Certificate2`
  where that pulls in unstable members (e.g. `Handle`), pass an explicit `IEqualityComparer<T>`

Test projects live in `tests/` with the naming pattern `{ProjectName}.Tests`. Alongside them,
`tests/FluentCertificates.TestSupport` holds support types shared between them and runs no tests of its
own; it is a library rather than a test project, so it takes `TUnit.Core` alone.

## Code conventions

### Namespace

All code uses the root namespace `FluentCertificates` regardless of which sub-package it belongs to. This provides a consistent API surface for consumers.

### Immutability

Builder classes use C# records with init-only properties. Internal state is stored in immutable collections (ImmutableHashSet, ImmutableList). Use `with` expressions for modifications.

### XML documentation

All public APIs require XML documentation comments (`///`). Documentation is generated for all packable projects (`GenerateDocumentationFile = true`).

### Internals visibility

Several projects expose internals to test projects and LINQPad via `InternalsVisibleTo`. Check .csproj files before making members internal.

### Key and certificate ownership

`X509Certificate2`, `AsymmetricAlgorithm` and `CertificateKey` are all disposable, and three rules decide
who releases them.

`CertificateKey` is the library's own abstraction over a key of any kind, and exists because .NET's
post-quantum key types derive from `object` rather than `AsymmetricAlgorithm`, so no
`AsymmetricAlgorithm`-typed signature can accept one. It owns and disposes the key it wraps, so
never dispose something reached through `AsAsymmetricAlgorithm`, `AsMLDsa` and friends - dispose the
`CertificateKey`. `GetPrivateKey()` returns one.

1. **Keys the builder generates** are disposed by `CertificateBuilder.Create` (see the `generateKeys` flag).
2. **Keys supplied by the caller**, via `SetKeyPair` or `SetPublicKey`, are never disposed by the library.
3. **Keys and certificates the library extracts** it must dispose itself. `GetPrivateKey()`,
   `GetRSAPublicKey()` and friends return a *new* instance per call, and `CopyWithPrivateKey` returns a
   new certificate that supersedes the original. Scope all of them with `using`.

Check rule 3 when adding any call to `Get*PrivateKey`, `Get*PublicKey` or `CopyWithPrivateKey`. Disposing
an extracted key does not affect the certificate it came from, or any sibling instance.

Two APIs are the exception, both emitting a mix of caller-owned originals and library-created copies that
are indistinguishable to the caller, so neither's output may be disposed:

- `FilterPrivateKeys`, whose stripped certificates are keyless copies.
- `X509ChainBuilder.Export()`, whose `Certificates` are the caller's own instances wherever the caller
  supplied them and keyless copies only for elements the platform supplied (a system-store root, an
  AIA-fetched intermediate).

## Working with certificates

### CertificateBuilder

The main API for creating certificates. Supports:
- Self-signed certificates
- CA-signed certificates
- Certificate Authorities (with path length constraints)
- Certificate Signing Requests (CSRs)
- Custom extensions
- Subject Alternative Names (SAN)
- Custom serial number generation
- Algorithm selection, via a single `KeyAlgorithm` descriptor that carries its own key length, curve or
  parameter set: `KeyAlgorithm.RSA(4096)`, `KeyAlgorithm.ECDsa(curve)`, `KeyAlgorithm.MLDsa65`. There is no
  separate `KeyLength` or `ECCurve` on the builder, so an invalid combination is unrepresentable rather than
  rejected, and `Validate()` has no combination guards to enforce. `KeyAlgorithm.Default(KeyAlgorithmFamily)`
  covers callers holding only a family, which is what an attribute or switch label can carry. Defaults are
  RSA 4096, DSA 1024 and EC nistP256.
- Non-signing certificates, via `KeyAlgorithm.CanSign`. This is `false` for `ECDiffieHellman` and the
  `MLKem` sets, and it alone drives the guards: `Validate()` requires an `Issuer` and rejects the `CA`,
  `CodeSign`, `OcspSigning` and `TimeStamping` usages, and `CreateCertificateSigningRequest` throws. A
  `SignatureGenerator` does not lift either restriction: it signs with an unrelated key, which neither
  self-signs nor proves possession. Key usage differs between the two, deliberately: ECDH asserts
  `keyAgreement`, while ML-KEM asserts `keyEncipherment`, because encapsulation is key transport rather than
  Diffie-Hellman agreement. An ECDH public key is byte-identical to an ECDsa one in SubjectPublicKeyInfo, so
  that distinction comes from `KeyAlgorithm` or the supplied key's runtime type, never from the certificate;
  a post-quantum key carries its own OID and needs no such workaround.
- Post-quantum certificates: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Composite ML-DSA and ML-KEM (FIPS 203).
  See "Post-quantum cryptography" below.
- External signing keys, via `SetPublicKey` (certify a key whose private half is unreachable) and
  `SetSignatureGenerator` (sign with a supplied `X509SignatureGenerator`). Used together they cover
  HSM/TPM/KMS keys. `Validate()` requires both when self-signing, since either alone yields a
  certificate that cannot verify.

### CertificateFinder

A LINQ-queryable interface for finding certificates across X509Store instances (CurrentUser,
LocalMachine, etc.) and file system directories. Filtering, ordering and projection all go through the
standard LINQ operators.

### Extension methods

Export, via `Export()` and the `CertificateExportBuilder` it returns:
- Configure, replacing state: `WithPrivateKey()` / `WithAllPrivateKeys()` / `WithoutPrivateKeys()` /
  `WithKeys(ExportKeys)` / `WithPassword(string?)` / `WithPassword(SecureString)` / `WithoutPassword()`
- Add, appending certificates: `AddChain(X509Chain)` / `AddChain(params IEnumerable<X509Certificate2>)` /
  `AddCertificates(params IEnumerable<X509Certificate2>)`. The C# 13 params-collections form means loose
  certificates, an array, a collection and a lazy sequence all bind to the one overload
- Format: `AsPem()` / `AsPkcs12()` / `AsPkcs7()` / `AsCert()`
- Terminate: `ToPemString()` (PEM only) / `ToByteArray()` / `ToFile(path)` / `ToStream(stream)`

`With*` configures and `Add*` accumulates; keep that split when adding methods. All the `Add*` methods
deduplicate by thumbprint, so a certificate already present is skipped. `WithChain(...)` and
`WithPrivateKeys(...)` are `[Obsolete]` and forward to `AddChain(...)` and `WithAllPrivateKeys(...)`.

**Private keys are opt-in.** `CertificateExportBuilder.Keys` defaults to `ExportKeys.None`, and so does
`X509Chain.ToCollection(ExportKeys)`; they are the only two places the enum carries a default, and both
say `None`. Every entry point inherits it, so an export writes a key only where the caller wrote
`WithPrivateKey()` (the anchor's) or `WithAllPrivateKeys()` (every one held). This is why `AsPkcs12()`
produces a keyless PFX unless asked otherwise. Keep any new default at `None`: a key the caller did not
request must never reach a file.

`WithPassword(SecureString)` is honoured by every format, but only `AsPem()` keeps it out of the managed
heap: the platform's PKCS#12 export takes a `string`, so `AsPkcs12()` has to materialise one. Each
`WithPassword` overload clears the other kind of password, so the last call wins; `WithoutPassword()`
clears both. Only a `with` expression can set both at once, and there `SecurePassword` takes precedence.

Ordering is decided by which API added the certificates, never by inspecting them at export time:

- A **chain** is sorted. `AddChain(...)` declares its argument a chain, so that group is ordered
  leaf-first and appended as a block. Each call is sorted separately, so several calls give several
  ordered chains in call order. A group that does not form one chain is appended as given.
- A **collection** is preserved. `AddCertificates(...)`, `collection.Export()` and the `IEnumerable`
  overload are bundles and are never reordered, chain or not.
- `chain.Export()` needs no sorting: `X509Chain.ChainElements` is already leaf-first.

All four formats write the list in that order. PEM is the one where order carries meaning (TLS servers
require the sender's certificate first), but PKCS#12 and PKCS#7 preserve it too, and it leaks back into
PEM the moment someone runs `openssl pkcs12 -nokeys`, so the same rule applies throughout.

`ExportKeys.Primary` and `AsCert()` are the only parts that need a designated certificate, and they read
it from the builder's `Anchor` rather than from list position. `cert.Export()` anchors on the certificate
itself and `chain.Export()` on the chain's end certificate, so `AddChain(...)` can never retarget them.
`collection.Export()` and the `IEnumerable` overload set no anchor, so those two throw
`InvalidOperationException` there: a bundle designates no leaf, and position is not evidence of one, even
when the certificates happen to form a chain. Every other export works fine without an anchor, because
nothing else asks.

`Anchor` is `private init`, so only those entry points set it, and an export whose anchor is not among
its certificates throws `ArgumentException`. That matters because `Certificates` is publicly settable and
a `with` expression can otherwise leave the anchor dangling.

Note `ExportKeys.Primary` means different things in different places: an export resolves it through the
anchor, while the public `FilterPrivateKeys` extension has no anchor to consult and always takes the
first certificate in the sequence.

Chain and validity helpers on `X509Certificate2` / `X509Chain`:
- `BuildChain()` - Starts a fluent `X509ChainBuilder`: `TrustRoot(...)` (custom root trust; system
  trust when never called), `AddCertificates(...)` (extra path-building candidates),
  `AllowInvalidTime()`, `WithPolicy(Action<X509ChainPolicy>)` (applied last, always wins; revocation
  defaults to `NoCheck`). Calling `TrustRoot` switches to `CustomRootTrust`, tracked by
  `CustomTrustEnabled` rather than inferred from `TrustedRoots` being non-empty, so trusting an empty
  set trusts nothing instead of falling back to system trust. `Create()` returns a disposable
  `ChainResult` (`Verified`, `Chain`, `ChainStatus`, `EnsureVerified()`, `Export()`) and never throws
  on verification failure; it disposes the chain itself if a `WithPolicy` action or `Build` throws.
  `Export()` on the builder verifies (throwing on failure, naming the statuses) and returns a
  `CertificateExportBuilder` anchored on the certificate. It disposes its internal chain, so each
  element is mapped back by thumbprint to the instance the caller supplied via the certificate,
  `TrustRoot`, `AddCertificates` or a `WithPolicy` action that populated `ExtraStore` or
  `CustomTrustStore` (later sources win, so the anchor always keeps its own instance); only an element
  the platform supplied itself (system-store root, AIA-fetched intermediate) is copied, and that copy
  is keyless and must not be disposed.
  Neither `Export()` seeds any key: like every export they default to `ExportKeys.None`, so a
  fullchain needs `WithPrivateKey()` for the leaf's key. `ChainResult.Export()` does not verify,
  matching every other `Export()`; use `EnsureVerified().Export()` for the guarded form.
- `IsValidNow()` / `IsValidAt(DateTimeOffset)` - Validity checks. `IsValidAt(DateTime)` is `[Obsolete]`: a
  `DateTime` carries no offset, so its `DateTimeKind` silently changes the answer.
- `IsSelfSigned()` / `IsIssuedBy()` - Relationship checks
- `CanSign()` - Whether the private key is usable for signing, rather than merely associated as
  `HasPrivateKey` reports. Every "cannot sign" outcome returns `false` rather than throwing, and it is
  independent of exportability: never implement either in terms of the other. See its XML docs


## Post-quantum cryptography

The PQC surface carries `[Experimental(Experiments.PostQuantumCryptography)]`, which is
`FLUENTCERT001`. The .NET types underneath are themselves `[Experimental]` under `SYSLIB5006`, so a
consumer naming one already has to suppress that. The library still declares its own ID, so its
experimental surface stays visible independently of Microsoft's.

That includes the four post-quantum members of `KeyAlgorithmFamily`, annotated individually rather than
the enum as a whole, so `KeyAlgorithm.Default(KeyAlgorithmFamily.MLDsa)` reports the diagnostic while
`Default(KeyAlgorithmFamily.Rsa)` stays clean. Annotating `Default` itself would flag the classical
families too. Every route into the surface must report `FLUENTCERT001`: when adding one, check that it
does.

The diagnostic fires only where a PQC member is *named in source*. Reaching one indirectly does not
trigger it and cannot be made to - `Enum.Parse<KeyAlgorithmFamily>("MLDsa")`, `Enum.GetValues`, a cast,
a `_ =>` arm that sweeps the PQC families into a default - so that hole stays open by construction.
Consumers who only ask *about* a key are unaffected anyway: `CanSign`, `IsPostQuantum`, `IsSupported`
and `IsEllipticCurve` are public, unannotated, and answer the ordinary questions without the enum.
Internal code implementing those classifiers has to name the members, so it suppresses at the call
site.

The public API does not vary by target framework. Every parameter set exists on net8.0 and net9.0
too, where selecting one throws `PlatformNotSupportedException`. Do not put PQC members behind
`#if NET10_0_OR_GREATER` - only their implementations.

### `IsSupported` means "usable to build a certificate"

Not "the key generates". The two come apart repeatedly, and a `true` that fails later in `Create()`
is worse than a `false`.

- Composite ML-DSA keys generate on Windows and Linux, but `X509SignatureGenerator.CreateForCompositeMLDsa`
  throws on both, so no platform can currently produce a composite certificate.
- ML-KEM certificates build anywhere, but `CopyWithPrivateKey(MLKem)` throws on Windows.

Both are settled by a cached probe in `PostQuantumSupport` rather than by naming operating systems,
so a runtime that gains support starts working with no change to the library. Add a probe, never an
OS check, when the next gap appears.

Probe at the granularity the answer varies at, and pay for it at that granularity too. Composite
ML-DSA is cached per parameter set by OID, because a provider may implement some sets and not others
and a single family-wide probe would deny the sets it does implement and vouch for the ones it does
not. But probing every set costs a key generation each, and the RSA-4096 sets take over half a second
apiece - `IsSupported` is a property, so that has to stay cheap. The family-wide question is therefore
settled first on the cheapest set to generate: a `PlatformNotSupportedException` from
`CreateForCompositeMLDsa` says the API is absent from this runtime, which no other set can contradict,
so the remaining seventeen are answered without generating anything. Per-set probing resumes the moment
that call succeeds. ML-KEM's gap is family-wide, so one probe covers it.

Both caches hold `Lazy<bool>`, not `bool`. `ConcurrentDictionary.GetOrAdd` may run its factory more
than once for the same key under contention, and the factory here generates a key; `Lazy<bool>`
defaults to `ExecutionAndPublication`, so it runs exactly once however many test threads ask at once.

Availability is a runtime capability, so `[SupportedOSPlatform]` cannot express it. Tests gate on
`SkipUnlessAlgorithmSupportedAttribute` (whole class) or `PostQuantumGate.SkipUnlessSupported(algorithm)`
(per parameter set, needed because Composite availability varies per set). Both route through
`PostQuantumGate`, so never call `Skip.Unless(algorithm.IsSupported, ...)` directly - that is the form
that cannot be turned off. A capability gate that silently matches nothing is a defect: a skipped test
must report as skipped, never as passed.

### Platform matrix as of .NET 10

|Algorithm|Windows|Linux OpenSSL 3.5+|Linux OpenSSL 3.0|
|---|---|---|---|
|ML-DSA|yes|yes|no|
|SLH-DSA|no|yes|no|
|ML-KEM|no|yes|no|
|Composite ML-DSA|no|no|no|

The OpenSSL version decides it, not the distribution: 3.5+ supports PQC, 3.0 supports none of it.
Check `openssl version` before concluding a platform is broken.

The `pqc` job in `.github/workflows/dotnet.yml` runs the net10.0 leg on **`ubuntu-26.04`** (OpenSSL
3.5.5), which is where PQC is actually verified in CI. It is pinned to that label rather than
`ubuntu-latest`, which resolves to `ubuntu-24.04` (OpenSSL 3.0.13) and would silently stop testing
anything; the main `build` job stays on `ubuntu-latest` and skips every PQC test as a result.

That job sets **`FLUENTCERT_REQUIRE_PQC=1`**, which stops every post-quantum gate from skipping, so an
unavailable algorithm surfaces as the `PlatformNotSupportedException` it is instead of a silent skip.
Without it the job would stay green on an image that had lost PQC support, having built nothing. It
covers all eighteen non-composite parameter sets, not a spot check, so losing one family or a handful of
sets fails as loudly as losing the lot; `PostQuantumRequiredTests` runs first only to name the missing
family before the rest of the suite turns it into noise. Composite ML-DSA is exempt, since no platform
can sign with one yet. Set the variable on any run meant to prove PQC works, and nowhere else - on
Windows it fails, correctly.

Locally on Windows, run PQC tests in Docker: `mcr.microsoft.com/dotnet/sdk:10.0-alpine3.24` works
(Alpine 3.22+ carries OpenSSL 3.5), with `-e FLUENTCERT_REQUIRE_PQC=1` to get the same assertion CI
makes. The default `10.0` tag is Ubuntu 24.04 and will not do, and there is no `10.0-trixie` tag.

### OIDs

`Oids.cs` holds all 33 post-quantum OIDs. They were read out of generated keys' SubjectPublicKeyInfo
rather than transcribed from a spec, and the 18 Composite sets have since been checked against the
registration table in draft-ietf-lamps-pq-composite-sigs-19 s7 - OID and algorithm name both, which is
what `KeyAlgorithm.Name` carries. Five Composite sets are unimplemented everywhere, so those are
spec-confirmed only and marked as such; `DeclaredOid_MatchesTheGeneratedKey` asserts every declared OID
against the real encoding for whatever the running platform supports, so a wrong one fails as soon as a
platform implements it. Keep that test passing rather than relaxing it.

Note SLH-DSA's arc is not in declaration order: SHA2 takes `.20`-`.25`, SHAKE takes `.26`-`.31`.

A post-quantum parameter set fixes both the key algorithm and the signature algorithm, so the two
share an OID and `SignatureAlgorithm` carries no `HashAlgorithm` for them, which is why that
property is nullable. `SignatureAlgorithm`'s lookup is built from
`KeyAlgorithm.PostQuantumAlgorithms`, so adding a parameter set there cannot be forgotten here.

## Additional notes

- Source Link is enabled for debugging into the library
- Symbol packages (snupkg) are generated alongside NuGet packages
- The solution file is `FluentCertificates.slnx` (XML solution format)
