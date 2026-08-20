# AGENTS.md

## Project Overview

FluentCertificates is a .NET library for working with X.509 certificates using an immutable fluent builder pattern. It's published as multiple NuGet packages and supports certificate creation, finding/querying, and export operations.

**Important:** The API is under initial development (v0.x.y) and may include breaking changes between minor versions.

## Build System

Plain `dotnet` CLI. There is no build-system wrapper: the NUKE build (`build.cmd` / `build.sh` /
`build/`) was removed, and CI in `.github/workflows/dotnet.yml` calls `dotnet` directly.

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

### Common Build Commands

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

## Architecture

### Package Structure

The solution is organized into five NuGet packages with clear separation of concerns. Every project under `src/` is published; there are no internal-only projects.

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

**BouncyCastle is not a dependency of any shipped package.** `CertificateBuilder` used it internally in
the past but no longer does; nothing under `src/` references `Org.BouncyCastle`.

Some tests still use BouncyCastle as a tool, to construct inputs and to pick apart output for assertions.
Those projects take their own `BouncyCastle.Cryptography` package reference, and the two conversion
helpers they need (`X509Name.ConvertToDotNet()`, `X509Extension.ConvertToBouncyCastle()`) live in
`tests/FluentCertificates.Builder.Tests/BouncyCastleTestExtensions.cs`. There was previously a
`src/FluentCertificates.Builder.BouncyCastle` project for this; it was never published and has been
removed. Do not reintroduce a BouncyCastle dependency under `src/`.

### Key Design Patterns

**Immutable Fluent Builder Pattern:**
All builder classes (CertificateBuilder, X500NameBuilder, GeneralNameListBuilder, CertificateFinder) are implemented as C# records with immutability. Each builder method returns a new instance rather than mutating state.

Example:
```csharp
var builder = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetSubject(b => b.SetCommonName("example.com"));
// 'builder' is unchanged, methods return new instances
```

**Fluent Export Builder:**
Export is reached through an `Export()` extension method on `X509Certificate2`, `X509Certificate2Collection`,
`X509Chain` and `IEnumerable<X509Certificate2>`, which returns a `CertificateExportBuilder`. Configure with
`With*`, choose a format with `As*`, then terminate with `To*`:

```csharp
cert.Export().WithPrivateKey().AsPem().ToPemString();
cert.Export().WithPassword(pw).AsPkcs12().ToFile(path);
```

The older `ExportAsPem()` / `ExportAsPkcs12()` / `ExportAsPkcs7()` / `ExportAsCert()` / `ToPemString()` /
`ToBase64String()` extension methods on `X509Certificate2`, `X509Certificate2Collection`, `X509Chain` and
`IEnumerable<X509Certificate2>` were deprecated and have now been removed. `Export()` is the only export API.

Note that `CertificateRequest.ExportAsPem()` / `ToPemString()` (in `CertificateRequestExtensions`) and the
`AsymmetricAlgorithm.ExportAs*Pem()` methods share those names but are **not** deprecated and have no builder
equivalent: the export builder works on certificates, not CSRs or bare keys.

### Target Frameworks

- All five library projects under `src/`: net8.0 and net9.0
- Test projects: net8.0, net9.0 and net10.0

Some dependencies use conditional package references based on target framework (see .csproj files).

### Test Framework

Tests use:
- **TUnit** as the testing framework, running on Microsoft.Testing.Platform (see `global.json`)
- `[Test]` for test methods, `[Arguments]` for inline cases, `[MethodDataSource]` for generated cases
- Assertions are async: `await Assert.That(actual).IsEqualTo(expected)`. Every test method returns `Task`
- TUnit parallelises tests by default, including methods within the same class; add `[NotInParallel]` where that isn't safe
- `SupportedOSAttribute` (a `TUnit.Core.SkipAttribute`) skips OS-specific tests
- Test projects target net8.0, net9.0 and net10.0

Two TUnit gotchas worth knowing:
- TUnit's implicit global usings make the bare name `Assembly` ambiguous with `System.Reflection.Assembly`; alias it
- `IsEquivalentTo` compares members structurally by reflection, not via `Equals`. For types like `X509Certificate2`
  where that pulls in unstable members (e.g. `Handle`), pass an explicit `IEqualityComparer<T>`

Test projects are located in `tests/` directory with naming pattern `{ProjectName}.Tests`.

## Code Conventions

### Namespace
All code uses the root namespace `FluentCertificates` regardless of which sub-package it belongs to. This provides a consistent API surface for consumers.

### Immutability
Builder classes use C# records with init-only properties. Internal state is stored in immutable collections (ImmutableHashSet, ImmutableList). Use `with` expressions for modifications.

### XML Documentation
All public APIs require XML documentation comments (`///`). Documentation is generated for all packable projects (`GenerateDocumentationFile = true`).

### Internals Visibility
Several projects expose internals to test projects and LINQPad via `InternalsVisibleTo`. Check .csproj files before making members internal.

### Key and Certificate Ownership
`X509Certificate2` and `AsymmetricAlgorithm` are both disposable, and three rules decide who releases them:

1. **Keys the builder generates** are disposed by `CertificateBuilder.Create` (see the `generateKeys` flag).
2. **Keys supplied by the caller**, via `SetKeyPair` or `SetPublicKey`, are never disposed by the library.
3. **Keys and certificates the library extracts** it must dispose itself. `GetPrivateKey()`,
   `GetRSAPublicKey()` and friends return a *new* instance per call, and `CopyWithPrivateKey` returns a
   new certificate that supersedes the original. Scope all of them with `using`.

Check rule 3 when adding any call to `Get*PrivateKey`, `Get*PublicKey` or `CopyWithPrivateKey`. Disposing
an extracted key does not affect the certificate it came from, or any sibling instance.

`FilterPrivateKeys` is the exception: it emits a mix of caller-owned originals and library-created keyless
copies, indistinguishable to the caller, so its output must not be disposed. See #46.

## Working with Certificates

### CertificateBuilder
The main API for creating certificates. Supports:
- Self-signed certificates
- CA-signed certificates
- Certificate Authorities (with path length constraints)
- Certificate Signing Requests (CSRs)
- Custom extensions
- Subject Alternative Names (SAN)
- Custom serial number generation
- Key agreement certificates, via `KeyAlgorithm.ECDiffieHellman`. An ECDH key cannot sign, so `Validate()`
  requires an `Issuer` and rejects the `CA`, `CodeSign`, `OcspSigning` and `TimeStamping` usages, and
  `CreateCertificateSigningRequest` throws. A `SignatureGenerator` does not lift either restriction: it
  signs with an unrelated key, which neither self-signs nor proves possession. The key
  usage bit becomes `keyAgreement` instead of `digitalSignature`. An ECDH public key is byte-identical to
  an ECDsa one in SubjectPublicKeyInfo, so the distinction comes from `KeyAlgorithm` or the supplied key's
  runtime type, never from the certificate.
- External signing keys, via `SetPublicKey` (certify a key whose private half is unreachable) and
  `SetSignatureGenerator` (sign with a supplied `X509SignatureGenerator`). Used together they cover
  HSM/TPM/KMS keys. `Validate()` requires both when self-signing, since either alone yields a
  certificate that cannot verify.

### CertificateFinder
Provides LINQ-queryable interface for finding certificates across:
- X509Store instances (CurrentUser, LocalMachine, etc.)
- File system directories
- Supports filtering, ordering, and projection via standard LINQ operators

### Extension Methods

Export, via `Export()` and the `CertificateExportBuilder` it returns:
- Configure: `WithPrivateKey()` / `WithPrivateKeys()` / `WithoutPrivateKeys()` / `WithKeys(ExportKeys)` /
  `WithPassword(string?)` / `WithChain(...)`
- Format: `AsPem()` / `AsPkcs12()` / `AsPkcs7()` / `AsCert()`
- Terminate: `ToPemString()` (PEM only) / `ToByteArray()` / `ToFile(path)` / `ToStream(stream)`

`WithPassword(SecureString)` is honoured by every format, but only `AsPem()` keeps it out of the managed
heap: the platform's PKCS#12 export takes a `string`, so `AsPkcs12()` has to materialise one.

Certificates forming a single issuer chain are reordered root-first at export, so the order they were
added in does not matter. PEM blocks are written leaf-first from that, `ExportKeys.Leaf` keeps the last
certificate's key, and `AsCert()` exports the first. A set that is not one unambiguous chain is left in
the order it was given.

Chain and validity helpers on `X509Certificate2` / `X509Chain`:
- `BuildChain()` - Build certificate chains. Two overloads: `(IEnumerable<X509Certificate2>?, bool)` and
  `(Action<X509ChainPolicy>)`. Both leave revocation set to `NoCheck`. Read `Verified` from the returned
  tuple to check the result; the old `VerifyChain()` wrapper has been removed.
- `IsValidNow()` / `IsValidAt(DateTimeOffset)` - Validity checks. `IsValidAt(DateTime)` is `[Obsolete]`: a
  `DateTime` carries no offset, so its `DateTimeKind` silently changes the answer.
- `IsSelfSigned()` / `IsIssuedBy()` - Relationship checks


## Additional Notes

- The project uses GitVersion for semantic versioning
- GitHub Actions CI is configured for automated builds and publishing
- Source Link is enabled for debugging into the library
- Symbol packages (snupkg) are generated alongside NuGet packages
- The solution includes .editorconfig for consistent code style
- The solution file is `FluentCertificates.slnx` (XML solution format)
