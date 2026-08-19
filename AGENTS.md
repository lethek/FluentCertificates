# AGENTS.md

## Project Overview

FluentCertificates is a .NET library for working with X.509 certificates using an immutable fluent builder pattern. It's published as multiple NuGet packages and supports certificate creation, finding/querying, and export operations.

**Important:** The API is under initial development (v0.x.y) and may include breaking changes between minor versions.

## Build System

This project uses **NUKE** as its build system. All build operations should use the NUKE build scripts.

### Common Build Commands

```bash
# Build the solution (default)
./build.cmd              # Windows
./build.sh               # Linux/macOS

# Run tests
./build.cmd Test         # Windows
./build.sh Test          # Linux/macOS

# Create NuGet packages (outputs to artifacts/ directory)
./build.cmd Pack         # Windows
./build.sh Pack          # Linux/macOS

# Clean build artifacts
./build.cmd Clean        # Windows
./build.sh Clean         # Linux/macOS
```

The build script will:
- Automatically install the correct .NET SDK if not present
- Use GitVersion for versioning
- Output packages to the `artifacts/` directory

### Direct dotnet Commands

While NUKE is preferred for full builds, you can also use dotnet CLI directly:

```bash
# Build
dotnet build

# Run all tests
dotnet test

# Run tests for a specific project
dotnet test tests/FluentCertificates.Builder.Tests/FluentCertificates.Builder.Tests.csproj

# Run a single test by name
dotnet test --filter "FullyQualifiedName~TestMethodName"
```

## Architecture

### Package Structure

The solution is organized into multiple NuGet packages with clear separation of concerns:

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

6. **FluentCertificates.Builder.BouncyCastle**
   - Interoperability with BouncyCastle library
   - Conversion extensions between .NET and BouncyCastle types
   - Location: `src/FluentCertificates.Builder.BouncyCastle/`

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

**Extension Methods for Export:**
Certificate export functionality is implemented as extension methods rather than instance methods, providing a consistent API across X509Certificate2, X509Chain, and collections.

### Target Frameworks

All projects target:
- .NET 8.0 (net8.0)
- .NET 9.0 (net9.0)

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

### CertificateFinder
Provides LINQ-queryable interface for finding certificates across:
- X509Store instances (CurrentUser, LocalMachine, etc.)
- File system directories
- Supports filtering, ordering, and projection via standard LINQ operators

### Extension Methods
Extensive extension methods provide export capabilities:
- `ExportAsPem()` / `ToPemString()` - PEM format
- `ExportAsPkcs12()` - PFX format (with private keys)
- `ExportAsPkcs7()` - P7B format (certificate chains)
- `ExportAsCert()` - DER/CER format
- `BuildChain()` - Build certificate chains
- `VerifyChain()` - Verify certificate chains
- `IsValidNow()` / `IsValidAt()` - Validity checks
- `IsSelfSigned()` / `IsIssuedBy()` - Relationship checks

## Additional Notes

- The project uses GitVersion for semantic versioning
- GitHub Actions CI is configured for automated builds and publishing
- Source Link is enabled for debugging into the library
- Symbol packages (snupkg) are generated alongside NuGet packages
- The solution includes .editorconfig for consistent code style

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
