# AGENTS.md

## Project overview

FluentCertificates is a .NET library for X.509 certificate creation, discovery and export, published as
five NuGet packages from `src/`. Every project under `src/` is published; there are no internal-only
projects.

All code uses the root namespace `FluentCertificates` regardless of which package it is in.

### Breaking changes

The API is pre-1.0 and breaking changes are expected between minor versions. They are free, and that a
change breaks compatibility carries no weight against it. Never rank one design above another on
compatibility grounds, never soften a design to preserve an existing signature, and never present the
break as a cost when weighing an option up. Judge a feature, fix or refactor on its other merits alone.

Record the break in `CHANGELOG.md` under `### Changed`, one line, prefixed `**Breaking:**`.

## Responsibility boundary

This is a library for building certificates, not a certificate authority. It does not own anyone's
issuance policy and must not adopt one on the caller's behalf.

Everything the builder consumes is the caller's own except a PKCS#10 signing request. A caller
configuring a builder is the trust authority for what they are making, and can already produce any
certificate they like from `CertificateRequest` in a few lines. A signing request is the one input that
arrives from someone else, and it contributes three things: a subject name, a public key, and whichever
extensions the caller explicitly accepted. That split decides what gets checked.

In scope:

- Encoding faithfully what the caller described.
- Correcting criticality where RFC 5280 states a MUST. The rule set is fixed, and it corrects rather
  than refuses.
- Never letting a signing request silently replace something the caller set explicitly. Either the
  caller's call wins or it throws; a silent no-op is a defect.
- Refusing a certificate that contradicts a stated `Usage` about whether it is a certificate authority
  and whether it may sign certificates.
- Checking what a signing request supplies where the requester cannot know the right answer, such as a
  key identifier naming the issuer's key.

Out of scope:

- Whether a requester is entitled to the name they asked for.
- Which extensions a policy permits and what values they may carry. Certificate policies, extended key
  usage purposes, revocation and access locations, and name constraints are all policy.
- Conformance with any profile beyond RFC 5280's MUSTs. The CA/Browser Forum's requirements are a
  policy the caller may or may not be operating under.
- Whether a certificate is fit to be trusted. No such property exists independently of the policy it
  was issued under.

### Judging a proposed check

Before adding a refusal, answer three questions. It needs a yes to one of them.

1. Does it protect against input the caller did not supply?
2. Does it stop the builder producing something other than what the caller asked for?
3. Does it catch a self-contradiction the caller cannot have intended, at negligible cost?

Three noes means the finding is a feature request against the caller's policy, not a defect here.
Document the hazard and leave the decision with them.

Weigh two costs against any new refusal. It fires on every caller, so a rule that is wrong in an edge
case removes a capability from people who were doing nothing wrong. And a refusal asserts a standards
claim: getting that claim wrong breaks working code, which is worse than not checking at all. Verify
the clause before citing it.

## Build and test

Plain `dotnet` CLI, no wrapper. `.github/workflows/dotnet.yml` calls it directly. The solution file is
`FluentCertificates.slnx`.

```bash
dotnet build -c Debug
dotnet test -c Debug

# Per project: --project, not a bare path
dotnet test -c Debug --project tests/FluentCertificates.Builder.Tests/FluentCertificates.Builder.Tests.csproj

# Coverage
dotnet test --coverage --coverage-output-format cobertura --results-directory ./coverage

# Packages
dotnet pack -c Release -p:PackageOutputPath="$PWD/artifacts/"
```

**`--filter` does not work** under Microsoft.Testing.Platform. Pass TUnit's tree-node filter after `--`,
scoped to the owning project: a project matching zero tests is reported as a failure, so a solution-wide
filter looks like it failed.

```bash
dotnet test -c Debug --project tests/FluentCertificates.Builder.Tests/FluentCertificates.Builder.Tests.csproj -- --treenode-filter "/*/*/*/TestMethodName*"
```

GitVersion computes versions in CI and passes them to `dotnet build`/`pack` via `-p:`. A local build
produces a default version; only CI-produced packages carry real ones. Releases are cut with the
`/release` skill (`.claude/skills/release/SKILL.md`), which stops before the push that publishes.

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Add one terse line under
`## [Unreleased]` for anything that reaches consumers, grouped under the spec's six headings. An entry
names what changed and nothing else: no rationale, no mechanism, no migration notes. One change gets one
entry, so a `Fixed` line restating a `Changed` line by its consequence is the same fact twice. Repo-only
changes (tests, CI, agent docs) get no entry.

`## [Unreleased]` is the diff since the last release, not the history behind it. A change both introduced
and fixed in that window gets no entry: amend the entry it corrects. Read the last release tag's tree to
settle what changed, since the commit log shows in-window churn as though it shipped.

## Mutation testing

`stryker-config.json` drives Stryker.NET. Set **`FLUENTCERT_MUTATION_TESTING=true`** for the run: it
relaxes `FLUENTCERT001` to a warning in `FluentCertificates.Builder`, and Stryker cannot mutate the
project without it. Never make that `NoWarn` unconditional; the `#pragma` directives in
`CertificateBuilder.cs` are the real suppression.

Two limits are the tool's, not the tests':

- **Static mutants cannot be killed.** The MTP runner reuses one test host, so at `--concurrency 1` every
  static mutant is a false survivor and above that they flip at random. Judge those files on the
  non-static mutants alone.
- **Timeouts count as kills and track machine load.** Compare killed counts across runs, not percentages.

Where a survivor genuinely cannot be killed, say so in a comment at the site rather than adding an ignore
to the config.

## Code conventions

- Public APIs require XML documentation. Contracts a caller or implementer must honour belong there, on
  the member, not in this file.
- Builders are immutable records with init-only properties and immutable collections. Methods return a
  new instance.
- Several projects expose internals via `InternalsVisibleTo` to test projects and LINQPad. Check the
  `.csproj` before making a member internal.
- **BouncyCastle is not a dependency of any shipped package.** Nothing under `src/` references
  `Org.BouncyCastle`, and nothing should. Some test projects use it as a tool and take their own
  package reference.

### Key and certificate ownership

`X509Certificate2`, `AsymmetricAlgorithm` and `CertificateKey` are all disposable. Three rules:

1. Keys the builder generates are disposed by `CertificateBuilder.Create`.
2. Keys supplied by the caller are never disposed by the library.
3. Keys and certificates the library *extracts* it must dispose itself. `GetPrivateKey()`,
   `Get*PublicKey()` and `CopyWithPrivateKey` each return a **new** instance per call. Scope them with
   `using`. Check this whenever adding such a call.

`CertificateKey` owns the key it wraps, so dispose it rather than anything reached through
`AsAsymmetricAlgorithm` / `AsMLDsa`.

`FilterPrivateKeys` and `X509ChainBuilder.Export()` are the exceptions: both emit a mix of caller-owned
originals and library-created copies that the caller cannot tell apart, so their elements must not be
disposed.

## Testing

**TUnit** on Microsoft.Testing.Platform (see `global.json`). Test projects are `tests/{Project}.Tests`;
`tests/FluentCertificates.TestSupport` holds shared types, runs no tests, and targets net8.0 alone while
the test projects target net8.0, net9.0 and net10.0.

Gotchas:

- TUnit parallelises methods within a class. Add `[NotInParallel]` where that isn't safe.
- TUnit's implicit global usings make the bare name `Assembly` ambiguous. Alias it.
- `IsEquivalentTo` compares structurally by reflection, not via `Equals`. For types like
  `X509Certificate2` that pulls in unstable members such as `Handle`, so pass an explicit
  `IEqualityComparer<T>`.
- An OS-specific test declares only the BCL's `[SupportedOSPlatform]` / `[UnsupportedOSPlatform]`.
  `SkipUnsupportedOSPlatformAttribute` reads them back and is applied at assembly level from the
  `.csproj`, so tests never mention it.

A capability gate that silently matches nothing is a defect: a skipped test must report as skipped, never
as passed.

## Post-quantum cryptography

The PQC surface is `[Experimental("FLUENTCERT001")]`, declared separately from Microsoft's `SYSLIB5006`
so it stays visible independently. Every route into the surface must report it; check when adding one.
The public API does not vary by target framework, so never put PQC members behind `#if NET10_0_OR_GREATER`
— only their implementations.

Availability is a runtime capability, not an OS fact. `KeyAlgorithm.IsSupported` means "usable to build a
certificate", not "the key generates", and is settled by cached probes in `PostQuantumSupport`. **Add a
probe, never an OS check**, when the next gap appears. Tests gate through `PostQuantumGate`, via
`SkipUnlessAlgorithmSupportedAttribute` or `PostQuantumGate.SkipUnlessSupported(algorithm)`; never call
`Skip.Unless(algorithm.IsSupported, ...)` directly, as that form cannot be turned off.

### Platform matrix as of .NET 10

|Algorithm|Windows|Linux OpenSSL 3.5+|Linux OpenSSL 3.0|
|---|---|---|---|
|ML-DSA|yes|yes|no|
|SLH-DSA|no|yes|no|
|ML-KEM|no|yes|no|
|Composite ML-DSA|no|no|no|

The OpenSSL version decides this, not the distribution. Check `openssl version` before concluding a
platform is broken.

CI runs PQC in the `pqc` job on **`ubuntu-26.04`** (OpenSSL 3.5.5), pinned rather than `ubuntu-latest`,
which is Ubuntu 24.04 with OpenSSL 3.0.13 and would silently stop testing anything. That job sets
**`FLUENTCERT_REQUIRE_PQC=1`**, which stops every PQC gate from skipping so an unavailable algorithm
fails loudly instead of vanishing. Set that variable only on runs meant to prove PQC works; on Windows it
fails, correctly.

Locally on Windows, run PQC tests in Docker with `mcr.microsoft.com/dotnet/sdk:10.0-alpine3.24` and
`-e FLUENTCERT_REQUIRE_PQC=1`. The default `10.0` tag is Ubuntu 24.04 and will not do.

`Oids.cs` holds the post-quantum OIDs, read out of generated keys rather than transcribed, and checked
against draft-ietf-lamps-pq-composite-sigs-19 s7. SLH-DSA's arc is not in declaration order: SHA2 takes
`.20`-`.25`, SHAKE takes `.26`-`.31`.
