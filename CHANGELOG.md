# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version number remains below 1.0.0 this library is under initial development, and
breaking changes may occur between minor versions.

Entries for v0.14.0 and earlier were reconstructed from the release history after the fact, so
they summarise each release rather than record it as it happened.

## [Unreleased]

### Added

- `CertificateExportBuilder.WithoutPassword()`, clearing both password kinds.
- `CertificateExportBuilder.Anchor`, naming the certificate `ExportKeys.Primary` and `AsCert()` target. Set by `cert.Export()` and `chain.Export()`.
- `CertificateExportBuilder.AddCertificates(...)`, appending certificates without declaring them a chain, so they are never reordered.
- `AddChain` and `AddCertificates` take `params IEnumerable<X509Certificate2>`, so loose certificates, an array, a collection or a lazy sequence all work.

### Changed

- **Breaking:** `ExportKeys.Leaf` is renamed to `ExportKeys.Primary`, since it now follows the export's anchor rather than a certificate's position in a chain.
- **Breaking:** Export orders a chain's certificates leaf-first instead of root-first, changing the certificate order within PKCS#12 and PKCS#7 output. PEM block order is unchanged.
- **Breaking:** Ordering is decided by which API added the certificates. `AddChain(...)` declares its argument a chain and sorts that group leaf-first, appending it as a block; `AddCertificates(...)`, `collection.Export()` and the `IEnumerable` overload are bundles and are never reordered, even when they form a chain.
- **Breaking:** `X509Chain.ToEnumerable()` and `ToCollection()` now return the chain leaf first, matching `X509Chain.ChainElements`.
- **Breaking:** `ExportKeys.Primary` and `AsCert()` now throw `InvalidOperationException` when no `Anchor` names a certificate, instead of exporting whichever came first. Only `cert.Export()` and `chain.Export()` set an anchor; an export holding exactly one certificate needs none.
- `ExportKeys.Primary` and `AsCert()` follow the builder's `Anchor` rather than list position, so `AddChain(...)` cannot retarget them even when the certificates do form a chain.
- Exporting throws `ArgumentException` when the `Anchor` is not among the certificates being exported.
- `FilterPrivateKeys(ExportKeys.Primary)` keeps the first certificate's private key instead of the last.

### Deprecated

- `CertificateExportBuilder.WithChain(...)`, renamed to `AddChain(...)` because it appends rather than configures. The old name forwards to the new one.

### Fixed

- Each `CertificateExportBuilder.WithPassword` overload now clears the other kind of password, so the last call wins.
- `AsCert()` now exports a chain's leaf certificate instead of its root.
- The `ExportKeys` enum's XML summary described ECDsa instead of the enum.

## [0.15.0] - 2026-08-20

### Added

- `IsValidAt(DateTimeOffset)` on `X509Certificate2`.
- `CertificateBuilder.SetValidity(TimeSpan)` and `SetValidity(DateTimeOffset, TimeSpan)`.
- `CertificateUsage.OcspSigning` and `CertificateUsage.TimeStamping`.
- `CertificateBuilder.SetSignatureGenerator` and `SetPublicKey`, for keys held in an HSM, TPM or KMS.
- `BuildChain(Action<X509ChainPolicy>)` overload on `X509Certificate2`.
- `CertificateBuilder.SetECCurve(ECCurve)`.
- `KeyAlgorithm.ECDiffieHellman`, for key agreement certificates. These assert `keyAgreement`
  instead of `digitalSignature`, and must be issued by a CA since an ECDH key cannot sign.

### Changed

- Generated ECDsa keys now default to nistP256 instead of the platform's choice.
- `CertificateUsage.CodeSign` no longer adds the `timeStamping` and `lifetimeSigning` EKUs.
- `keyEncipherment` is now set only on RSA certificates. Affects `CertificateUsage.Server` and `SMime`.
- `GeneralNameListBuilder` validates DNS names, email addresses and IP addresses as they are added.
- Setting `SetECCurve` with a non-ECDsa `KeyAlgorithm` is now rejected by `Validate` instead of ignored.

### Deprecated

- `IsValidAt(DateTime)`. Use the `DateTimeOffset` overload.
- `KeyAlgorithm.DSA` now carries guidance on its `[Obsolete]` attribute.

### Removed

- The deprecated `ExportAs*`, `ToPemString` and `ToBase64String` methods on certificates, collections
  and chains. Use `Export()`.
- `VerifyChain`. Use `BuildChain` and read `Verified`.

### Fixed

- Export now orders a certificate chain root-first however it was assembled. `cert.Export().WithChain(...)`
  previously wrote PEM blocks in a jumbled order and kept the issuer's private key instead of the leaf's.
- PEM export no longer copies a `SecureString` password into a managed string it cannot erase.
- PEM export ignored a `SecureString` password and wrote the private key unencrypted.
- An ECDH certificate could be self-signed, and an ECDH CSR created, via `SetSignatureGenerator`.
  Neither can verify; both are now rejected.
- Keys and certificates extracted internally were never disposed.
- PEM and PKCS#12 export leaked a certificate per stripped private key.
- `CertificateFinder` skipped PKCS#12 files (`.pfx`, `.p12`) on .NET 9 and later.
- `CertificateFinder` ignored certificate file extensions that were not lowercase.

## [0.14.0] - 2026-08-19

### Added

- Fluent certificate export API: `Export()` on `X509Certificate2`, `X509Certificate2Collection`,
  `X509Chain` and `IEnumerable<X509Certificate2>` returns a `CertificateExportBuilder`, configured
  with `With*`, given a format with `As*`, and terminated with `To*`.

### Changed

- Test suite migrated from xUnit to TUnit, and the solution moved to the `.slnx` format.
- Build moved from NUKE to the `dotnet` CLI directly.

### Deprecated

- The legacy `ExportAs*`, `ToPemString` and `ToBase64String` export extension methods, each with a
  message naming its `Export()` replacement.
- `KeyAlgorithm.DSA`.

### Removed

- The `FluentCertificates.Builder.BouncyCastle` project. It was never published; the two conversion
  helpers it provided now live in the Builder test project.

## [0.13.0] - 2025-06-04

### Added

- `VerifyChain` extension method on `X509Certificate2`.
- `CertificateBuilder.SetSerialNumberGenerator`, for supplying a custom serial number generator.

### Changed

- `CertificateBuilder.Extensions` and `SubjectAlternativeNames` now return interfaces rather than
  concrete collection types.
- Certificate chain building and validity check signatures clarified.

## [0.12.0] - 2025-06-03

### Added

- `CertificateFinder` can recurse into subdirectories, and accepts custom certificate sources for
  searching stores other than the file system or an `X509Store`.
- File system access in `CertificateFinder` is abstracted, making it mockable in tests.

### Changed

- `CertificateFinder.Stores` renamed to `Sources`, and `ClearStores` to `ClearSources`.
- Migrated away from deprecated .NET cryptography APIs.

### Removed

- `CertificateFinder.SetStore` methods, made redundant by `ClearSources` plus `AddStore`.

## [0.11.0] - 2025-05-29

### Added

- `GeneralNameListBuilder`, which converts implicitly to `ImmutableList<GeneralName>`.
- `Oids` is now public.

### Changed

- `CertificateBuilder.SetSubjectAlternativeName` renamed to `SetSubjectAlternativeNames`, since it
  sets the contents of the extension rather than the extension itself.
- General name handling generalised across the library.

### Removed

- `SubjectAlternativeNameBuilderExtensions` and `GeneralNameList`, superseded by
  `GeneralNameListBuilder`.

### Fixed

- Subject Alternative Name handling, and `X509NameConstraintExtension` after the general name
  changes.

## [0.10.1] - 2024-11-29

### Fixed

- Multi-targeting issues in the published packages.

## [0.10.0] - 2024-11-28

### Added

- .NET 8 target.
- A range of `Get` methods on `X500NameBuilder`.
- `CertificateBuilder.SetKeyStorageFlags`.
- Experimental `X509NameConstraintExtension`.

### Changed

- `CertificateFinder` overhauled, including breaking changes.

### Removed

- Support for target frameworks older than .NET 8.

## [0.9.1] - 2023-08-11

### Removed

- `FluentCertificates.Builder`'s dependency on Portable.BouncyCastle.

## [0.9.0] - 2023-08-10

### Added

- `CertificateFinder` can include file system directories in a search.
- String encoding types can be specified when building X.500 names.
- An internal `Oids` class, and a polyfill of .NET 7's `X500DistinguishedNameBuilder`.
- XML documentation is now included in the NuGet packages.

### Changed

- `X500NameBuilder.Attributes` renamed to `RelativeDistinguishedNames`, and `Equivalent` renamed to
  `EquivalentTo`.
- `X500NameBuilder` no longer exposes BouncyCastle types, and several operator overloads were
  removed.

### Removed

- Support for .NET 5 and .NET Core 3.1.

### Fixed

- `X500NameBuilder.EquivalentTo` compared raw encoded data when `orderMatters` was true; it now
  compares the individual RDN values regardless of how they were encoded.

## [0.8.0] - 2022-07-07

### Added

- `CertificateSigningRequest` class, and the ability to create a CSR directly from
  `CertificateBuilder`.

### Changed

- All `Build` methods renamed to `Create`.

## [0.7.1] - 2022-06-24

### Fixed

- The padding mode is now detected when verifying RSA certificate signatures.

## [0.7.0] - 2022-06-24

### Changed

- Private and public key handling reworked, removing further BouncyCastle dependencies.

## [0.6.0] - 2022-06-23

### Added

- Basic support for encrypting private keys exported to PEM. The encryption options are not yet
  configurable.
- `GetTbsData` and `GetSignatureData` extension methods on `X509Certificate2`.
- A `verifySignature` parameter on `IsIssuedBy` and `IsSelfSigned`.

### Changed

- Certificate signatures are verified without relying on BouncyCastle.
- Trailing newline characters removed from PEM exports, to match the .NET 7 export methods.

### Removed

- The `X509Certificate2.VerifyIssuer` extension method, replaced by `IsIssuedBy` with
  `verifySignature`.

### Fixed

- The PEM password was passed to the wrong method during export.

## [0.5.4] - 2022-06-20

### Fixed

- Certificate collection order when exporting to PEM.

## [0.5.3] - 2022-06-20

### Fixed

- Private keys are now written before certificates when exporting to PEM.
- `X509Chain.ToEnumerable()` and `ToCollection()` return the chain leaf last.
- Certificate chain building on .NET Standard 2.1.

## [0.5.2] - 2022-06-18

### Fixed

- A potential resource leak: keys are now created from their parameters only when needed, and
  disposed immediately.

## [0.5.1] - 2022-06-17

### Changed

- Documentation updates.

## [0.5.0] - 2022-06-17

### Added

- Overloads for exporting to PKCS#12 and PKCS#7 via a `BinaryWriter`, and `ExportAsPem` overloads
  taking a `TextWriter`.
- Extension methods for exporting keys to PEM.
- Constructor overloads on `X500NameBuilder` for an `X500DistinguishedName`, a BouncyCastle
  `X509Name`, or a string, plus further `CertificateBuilder.SetSubject` overloads.

### Changed

- `X509NameBuilder` renamed to `X500NameBuilder`, and its attribute collection now holds `Oid`
  instances instead of BouncyCastle `DerObjectIdentifier` instances.
- PEM files and strings are written without BouncyCastle.

### Removed

- All static factory methods named `Create`, replaced by constructor overloads.

## [0.4.1] - 2022-06-10

### Added

- Support for signing a certificate whose key algorithm differs from the issuer's.
- Partial support for DSA certificates, on .NET 6 and later.
- `CertificateBuilder.GenerateKeyPair()`.
- README included in the NuGet packages.

## [0.4.0] - 2022-06-02

### Added

- Basic support for ECDsa keys.

## [0.3.2] - 2022-05-31

### Changed

- CI version stamping.

## [0.3.1] - 2022-05-30

### Added

- `FluentCertificates.Finder` targets netstandard2.0, so it can be used from .NET Framework
  projects.

## [0.3.0] - 2022-05-30

### Added

- Split into `FluentCertificates.Builder` and `FluentCertificates.Finder`, with `FluentCertificates`
  as a meta-package pulling in both.
- Certificate signing request support, including extension methods for exporting a
  `CertificateRequest` to a PEM string or file.
- Extension methods for S/MIME certificates.
- `IsValidNow`, `IsValid(DateTime)`, `IsSelfSigned`, `IsIssuedBy` and `VerifyIssuerSignature`
  extension methods on `X509Certificate2`.
- Options for selecting the hash algorithm and RSA signature padding.
- Methods for customising and overriding certificate extensions, and for supplying an existing key
  pair for renewal scenarios.

### Changed

- X.509 extension handling uses the native .NET `X509Extension` class rather than the BouncyCastle
  equivalent, with extension methods for converting between the two.

### Removed

- `CertificateBuilder.GenerateKey()`, replaced by `SetKey(AsymmetricAlgorithm)`. A key pair must be
  supplied explicitly when creating a CSR.

### Fixed

- `FriendlyName` was lost on newly generated certificates.

## [0.2.0] - 2022-05-12

### Added

- `X509NameBuilder` gains `Add`, `Set`, `Remove`, `AddOrganizationalUnit(s)`,
  `SetOrganizationalUnits`, `AddDomainComponent(s)` and `SetDomainComponents`, converts implicitly
  to `string`, and exposes an immutable attribute collection.

### Changed

- `CertificateBuilder.Subject` and `Usage` now have defaults and are optional.
- `X509NameBuilder` uses the immutable builder pattern.
- Default key length reduced to 2048 bits.

### Fixed

- Certificate creation on .NET Core 3.1 running on Linux.

## [0.1.0] - 2022-05-06

### Added

- Initial release: `CertificateBuilder`, `X509NameBuilder`, certificate finding, and PEM export
  including `X509Chain.ToPemString()`. Targets .NET Standard 2.1, .NET 5 and .NET 6.

[Unreleased]: https://github.com/lethek/FluentCertificates/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/lethek/FluentCertificates/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/lethek/FluentCertificates/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/lethek/FluentCertificates/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/lethek/FluentCertificates/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/lethek/FluentCertificates/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/lethek/FluentCertificates/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/lethek/FluentCertificates/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/lethek/FluentCertificates/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/lethek/FluentCertificates/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/lethek/FluentCertificates/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/lethek/FluentCertificates/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/lethek/FluentCertificates/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/lethek/FluentCertificates/compare/v0.5.4...v0.6.0
[0.5.4]: https://github.com/lethek/FluentCertificates/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/lethek/FluentCertificates/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/lethek/FluentCertificates/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/lethek/FluentCertificates/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/lethek/FluentCertificates/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/lethek/FluentCertificates/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/lethek/FluentCertificates/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/lethek/FluentCertificates/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/lethek/FluentCertificates/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/lethek/FluentCertificates/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lethek/FluentCertificates/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lethek/FluentCertificates/releases/tag/v0.1.0
