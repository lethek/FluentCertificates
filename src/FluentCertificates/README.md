# 📖 FluentCertificates Overview

⚠️ **Note:** *while version numbers are v0.x.y, this software is under initial development and there'll be breaking-changes in its API from version to version.*

[![GitHub license](https://img.shields.io/github/license/lethek/FluentCertificates)](https://github.com/lethek/FluentCertificates/blob/main/LICENSE)
[![NuGet Stats](https://img.shields.io/nuget/v/FluentCertificates.svg)](https://www.nuget.org/packages/FluentCertificates)
[![Build & Publish](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml/badge.svg)](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml)

FluentCertificates is a library using the Immutable Fluent Builder pattern for easily creating, finding and exporting certificates. Makes it simple to generate your own certificate chains, or just stand-alone self-signed certificates.

This project is published in several NuGet packages:

* [FluentCertificates](https://www.nuget.org/packages/FluentCertificates): Top-level package that doesn't introduce any new functionality, it just imports the FluentCertificates.Builder, FluentCertificates.Extensions and FluentCertificates.Finder packages.
* [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder): Provides `CertificateBuilder` for building certificates and also includes a bunch of convenient extension-methods. [Examples below](#certificatebuilder-examples)
* [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions): Provides a bunch of convenient extension-methods. [Examples below](#x509certificate2-extension-methods)
* [FluentCertificates.Finder](https://www.nuget.org/packages/FluentCertificates.Finder): Provides `CertificateFinder` for finding certificates across a collection of X509Stores. [Examples below](#certificatefinder-examples)

Unfortunately documentation is incomplete. You may find more examples within the project's unit tests.

## `CertificateBuilder` examples

`CertificateBuilder` requires the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and is found under the `FluentCertificates` namespace.

### **Create a `CertificateRequest` for signing, exporting and passing to a 3rd party CA:**

```csharp
var request = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetSubject(b => b.SetCommonName("*.fake.domain"))
    .SetDnsNames("*.fake.domain", "fake.domain")
    .ToCertificateRequest();
```

### **Build a self-signed web server certificate:**

```csharp
//Using a fluent style
using var cert = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetFriendlyName("Example self-signed web-server certificate")
    .SetSubject(b => b.SetCommonName("*.fake.domain"))
    .SetDnsNames("*.fake.domain", "fake.domain")
    .SetNotAfter(DateTimeOffset.UtcNow.AddMonths(1))
    .Build();

//And just to demonstrate using object initializers (I'll use fluent style from now on though)
using var builder = new CertificateBuilder() {
    Usage = CertificateUsage.Server,
    FriendlyName = "Example self-signed web-server certificate",
    Subject = new X500NameBuilder().SetCommonName("*.fake.domain"),
    DnsNames = new[] { "*.fake.domain", "fake.domain" },
    NotAfter = DateTimeOffset.UtcNow.AddMonths(1)
};
var cert = builder.Build();
```

### **Build a CA (certificate authority):**

```csharp
//A CA's expiry date must be later than that of any certificates it will issue
using var issuer = new CertificateBuilder()
    .SetUsage(CertificateUsage.CA)
    .SetFriendlyName("Example root CA")
    .SetSubject(b => b.SetCommonName("Example root CA"))
    .SetNotAfter(DateTimeOffset.UtcNow.AddYears(100))
    .Build();
```

### **Build a client-auth certificate signed by a CA:**

```csharp
//Note: the 'issuer' certificate used must have a private-key attached in order to sign this new certificate
using var cert = new CertificateBuilder()
    .SetUsage(CertificateUsage.Client)
    .SetFriendlyName("Example client-auth certificate")
    .SetSubject(b => b.SetCommonName("User: Michael"))
    .SetNotAfter(DateTimeOffset.UtcNow.AddYears(1))
    .SetIssuer(issuer)
    .Build();
```

### **Advanced: Build a certificate with customized extensions:**

```csharp
using var cert = new CertificateBuilder()
    .SetFriendlyName("Example certificate with customized extensions")
    .SetSubject(b => b.SetCommonName("Example certificate with customized extensions"))
    .AddExtension(new X509BasicConstraintsExtension(false, false, 0, true))
    .AddExtension(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment, true))
    .AddExtension(new X509EnhancedKeyUsageExtension(new OidCollection { new(KeyPurposeID.AnyExtendedKeyUsage.Id) }, false))
    .SetIssuer(issuer)
    .Build();
```

---

## `CertificateFinder` examples

`CertificateFinder` requires the [FluentCertificates.Finder](https://www.nuget.org/packages/FluentCertificates.Finder) package and is found under the `FluentCertificates` namespace.

*TODO: document this*

---

## `X500NameBuilder` examples

`X500NameBuilder` requires the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and is found under the `FluentCertificates` namespace.

*TODO: document this; see unit tests for more examples*

---

## `X509Certificate2` extension-methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

*TODO: document these; see unit tests for more examples*

|Extension-Method|Description|
|-|-|
|`BuildChain`||
|`ExportAsCert`||
|`ExportAsPkcs12`||
|`ExportAsPkcs7`||
|`ExportAsPem`||
|`ToPemString`||
|`ToBase64String`||
|`GetPrivateKey`||
|`GetSignatureData`||
|`GetTbsData`||
|`IsValidNow`||
|`IsValid`||
|`IsSelfSigned`||
|`IsIssuedBy`||

---

## `X509Chain` extension-methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

*TODO: document these*

|Extension-Method|Description|
|-|-|
|`ToCollection`||
|`ToEnumerable`||
|`ExportAsPkcs7`||
|`ExportAsPkcs12`||
|`ExportAsPem`||
|`ToPemString`||

---

## `X509Certificate2Collection` extension-methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

*TODO: document these*

|Extension-Method|Description|
|-|-|
|`ToEnumerable`||
|`ExportAsPkcs7`||
|`ExportAsPkcs12`||
|`ExportAsPem`||
|`ToPemString`||

---

## `IEnumerable<X509Certificate2>` extension-methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

*TODO: document these*

|Extension-Method|Description|
|-|-|
|`ToCollection`||
|`FilterPrivateKeys`||
|`ExportAsPkcs7`||
|`ExportAsPkcs12`||
|`ExportAsPem`||
|`ToPemString`||

---

## `AsymmetricAlgorithm` extension-methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

*TODO: document these*

|Extension-Method|Description|
|-|-|
|`ToPrivateKeyPemString`||
|`ToPublicKeyPemString`||
|`ExportAsPrivateKeyPem`||
|`ExportAsPublicKeyPem`||

---

## `CertificateRequest` extension-methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToPemString()`|Exports the `CertificateRequest` to a PEM string.|
|`ExportAsPem(string path)`|Exports the `CertificateRequest` to the specified PEM file.|
|`ExportAsPem(TextWriter writer)`|Exports the `CertificateRequest` in PEM format to the given `TextWriter`.|
|`ConvertToBouncyCastle()`|Converts the `CertificateRequest` to a BouncyCastle `Pkcs10CertificationRequest`|

---

## `X509Extension` extension-methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`dnExtension.ConvertToBouncyCastle()`|Converts a DotNet `X509Extension` to a BouncyCastle `X509Extension`.|
|`bcExtension.ConvertToDotNet(string oid)`|Converts a BouncyCastle `X509Extension` to a DotNet `X509Extension`. A DotNet `X509Extension` includes an OID, but a BouncyCastle one doesn't, therefore one must be supplied in the parameters here.|
|`bcExtension.ConvertToDotNet(DerObjectIdentifier oid)`|Converts a BouncyCastle `X509Extension` to a DotNet `X509Extension`. A DotNet `X509Extension` includes an OID, but a BouncyCastle one doesn't, therefore one must be supplied in the parameters here.|
