# 📖 FluentCertificates Overview

⚠️ **Note:** *while version numbers are v0.x.y, this software is under initial development and there there may be breaking-changes in its API between minor versions.* ⚠️

[![NuGet](https://img.shields.io/nuget/v/FluentCertificates.svg)](https://www.nuget.org/packages/FluentCertificates)
[![Build & Publish](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml/badge.svg)](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml)
[![GitHub license](https://img.shields.io/github/license/lethek/FluentCertificates)](https://github.com/lethek/FluentCertificates/blob/main/LICENSE)

FluentCertificates is a library using the Immutable Fluent Builder pattern for easily creating, finding, and exporting certificates. It makes it simple to generate your own certificate chains or just stand-alone self-signed certificates.

## NuGet Packages

This project is published in several NuGet packages:

* [FluentCertificates](https://www.nuget.org/packages/FluentCertificates): Top-level package that imports the Builder, Extensions, and Finder packages.
* [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder): Provides `CertificateBuilder` for building certificates and also includes a bunch of convenient extension methods. [Examples below](#certificatebuilder-examples)
* [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions): Provides additional extension methods. [Examples below](#x509certificate2-extension-methods)
* [FluentCertificates.Finder](https://www.nuget.org/packages/FluentCertificates.Finder): Provides `CertificateFinder` for finding certificates across X509Stores and directories. [Examples below](#certificatefinder-examples)

Documentation is incomplete. More examples can be found in the project's [unit tests](https://github.com/lethek/FluentCertificates/tree/main/tests).

## CertificateBuilder Examples

`CertificateBuilder` requires the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and is found under the `FluentCertificates` namespace.

### **Minimum Example**

_The absolute minimum needed to create a certificate, whether it's useful or not._

```csharp
using var cert = new CertificateBuilder().Create();
```

### **Create a Certificate Signing Request**

_For signing, exporting and passing to a 3rd party CA._

```csharp
//A public & private keypair must be created first, outside of the CertificateBuilder, otherwise you'd have no way to retrieve the private-key used for the new CertificateSigningRequest object
using var keys = RSA.Create();

//Creating a CertificateSigningRequest
var csr = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetSubject(b => b.SetCommonName("*.fake.domain"))
    .SetSubjectAlternativeNames(x => x.AddDnsNames("*.fake.domain", "fake.domain"))
    .SetKeyPair(keys)
    .CreateCertificateSigningRequest();

//The CertificateRequest object is accessible here:
var certRequest = csr.CertificateRequest;

//CSR can be exported to a string
Console.WriteLine(csr.ToPemString());

//Or to a file or StringWriter instance
csr.ExportAsPem("csr.pem");
```

### **Build a Self-Signed Web Server Certificate**

_Using the fluent style:_

```csharp
using var webCert = new CertificateBuilder()
    .SetFriendlyName("Example self-signed web-server certificate")
    .SetUsage(CertificateUsage.Server)
    .SetSubject(b => b.SetCommonName("*.fake.domain"))
    .SetSubjectAlternativeNames(x => x.AddDnsNames("*.fake.domain", "fake.domain"))
    .SetNotAfter(DateTimeOffset.UtcNow.AddMonths(1))
    .Create();
```

_Or alternatively using object initializers (other examples will use fluent style from now on though):_
```csharp
var builder = new CertificateBuilder() {
    FriendlyName = "Example self-signed web-server certificate",
    Usage = CertificateUsage.Server,
    Subject = new X500NameBuilder().SetCommonName("*.fake.domain"),
    SubjectAlternativeNames = new GeneralNameListBuilder().AddDnsNames("*.fake.domain", "fake.domain"),
    NotAfter = DateTimeOffset.UtcNow.AddMonths(1)
};
using var webCert = builder.Create();
```

### **Build a Certificate Authority (CA)**

```csharp
//A CA's expiry date must be later than that of any certificates it will issue
using var issuer = new CertificateBuilder()
    .SetFriendlyName("Example root CA")
    .SetUsage(CertificateUsage.CA)
    .SetSubject(b => b.SetCommonName("Example root CA"))
    .SetNotAfter(DateTimeOffset.UtcNow.AddYears(100))
    .Create();
```

### **Build a Client-Auth Certificate Signed by a CA**

```csharp
//Note: the 'issuer' certificate used must have a private-key attached in order to sign this new certificate
using var clientAuthCert = new CertificateBuilder()
    .SetFriendlyName("Example client-auth certificate")
    .SetUsage(CertificateUsage.Client)
    .SetSubject(b => b.SetCommonName("User: Michael"))
    .SetNotAfter(DateTimeOffset.UtcNow.AddYears(1))
    .SetIssuer(issuer)
    .Create();
```

### **Advanced: Certificate with Customized Extensions**

```csharp
using var customCert = new CertificateBuilder()
    .SetFriendlyName("Example certificate with customized extensions")
    .SetSubject(b => b.SetCommonName("Example certificate with customized extensions"))
    .AddExtension(new X509BasicConstraintsExtension(false, false, 0, true))
    .AddExtension(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment, true))
    .AddExtension(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(Oids.AnyExtendedKeyUsage) }, false))
    .SetIssuer(issuer)
    .Create();
```

### **Advanced: Certificates with Custom Name Constraints and CRL Distribution Points**

```csharp
//Permit the CA cert to issue certificates for specific names and IP addresses
var permittedNames = new GeneralNameListBuilder()
    .AddDnsName(".mydomain.local")
    .AddEmailAddress("@mydomain.local")
    .AddIPAddress(ipAddress: "192.168.0.0", subnetMask: "255.255.255.0")
    .Create();

using var issuer = new CertificateBuilder()
    .SetFriendlyName("Example constrained root CA")
    .SetUsage(CertificateUsage.CA)
    .SetSubject(b => b.SetCommonName("Example constrained root CA"))
    .SetNotAfter(DateTimeOffset.UtcNow.AddMonths(1))
    .SetPathLength(1)
    .AddExtension(new X509NameConstraintExtension(permittedNames, null))
    .Create();

using var webCert = new CertificateBuilder()
    .SetFriendlyName("Example certificate with a CRL distribution point")
    .SetUsage(CertificateUsage.Server)
    .SetIssuer(issuer)
    .SetSubject(b => b.SetCommonName("*.mydomain.local"))
    .SetSubjectAlternativeNames(x => x.AddDnsName("*.mydomain.local"))
    //Extension specifies CRL URLs
    .AddExtension(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([$"http://crl.mydomain.local/"]))
    .Create();
```

---

## CertificateFinder Examples

`CertificateFinder` requires the [FluentCertificates.Finder](https://www.nuget.org/packages/FluentCertificates.Finder) package and is found under the `FluentCertificates` namespace.

The CertificateFinder class allows you to configure, add, and query certificate sources (stores and directories) in a fluent and immutable manner. It supports LINQ queries for flexible certificate searching.

### **Find a Specific Certificate by Thumbprint**

_The "common stores" include the CurrentUser and LocalMachine certificate stores, such as "My", "Root", "CA", etc. You can also add custom directories or other X509 stores to search for certificates._

```csharp
const string thumbprint = "622A2B8374D9BBE3969B91EDBC8F5152783AFC78";

var cert = new CertificateFinder()
    .AddCommonStores()
    .FirstOrDefault(x => x.Certificate.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase));
```

### **Find a Valid Certificate with Matching Subject, Giving Preference to Included Private Keys**

```csharp
var subject = new X500NameBuilder()
    .SetOrganization("My Org")
    .SetCountry("AU")
    .SetCommonName("fake.domain");

var cert = new CertificateFinder()
    .AddCommonStores()
    .Select(x => x.Certificate)
    .Where(x => x.IsValidNow())
    .OrderBy(x => !x.HasPrivateKey) //Ensure certs with private keys are listed before those without
    .FirstOrDefault(x => subject.EquivalentTo(x.SubjectName, false));
```

---

## X500NameBuilder Examples

`X500NameBuilder` requires the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and is found under the `FluentCertificates` namespace.

*TODO: document this; see unit tests for more examples*

---

## X509Certificate2 Extension Methods

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
|`GetToBeSignedData`||
|`IsValidNow`||
|`IsValid`||
|`IsSelfSigned`||
|`IsIssuedBy`||

---

## X509Chain Extension Methods

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

## X509Certificate2Collection Extension Methods

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

## IEnumerable<X509Certificate2> Extension Methods

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

## AsymmetricAlgorithm Extension Methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

*TODO: document these*

|Extension-Method|Description|
|-|-|
|`ToPrivateKeyPemString`||
|`ToPublicKeyPemString`||
|`ExportAsPrivateKeyPem`||
|`ExportAsPublicKeyPem`||

---

## CertificateRequest Extension Methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToPemString()`|Exports the `CertificateRequest` to a PEM string.|
|`ExportAsPem(string path)`|Exports the `CertificateRequest` to the specified PEM file.|
|`ExportAsPem(TextWriter writer)`|Exports the `CertificateRequest` in PEM format to the given `TextWriter`.|
|`ConvertToBouncyCastle()`|Converts the `CertificateRequest` to a BouncyCastle `Pkcs10CertificationRequest`|

---

## X509Extension Extension Methods

These extension methods require the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`dnExtension.ConvertToBouncyCastle()`|Converts a DotNet `X509Extension` to a BouncyCastle `X509Extension`.|
|`bcExtension.ConvertToDotNet(string oid)`|Converts a BouncyCastle `X509Extension` to a DotNet `X509Extension`. A DotNet `X509Extension` includes an OID, but a BouncyCastle one doesn't, therefore one must be supplied in the parameters here.|
|`bcExtension.ConvertToDotNet(DerObjectIdentifier oid)`|Converts a BouncyCastle `X509Extension` to a DotNet `X509Extension`. A DotNet `X509Extension` includes an OID, but a BouncyCastle one doesn't, therefore one must be supplied in the parameters here.|
