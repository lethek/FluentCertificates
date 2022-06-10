# FluentCertificates

[![GitHub license](https://img.shields.io/github/license/lethek/FluentCertificates)](https://github.com/lethek/FluentCertificates/blob/main/LICENSE)
[![NuGet Stats](https://img.shields.io/nuget/v/FluentCertificates.svg)](https://www.nuget.org/packages/FluentCertificates)
[![Build & Publish](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml/badge.svg)](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml)

FluentCertificates is a library using the Immutable Fluent Builder pattern for easily creating, finding and exporting certificates. Makes it simple to generate your own certificate chains, or just stand-alone self-signed certificates.

This project is published in three NuGet packages:

* [FluentCertificates](https://www.nuget.org/packages/FluentCertificates): Simply brings in both the FluentCertificates.Builder and FluentCertificates.Finder packages.
* [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder): Provides `CertificateBuilder` for building certificates and also includes a bunch of convenient extension-methods. [Examples below](#certificatebuilder-examples)
* [FluentCertificates.Finder](https://www.nuget.org/packages/FluentCertificates.Finder): Provides `CertificateFinder` for finding certificates across a collection of X509Stores. [Examples below](#certificatefinder-examples)

## `CertificateBuilder` examples

### **Create a `CertificateRequest` for signing, exporting and passing to a 3rd party CA:**

```csharp
var request = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetSubject(new X509NameBuilder().SetCommonName("*.fake.domain"))
    .SetDnsNames("*.fake.domain", "fake.domain")
    .ToCertificateRequest();
```

### **Build a self-signed web server certificate:**

```csharp
//Using a fluent style
var cert = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetFriendlyName("Example self-signed web-server certificate")
    .SetSubject(new X509NameBuilder().SetCommonName("*.fake.domain"))
    .SetDnsNames("*.fake.domain", "fake.domain")
    .SetNotAfter(DateTimeOffset.UtcNow.AddMonths(1))
    .Build();

//And just to demonstrate using object initializers (I'll use fluent style from now on though)
var builder = new CertificateBuilder() {
    Usage = CertificateUsage.Server,
    FriendlyName = "Example self-signed web-server certificate",
    Subject = new X509NameBuilder().SetCommonName("*.fake.domain"),
    DnsNames = new[] { "*.fake.domain", "fake.domain" },
    NotAfter = DateTimeOffset.UtcNow.AddMonths(1)
};
var cert = builder.Build();
```

### **Build a CA (certificate authority):**

```csharp
//A CA's expiry date must be later than that of any certificates it will issue
var issuer = new CertificateBuilder()
    .SetUsage(CertificateUsage.CA)
    .SetFriendlyName("Example root CA")
    .SetSubject(new X509NameBuilder().SetCommonName("Example root CA"))
    .SetNotAfter(DateTimeOffset.UtcNow.AddYears(100))
    .Build();
```

### **Build a client-auth certificate signed by a CA:**

```csharp
//Note: the 'issuer' certificate used must have a private-key attached in order to sign this new certificate
var cert = new CertificateBuilder()
    .SetUsage(CertificateUsage.Client)
    .SetFriendlyName("Example client-auth certificate")
    .SetSubject(new X509NameBuilder().SetCommonName("User: Michael"))
    .SetNotAfter(DateTimeOffset.UtcNow.AddYears(1))
    .SetIssuer(issuer)
    .Build();
```

### **Advanced: Build a certificate with customized extensions:**

```csharp
var cert = new CertificateBuilder()
    .SetFriendlyName("Example certificate with customized extensions")
    .SetSubject(new X509NameBuilder().SetCommonName("Example certificate with customized extensions"))
    .AddExtension(new X509BasicConstraintsExtension(false, false, 0, true))
    .AddExtension(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment, true))
    .AddExtension(new X509EnhancedKeyUsageExtension(new OidCollection { new(KeyPurposeID.AnyExtendedKeyUsage.Id) }, false))
    .SetIssuer(issuer)
    .Build();
```

---

## `CertificateFinder` examples

*TODO: document this*

## `X509NameBuilder` examples

*TODO: document this*

## `X509Certificate2` extension-methods

*TODO: document this*

## `X509Certificate2Collection` extension-methods

*TODO: document this*

## `X509Chain` extension-methods

*TODO: document this*

---

## `X509Extension` extension-methods

|Extension-Method|Description|
|-|-|
|`dnExtension.ConvertToBouncyCastle()`|Converts a DotNet `X509Extension` to a BouncyCastle `X509Extension`.|
|`bcExtension.ConvertToDotNet(string oid)`|Converts a BouncyCastle `X509Extension` to a DotNet `X509Extension`. A DotNet `X509Extension` includes an OID, but a BouncyCastle one doesn't, therefore one must be supplied in the parameters here.|
|`bcExtension.ConvertToDotNet(DerObjectIdentifier oid)`|Converts a BouncyCastle `X509Extension` to a DotNet `X509Extension`. A DotNet `X509Extension` includes an OID, but a BouncyCastle one doesn't, therefore one must be supplied in the parameters here.|

---

## `CertificateRequest` extension-methods
|Extension-Method|Description|
|-|-|
|`ToPemString()`|Exports the `CertificateRequest` to a PEM string.|
|`ExportAsPem(string path)`|Exports the `CertificateRequest` to the specified PEM file.|
|`ConvertToBouncyCastle()`|Converts the `CertificateRequest` to a BouncyCastle `Pkcs10CertificationRequest`|
