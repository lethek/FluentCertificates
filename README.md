# 📖 FluentCertificates Overview

⚠️ **Note:** *while version numbers are v0.x.y, this software is under initial development and there may be breaking-changes in its API between minor versions.* ⚠️

[![NuGet](https://img.shields.io/nuget/v/FluentCertificates.svg)](https://www.nuget.org/packages/FluentCertificates)
[![Build & Publish](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml/badge.svg)](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml)
[![GitHub license](https://img.shields.io/github/license/lethek/FluentCertificates)](https://github.com/lethek/FluentCertificates/blob/main/LICENSE)

FluentCertificates is a library using the Immutable Fluent Builder pattern for easily creating, finding, and exporting certificates. It makes it simple to generate your own certificate chains or just stand-alone self-signed certificates.

## NuGet Packages

This project is published in several NuGet packages:

* [FluentCertificates](https://www.nuget.org/packages/FluentCertificates): Top-level package that imports the Builder, Extensions, and Finder packages.
* [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder): Provides `CertificateBuilder` for building certificates and also includes a bunch of convenient extension methods. [Examples below](#certificatebuilder-examples)
* [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions): Provides certificate exporting via `Export()`, plus additional extension methods. [Examples below](#exporting-certificates)
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

### **Set a Validity Period from a Duration**

`SetValidity` sets `NotBefore` and `NotAfter` together. The single-argument overload starts at the
current time; note that it does not backdate the start, so use the two-argument overload if you need
to tolerate clock skew on the verifying machine.

```csharp
using var cert = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetSubject(b => b.SetCommonName("*.fake.domain"))
    .SetValidity(TimeSpan.FromDays(90))
    .Create();

//Backdated by 5 minutes to allow for clock skew
using var skewTolerant = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetSubject(b => b.SetCommonName("*.fake.domain"))
    .SetValidity(DateTimeOffset.UtcNow.AddMinutes(-5), TimeSpan.FromDays(90))
    .Create();
```

### **Choose an Elliptic Curve**

When the builder generates an ECDsa key it uses nistP256 unless told otherwise. A key supplied
through `SetKeyPair` already carries its own curve, so `SetECCurve` has no effect on it. Setting a
curve while the key algorithm is RSA or DSA throws, rather than quietly generating a key you didn't
ask for.

```csharp
using var cert = new CertificateBuilder()
    .SetKeyAlgorithm(KeyAlgorithm.ECDsa)
    .SetECCurve(ECCurve.NamedCurves.nistP384)
    .SetSubject(b => b.SetCommonName("Example P-384 certificate"))
    .Create();
```

### **Build an OCSP Responder or Time-Stamping Certificate**

```csharp
using var ocspResponder = new CertificateBuilder()
    .SetUsage(CertificateUsage.OcspSigning)
    .SetSubject(b => b.SetCommonName("Example OCSP responder"))
    .SetIssuer(issuer)
    .Create();

//RFC 3161 requires a TSA certificate's extended key usage to be critical, which the builder does
using var timeStampingAuthority = new CertificateBuilder()
    .SetUsage(CertificateUsage.TimeStamping)
    .SetSubject(b => b.SetCommonName("Example TSA"))
    .SetIssuer(issuer)
    .Create();
```

### **Advanced: Signing with a Key Held in an HSM, TPM or Cloud KMS**

When the private key can't leave the device, supply the public key to certify with `SetPublicKey` and
an `X509SignatureGenerator` to do the signing with `SetSignatureGenerator`. The builder never needs
the private key, and the certificate it returns has none attached.

```csharp
//Your implementation, calling out to the HSM/TPM/KMS to sign
var remoteSigner = new MyRemoteSignatureGenerator(keyId);

//Issuing from a CA whose key is remote: the issuer certificate needs no private key
using var issuedCert = new CertificateBuilder()
    .SetUsage(CertificateUsage.Server)
    .SetSubject(b => b.SetCommonName("*.fake.domain"))
    .SetIssuer(caCertWithoutPrivateKey)
    .SetSignatureGenerator(remoteSigner)
    .Create();

//Self-signing a root whose key is remote: supply both halves of that key
using var rootCert = new CertificateBuilder()
    .SetUsage(CertificateUsage.CA)
    .SetSubject(b => b.SetCommonName("Example HSM-backed root CA"))
    .SetPublicKey(remotePublicKey)
    .SetSignatureGenerator(remoteSigner)
    .Create();
```

Nothing checks that the generator matches the public key you supplied; that pairing is yours to get
right. What is checked is that you supply both when self-signing, since either one alone produces a
certificate that cannot verify.

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

## Exporting Certificates

Exporting requires the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package (included in the top-level `FluentCertificates` package) and is found under the `FluentCertificates` namespace.

Everything goes through the `Export()` extension method, available on `X509Certificate2`, `X509Certificate2Collection`, `X509Chain` and `IEnumerable<X509Certificate2>`. It returns a `CertificateExportBuilder`: configure it with `With*`, choose a format with `As*`, then finish with `To*`.

```csharp
//PEM, certificate only
cert.Export().WithoutPrivateKeys().AsPem().ToPemString();

//PEM including the private key
cert.Export().WithPrivateKey().AsPem().ToFile("cert.pem");

//Password-protected PKCS#12 (PFX)
cert.Export().WithPassword("hunter2").AsPkcs12().ToFile("cert.pfx");

//Raw DER/CER bytes
cert.Export().AsCert().ToByteArray();

//A whole chain as PKCS#7
chain.Export().AsPkcs7().ToByteArray();

//A leaf plus its issuers, with all private keys stripped
leafCert.Export().WithChain([leafCert, intermediateCert, rootCert]).WithoutPrivateKeys().AsPkcs12().ToByteArray();
```

|Stage|Methods|
|-|-|
|Configure|`WithPrivateKey()`, `WithPrivateKeys()`, `WithoutPrivateKeys()`, `WithKeys(ExportKeys)`, `WithPassword(string?)`, `WithPassword(SecureString)`, `WithChain(...)`|
|Format|`AsPem()`, `AsPkcs12()`, `AsPkcs7()`, `AsCert()`|
|Finish|`ToPemString()` (PEM only), `ToByteArray()`, `ToFile(path)`, `ToStream(stream)`|


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

`X500NameBuilder` builds the distinguished names used for a certificate's subject and issuer. Like
the other builders it is immutable: every method returns a new instance, so a builder can be shared
and used as a template safely.

### **Building a subject name**

```csharp
var subject = new X500NameBuilder()
    .SetCommonName("*.fake.domain")
    .SetOrganization("Example Pty Ltd")
    .SetOrganizationalUnits("Engineering", "Platform")
    .SetCountry("AU")
    .SetState("Victoria")
    .SetLocality("Melbourne")
    .SetEmail("admin@fake.domain");

//Renders as a string in the usual RFC 4514 form
Console.WriteLine(subject.ToString());

//Converts to X500DistinguishedName explicitly or implicitly
var dn = subject.Create();
X500DistinguishedName implicitly = subject;
```

`CertificateBuilder.SetSubject` and `SetIssuer` take a delegate, so the same methods are usually
used inline:

```csharp
using var cert = new CertificateBuilder()
    .SetSubject(b => b.SetCommonName("*.fake.domain").SetOrganization("Example Pty Ltd"))
    .Create();
```

### **Reading values back**

Every `Set*` method has a matching `Get*`. Single-valued attributes return `null` when absent, and
multi-valued ones return an empty sequence.

```csharp
string? cn = subject.GetCommonName();                       //"*.fake.domain"
string? org = subject.GetOrganization();                    //"Example Pty Ltd"
IEnumerable<string> ous = subject.GetOrganizationalUnits();  //"Engineering", "Platform"
string? missing = new X500NameBuilder().GetCommonName();     //null
```

### **Starting from an existing name**

```csharp
var fromString = new X500NameBuilder("CN=example.com, O=Example Pty Ltd");
var fromDn = new X500NameBuilder(cert.SubjectName);

//Builders are immutable, so this leaves fromString untouched
var renamed = fromString.SetCommonName("other.example.com");
```

### **Attributes without a dedicated method**

Use `Add` or `Set` with an OID, optionally choosing the ASN.1 string encoding. `Add` appends another
RDN with the same OID; `Set` replaces any existing ones.

```csharp
var custom = new X500NameBuilder()
    .SetCommonName("example.com")
    .Add("0.9.2342.19200300.100.1.25", UniversalTagNumber.IA5String, "example", "com")
    .Remove(Oids.EmailAddressOid);
```

### **Comparing names**

`EquivalentTo` compares the attributes themselves and ignores ordering by default, which is usually
what you want when asking whether two names describe the same entity.

```csharp
var a = new X500NameBuilder().SetCommonName("example.com").SetCountry("AU");
var b = new X500NameBuilder().SetCountry("AU").SetCommonName("example.com");

a.EquivalentTo(b);                          //true: same attributes, different order
a.EquivalentTo(b, orderMatters: true);      //false
a.EquivalentTo("CN=example.com, C=AU");     //true
```

`Equals` is a different question: it compares the **encoded bytes**. Two names that render as the
same string can still differ, because the ASN.1 string encoding is part of the encoding. The
`Set*` methods use `UTF8String`, whereas parsing a string into an `X500DistinguishedName` yields
`PrintableString` for values that fit it:

```csharp
var built = new X500NameBuilder().SetCommonName("example.com").SetCountry("AU");

built.ToString();                           //"CN=example.com, C=AU"
built.Equals("CN=example.com, C=AU");       //false: UTF8String vs PrintableString
built.EquivalentTo("CN=example.com, C=AU"); //true
```

Reach for `EquivalentTo` unless you specifically need byte-for-byte identity. If you do need the
encoding to match, set it explicitly with `Set(oid, UniversalTagNumber.PrintableString, value)`.

### **Method summary**

|Method|Description|
|-|-|
|`SetCommonName`, `SetCountry`, `SetLocality`, `SetState`, `SetOrganization`, `SetStreetAddress`, `SetPostalCode`, `SetEmail`, `SetPhoneNumber`, `SetGivenName`, `SetSurname`, `SetTitle`, `SetSerialNumber`, `SetUserId`, `SetDistinguishedNameQualifier`|Set a single-valued attribute, replacing any existing value.|
|`SetOrganizationalUnits`, `SetDomainComponents`|Replace all values of a multi-valued attribute.|
|`AddOrganizationalUnit(s)`, `AddDomainComponent(s)`|Append to a multi-valued attribute.|
|`Add(oid, ...)`, `Set(oid, ...)`|Append or replace by OID, with an optional `UniversalTagNumber` encoding. The OID may be an `Oid` or a string.|
|`Remove(oid)`, `Clear()`|Remove attributes by OID, or all of them.|
|`GetCommonName`, `GetCountry`, ... `GetOrganizationalUnits`, `GetDomainComponents`|Read attribute values back.|
|`Create()`|Build the `X500DistinguishedName`. Also available as an implicit conversion.|
|`EquivalentTo(other, orderMatters = false)`|Compare attributes against another builder, an `X500DistinguishedName` or a string.|
|`Equals(other)`|Compare encoded bytes against an `X500DistinguishedName` or a string.|
|`RelativeDistinguishedNames`|The attributes as `(Oid, UniversalTagNumber, string)` tuples.|

---

## X509Certificate2 Extension Methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`BuildChain(IEnumerable<X509Certificate2>? extraCerts = null, bool customRootTrust = false)`|Builds an `X509Chain`, returning a `(bool Verified, X509Chain Chain)` tuple. `extraCerts` supplies intermediates that are not installed; `customRootTrust` treats them as the only trusted roots.|
|`BuildChain(Action<X509ChainPolicy> configurePolicy)`|Builds an `X509Chain` after handing the `X509ChainPolicy` to `configurePolicy`, for cases the two-argument overload doesn't cover: revocation checking, `VerificationFlags`, `ApplicationPolicy`, a custom `VerificationTime`, and so on. Revocation is pre-set to `NoCheck` before the action runs, so turn it on there if you want it.|
|`IsValidNow()`|Whether the current UTC time falls within the certificate's validity period.|
|`IsValidAt(DateTimeOffset atTime)`|Whether the given instant falls within the validity period. Both bounds are inclusive. The `DateTime` overload is **deprecated**, because a `DateTime` carries no offset and its `DateTimeKind` changes the result.|
|`IsSelfSigned(bool verifySignature = false)`|Whether subject and issuer match. Pass `true` to also verify the certificate's signature against its own public key.|
|`IsIssuedBy(X509Certificate2 issuer, bool verifySignature = false)`|Whether the certificate names the given issuer. Pass `true` to also verify the signature, which is what distinguishes a genuine issuer from one merely claiming the name.|
|`GetPrivateKey()`|Returns the private key as an `AsymmetricAlgorithm`, whatever its algorithm.|
|`GetSignatureAlgorithm()`|Returns the `SignatureAlgorithm` the certificate was signed with, combining key algorithm, hash and padding.|
|`GetToBeSignedData()`|The raw "to be signed" (TBS) bytes, i.e. what the issuer's signature covers.|
|`GetSignatureData()`|The raw signature bytes. Together with `GetToBeSignedData()` this allows verifying a signature yourself.|
|`Export()`|Returns a `CertificateExportBuilder`; see [Exporting Certificates](#exporting-certificates)|

---

## X509Chain Extension Methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToEnumerable()`|Returns the chain's certificates in **root-first** order, which is the reverse of `X509Chain.ChainElements`. The leaf is therefore last.|
|`ToCollection(ExportKeys include = ExportKeys.All)`|As `ToEnumerable()`, but returns an `X509Certificate2Collection` and applies `FilterPrivateKeys(include)`.|
|`Export()`|Returns a `CertificateExportBuilder`; see [Exporting Certificates](#exporting-certificates)|

---

## X509Certificate2Collection Extension Methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToEnumerable()`|Exposes the collection as an `IEnumerable<X509Certificate2>`, so the LINQ operators and the extension methods below can be used against it.|
|`Export()`|Returns a `CertificateExportBuilder`; see [Exporting Certificates](#exporting-certificates)|

---

## IEnumerable<X509Certificate2> Extension Methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToCollection()`|Copies the sequence into a new `X509Certificate2Collection`.|
|`FilterPrivateKeys(ExportKeys include)`|Returns the sequence with private keys kept or stripped according to `include`. `ExportKeys.Leaf` keeps only the last certificate's private key, as the leaf is assumed to come last.|
|`Export()`|Returns a `CertificateExportBuilder`; see [Exporting Certificates](#exporting-certificates)|

---

## AsymmetricAlgorithm Extension Methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToPrivateKeyPemString(string? password = null)`|Returns the private key as a PEM-encoded string. When a password is supplied the key is encrypted.|
|`ToPublicKeyPemString()`|Returns the public key as a PEM-encoded string.|
|`ExportAsPrivateKeyPem(TextWriter writer, string? password = null)`|Writes the private key as PEM to a `TextWriter`, encrypting it when a password is supplied. Returns the key for chaining.|
|`ExportAsPrivateKeyPem(string path, string? password = null)`|Writes the private key as PEM to a file, encrypting it when a password is supplied. Returns the key for chaining.|
|`ExportAsPublicKeyPem(TextWriter writer)`|Writes the public key as PEM to a `TextWriter`. Returns the key for chaining.|
|`ExportAsPublicKeyPem(string path)`|Writes the public key as PEM to a file. Returns the key for chaining.|

---

## CertificateRequest Extension Methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToPemString()`|Exports the `CertificateRequest` to a PEM string.|
|`ExportAsPem(string path)`|Exports the `CertificateRequest` to the specified PEM file.|
|`ExportAsPem(TextWriter writer)`|Exports the `CertificateRequest` in PEM format to the given `TextWriter`.|

