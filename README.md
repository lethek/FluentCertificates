# 📖 FluentCertificates Overview

⚠️ **Note:** while version numbers are v0.x.y, this software is under initial development and there may be breaking changes in its API between minor versions. ⚠️

[![NuGet](https://img.shields.io/nuget/v/FluentCertificates.svg)](https://www.nuget.org/packages/FluentCertificates)
[![Build & Publish](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml/badge.svg)](https://github.com/lethek/FluentCertificates/actions/workflows/dotnet.yml)
[![GitHub license](https://img.shields.io/github/license/lethek/FluentCertificates)](https://github.com/lethek/FluentCertificates/blob/main/LICENSE)

FluentCertificates is a library for creating, finding, and exporting certificates, built around an immutable fluent builder pattern. Use it to generate your own certificate chains, or just stand-alone self-signed certificates.

## NuGet packages

This project is published in several NuGet packages:

* [FluentCertificates](https://www.nuget.org/packages/FluentCertificates): Top-level package that imports the Builder, Extensions, and Finder packages.
* [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder): Provides `CertificateBuilder` for building certificates and also includes a bunch of convenient extension methods. [Examples below](#certificatebuilder-examples)
* [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions): Provides certificate exporting via `Export()`, plus additional extension methods. [Examples below](#exporting-certificates)
* [FluentCertificates.Finder](https://www.nuget.org/packages/FluentCertificates.Finder): Provides `CertificateFinder` for finding certificates across X509Stores and directories. [Examples below](#certificatefinder-examples)

Documentation is incomplete. More examples can be found in the project's [unit tests](https://github.com/lethek/FluentCertificates/tree/main/tests).

## CertificateBuilder examples

`CertificateBuilder` requires the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and is found under the `FluentCertificates` namespace.

### Minimum example

_The absolute minimum needed to create a certificate, whether it's useful or not._

```csharp
using var cert = new CertificateBuilder().Create();
```

### Create a certificate signing request

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

### Build a self-signed web server certificate

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

### Build a certificate authority (CA)

```csharp
//A CA's expiry date must be later than that of any certificates it will issue
using var issuer = new CertificateBuilder()
    .SetFriendlyName("Example root CA")
    .SetUsage(CertificateUsage.CA)
    .SetSubject(b => b.SetCommonName("Example root CA"))
    .SetNotAfter(DateTimeOffset.UtcNow.AddYears(100))
    .Create();
```

### Build a client-auth certificate signed by a CA

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

### Set a validity period from a duration

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

### Choose a key algorithm

A `KeyAlgorithm` carries its own parameters: a key length for RSA and DSA, a curve for the
elliptic-curve algorithms, a parameter set for the post-quantum ones. There is no separate
`KeyLength` or `ECCurve` to set alongside it, so a curve can never be paired with RSA and a key
length can never be paired with ECDsa. Defaults are RSA-4096, DSA-1024 and nistP256.

```csharp
using var rsa = new CertificateBuilder()
    .SetKeyAlgorithm(KeyAlgorithm.RSA(2048))
    .SetSubject(b => b.SetCommonName("Example RSA-2048 certificate"))
    .Create();

using var cert = new CertificateBuilder()
    .SetKeyAlgorithm(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384))
    .SetSubject(b => b.SetCommonName("Example P-384 certificate"))
    .Create();
```

A key supplied through `SetKeyPair` already carries its own parameters and takes precedence over
anything set here.

### Build an OCSP responder or time-stamping certificate

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

### Build a key agreement (ECDH) certificate

An ECDH key derives a shared secret and cannot sign anything, so these certificates assert
`keyAgreement` rather than `digitalSignature` and must be issued by a CA. Self-signing, CSRs, and the
`CA`, `CodeSign`, `OcspSigning` and `TimeStamping` usages are all rejected. Supplying a
`SignatureGenerator` does not lift those restrictions, since it signs with an unrelated key.

```csharp
using var ecdhCert = new CertificateBuilder()
    .SetUsage(CertificateUsage.SMime)
    .SetSubject(b => b.SetCommonName("user@fake.domain"))
    .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman(ECCurve.NamedCurves.nistP384))
    .SetIssuer(issuer)
    .Create();

using var privateKey = ecdhCert.GetECDiffieHellmanPrivateKey();
```

An ECDH public key is indistinguishable from an ECDsa one inside a certificate: same algorithm OID,
same curve parameters. The builder therefore takes the distinction from `SetKeyAlgorithm`, or from the
runtime type of a key passed to `SetKeyPair`. If you use `SetPublicKey` for an ECDH key held elsewhere,
call `SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman())` first, or the key will be treated as ECDsa.

### Build a post-quantum certificate

> ⚠️ **Experimental.** The post-quantum surface is marked `[Experimental("FLUENTCERT001")]` and may
> change. Suppress it per call site with `#pragma warning disable FLUENTCERT001`, or project-wide
> with `<NoWarn>$(NoWarn);FLUENTCERT001</NoWarn>`. The .NET types underneath are themselves
> experimental under `SYSLIB5006`, so any code naming one already has to suppress that; this library
> adds its own ID rather than implying only Microsoft's half is unsettled.

Requires .NET 10 at runtime. ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Composite ML-DSA and ML-KEM
(FIPS 203) each expose their parameter sets as `KeyAlgorithm` members.

```csharp
#pragma warning disable FLUENTCERT001

using var cert = new CertificateBuilder()
    .SetKeyAlgorithm(KeyAlgorithm.MLDsa65)
    .SetSubject(b => b.SetCommonName("Example ML-DSA certificate"))
    .Create();
```

Availability depends on the platform's cryptographic provider at runtime, so test for it rather than
inferring it from the operating system:

```csharp
if (KeyAlgorithm.SlhDsaSha2_128f.IsSupported) {
    //...
}
```

`IsSupported` reports whether a certificate can actually be built, not merely whether a key can be
generated. The two come apart in practice. As of .NET 10:

|Algorithm|Windows|Linux, OpenSSL 3.5+|Linux, OpenSSL 3.0|
|---|---|---|---|
|ML-DSA|✅|✅|❌|
|SLH-DSA|❌|✅|❌|
|ML-KEM|❌ *(key cannot be attached to a certificate)*|✅|❌|
|Composite ML-DSA|❌ *(no platform can sign a certificate with one)*|❌|❌|

On Linux what decides it is the OpenSSL version, not the distribution. OpenSSL 3.5+ supports these
algorithms and 3.0 supports none of them, so Ubuntu 26.04, Debian 13 and Alpine 3.22+ work while
Ubuntu 24.04 does not. Selecting an unsupported algorithm throws `PlatformNotSupportedException`
from `Create()` rather than producing a certificate that does not work.

The members exist on every target framework so the API surface does not vary; on .NET 8 and .NET 9
selecting one throws.

ML-KEM is key encapsulation, not signing. Like `ECDiffieHellman`, an ML-KEM certificate must be
issued by a CA, cannot self-sign, cannot be a CA or a code-signing, OCSP-signing or time-stamping
certificate, and has no CSR. It asserts `keyEncipherment`, not `keyAgreement`: encapsulating to the
certified key is key transport rather than Diffie-Hellman agreement.

### Advanced: signing with a key held in an HSM, TPM or cloud KMS

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

### Advanced: certificate with customized extensions

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

### Advanced: certificates with custom name constraints and CRL distribution points

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

## Key ownership and disposal

`X509Certificate2`, every `AsymmetricAlgorithm` and every `CertificateKey` are disposable. Three
rules cover who releases what:

* Keys the builder generates are disposed by the builder, as soon as `Create()` no longer needs
  them. You never see them.
* Keys you supply, through `SetKeyPair` or `SetPublicKey`, are yours. The builder never disposes
  them, so the same key can be reused across as many certificates as you like.
* Keys you extract from a certificate, through `GetPrivateKey()` or .NET's own
  `GetRSAPrivateKey()` and friends, are yours to dispose. Each call hands back a *new* instance, so
  calling it in a loop without a `using` leaks one handle per iteration.

Disposing an extracted key doesn't affect the certificate it came from, or any other instance
obtained from it, so the certificate stays usable and can be asked for its key again.

```csharp
//The certificate and the extracted key are separate disposables
using var cert = new CertificateBuilder().SetSubject(b => b.SetCommonName("Example")).Create();
using var key = cert.GetPrivateKey();
```

Certificates the library returns to you are always yours. Nothing in `CertificateFinder` or the export
path disposes a certificate you can still reach.

`CertificateFinder` does dispose certificates you can't reach: ones it loaded from a store or a file and
then discarded, because a `Where` rejected them or because deduplication dropped them as a repeat. You
never see those, and nothing else could release them. Certificates you supplied yourself, through
`AddCustomSource` or a custom source that overrides `Release` to a no-op, are left alone either way.

Two exceptions, both producing a sequence that mixes objects you own with objects the call created, with
no way to tell them apart, so don't dispose their elements:

- `FilterPrivateKeys`: when it strips a private key it returns a keyless copy, and otherwise passes your
  original through.
- `X509ChainBuilder.Export()`: it hands back your own instances wherever you supplied them, and a keyless
  copy only for a chain element the platform supplied itself. See
  [Building a Certificate Chain](#building-a-certificate-chain).

---

## Exporting certificates

Exporting requires the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package (included in the top-level `FluentCertificates` package) and is found under the `FluentCertificates` namespace.

Everything goes through the `Export()` extension method, available on `X509Certificate2`, `X509Certificate2Collection`, `X509Chain` and `IEnumerable<X509Certificate2>`. It returns a `CertificateExportBuilder`: configure it with `With*`, choose a format with `As*`, then finish with `To*`.

**Private keys are opt-in.** An export carries certificates and nothing else until you ask for a key, so
`cert.Export().AsPkcs12().ToFile("cert.pfx")` writes a PFX with **no** private key in it. Add
`WithPrivateKey()` for the anchor's key (see below), or `WithAllPrivateKeys()` for every key you hold.

```csharp
//PEM, certificate only
cert.Export().AsPem().ToPemString();

//PEM including the private key
cert.Export().WithPrivateKey().AsPem().ToFile("cert.pem");

//Password-protected PKCS#12 (PFX), key included
cert.Export().WithPrivateKey().WithPassword("hunter2").AsPkcs12().ToFile("cert.pfx");

//Raw DER/CER bytes
cert.Export().AsCert().ToByteArray();

//A whole chain as PKCS#7
chain.Export().AsPkcs7().ToByteArray();

//A leaf plus its issuers, no private keys anywhere
leafCert.Export().AddChain([leafCert, intermediateCert, rootCert]).AsPkcs12().ToByteArray();
```

|Stage|Methods|
|-|-|
|Configure|`WithPrivateKey()`, `WithAllPrivateKeys()`, `WithoutPrivateKeys()`, `WithKeys(ExportKeys)`, `WithPassword(string?)`, `WithPassword(SecureString)`, `WithoutPassword()`|
|Add|`AddChain(X509Chain)`, `AddChain(...)`, `AddCertificates(...)`|
|Format|`AsPem()`, `AsPkcs12()`, `AsPkcs7()`, `AsCert()`|
|Finish|`ToPemString()` (PEM only), `ToByteArray()`, `ToFile(path)`, `ToStream(stream)`|

`With*` configures the export and replaces whatever was set before; `Add*` appends certificates to it.
Every `Add*` method deduplicates by thumbprint, so a certificate already present is skipped.

`WithPrivateKey()` (singular, the anchor's key) and `WithAllPrivateKeys()` (every key) do different
things, so they are named to be hard to confuse.

`AddChain` and `AddCertificates` take `params IEnumerable<X509Certificate2>`, so an array, a LINQ query,
an `X509Certificate2Collection`, or a handful of individual certificates all bind to the same method:

```csharp
leafCert.Export().AddChain(midCert, rootCert);              //loose arguments
leafCert.Export().AddChain(chainArray);                     //an array
leafCert.Export().AddCertificates(store.Certificates);      //an X509Certificate2Collection
leafCert.Export().AddCertificates(certs.Where(IsCurrent));  //a lazy sequence
```

Each `WithPassword` overload clears the other kind of password, so the last call wins, and
`WithoutPassword()` clears both. A `SecureString` password is honoured by every format, but only
`AsPem()` keeps it out of the managed heap: the platform's PKCS#12 export takes a `string`, so
`AsPkcs12()` has to materialise one.

**Ordering follows the API you used, not what the certificates look like.** A chain is sorted; a
collection is preserved:

```csharp
//A chain: AddChain declares it one, so it is sorted leaf-first however it arrives
leafCert.Export().AddChain([rootCert, midCert]).AsPem().ToPemString();
//  -> leaf, mid, root

//Several chains: each call sorted as a unit, blocks appended in call order
leaf1.Export().AddChain([mid1, root1]).AddChain([root2, mid2, leaf2]).AsPem().ToPemString();
//  -> leaf1, mid1, root1, leaf2, mid2, root2

//A collection: a bundle, written exactly as supplied even if it happens to form a chain
new[] { rootCert, midCert, leafCert }.Export().AsPem().ToPemString();
//  -> root, mid, leaf

//AddCertificates appends without claiming a relationship, so it never reorders either
leafCert.Export().AddChain([rootCert, midCert]).AddCertificates([otherRoot, unrelated]).AsPem().ToPemString();
//  -> leaf, mid, root, otherRoot, unrelated
```

`chain.Export()` needs no sorting, since `X509Chain.ChainElements` is already leaf-first. An `AddChain`
group that does not form a single chain is appended in the order given.

This matters most for PEM, where TLS servers require the sender's certificate first, but the order is
preserved in PKCS#12 and PKCS#7 too and reappears in PEM as soon as anyone runs
`openssl pkcs12 -in cert.pfx -nokeys`.

`ExportKeys.Primary` and `AsCert()` are the only parts that need a designated certificate, and they read
it from the builder's `Anchor` rather than from position. `cert.Export()` anchors on that certificate and
`chain.Export()` on the chain's end certificate, so adding issuers with `AddChain(...)` can never
retarget the export, even when the result does form a valid chain:

```csharp
//Exports the intermediate, because that is what the builder was anchored on
intermediateCert.Export().AddChain([rootCert, leafCert]).AsCert().ToByteArray();
```

`collection.Export()` and the `IEnumerable<X509Certificate2>` overload designate no leaf, so both throw
`InvalidOperationException` there. This holds even when the certificates do form a chain: a bundle names
no primary certificate, and arriving first is not evidence of being one. Since keys are opt-in, the
`ExportKeys.Primary` half of that only bites when you actually write `WithPrivateKey()` on a bundle.

```csharp
//Throws: a bundle, so nothing says which certificate to export
new[] { rootCert, midCert, leafCert }.Export().AsCert().ToByteArray();

//Fine: declaring a chain is what makes the leaf knowable
leafCert.Export().AddChain([rootCert, midCert]).AsCert().ToByteArray();
```


---

## CertificateFinder examples

`CertificateFinder` requires the [FluentCertificates.Finder](https://www.nuget.org/packages/FluentCertificates.Finder) package and is found under the `FluentCertificates` namespace.

`CertificateFinder` configures, adds, and queries certificate sources (stores, directories, and
certificates you already hold). Like the other builders it is immutable, and it supports LINQ.

Each source is responsible for finding, loading and filtering its own certificates. The finder composes
sources and collates what they return. `Where` is where that matters: it takes an expression tree and
hands it to every source, so a source able to answer it natively can, and one that cannot applies it
itself. Both forms bind to it:

```csharp
finder.Where(x => x.Certificate.Subject.Contains("example.com"));
from x in finder where x.Certificate.HasPrivateKey select x.Certificate;
```

`Any`, `All`, `First`, `FirstOrDefault`, `Last`, `LastOrDefault`, `Single`, `SingleOrDefault` and `Count`
take a predicate and push it down the same way. `All` pushes down the negation, since what a source can
stop at is the first certificate that fails. Any other LINQ operator runs after collation, which is still
correct, just more work.
So does a predicate you hold in a `Func<>` variable rather than writing inline, since only a lambda
becomes an expression tree.

Results carry a `Source` and a `Location` saying where the certificate was found, so the same
certificate present in two stores is reported twice, once for each, and a file that two overlapping
directory sources both reach is reported by each of them. Results are never deduplicated, because where
a certificate was found is part of the answer. To collapse them, add
`.DistinctBy(r => (r.Certificate.Thumbprint, r.Source.Kind, r.Location))`.

### Find a specific certificate by thumbprint

_The "common stores" include the CurrentUser and LocalMachine certificate stores, such as "My", "Root", "CA", etc. You can also add custom directories or other X509 stores to search for certificates._

```csharp
const string thumbprint = "622A2B8374D9BBE3969B91EDBC8F5152783AFC78";

var cert = new CertificateFinder()
    .AddCommonStores()
    .FirstOrDefault(x => x.Certificate.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase));
```

### Find a valid certificate with matching subject, giving preference to included private keys

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

### Find a certificate whose private key can actually sign

`HasPrivateKey` only reports that the certificate carries metadata naming a key. Picking an issuer on
that basis can select one whose key container was deleted, whose key ACL excludes you, or whose token
is absent, and the failure then surfaces much later as `CryptographicException: Keyset does not exist`
from somewhere unrelated. `CanSign()` resolves the key instead, so the dud is rejected at selection
time:

```csharp
var ca = new CertificateFinder()
    .AddCommonStores()
    .Select(x => x.Certificate)
    .Where(x => subject.EquivalentTo(x.SubjectName, false))
    .FirstOrDefault(x => x.CanSign());
```

It reaches the key store, so it costs far more than the property read it replaces. Narrow by subject or
thumbprint first and apply it last, as above.

---

## X500NameBuilder examples

`X500NameBuilder` requires the [FluentCertificates.Builder](https://www.nuget.org/packages/FluentCertificates.Builder) package and is found under the `FluentCertificates` namespace.

`X500NameBuilder` builds the distinguished names used for a certificate's subject and issuer. Like
the other builders it is immutable: every method returns a new instance, so a builder can be shared
and used as a template safely.

### Building a subject name

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

### Reading values back

Every `Set*` method has a matching `Get*`. Single-valued attributes return `null` when absent, and
multi-valued ones return an empty sequence.

```csharp
string? cn = subject.GetCommonName();                       //"*.fake.domain"
string? org = subject.GetOrganization();                    //"Example Pty Ltd"
IEnumerable<string> ous = subject.GetOrganizationalUnits();  //"Engineering", "Platform"
string? missing = new X500NameBuilder().GetCommonName();     //null
```

### Starting from an existing name

```csharp
var fromString = new X500NameBuilder("CN=example.com, O=Example Pty Ltd");
var fromDn = new X500NameBuilder(cert.SubjectName);

//Builders are immutable, so this leaves fromString untouched
var renamed = fromString.SetCommonName("other.example.com");
```

### Attributes without a dedicated method

Use `Add` or `Set` with an OID, optionally choosing the ASN.1 string encoding. `Add` appends another
RDN with the same OID; `Set` replaces any existing ones.

```csharp
var custom = new X500NameBuilder()
    .SetCommonName("example.com")
    .Add("0.9.2342.19200300.100.1.25", UniversalTagNumber.IA5String, "example", "com")
    .Remove(Oids.EmailAddressOid);
```

### Comparing names

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

### Method summary

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

## X509Certificate2 extension methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`BuildChain()`|Starts a fluent `X509ChainBuilder` for building and verifying a chain for this certificate. See [Building a certificate chain](#building-a-certificate-chain).|
|`IsValidNow()`|Whether the current UTC time falls within the certificate's validity period.|
|`IsValidAt(DateTimeOffset atTime)`|Whether the given instant falls within the validity period. Both bounds are inclusive. There is no `DateTime` overload, because a `DateTime` carries no offset and its `DateTimeKind` would change the result.|
|`IsSelfSigned(bool verifySignature = false)`|Whether subject and issuer match. Pass `true` to also verify the certificate's signature against its own public key.|
|`IsIssuedBy(X509Certificate2 issuer, bool verifySignature = false)`|Whether the certificate names the given issuer. Pass `true` to also verify the signature, which is what distinguishes a genuine issuer from one merely claiming the name.|
|`CanSign()`|Whether the private key can actually be used for signing, as opposed to merely being associated with the certificate. Every "cannot sign" outcome returns `false` rather than throwing. Costs a key-store lookup. See [Find a certificate whose private key can actually sign](#find-a-certificate-whose-private-key-can-actually-sign).|
|`GetPrivateKey()`|Returns the private key as a `CertificateKey`, whatever its algorithm, classical or post-quantum. Reach a classical key through `.AsAsymmetricAlgorithm`. Every call returns a **new instance which you own and should dispose**; see [Key ownership](#key-ownership-and-disposal).|
|`GetSignatureAlgorithm()`|Returns the `SignatureAlgorithm` the certificate was signed with, combining key algorithm, hash and padding.|
|`GetToBeSignedData()`|The raw "to be signed" (TBS) bytes, i.e. what the issuer's signature covers.|
|`GetSignatureData()`|The raw signature bytes. Together with `GetToBeSignedData()` this allows verifying a signature yourself.|
|`Export()`|Returns a `CertificateExportBuilder`; see [Exporting Certificates](#exporting-certificates)|

---

## Building a certificate chain

`cert.BuildChain()` returns an immutable `X509ChainBuilder`. Configure it, then terminate with either
`Create()` (inspect the outcome) or `Export()` (verify and export in one step).

|Method|Description|
|-|-|
|`TrustRoot(params IEnumerable<X509Certificate2> roots)`|Trusts these certificates as the only valid roots (`X509ChainTrustMode.CustomRootTrust`). Never calling it leaves the system trust store in effect. Calling it is what replaces system trust, not the number of roots passed, so an empty set trusts no root at all rather than falling back.|
|`AddCertificates(params IEnumerable<X509Certificate2> certs)`|Offers extra certificates, typically intermediates, to path building via `ExtraStore`. Candidates only: an untrusted root stays untrusted however it arrives here.|
|`AllowInvalidTime()`|Ignores expired or not-yet-valid certificates anywhere in the chain. Structural and trust failures still fail.|
|`WithPolicy(Action<X509ChainPolicy> configure)`|Escape hatch for anything else: revocation checking, `ApplicationPolicy`, a custom `VerificationTime`, and so on. Applied after the builder's own settings, so it always wins; multiple calls run in registration order.|
|`Create()`|Builds the chain and returns a disposable `ChainResult`. Never throws on verification failure.|
|`Export()`|Builds, verifies, and returns a `CertificateExportBuilder` over the chain's certificates, leaf first. Throws `CryptographicException` naming the failed statuses when the chain does not verify, so a gap can never silently reach the exported file.|

Revocation defaults to `NoCheck`, so a chain build never reaches the network unless `WithPolicy` says so.

`ChainResult` owns the built chain and exposes `Verified`, `Chain`, `ChainStatus`, `EnsureVerified()`
(throws unless verified, otherwise returns itself) and `Export()`.

```csharp
//Verify and write a leaf-first fullchain in one line
leaf.BuildChain().TrustRoot(root).AddCertificates(mid).Export().AsPem().ToFile("fullchain.pem");

//Or inspect the outcome rather than throwing on it
using var result = leaf.BuildChain().TrustRoot(root).AddCertificates(mid).Create();
if (!result.Verified) {
    Console.WriteLine(String.Join("; ", result.ChainStatus.Select(x => x.Status)));
    return;
}
result.Export().WithPrivateKey().AsPkcs12().ToFile("bundle.pfx");
```

`ChainResult.Export()` does **not** verify, matching every other `Export()` in the library: exporting an
unverified result writes whatever was built, which for a partial chain is an incomplete bundle. Check
`Verified` first as above, or write `result.EnsureVerified().Export()`. Only `builder.Export()` verifies
on your behalf, because it is a one-liner with nowhere to intervene.

Neither terminator carries a private key until you ask, the same as every other export. Call
`WithPrivateKey()` for the leaf's, which is what a fullchain wants, or `WithAllPrivateKeys()` to include
any CA keys you happen to hold.

`builder.Export()` disposes its internal chain before returning, so it cannot hand out the chain's own
element certificates. Each element is mapped back to the instance you supplied through the certificate
itself, `TrustRoot(...)`, `AddCertificates(...)` or a `WithPolicy(...)` action that populated `ExtraStore`
or `CustomTrustStore`, which you already own and dispose. Only an element the platform supplied itself,
such as a root from the system store or an intermediate fetched via AIA, has no such instance and is
copied; that copy is keyless and must **not** be disposed by you (the same rule as `FilterPrivateKeys`;
see [Key ownership](#key-ownership-and-disposal)). `result.Export()` copies nothing, so keep the
`ChainResult` undisposed until that export terminates.

---

## X509Chain extension methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToEnumerable()`|Returns the chain's certificates in **leaf-first** order, matching `X509Chain.ChainElements`. The root is therefore last.|
|`ToCollection(ExportKeys include = ExportKeys.None)`|As `ToEnumerable()`, but returns an `X509Certificate2Collection` and applies `FilterPrivateKeys(include)`. Keys are opt-in, as everywhere else.|
|`Export()`|Returns a `CertificateExportBuilder`; see [Exporting Certificates](#exporting-certificates)|

---

## X509Certificate2Collection extension methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToEnumerable()`|Exposes the collection as an `IEnumerable<X509Certificate2>`, so the LINQ operators and the extension methods below can be used against it.|
|`Export()`|Returns a `CertificateExportBuilder`; see [Exporting Certificates](#exporting-certificates)|

---

## IEnumerable<X509Certificate2> extension methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToCollection()`|Copies the sequence into a new `X509Certificate2Collection`.|
|`FilterPrivateKeys(ExportKeys include)`|Returns the sequence with private keys kept or stripped according to `include`. `ExportKeys.Primary` keeps only the first certificate's private key: a bare sequence has no anchor, so the primary one is taken to be the first.|
|`Export()`|Returns a `CertificateExportBuilder`; see [Exporting Certificates](#exporting-certificates)|

---

## AsymmetricAlgorithm extension methods

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

## CertificateRequest extension methods

These extension methods require the [FluentCertificates.Extensions](https://www.nuget.org/packages/FluentCertificates.Extensions) package and are found under the `FluentCertificates` namespace.

|Extension-Method|Description|
|-|-|
|`ToPemString()`|Exports the `CertificateRequest` to a PEM string.|
|`ExportAsPem(string path)`|Exports the `CertificateRequest` to the specified PEM file.|
|`ExportAsPem(TextWriter writer)`|Exports the `CertificateRequest` in PEM format to the given `TextWriter`.|

