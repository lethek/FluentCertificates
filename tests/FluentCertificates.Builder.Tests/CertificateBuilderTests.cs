using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;

using TUnit.Assertions.Enums;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

public class CertificateBuilderTests
{
    [Test]
    public async Task Build_Certificate_HasPrivateKey()
    {
        using var cert1 = new CertificateBuilder().Create();
        await Assert.That(cert1.HasPrivateKey).IsTrue();

        using var cert2 = new CertificateBuilder().SetKeyStorageFlags(X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable).Create();
        await Assert.That(cert2.HasPrivateKey).IsTrue();
    }


    [Test]
    public async Task Build_Certificate_WithSubject()
    {
        const string testName = nameof(Build_Certificate_WithSubject);
        const string expected = $"CN={testName}";

        //Test several different, equivalent ways of setting the Subject

        using var cert1 = new CertificateBuilder().SetSubject(b => b.SetCommonName(testName)).Create();
        await Assert.That(cert1.Subject).IsEqualTo(expected);

        using var cert2 = new CertificateBuilder().SetSubject(new X500NameBuilder().SetCommonName(testName)).Create();
        await Assert.That(cert2.Subject).IsEqualTo(expected);

        using var cert3 = new CertificateBuilder().SetSubject(new X500DistinguishedName(expected)).Create();
        await Assert.That(cert3.Subject).IsEqualTo(expected);

        using var cert5 = new CertificateBuilder().SetSubject(expected).Create();
        await Assert.That(cert5.Subject).IsEqualTo(expected);

        using var cert6 = new CertificateBuilder {Subject = new X500NameBuilder(expected)}.Create();
        await Assert.That(cert6.Subject).IsEqualTo(expected);
    }


    [Test]
    public async Task Build_Certificate_WithRSAKeys()
    {
        using var keys = RSA.Create();
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Create();
        await Assert.That(cert1.GetKeyAlgorithm()).IsEqualTo(PkcsObjectIdentifiers.RsaEncryption.Id);

        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.RSA()).Create();
        await Assert.That(cert2.GetKeyAlgorithm()).IsEqualTo(PkcsObjectIdentifiers.RsaEncryption.Id);
    }


    [Test]
    public async Task Build_Certificate_WithECDsaKeys()
    {
        using var keys = ECDsa.Create();
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Create();
        await Assert.That(cert1.GetKeyAlgorithm()).IsEqualTo(X9ObjectIdentifiers.IdECPublicKey.Id);

        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.ECDsa()).Create();
        await Assert.That(cert2.GetKeyAlgorithm()).IsEqualTo(X9ObjectIdentifiers.IdECPublicKey.Id);
    }


    [Test]
    [SupportedOSPlatform("Windows")]
    [SupportedOSPlatform("Linux")]
    public async Task Build_Certificate_WithDSAKeys()
    {
        using var keys = DSA.Create(1024);
        using var cert1 = new CertificateBuilder().SetKeyPair(keys).Create();
        await Assert.That(cert1.GetKeyAlgorithm()).IsEqualTo(X9ObjectIdentifiers.IdDsa.Id);

#pragma warning disable CS0618 // Type or member is obsolete
        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.DSA()).Create();
#pragma warning restore CS0618 // Type or member is obsolete
        await Assert.That(cert2.GetKeyAlgorithm()).IsEqualTo(X9ObjectIdentifiers.IdDsa.Id);
    }


    [Test]
    public async Task Build_RSACertificate_WithECDsaIssuer()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(now.AddHours(1))
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
            .Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(rootCA)
            .SetKeyAlgorithm(KeyAlgorithm.RSA())
            .Create();

        await Assert.That(cert.IsIssuedBy(rootCA, true)).IsTrue();
    }


    [Test]
    public async Task Build_ECDsaCertificate_WithRSAIssuer()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCA = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(now.AddHours(1))
            .SetKeyAlgorithm(KeyAlgorithm.RSA())
            .Create();

        using var cert = new CertificateBuilder()
            .SetIssuer(rootCA)
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
            .Create();

        await Assert.That(cert.IsIssuedBy(rootCA, true)).IsTrue();
    }


    [Test]
    [SupportedOSPlatform("Windows")]
    public async Task Build_CertificateOnWindows_WithFriendlyName()
    {
        const string friendlyName = "A FriendlyName can be set on Windows";

        using var cert1 = new CertificateBuilder().SetFriendlyName(friendlyName).Create();
        await Assert.That(cert1.FriendlyName).IsEqualTo(friendlyName);

        using var cert2 = new CertificateBuilder().SetFriendlyName(friendlyName).SetKeyStorageFlags(X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable).Create();
        await Assert.That(cert2.FriendlyName).IsEqualTo(friendlyName);
    }


    [Test]
    public async Task KeyAlgorithm_InvalidKeyLength_ThrowsAtConstruction()
    {
        //A key length now belongs to the algorithm rather than sitting beside it, so an invalid one is
        //rejected where it is named instead of surviving until Create()
        await Assert.That(() => KeyAlgorithm.RSA(0)).ThrowsExactly<ArgumentOutOfRangeException>();
        await Assert.That(() => KeyAlgorithm.RSA(-1024)).ThrowsExactly<ArgumentOutOfRangeException>();

        //A positive but unusably small length is still the platform's to reject, not ours
        await Assert.That(() => {
            using var cert = new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.RSA(10)).Create();
        }).Throws<Exception>();
    }


    [Test]
    public async Task Build_MinimalCertificate_IsValid()
    {
        using var cert = new CertificateBuilder().Create();

        await Assert.That(cert.Subject).IsEmpty();
        await Assert.That(cert.SerialNumberBytes.Length).IsEqualTo(18);
        await Assert.That(cert.IsValidNow()).IsTrue();
    }


    [Test]
    public async Task Build_RootCA_IsSelfSigned()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .Create();

        await Assert.That(rootCa.Extensions.OfType<X509BasicConstraintsExtension>()).Contains(x => x.CertificateAuthority);
        await Assert.That(rootCa.IsSelfSigned()).IsTrue();
    }


    [Test]
    public async Task Build_SubordinateCA_IsSignedByRoot()
    {
        var now = DateTimeOffset.UtcNow;

        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(now.AddHours(1))
            .Create();

        using var subCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Subordinate CA Test"))
            .SetNotAfter(now.AddMinutes(1))
            .SetIssuer(rootCa)
            .Create();

        await Assert.That(rootCa.Extensions.OfType<X509BasicConstraintsExtension>()).Contains(x => x.CertificateAuthority);
        await Assert.That(subCa.IsIssuedBy(rootCa, true)).IsTrue();
    }


    [Test]
    public async Task Build_WebCertificate_IsValid()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(7))
            .Create();

        using var subCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Intermediate CA Test"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(6))
            .SetIssuer(rootCa)
            .Create();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetFriendlyName("FluentCertificates Server Test")
            .SetSubjectAlternativeNames(x => x.AddDnsNames("*.fake.domain", "fake.domain", "another.domain"))
            .SetSubject(x => x.SetCommonName("*.fake.domain"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .SetIssuer(subCa)
            .Create();

        await Assert.That(cert.IsValidNow()).IsTrue();
        await Assert.That(rootCa.IsIssuedBy(rootCa, true)).IsTrue();
        await Assert.That(subCa.IsIssuedBy(rootCa, true)).IsTrue();
        await Assert.That(cert.IsIssuedBy(subCa, true)).IsTrue();

        //Assert correct DNS names in the SAN
        var ext = cert.Extensions[X509Extensions.SubjectAlternativeName.Id];
        var san = EnumerateNamesFromSan(ext!).Where(x => x.TagNo == Org.BouncyCastle.Asn1.X509.GeneralName.DnsName).ToList();
        await Assert.That(san).Contains(x => x.Name.ToString() == "*.fake.domain");
        await Assert.That(san).Contains(x => x.Name.ToString() == "fake.domain");
        await Assert.That(san).Contains(x => x.Name.ToString() == "another.domain");
    }


    [Test]
    public async Task Build_CertificateSigningRequest_WithRSAKeys()
    {
        using var keys = RSA.Create();

        var csr = new CertificateBuilder()
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        await Assert.That(csr.GetRawData().IsEmpty).IsFalse();

        var cr = csr.CertificateRequest;
        var algorithm = csr.GetSignatureAlgorithm();
        var cri = csr.GetRequestData().ToArray();
        var sig = csr.GetSignatureData().ToArray();

        await Assert.That(algorithm).IsEqualTo(SignatureAlgorithm.SHA256RSA);
        await Assert.That(cr.PublicKey.GetRSAPublicKey()!.VerifyData(cri, sig, algorithm.HashAlgorithm!.Value, algorithm.RSASignaturePadding!)).IsTrue();
    }


    [Test]
    public async Task Build_CertificateSigningRequest_WithDSAKeys()
    {
        using var keys = DSA.Create();

        var csr = new CertificateBuilder()
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        await Assert.That(csr.GetRawData().IsEmpty).IsFalse();

        var cr = csr.CertificateRequest;
        var algorithm = csr.GetSignatureAlgorithm();
        var cri = csr.GetRequestData().ToArray();
        var sig = csr.GetSignatureData().ToArray();

#pragma warning disable CS0618 // Type or member is obsolete
        await Assert.That(algorithm).IsEqualTo(SignatureAlgorithm.SHA256DSA);
#pragma warning restore CS0618 // Type or member is obsolete
        await Assert.That(cr.PublicKey.GetDSAPublicKey()!.VerifyData(cri, sig, algorithm.HashAlgorithm!.Value, DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
    }


    [Test]
    public async Task Build_CertificateSigningRequest_WithECDsaKeys()
    {
        using var keys = ECDsa.Create();

        var csr = new CertificateBuilder()
            .SetHashAlgorithm(HashAlgorithmName.SHA256)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        await Assert.That(csr.GetRawData().IsEmpty).IsFalse();

        var cr = csr.CertificateRequest;
        var algorithm = csr.GetSignatureAlgorithm();
        var cri = csr.GetRequestData().ToArray();
        var sig = csr.GetSignatureData().ToArray();

        await Assert.That(algorithm).IsEqualTo(SignatureAlgorithm.SHA256ECDSA);
        await Assert.That(cr.PublicKey.GetECDsaPublicKey()!.VerifyData(cri, sig, algorithm.HashAlgorithm!.Value, DSASignatureFormat.Rfc3279DerSequence)).IsTrue();
    }


    [Test]
    public async Task Build_ClientCertificate_HasClientAuthEKU()
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetSubject(x => x.SetCommonName("Client Test"))
            .Create();

        await Assert.That(GetEkuOids(cert)).IsEquivalentTo(["1.3.6.1.5.5.7.3.2"]);
        await Assert.That(GetKeyUsages(cert)).IsEqualTo(X509KeyUsageFlags.DigitalSignature);
        await Assert.That(cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority).IsFalse();
    }


    [Test]
    public async Task Build_CodeSignCertificate_HasCodeSigningEKU()
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CodeSign)
            .SetSubject(x => x.SetCommonName("CodeSign Test"))
            .Create();

        await Assert.That(GetEkuOids(cert)).IsEquivalentTo(["1.3.6.1.5.5.7.3.3"]);
        await Assert.That(GetKeyUsages(cert)).IsEqualTo(X509KeyUsageFlags.DigitalSignature);
    }


    [Test]
    public async Task Build_OcspSigningCertificate_HasOcspSigningEKU()
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.OcspSigning)
            .SetSubject(x => x.SetCommonName("OCSP Responder Test"))
            .Create();

        await Assert.That(GetEkuOids(cert)).IsEquivalentTo(["1.3.6.1.5.5.7.3.9"]);
        await Assert.That(GetKeyUsages(cert)).IsEqualTo(X509KeyUsageFlags.DigitalSignature);
        await Assert.That(cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().Critical).IsFalse();
        await Assert.That(cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority).IsFalse();
    }


    [Test]
    public async Task Build_TimeStampingCertificate_HasCriticalTimeStampingEKU()
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.TimeStamping)
            .SetSubject(x => x.SetCommonName("TSA Test"))
            .Create();

        await Assert.That(GetEkuOids(cert)).IsEquivalentTo(["1.3.6.1.5.5.7.3.8"]);
        await Assert.That(GetKeyUsages(cert)).IsEqualTo(X509KeyUsageFlags.DigitalSignature);

        //RFC 3161 s2.3 requires the extended key usage extension on a TSA certificate to be critical
        await Assert.That(cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().Critical).IsTrue();
        await Assert.That(cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority).IsFalse();
    }


    [Test]
    [Arguments(CertificateUsage.Server, false)]
    [Arguments(CertificateUsage.Client, false)]
    [Arguments(CertificateUsage.CodeSign, false)]
    [Arguments(CertificateUsage.SMime, false)]
    [Arguments(CertificateUsage.OcspSigning, false)]
    [Arguments(CertificateUsage.TimeStamping, true)]
    public async Task Build_EndEntityCertificate_MarksConstraintsAndKeyUsageCritical(CertificateUsage usage, bool ekuIsCritical)
    {
        using var cert = new CertificateBuilder()
            .SetUsage(usage)
            .SetSubject(x => x.SetCommonName($"{usage} Criticality Test"))
            .Create();

        //RFC 5280 s4.2.1.9 requires basicConstraints to be critical wherever it appears in a CA
        //certificate, and s4.2.1.3 says the same of keyUsage; an end-entity certificate that leaves
        //either non-critical lets a relying party ignore the limits it is asserting.
        var basicConstraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        await Assert.That(basicConstraints.Critical).IsTrue();
        await Assert.That(basicConstraints.CertificateAuthority).IsFalse();
        await Assert.That(basicConstraints.HasPathLengthConstraint).IsFalse();
        await Assert.That(basicConstraints.PathLengthConstraint).IsEqualTo(0);

        await Assert.That(cert.Extensions.OfType<X509KeyUsageExtension>().Single().Critical).IsTrue();
        await Assert.That(cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().Critical).IsEqualTo(ekuIsCritical);
    }


    [Test]
    [Arguments(KeyAlgorithmFamily.Rsa, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment)]
    [Arguments(KeyAlgorithmFamily.ECDsa, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)]
    public async Task Build_SMimeCertificate_HasEmailProtectionEKU(KeyAlgorithmFamily family, X509KeyUsageFlags expectedUsages)
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.SMime)
            .SetKeyAlgorithm(KeyAlgorithm.Default(family))
            .SetSubject(x => x.SetCommonName("SMime Test"))
            .Create();

        await Assert.That(GetEkuOids(cert)).IsEquivalentTo(["1.3.6.1.5.5.7.3.4"]);
        await Assert.That(GetKeyUsages(cert)).IsEqualTo(expectedUsages);
    }


    [Test]
    [Arguments(KeyAlgorithmFamily.Rsa, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment)]
    [Arguments(KeyAlgorithmFamily.ECDsa, X509KeyUsageFlags.DigitalSignature)]
    public async Task Build_ServerCertificate_HasServerAuthEKU(KeyAlgorithmFamily family, X509KeyUsageFlags expectedUsages)
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetKeyAlgorithm(KeyAlgorithm.Default(family))
            .SetSubject(x => x.SetCommonName("Server Test"))
            .Create();

        //keyEncipherment is only meaningful for RSA: an EC key cannot do key transport
        await Assert.That(GetEkuOids(cert)).IsEquivalentTo(["1.3.6.1.5.5.7.3.1"]);
        await Assert.That(GetKeyUsages(cert)).IsEqualTo(expectedUsages);
    }


    [Test]
    public async Task Build_ServerCertificate_KeyUsageFollowsTheSuppliedKeyPair()
    {
        //The decision must follow the actual key, not only an explicit SetKeyAlgorithm call
        using var ecKeys = ECDsa.Create();
        using var ecCert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject(x => x.SetCommonName("Supplied EC Key"))
            .SetKeyPair(ecKeys)
            .Create();

        using var rsaKeys = RSA.Create(2048);
        using var rsaCert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject(x => x.SetCommonName("Supplied RSA Key"))
            .SetKeyPair(rsaKeys)
            .Create();

        await Assert.That(GetKeyUsages(ecCert)).IsEqualTo(X509KeyUsageFlags.DigitalSignature);
        await Assert.That(GetKeyUsages(rsaCert))
            .IsEqualTo(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
    }


    [Test]
    public async Task Build_RootCA_HasKeyUsageCertSignAndCrlSign()
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Root CA Test"))
            .Create();

        await Assert.That(GetKeyUsages(rootCa))
            .IsEqualTo(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign);

        var ski = rootCa.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single();
        await Assert.That(ski.SubjectKeyIdentifier).IsNotNull().And.IsNotEmpty();
        await Assert.That(ski.Critical).IsFalse();

        //A CA has no EKU restriction
        await Assert.That(rootCa.Extensions.OfType<X509EnhancedKeyUsageExtension>()).IsEmpty();
    }


    [Test]
    public async Task Build_Certificate_WithEmptySubjectAndSAN_SanIsCritical()
    {
        //RFC 5280 s4.1.2.6: the SAN extension MUST be critical when the Subject is empty
        using var withoutSubject = new CertificateBuilder()
            .SetSubjectAlternativeNames(x => x.AddDnsNames("fake.domain"))
            .Create();

        await Assert.That(withoutSubject.SubjectName.Name).IsEqualTo(String.Empty);
        await Assert.That(GetSanExtension(withoutSubject).Critical).IsTrue();

        using var withSubject = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("fake.domain"))
            .SetSubjectAlternativeNames(x => x.AddDnsNames("fake.domain"))
            .Create();

        await Assert.That(GetSanExtension(withSubject).Critical).IsFalse();
    }


    [Test]
    public async Task Validate_NotBeforeNotEarlierThanNotAfter_Throws()
    {
        var now = DateTimeOffset.UtcNow;

        await Assert
            .That(() => new CertificateBuilder().SetNotBefore(now).SetNotAfter(now.AddHours(-1)).Validate())
            .ThrowsExactly<ArgumentException>();

        //The bound is exclusive: equal timestamps are rejected too
        await Assert
            .That(() => new CertificateBuilder().SetNotBefore(now).SetNotAfter(now).Validate())
            .ThrowsExactly<ArgumentException>();

        await Assert
            .That(() => new CertificateBuilder().SetNotBefore(now).SetNotAfter(now.AddSeconds(1)).Validate())
            .ThrowsNothing();
    }


    [Test]
    public async Task SetValidity_FromAndDuration_SetsBothBounds()
    {
        var from = new DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero);

        var builder = new CertificateBuilder().SetValidity(from, TimeSpan.FromDays(30));

        await Assert.That(builder.NotBefore).IsEqualTo(from);
        await Assert.That(builder.NotAfter).IsEqualTo(from.AddDays(30));
    }


    [Test]
    public async Task SetValidity_DurationOnly_StartsNowWithoutBackdating()
    {
        var before = DateTimeOffset.UtcNow;
        var builder = new CertificateBuilder().SetValidity(TimeSpan.FromDays(30));
        var after = DateTimeOffset.UtcNow;

        //Unlike the default NotBefore, this overload does not backdate the start time
        await Assert.That(builder.NotBefore).IsGreaterThanOrEqualTo(before).And.IsLessThanOrEqualTo(after);
        await Assert.That(builder.NotAfter - builder.NotBefore).IsEqualTo(TimeSpan.FromDays(30));
    }


    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    public async Task SetValidity_NonPositiveDuration_Throws(int ticks)
    {
        var duration = TimeSpan.FromTicks(ticks);

        await Assert
            .That(() => new CertificateBuilder().SetValidity(duration))
            .ThrowsExactly<ArgumentOutOfRangeException>();

        await Assert
            .That(() => new CertificateBuilder().SetValidity(DateTimeOffset.UtcNow, duration))
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }


    [Test]
    public async Task ECDsaWithCurve_GeneratesKeyOnTheRequestedCurve()
    {
        using var p384 = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384))
            .SetSubject(x => x.SetCommonName("P-384 Test"))
            .Create();

        using var p521 = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP521))
            .SetSubject(x => x.SetCommonName("P-521 Test"))
            .Create();

        using var key384 = p384.GetECDsaPublicKey()!;
        using var key521 = p521.GetECDsaPublicKey()!;

        await Assert.That(key384.KeySize).IsEqualTo(384);
        await Assert.That(key521.KeySize).IsEqualTo(521);
    }


    [Test]
    public async Task GenerateKeyPair_ECDsaWithoutExplicitCurve_DefaultsToNistP256()
    {
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
            .SetSubject(x => x.SetCommonName("Default Curve Test"))
            .Create();

        //The default is pinned rather than left to the platform's ECDsa.Create() choice
        using var key = cert.GetECDsaPublicKey()!;
        await Assert.That(key.KeySize).IsEqualTo(256);
    }


    [Test]
    public async Task KeyAlgorithm_CarriesItsOwnParameters_SoMismatchesCannotBeExpressed()
    {
        //A curve used to be a separate property that Validate() had to reject when paired with RSA or DSA.
        //It now belongs to the algorithm that takes one, so there is no combination left to reject: the
        //non-EC families expose no way to name a curve at all.
        await Assert.That(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384).Curve).IsNotNull();
        await Assert.That(KeyAlgorithm.RSA(2048).Curve).IsNull();
        await Assert.That(KeyAlgorithm.RSA(2048).KeyLength).IsEqualTo(2048);
        await Assert.That(KeyAlgorithm.ECDsa().KeyLength).IsNull();

        //Two curves of the same family are distinguishable, so a builder configured with one is not equal
        //to a builder configured with the other
        await Assert
            .That(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384))
            .IsNotEqualTo(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP521));

        await Assert
            .That(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384))
            .IsEqualTo(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384));
    }


    [Test]
    public async Task Validate_AlgorithmSupersededBySuppliedKeyPair_DoesNotThrow()
    {
        //A supplied key overrides generation settings rather than conflicting with them
        using var keys = RSA.Create(2048);
        var builder = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384))
            .SetKeyPair(keys);

        await Assert.That(() => builder.Validate()).ThrowsNothing();
        await Assert.That(builder.KeyAlgorithm.Family).IsEqualTo(KeyAlgorithmFamily.Rsa);
    }


    [Test]
    public async Task SuppliedKeyPair_KeepsItsOwnCurve()
    {
        //A supplied key already carries its own curve; the builder must not try to regenerate it
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP521))
            .SetKeyPair(keys)
            .SetSubject(x => x.SetCommonName("Supplied Curve Test"))
            .Create();

        using var key = cert.GetECDsaPublicKey()!;
        await Assert.That(key.KeySize).IsEqualTo(384);
    }


    [Test]
    public async Task SetSignatureGenerator_SignsWithAnIssuerThatHasNoPrivateKey()
    {
        //The scenario the feature exists for: the CA's key is unreachable, only the generator can use it
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=HSM Root CA")
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .Create();

        using var rootPublicOnly = Internals.CertTools.LoadCertificate(rootCa.RawData);
        await Assert.That(rootPublicOnly.HasPrivateKey).IsFalse();

        using var rootKey = rootCa.GetRSAPrivateKey()!;
        var generator = new RecordingSignatureGenerator(X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1));

        using var leaf = new CertificateBuilder()
            .SetSubject("CN=Leaf")
            .SetIssuer(rootPublicOnly)
            .SetSignatureGenerator(generator)
            .Create();

        await Assert.That(generator.SignCount).IsEqualTo(1);
        await Assert.That(leaf.Issuer).IsEqualTo(rootCa.Subject);
        await Assert.That(leaf.IsIssuedBy(rootCa, true)).IsTrue();
    }


    [Test]
    public async Task SetSignatureGenerator_SelfSigns_AndItsAlgorithmWinsOverTheBuilderDefault()
    {
        using var keys = RSA.Create(2048);

        //The builder's own default is Pkcs1, so a PSS signature can only have come from the generator
        var generator = new RecordingSignatureGenerator(X509SignatureGenerator.CreateForRSA(keys, RSASignaturePadding.Pss));

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Self Signed By Generator")
            .SetKeyPair(keys)
            .SetSignatureGenerator(generator)
            .Create();

        await Assert.That(generator.SignCount).IsEqualTo(1);
        await Assert.That(cert.SignatureAlgorithm.Value).IsEqualTo(Oids.RsaPss);
        await Assert.That(cert.IsSelfSigned(true)).IsTrue();
    }


    [Test]
    public async Task SetSignatureGenerator_SignsACertificateSigningRequest()
    {
        using var keys = RSA.Create(2048);
        var generator = new RecordingSignatureGenerator(X509SignatureGenerator.CreateForRSA(keys, RSASignaturePadding.Pss));

        var csr = new CertificateBuilder()
            .SetSubject("CN=Generated CSR")
            .SetKeyPair(keys)
            .SetSignatureGenerator(generator)
            .CreateCertificateSigningRequest();

        await Assert.That(generator.SignCount).IsGreaterThan(0);

        //The builder's own default is Pkcs1, so a PSS signature can only have come from the generator
        var algorithm = csr.GetSignatureAlgorithm();
        await Assert.That(algorithm.Oid).IsEqualTo(Oids.RsaPss);
        await Assert
            .That(keys.VerifyData(
                csr.GetRequestData().Span,
                csr.GetSignatureData().Span,
                algorithm.HashAlgorithm!.Value,
                algorithm.RSASignaturePadding!))
            .IsTrue();
    }


    [Test]
    public async Task SetSignatureGenerator_WithoutIssuerOrKeyPair_Throws()
    {
        using var keys = RSA.Create(2048);
        var generator = X509SignatureGenerator.CreateForRSA(keys, RSASignaturePadding.Pkcs1);

        //Nothing ties the generated key to the generator, so the self-signature could not verify
        await Assert
            .That(() => new CertificateBuilder().SetSignatureGenerator(generator).Validate())
            .ThrowsExactly<ArgumentException>();

        //Either an issuer or a supplied key pair resolves it
        await Assert
            .That(() => new CertificateBuilder().SetSignatureGenerator(generator).SetKeyPair(keys).Validate())
            .ThrowsNothing();
    }


    [Test]
    public async Task SetSignatureGenerator_Null_FallsBackToTheDerivedGenerator()
    {
        using var cert = new CertificateBuilder()
            .SetSubject("CN=No Generator")
            .SetSignatureGenerator(null)
            .Create();

        await Assert.That(cert.SignatureAlgorithm.Value).IsEqualTo(Oids.RsaPkcs1Sha256);
        await Assert.That(cert.IsSelfSigned(true)).IsTrue();
    }


    [Test]
    public async Task SetPublicKey_CertifiesThatKeyWithoutGeneratingOrAttachingAPrivateKey()
    {
        using var issuer = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Issuer")
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .Create();

        //Stands in for a key whose private half never leaves the device
        using var remoteKeys = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var publicKey = new PublicKey(remoteKeys);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Remote Key")
            .SetPublicKey(publicKey)
            .SetIssuer(issuer)
            .Create();

        //The certified key is the supplied one, not a freshly generated stand-in
        using var certified = cert.GetECDsaPublicKey()!;
        await Assert.That(certified.ExportSubjectPublicKeyInfo()).IsEquivalentTo(remoteKeys.ExportSubjectPublicKeyInfo());
        await Assert.That(cert.HasPrivateKey).IsFalse();
        await Assert.That(cert.IsIssuedBy(issuer, true)).IsTrue();
    }


    [Test]
    public async Task SetPublicKey_UpdatesKeyAlgorithmAndClearsAnyKeyPair()
    {
        using var rsaKeys = RSA.Create(2048);
        using var ecKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var builder = new CertificateBuilder()
            .SetKeyPair(rsaKeys)
            .SetPublicKey(new PublicKey(ecKeys));

        await Assert.That(builder.KeyAlgorithm).IsEqualTo(KeyAlgorithm.ECDsa());

        //With the key pair cleared there is nothing left to self-sign with
        await Assert.That(() => builder.Validate()).ThrowsExactly<ArgumentException>();
    }


    [Test]
    public async Task SetPublicKey_WithSignatureGenerator_SelfSignsWithoutAPrivateKeyInHand()
    {
        using var remoteKeys = RSA.Create(2048);

        //Both halves describe the same external key: the public half to certify, the generator to sign
        var generator = new RecordingSignatureGenerator(X509SignatureGenerator.CreateForRSA(remoteKeys, RSASignaturePadding.Pkcs1));

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=HSM Backed Root")
            .SetPublicKey(new PublicKey(remoteKeys))
            .SetSignatureGenerator(generator)
            .Create();

        await Assert.That(generator.SignCount).IsEqualTo(1);
        await Assert.That(cert.HasPrivateKey).IsFalse();
        await Assert.That(cert.IsSelfSigned(true)).IsTrue();
    }


    [Test]
    public async Task SetPublicKey_SelfSignedWithoutASignatureGenerator_Throws()
    {
        using var remoteKeys = RSA.Create(2048);

        //Nothing here can produce a signature
        await Assert
            .That(() => new CertificateBuilder().SetPublicKey(new PublicKey(remoteKeys)).Validate())
            .ThrowsExactly<ArgumentException>();
    }


    [Test]
    public async Task SetPublicKey_Null_RestoresAutomaticKeyGeneration()
    {
        using var remoteKeys = RSA.Create(2048);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Regenerated")
            .SetPublicKey(new PublicKey(remoteKeys))
            .SetPublicKey(null)
            .Create();

        await Assert.That(cert.HasPrivateKey).IsTrue();
        await Assert.That(cert.IsSelfSigned(true)).IsTrue();
    }


    [Test]
    public async Task Create_ReleasesOnlyTheKeysItOwns()
    {
        using var issuer = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Reused Issuer")
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .Create();

        //Create() extracts and releases the issuer's private key each time, so signing must stay repeatable
        using var first = new CertificateBuilder().SetSubject("CN=First").SetIssuer(issuer).Create();
        using var second = new CertificateBuilder().SetSubject("CN=Second").SetIssuer(issuer).Create();

        await Assert.That(first.IsIssuedBy(issuer, true)).IsTrue();
        await Assert.That(second.IsIssuedBy(issuer, true)).IsTrue();

        using var issuerKey = issuer.GetPrivateKey();
        await Assert.That(issuerKey.ExportSubjectPublicKeyInfo()).IsEquivalentTo(issuer.PublicKey.ExportSubjectPublicKeyInfo());

        //Create() also disposes the keyless certificate that CopyWithPrivateKey superseded, which must
        //leave the returned certificate's own key intact
        using var firstKey = first.GetPrivateKey();
        await Assert.That(first.HasPrivateKey).IsTrue();
        await Assert.That(firstKey.ExportSubjectPublicKeyInfo()).IsEquivalentTo(first.PublicKey.ExportSubjectPublicKeyInfo());
    }


    [Test]
    public async Task Create_WithSuppliedKeyPair_LeavesThatKeyUsable()
    {
        //Documented ownership: a key handed to the builder belongs to the caller and is never disposed by it
        using var keys = RSA.Create(2048);

        using var first = new CertificateBuilder().SetSubject("CN=First").SetKeyPair(keys).Create();
        using var second = new CertificateBuilder().SetSubject("CN=Second").SetKeyPair(keys).Create();

        await Assert.That(() => keys.ExportParameters(false)).ThrowsNothing();
        await Assert.That(first.PublicKey.ExportSubjectPublicKeyInfo()).IsEquivalentTo(second.PublicKey.ExportSubjectPublicKeyInfo());
    }


    [Test]
    public async Task Build_ECDiffieHellmanCertificate_AssertsKeyAgreementAndCarriesAUsableKey()
    {
        using var issuer = BuildEcdhIssuer();

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.SMime)
            .SetSubject("CN=ECDH Subject")
            .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman())
            .SetIssuer(issuer)
            .Create();

        //An ECDH key agrees on a secret rather than signing, so digitalSignature must not be asserted
        await Assert.That(GetKeyUsages(cert))
            .IsEqualTo(X509KeyUsageFlags.KeyAgreement | X509KeyUsageFlags.NonRepudiation);
        await Assert.That(cert.GetKeyAlgorithm()).IsEqualTo(X9ObjectIdentifiers.IdECPublicKey.Id);
        await Assert.That(cert.IsIssuedBy(issuer, true)).IsTrue();

        //The attached key must survive as a working ECDH key, not merely be present
        await Assert.That(cert.HasPrivateKey).IsTrue();
        using var certKey = cert.GetECDiffieHellmanPrivateKey()!;
        using var otherParty = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var certPublic = cert.GetECDiffieHellmanPublicKey()!;

        var fromCert = certKey.DeriveKeyMaterial(otherParty.PublicKey);
        var fromOther = otherParty.DeriveKeyMaterial(certPublic.PublicKey);
        await Assert.That(fromCert).IsEquivalentTo(fromOther);
    }


    [Test]
    public async Task Build_ECDiffieHellmanCertificate_SelfSigned_Throws()
    {
        //Nothing in a self-signed build could produce the signature
        await Assert
            .That(() => new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman()).Validate())
            .ThrowsExactly<ArgumentException>();

        using var issuer = BuildEcdhIssuer();
        await Assert
            .That(() => new CertificateBuilder().SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman()).SetIssuer(issuer).Validate())
            .ThrowsNothing();
    }


    [Test]
    [Arguments(CertificateUsage.CA)]
    [Arguments(CertificateUsage.CodeSign)]
    [Arguments(CertificateUsage.OcspSigning)]
    [Arguments(CertificateUsage.TimeStamping)]
    public async Task Build_ECDiffieHellmanWithASigningUsage_Throws(CertificateUsage usage)
    {
        using var issuer = BuildEcdhIssuer();

        await Assert
            .That(() => new CertificateBuilder()
                .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman())
                .SetUsage(usage)
                .SetIssuer(issuer)
                .Validate())
            .ThrowsExactly<ArgumentException>();
    }


    [Test]
    [Arguments(CertificateUsage.Server)]
    [Arguments(CertificateUsage.Client)]
    [Arguments(CertificateUsage.SMime)]
    public async Task Build_ECDiffieHellmanWithAKeyAgreementUsage_IsAccepted(CertificateUsage usage)
    {
        using var issuer = BuildEcdhIssuer();

        using var cert = new CertificateBuilder()
            .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman())
            .SetUsage(usage)
            .SetSubject($"CN=ECDH {usage}")
            .SetIssuer(issuer)
            .Create();

        await Assert.That(GetKeyUsages(cert).HasFlag(X509KeyUsageFlags.KeyAgreement)).IsTrue();
        await Assert.That(GetKeyUsages(cert).HasFlag(X509KeyUsageFlags.DigitalSignature)).IsFalse();

        //keyEncipherment is key transport, which an EC key cannot do either
        await Assert.That(GetKeyUsages(cert).HasFlag(X509KeyUsageFlags.KeyEncipherment)).IsFalse();
    }


    [Test]
    public async Task Build_ECDiffieHellmanCertificate_FollowsASuppliedKeyPair()
    {
        using var issuer = BuildEcdhIssuer();
        using var keys = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetSubject("CN=Supplied ECDH Key")
            .SetKeyPair(keys)
            .SetIssuer(issuer)
            .Create();

        //The algorithm is taken from the key's runtime type, since its public half looks like ECDsa's
        await Assert.That(GetKeyUsages(cert)).IsEqualTo(X509KeyUsageFlags.KeyAgreement);
        using var certPublic = cert.GetECDiffieHellmanPublicKey()!;
        await Assert.That(certPublic.KeySize).IsEqualTo(384);
    }


    [Test]
    public async Task Curve_AppliesToGeneratedECDiffieHellmanKeys()
    {
        using var issuer = BuildEcdhIssuer();

        using var cert = new CertificateBuilder()
            .SetSubject("CN=ECDH P-521")
            .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman(ECCurve.NamedCurves.nistP521))
            .SetIssuer(issuer)
            .Create();

        using var certPublic = cert.GetECDiffieHellmanPublicKey()!;
        await Assert.That(certPublic.KeySize).IsEqualTo(521);
    }


    [Test]
    public async Task CreateCertificateSigningRequest_WithECDiffieHellman_Throws()
    {
        //A CSR is signed by the subject's own key, which an ECDH key cannot do
        using var keys = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        await Assert
            .That(() => new CertificateBuilder().SetSubject("CN=ECDH CSR").SetKeyPair(keys).CreateCertificateSigningRequest())
            .ThrowsExactly<NotSupportedException>();
    }


    [Test]
    public async Task CreateCertificateSigningRequest_WithECDiffieHellmanAndASignatureGenerator_Throws()
    {
        //A generator signs with some other key, so the proof-of-possession would be over a key the
        //request isn't asking to have certified
        using var keys = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var signingKey = RSA.Create(2048);
        var generator = X509SignatureGenerator.CreateForRSA(signingKey, RSASignaturePadding.Pkcs1);

        await Assert
            .That(() => new CertificateBuilder()
                .SetSubject("CN=ECDH CSR")
                .SetKeyPair(keys)
                .SetSignatureGenerator(generator)
                .CreateCertificateSigningRequest())
            .ThrowsExactly<NotSupportedException>();
    }


    [Test]
    public async Task CreateCertificateSigningRequest_WithAnECDiffieHellmanPublicKeyOnly_Throws()
    {
        //The key algorithm is the only thing that distinguishes ECDH here: the public key itself is
        //byte-identical to an ECDsa one
        using var keys = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var signingKey = RSA.Create(2048);
        var generator = X509SignatureGenerator.CreateForRSA(signingKey, RSASignaturePadding.Pkcs1);

        await Assert
            .That(() => new CertificateBuilder()
                .SetSubject("CN=ECDH CSR")
                .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman())
                .SetPublicKey(new PublicKey(keys))
                .SetSignatureGenerator(generator)
                .CreateCertificateSigningRequest())
            .ThrowsExactly<NotSupportedException>();
    }


    [Test]
    public async Task Build_ECDiffieHellmanSelfSignedWithASignatureGenerator_Throws()
    {
        //Signing a self-issued certificate with an unrelated key produces one whose signature can never
        //verify against its own subject key, so a generator is no substitute for an Issuer here
        using var keys = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var signingKey = RSA.Create(2048);
        var generator = X509SignatureGenerator.CreateForRSA(signingKey, RSASignaturePadding.Pkcs1);

        await Assert
            .That(() => new CertificateBuilder()
                .SetSubject("CN=ECDH Self-Signed")
                .SetKeyPair(keys)
                .SetSignatureGenerator(generator)
                .Validate())
            .ThrowsExactly<ArgumentException>();
    }


    [Test]
    public async Task Build_ECDiffieHellmanWithAnIssuerAndASignatureGenerator_IsAccepted()
    {
        //The HSM-held CA case stays open: the Issuer names who signed, the generator does the signing
        using var issuer = BuildEcdhIssuer();
        using var issuerKey = issuer.GetRSAPrivateKey()!;
        var generator = X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetSubject("CN=ECDH via HSM CA")
            .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman())
            .SetIssuer(issuer)
            .SetSignatureGenerator(generator)
            .Create();

        //verifySignature: the generator doing the signing is the whole point, so a name match is not enough
        await Assert.That(cert.IsIssuedBy(issuer, true)).IsTrue();
        await Assert.That(GetKeyUsages(cert)).IsEqualTo(X509KeyUsageFlags.KeyAgreement);
    }


    private static X509Certificate2 BuildEcdhIssuer()
        => new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=ECDH Test CA")
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .Create();


    [Test]
    public async Task CreateCertificateRequest_WithoutKeyPair_Throws()
        => await Assert
            .That(() => new CertificateBuilder().CreateCertificateRequest())
            .ThrowsExactly<ArgumentNullException>();


    [Test]
    public async Task Default_ForFamilyWithNoDefault_Throws()
        //An unknown algorithm can no longer be forged by casting an out-of-range value, so the remaining
        //boundary is a family the library has no default parameters for
        => await Assert
            .That(() => KeyAlgorithm.Default((KeyAlgorithmFamily)999))
            .ThrowsExactly<ArgumentOutOfRangeException>();


    [Test]
    public async Task Build_CallerSuppliedExtension_OverridesGeneratedOneWithSameOid()
    {
        //The builder de-duplicates extensions by OID, preferring the caller's own
        var basicConstraints = new X509BasicConstraintsExtension(true, true, 7, true);

        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetSubject(x => x.SetCommonName("Override Test"))
            .AddExtension(basicConstraints)
            .Create();

        var actual = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();

        await Assert.That(actual.CertificateAuthority).IsTrue();
        await Assert.That(actual.HasPathLengthConstraint).IsTrue();
        await Assert.That(actual.PathLengthConstraint).IsEqualTo(7);
    }


    [Test]
    public async Task CertificateSigningRequest_ToPemString_RoundTripsRawData()
    {
        using var keys = ECDsa.Create();
        var csr = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("CSR Pem Test"))
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        var pem = csr.ToPemString();

        await Assert.That(pem).Contains("-----BEGIN CERTIFICATE REQUEST-----");
        await Assert.That(pem).Contains("-----END CERTIFICATE REQUEST-----");

        var fields = PemEncoding.Find(pem);
        await Assert.That(pem[fields.Label].ToString()).IsEqualTo("CERTIFICATE REQUEST");

        var decoded = Convert.FromBase64String(pem[fields.Base64Data].ToString());
        await Assert.That(decoded).IsEquivalentTo(csr.GetRawData().ToArray(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task CertificateSigningRequest_ExportAsPem_WriterAndFileAgreeWithToPemString()
    {
        using var keys = ECDsa.Create();
        var csr = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("CSR Export Test"))
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();

        var expected = csr.ToPemString();

        var sw = new StringWriter();
        var returnedFromWriter = csr.ExportAsPem(sw);
        await Assert.That(sw.ToString()).IsEqualTo(expected);
        await Assert.That(returnedFromWriter).IsSameReferenceAs(csr);

        var path = Path.Combine(Path.GetTempPath(), $"csr-{Guid.NewGuid():N}.pem");
        try {
            var returnedFromFile = csr.ExportAsPem(path);
            await Assert.That(File.ReadAllText(path)).IsEqualTo(expected);
            await Assert.That(returnedFromFile).IsSameReferenceAs(csr);
        } finally {
            if (File.Exists(path)) File.Delete(path);
        }
    }


    [Test]
    [Arguments(0)]
    [Arguments(2)]
    public async Task Build_CACertificate_WithPathLength_ConstrainsTheChainDepth(int pathLength)
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("Path Length Test"))
            .SetPathLength(pathLength)
            .Create();

        var basicConstraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();

        await Assert.That(basicConstraints.CertificateAuthority).IsTrue();
        await Assert.That(basicConstraints.HasPathLengthConstraint).IsTrue();
        await Assert.That(basicConstraints.PathLengthConstraint).IsEqualTo(pathLength);
    }


    [Test]
    public async Task Build_CACertificate_WithoutPathLength_LeavesTheChainDepthUnconstrained()
    {
        //A path length of 0 and an absent one are different constraints, so the unset case must not encode as 0
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName("No Path Length Test"))
            .Create();

        var basicConstraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();

        await Assert.That(basicConstraints.CertificateAuthority).IsTrue();
        await Assert.That(basicConstraints.HasPathLengthConstraint).IsFalse();
    }


    [Test]
    public async Task Build_Certificate_WithSerialNumberGenerator_UsesTheGeneratedSerialNumber()
    {
        byte[] serialNumber = [0x4D, 0x58, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        var calls = 0;

        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("Serial Number Test"))
            .SetSerialNumberGenerator(() => {
                calls++;
                return serialNumber;
            })
            .Create();

        await Assert.That(cert.SerialNumber).IsEqualTo(Convert.ToHexString(serialNumber));
        await Assert.That(calls).IsEqualTo(1);
    }


    [Test]
    public async Task Build_Certificate_WithoutSerialNumberGenerator_GeneratesADistinctSerialNumberEachTime()
    {
        using var cert1 = new CertificateBuilder().SetSubject(x => x.SetCommonName("Default Serial Test")).Create();
        using var cert2 = new CertificateBuilder().SetSubject(x => x.SetCommonName("Default Serial Test")).Create();

        await Assert.That(cert1.SerialNumber).IsNotEqualTo(cert2.SerialNumber);
    }


    [Test]
    public async Task Build_RSACertificate_WithPssPadding_SignsWithRSASSAPSS()
    {
        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("RSA-PSS Test"))
            .SetKeyAlgorithm(KeyAlgorithm.RSA(2048))
            .SetRSASignaturePadding(RSASignaturePadding.Pss)
            .Create();

        await Assert.That(cert.SignatureAlgorithm.Value).IsEqualTo(PkcsObjectIdentifiers.IdRsassaPss.Id);
        await Assert.That(cert.IsSelfSigned(true)).IsTrue();
    }


    [Test]
    public async Task Build_RSACertificate_WithoutPaddingSpecified_SignsWithPkcs1()
    {
        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("RSA Default Padding Test"))
            .SetKeyAlgorithm(KeyAlgorithm.RSA(2048))
            .Create();

        await Assert.That(cert.SignatureAlgorithm.Value).IsEqualTo(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
        await Assert.That(cert.IsSelfSigned(true)).IsTrue();
    }


    [Test]
    public async Task Build_AddExtensions_AddsEveryExtensionGiven()
    {
        using var certFromParams = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("AddExtensions Params Test"))
            .AddExtensions(TestExtension(TestExtensionOid1), TestExtension(TestExtensionOid2))
            .Create();

        await Assert.That(GetExtensionOids(certFromParams)).Contains(TestExtensionOid1);
        await Assert.That(GetExtensionOids(certFromParams)).Contains(TestExtensionOid2);

        using var certFromEnumerable = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("AddExtensions Enumerable Test"))
            .AddExtension(TestExtension(TestExtensionOid1))
            .AddExtensions(new List<X509Extension> { TestExtension(TestExtensionOid2), TestExtension(TestExtensionOid3) })
            .Create();

        await Assert.That(GetExtensionOids(certFromEnumerable)).Contains(TestExtensionOid1);
        await Assert.That(GetExtensionOids(certFromEnumerable)).Contains(TestExtensionOid2);
        await Assert.That(GetExtensionOids(certFromEnumerable)).Contains(TestExtensionOid3);
    }


    [Test]
    public async Task Build_SetExtensions_DiscardsExtensionsAddedEarlier()
    {
        using var certFromParams = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("SetExtensions Params Test"))
            .AddExtension(TestExtension(TestExtensionOid1))
            .SetExtensions(TestExtension(TestExtensionOid2), TestExtension(TestExtensionOid3))
            .Create();

        await Assert.That(GetExtensionOids(certFromParams)).DoesNotContain(TestExtensionOid1);
        await Assert.That(GetExtensionOids(certFromParams)).Contains(TestExtensionOid2);
        await Assert.That(GetExtensionOids(certFromParams)).Contains(TestExtensionOid3);

        using var certFromEnumerable = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName("SetExtensions Enumerable Test"))
            .AddExtension(TestExtension(TestExtensionOid1))
            .SetExtensions(new List<X509Extension> { TestExtension(TestExtensionOid2) })
            .Create();

        await Assert.That(GetExtensionOids(certFromEnumerable)).DoesNotContain(TestExtensionOid1);
        await Assert.That(GetExtensionOids(certFromEnumerable)).Contains(TestExtensionOid2);
    }


    private const string TestExtensionOid1 = "1.3.6.1.4.1.99999.1";
    private const string TestExtensionOid2 = "1.3.6.1.4.1.99999.2";
    private const string TestExtensionOid3 = "1.3.6.1.4.1.99999.3";


    //DER NULL as the payload: an arbitrary OID carries no meaning to the platform, so any well-formed value does
    private static X509Extension TestExtension(string oid)
        => new(new Oid(oid), [0x05, 0x00], false);


    private static IEnumerable<string> GetExtensionOids(X509Certificate2 cert)
        => cert.Extensions.Select(x => x.Oid!.Value!);


    private static IEnumerable<string> GetEkuOids(X509Certificate2 cert)
        => cert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Single()
            .EnhancedKeyUsages
            .Cast<Oid>()
            .Select(x => x.Value!);


    private static X509KeyUsageFlags GetKeyUsages(X509Certificate2 cert)
        => cert.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages;


    private static X509Extension GetSanExtension(X509Certificate2 cert)
        => cert.Extensions.Single(x => x.Oid?.Value == "2.5.29.17");


    private static IEnumerable<Org.BouncyCastle.Asn1.X509.GeneralName> EnumerateNamesFromSan(X509Extension extension)
        => Asn1Sequence
            .GetInstance(extension.ConvertToBouncyCastle().GetParsedValue())
            .Select(Org.BouncyCastle.Asn1.X509.GeneralName.GetInstance);


    /// <summary>
    /// Stands in for a generator backed by a key this process cannot use directly (an HSM, TPM or cloud KMS),
    /// by delegating to a local one and counting the signatures it is asked for.
    /// </summary>
    private sealed class RecordingSignatureGenerator(X509SignatureGenerator inner) : X509SignatureGenerator
    {
        public int SignCount { get; private set; }

        protected override PublicKey BuildPublicKey()
            => inner.PublicKey;

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
            => inner.GetSignatureAlgorithmIdentifier(hashAlgorithm);

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            SignCount++;
            return inner.SignData(data, hashAlgorithm);
        }
    }
}
