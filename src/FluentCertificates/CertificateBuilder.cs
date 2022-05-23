using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
#if !NET5_0_OR_GREATER
using System.Runtime.InteropServices;
#endif
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Extensions;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509;

namespace FluentCertificates;

public record CertificateBuilder
{
    public CertificateUsage? Usage { get; init; }
    public int KeyLength { get; init; } = 2048;
    public int? PathLength { get; init; }
    public DateTimeOffset NotBefore { get; init; } = DateTimeOffset.UtcNow.AddHours(-1);
    public DateTimeOffset NotAfter { get; init; } = DateTimeOffset.UtcNow.AddHours(1);
    public X509Name Subject { get; init; } = EmptyName;
    public X509Certificate2? Issuer { get; init; }
    public string[] DnsNames { get; init; } = Array.Empty<string>();
    public string? FriendlyName { get; init; }
    public string? Email { get; init; }
    public ImmutableHashSet<X509ExtensionItem> Extensions { get; init; } = ImmutableHashSet<X509ExtensionItem>.Empty.WithComparer(X509ExtensionItem.OidEqualityComparer);


    private AsymmetricAlgorithm? KeyPair { get; init; }


    public static CertificateBuilder Create()
        => new();


    public CertificateBuilder SetUsage(CertificateUsage value)
        => this with { Usage = value };

    public CertificateBuilder SetKeyLength(int value)
        => this with { KeyLength = value };

    public CertificateBuilder SetNotBefore(DateTimeOffset value)
        => this with { NotBefore = value };

    public CertificateBuilder SetNotAfter(DateTimeOffset value)
        => this with { NotAfter = value };

    public CertificateBuilder SetSubject(X509Name value)
        => this with { Subject = value };

    public CertificateBuilder SetIssuer(X509Certificate2 value)
        => this with { Issuer = value };

    public CertificateBuilder SetDnsNames(IEnumerable<string> values)
        => this with { DnsNames = values.ToArray() };

    public CertificateBuilder SetDnsNames(params string[] values)
        => this with { DnsNames = values.ToArray() };

    public CertificateBuilder SetFriendlyName(string value)
        => this with { FriendlyName = value };

    public CertificateBuilder SetEmail(string value)
        => this with { Email = value };

    public CertificateBuilder SetPathLength(int? value)
        => this with { PathLength = value };

    public CertificateBuilder SetKeyPair(AsymmetricAlgorithm? value)
        => this with { KeyPair = value };

    public CertificateBuilder AddExtension(DerObjectIdentifier oid, Org.BouncyCastle.Asn1.X509.X509Extension extension)
        => AddExtension(new X509ExtensionItem(oid, extension));

    public CertificateBuilder AddExtension(X509ExtensionItem extension)
        => this with { Extensions = Extensions.Add(extension) };

    public CertificateBuilder AddExtensions(IEnumerable<X509ExtensionItem> values)
        => this with { Extensions = Extensions.Union(values) };

    public CertificateBuilder SetExtensions(IEnumerable<X509ExtensionItem> values)
        => this with { Extensions = values.ToImmutableHashSet(X509ExtensionItem.OidEqualityComparer) };


    public void Validate()
    {
        if (KeyLength <= 0 && KeyPair == null) throw new ArgumentException($"{nameof(KeyLength)} must be greater than zero", nameof(KeyLength));
        if (NotBefore >= NotAfter) throw new ArgumentException($"{nameof(NotBefore)} cannot be later than or equal to {nameof(NotAfter)}", nameof(NotAfter));
    }


    public Pkcs10CertificationRequest ToCsr()
    {
        var keypair = KeyPair ?? throw new ArgumentNullException(nameof(KeyPair), "Call SetKeyPair(key) first to provide a public/private keypair");
        var bouncyKeyPair = DotNetUtilities.GetKeyPair(keypair);
        var extensions = new X509Extensions(BuildExtensions(this).ToDictionary(x => x.Oid, x => x.Extension));
        var attributes = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions)));
        var sigFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, bouncyKeyPair.Private);
        return new Pkcs10CertificationRequest(sigFactory, Subject, bouncyKeyPair.Public, attributes);
    }


    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    public X509Certificate2 Build()
    {
        Validate();

        var builder = KeyPair == null
            ? SetKeyPair(GenerateRsaKeyPair(KeyLength))
            : this;

        var keypair = (RSA)builder.KeyPair!;
        
        var csr = new CertificateRequest(builder.Subject.ToString(), keypair, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        foreach (var item in BuildExtensions(builder)) {
            csr.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension(
                item.Oid.Id, item.Extension.Value.GetOctets(), item.Extension.IsCritical
            ));
        }

        if (builder.Issuer != null) {
            csr.CertificateExtensions.Add(new X509AuthorityKeyIdentifierExtension(builder.Issuer, false));
        }

        var cert = builder.Issuer != null
            ? csr.Create(
                builder.Issuer,
                builder.NotBefore,
                builder.NotAfter,
                GenerateSerialNumber().ToByteArray()
            )
            : csr.Create(
                new X500DistinguishedName(builder.Subject.ToString()),
                X509SignatureGenerator.CreateForRSA(keypair, RSASignaturePadding.Pkcs1),
                builder.NotBefore,
                builder.NotAfter,
                GenerateSerialNumber().ToByteArray()
            );

        if (!String.IsNullOrEmpty(builder.FriendlyName) && IsWindows()) {
            cert.FriendlyName = builder.FriendlyName;
        }

        return builder.KeyPair switch {
            RSA rsa => cert.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => cert.CopyWithPrivateKey(ecdsa),
            DSA dsa => cert.CopyWithPrivateKey(dsa),
            _ => cert
        };
    }


    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    public X509Certificate2 BouncyBuild()
    {
        Validate();

        var builder = KeyPair == null
            ? SetKeyPair(GenerateRsaKeyPair(KeyLength))
            : this;

        var issuerCert = (builder.Issuer != null)
            ? DotNetUtilities.FromX509Certificate(builder.Issuer)
            : null;

        var bouncyKeyPair = DotNetUtilities.GetKeyPair(builder.KeyPair);

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(GenerateSerialNumber());
        generator.SetIssuerDN(issuerCert?.SubjectDN ?? builder.Subject);
        generator.SetSubjectDN(builder.Subject);
        generator.SetPublicKey(bouncyKeyPair?.Public);
        generator.SetNotBefore(builder.NotBefore.DateTime);
        generator.SetNotAfter(builder.NotAfter.DateTime);

        if (issuerCert != null) {
            generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuerCert.GetPublicKey()));
        }

        foreach (var extension in BuildExtensions(builder)) {
            generator.AddExtension(extension.Oid, extension.Extension.IsCritical, extension.Extension.GetParsedValue());
        }

        //Create certificate
        var algorithm = PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString();
        var cert = builder.Issuer != null
            ? generator.Generate(new Asn1SignatureFactory(algorithm, builder.Issuer.GetBouncyCastleRsaKeyPair().Private, InternalTools.SecureRandom))
            : generator.Generate(new Asn1SignatureFactory(algorithm, bouncyKeyPair?.Private, InternalTools.SecureRandom));

        //Place the certificate and private-key into a PKCS12 store
        var store = new Pkcs12Store();
        var certEntry = new X509CertificateEntry(cert);
        store.SetCertificateEntry(cert.SerialNumber.ToString(), certEntry);
        store.SetKeyEntry(cert.SerialNumber.ToString(), new AsymmetricKeyEntry(bouncyKeyPair?.Private), new[] { certEntry });

        //Finally copy the PKCS12 store to a .NET X509Certificate2 structure to return
        using var pfxStream = new MemoryStream();
        var pwd = InternalTools.CreateRandomCharArray(20);
        store.Save(pfxStream, pwd, InternalTools.SecureRandom);
        pfxStream.Seek(0, SeekOrigin.Begin);
        var newCert = new X509Certificate2(pfxStream.ToArray(), new String(pwd), X509KeyStorageFlags.Exportable);
        if (!String.IsNullOrEmpty(builder.FriendlyName) && IsWindows()) {
            newCert.FriendlyName = builder.FriendlyName;
        }

        return newCert;
    }


    private static ImmutableHashSet<X509ExtensionItem> BuildExtensions(CertificateBuilder builder)
    {
        //Setup default extensions based on selected certificate Usage
        var extensions = GetCommonExtensions(builder);
        extensions.AddRange(builder.Usage switch {
            null => new List<X509ExtensionItem>(),
            CertificateUsage.CA => GetCaExtensions(builder),
            CertificateUsage.Server => GetServerExtensions(builder),
            CertificateUsage.Client => GetClientExtensions(builder),
            CertificateUsage.CodeSign => GetCodeSigningExtensions(builder),
            CertificateUsage.SMime => GetSMimeExtensions(builder),
            _ => throw new NotSupportedException($"{builder.Usage} {nameof(Usage)} not yet supported")
        });

        //Setup extension for Subject Alternative Name if necessary
        var sanGeneralNames = new List<GeneralName>();
        if (builder.DnsNames.Any()) {
            sanGeneralNames.AddRange(builder.DnsNames.Select(dnsName => new GeneralName(GeneralName.DnsName, dnsName)));
        }
        if (!String.IsNullOrEmpty(builder.Email)) {
            sanGeneralNames.Add(new GeneralName(GeneralName.Rfc822Name, builder.Email));
        }
        if (sanGeneralNames.Any()) {
            extensions.Add(new(X509Extensions.SubjectAlternativeName, false, new GeneralNames(sanGeneralNames.ToArray())));
        }

        //Collate extensions; manually specified ones take precedence over those generated from other builder properties (e.g. Usage, DnsNames, Email)
        return extensions.Any()
            ? builder.Extensions.Union(extensions)
            : builder.Extensions;
    }


    private static List<X509ExtensionItem> GetCommonExtensions(CertificateBuilder builder)
        => new() {
            new X509ExtensionItem(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(DotNetUtilities.GetKeyPair(builder.KeyPair)?.Public)),
        };


    private static List<X509ExtensionItem> GetCaExtensions(CertificateBuilder builder)
        => new() {
            new (X509Extensions.BasicConstraints, true, builder.PathLength.HasValue ? new BasicConstraints(builder.PathLength.Value) : new BasicConstraints(true)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign)),
        };


    private static List<X509ExtensionItem> GetServerExtensions(CertificateBuilder builder)
        => new() {
            new (X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)),
            new (X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth)),
        };


    private static List<X509ExtensionItem> GetClientExtensions(CertificateBuilder builder)
        => new() {
            new (X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature)),
            new (X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth)),
        };


    private static List<X509ExtensionItem> GetCodeSigningExtensions(CertificateBuilder builder)
        => new() {
            new (X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)),
            new (X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(new DerSequence(
                KeyPurposeID.IdKPCodeSigning,
                KeyPurposeID.IdKPTimeStamping,
                new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.13")
            ))),
        };

    private static List<X509ExtensionItem> GetSMimeExtensions(CertificateBuilder builder)
        => new() {
            new(X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.NonRepudiation | KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)),
            new(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection)),
        };


    private static bool IsWindows()
#if NET5_0_OR_GREATER
        => OperatingSystem.IsWindows();
#else
        => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
#endif


    private static AsymmetricAlgorithm GenerateRsaKeyPair(int length)
    {
        var key = RSA.Create(length);
        return key;

        //return DotNetUtilities.GetKeyPair(key);

        //var parameters = new KeyGenerationParameters(InternalTools.SecureRandom, length);
        //var generator = new RsaKeyPairGenerator();
        //generator.Init(parameters);
        //return generator.GenerateKeyPair();
    }


    private static AsymmetricCipherKeyPair GenerateEcKeyPair(string curveName)
    {
        var ecParam = SecNamedCurves.GetByName(curveName);
        var ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N);
        var parameters = new ECKeyGenerationParameters(ecDomain, InternalTools.SecureRandom);
        var generator = new ECKeyPairGenerator();
        generator.Init(parameters);
        return generator.GenerateKeyPair();
    }


    private static BigInteger GenerateSerialNumber()
    {
        Span<byte> span = stackalloc byte[18];
        BinaryPrimitives.WriteInt16BigEndian(span.Slice(0, 2), 0x4D58);
        BinaryPrimitives.WriteInt64BigEndian(span.Slice(2, 8), DateTime.UtcNow.Ticks);
        BinaryPrimitives.WriteInt64BigEndian(span.Slice(10, 8), InternalTools.SecureRandom.NextLong());
        return new BigInteger(span.ToArray());
    }


    private static readonly X509Name EmptyName = new X509NameBuilder();
}