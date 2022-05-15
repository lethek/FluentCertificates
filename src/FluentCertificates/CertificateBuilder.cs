using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
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


    private AsymmetricCipherKeyPair? KeyPair { get; init; }


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
        => this with { KeyPair = DotNetUtilities.GetKeyPair(value) };

    public CertificateBuilder SetKeyPair(AsymmetricCipherKeyPair? value)
        => this with { KeyPair = value };

    public CertificateBuilder AddExtension(DerObjectIdentifier oid, Org.BouncyCastle.Asn1.X509.X509Extension extension)
        => AddExtension(new X509ExtensionItem(oid, extension));

    public CertificateBuilder AddExtension(X509ExtensionItem extension)
        => this with { Extensions = Extensions.Add(extension) };

    public CertificateBuilder AddExtensions(IEnumerable<X509ExtensionItem> values)
        => this with { Extensions = Extensions.Union(values) };

    public CertificateBuilder SetExtensions(IEnumerable<X509ExtensionItem> values)
        => this with { Extensions = values.ToImmutableHashSet(X509ExtensionItem.OidEqualityComparer) };


    public X509Certificate2 Build()
        => CreateCertificate(this);


    public Pkcs10CertificationRequest ToCsr()
    {
        var keypair = KeyPair ?? throw new ArgumentNullException(nameof(KeyPair), "Call SetKeyPair(key) first to create a private/public keypair");
        var extensions = new X509Extensions(BuildExtensions(this).ToDictionary(x => x.Oid, x => x.Extension));
        var attributes = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions)));
        var sigFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, keypair.Private);
        return new Pkcs10CertificationRequest(sigFactory, this.Subject, keypair.Public, attributes);
    }


    public void Validate()
        => Validate(this);


    private static void Validate(CertificateBuilder options)
    {
        if (options.KeyLength <= 0) throw new ArgumentException($"{nameof(KeyLength)} must be greater than zero", nameof(KeyLength));
        if (options.NotBefore >= options.NotAfter) throw new ArgumentException($"{nameof(NotBefore)} cannot be later than or equal to {nameof(NotAfter)}", nameof(NotAfter));
    }

    public static List<X509ExtensionItem> GetCommonExtensions(CertificateBuilder options)
        => new() {
            new X509ExtensionItem(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(options.KeyPair.Public))
        };


    private static List<X509ExtensionItem> GetCaExtensions(CertificateBuilder options)
        => new() {
            new (X509Extensions.BasicConstraints, true, options.PathLength.HasValue ? new BasicConstraints(options.PathLength.Value) : new BasicConstraints(true)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign))
        };


    private static List<X509ExtensionItem> GetServerExtensions(CertificateBuilder options)
        => new() {
            new (X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)),
            new (X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth)),
        };


    private static List<X509ExtensionItem> GetClientExtensions(CertificateBuilder options)
        => new() {
            new (X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature)),
            new (X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth)),
        };


    private static List<X509ExtensionItem> GetCodeSigningExtensions(CertificateBuilder options)
        => new() {
            new (X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)),
            new (X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(new DerSequence(
                KeyPurposeID.IdKPCodeSigning,
                KeyPurposeID.IdKPTimeStamping,
                new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.13")
            ))),
        };


    private static ImmutableHashSet<X509ExtensionItem> BuildExtensions(CertificateBuilder options)
    {
        //Setup default extensions based on selected certificate Usage
        var extensions = GetCommonExtensions(options);
        extensions.AddRange(options.Usage switch {
            null => new List<X509ExtensionItem>(),
            CertificateUsage.CA => GetCaExtensions(options),
            CertificateUsage.Server => GetServerExtensions(options),
            CertificateUsage.Client => GetClientExtensions(options),
            CertificateUsage.CodeSign => GetCodeSigningExtensions(options),
            _ => throw new NotSupportedException($"{options.Usage} {nameof(Usage)} not yet supported")
        });

        //Setup extension for Subject Alternative Name if necessary
        var sanGeneralNames = new List<GeneralName>();
        if (options.DnsNames.Any()) {
            sanGeneralNames.AddRange(options.DnsNames.Select(dnsName => new GeneralName(GeneralName.DnsName, dnsName)));
        }
        if (!String.IsNullOrEmpty(options.Email)) {
            sanGeneralNames.Add(new GeneralName(GeneralName.Rfc822Name, options.Email));
        }
        if (sanGeneralNames.Any()) {
            extensions.Add(new(X509Extensions.SubjectAlternativeName, false, new GeneralNames(sanGeneralNames.ToArray())));
        }

        //Collate extensions; manually specified ones take precedence over those generated from other builder properties (e.g. Usage, DnsNames, Email)
        return extensions.Any()
            ? options.Extensions.Union(extensions)
            : options.Extensions;
    }


    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    private static X509Certificate2 CreateCertificate(CertificateBuilder options)
    {
        var builder = options.SetKeyPair(options.KeyPair ?? GenerateRsaKeyPair(options.KeyLength));

        Validate(builder);

        var issuerCert = (builder.Issuer != null)
            ? DotNetUtilities.FromX509Certificate(builder.Issuer)
            : null;

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(GenerateSerialNumber());
        generator.SetIssuerDN(issuerCert?.SubjectDN ?? builder.Subject);
        generator.SetSubjectDN(builder.Subject);
        generator.SetPublicKey(builder.KeyPair?.Public);
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
            : generator.Generate(new Asn1SignatureFactory(algorithm, builder.KeyPair?.Private, InternalTools.SecureRandom));

        //Place the certificate and private-key into a PKCS12 store
        var store = new Pkcs12Store();
        var certEntry = new X509CertificateEntry(cert);
        store.SetCertificateEntry(cert.SerialNumber.ToString(), certEntry);
        store.SetKeyEntry(cert.SerialNumber.ToString(), new AsymmetricKeyEntry(builder.KeyPair?.Private), new[] { certEntry });

        //Finally copy the PKCS12 store to a .NET X509Certificate2 structure to return
        using var pfxStream = new MemoryStream();
        var pwd = InternalTools.CreateRandomCharArray(20);
        store.Save(pfxStream, pwd, InternalTools.SecureRandom);
        pfxStream.Seek(0, SeekOrigin.Begin);
        var newCert = new X509Certificate2(pfxStream.ToArray(), new String(pwd), X509KeyStorageFlags.Exportable);
        if (builder.FriendlyName != null && IsWindows()) {
            newCert.FriendlyName = builder.FriendlyName;
        }

        return newCert;
    }


    private static bool IsWindows()
#if NET5_0_OR_GREATER
        => OperatingSystem.IsWindows();
#else
        => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
#endif


    private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
    {
        var key = RSA.Create(length);
        return DotNetUtilities.GetKeyPair(key);
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