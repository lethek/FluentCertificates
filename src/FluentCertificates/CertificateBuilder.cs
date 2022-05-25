using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Extensions;
using FluentCertificates.Internals;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using X509ExtensionBC = Org.BouncyCastle.Asn1.X509.X509Extension;


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
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;
    public RSASignaturePadding RSASignaturePadding { get; init; } = RSASignaturePadding.Pkcs1;
    public ImmutableHashSet<X509Extension> Extensions { get; init; } = ImmutableHashSet<X509Extension>.Empty.WithComparer(X509ExtensionOidEqualityComparer);


    private AsymmetricAlgorithm? KeyPair { get; init; }


    /// <summary>
    /// Creates a new instance of the CertificateBuilder class with default values.
    /// </summary>
    /// <returns>A new instance of the CertificateBuilder class with default values.</returns>
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

    public CertificateBuilder SetIssuer(X509Certificate2? value)
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

    public CertificateBuilder SetHashAlgorithm(HashAlgorithmName value)
        => this with { HashAlgorithm = value };

    public CertificateBuilder SetRSASignaturePadding(RSASignaturePadding value)
        => this with { RSASignaturePadding = value };

    public CertificateBuilder SetKeyPair(AsymmetricAlgorithm? value)
        => this with { KeyPair = value };

    public CertificateBuilder AddExtension(X509Extension extension)
        => this with { Extensions = Extensions.Add(extension) };

    public CertificateBuilder AddExtension(DerObjectIdentifier oid, X509ExtensionBC extension)
        => AddExtension(extension.ConvertToDotNet(oid));

    public CertificateBuilder AddExtensions(params X509Extension[] values)
        => this with { Extensions = Extensions.Union(values) };

    public CertificateBuilder AddExtensions(IEnumerable<X509Extension> values)
        => this with { Extensions = Extensions.Union(values) };

    public CertificateBuilder SetExtensions(params X509Extension[] values)
        => this with { Extensions = values.ToImmutableHashSet(X509ExtensionOidEqualityComparer) };

    public CertificateBuilder SetExtensions(IEnumerable<X509Extension> values)
        => this with { Extensions = values.ToImmutableHashSet(X509ExtensionOidEqualityComparer) };


    public void Validate()
    {
        if (KeyLength <= 0 && KeyPair == null) {
            throw new ArgumentException($"{nameof(KeyLength)} must be greater than zero", nameof(KeyLength));
        }

        if (NotBefore >= NotAfter) {
            throw new ArgumentException($"{nameof(NotBefore)} cannot be later than or equal to {nameof(NotAfter)}", nameof(NotAfter));
        }
    }


    public Pkcs10CertificationRequest ToCsr()
    {
        //TODO: replace this with a ToCertificateRequest() for native .NET; write CertificateRequest extension methods for exporting to PEM etc.
        var keypair = KeyPair ?? throw new ArgumentNullException(nameof(KeyPair), "Call SetKeyPair(key) first to provide a public/private keypair");
        var bouncyKeyPair = DotNetUtilities.GetKeyPair(keypair);
        var extensions = new X509Extensions(BuildExtensions(this).ToDictionary(x => x.Oid!, x => x.ConvertToBouncyCastle()));
        var attributes = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions)));
        var sigFactory = new Asn1SignatureFactory(GetSignatureAlgorithm(this).Id, bouncyKeyPair.Private);
        return new Pkcs10CertificationRequest(sigFactory, Subject, bouncyKeyPair.Public, attributes);
    }


    /// <summary>
    /// Builds an X509Certificate2 instance based on the parameters that have been set previously in the builder.
    /// </summary>
    /// <returns>An X509Certificate2 instance.</returns>
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    public X509Certificate2 Build()
    {
        Validate();

        //TODO: Add support for other key algorithms such as ECDsa
        var builder = KeyPair == null
            ? SetKeyPair(RSA.Create(KeyLength))
            : this;

        var keypair = (RSA)builder.KeyPair!;

        var csr = new CertificateRequest(builder.Subject.ToString(), keypair, builder.HashAlgorithm, builder.RSASignaturePadding);

        foreach (var extension in BuildExtensions(builder)) {
            csr.CertificateExtensions.Add(extension);
        }

        if (builder.Issuer != null) {
            csr.CertificateExtensions.Add(new X509AuthorityKeyIdentifierExtension(builder.Issuer, false));
        }

        var cert = builder.Issuer != null
            ? csr.Create(
                builder.Issuer,
                builder.NotBefore,
                builder.NotAfter,
                GenerateSerialNumber()
            )
            : csr.Create(
                new X500DistinguishedName(builder.Subject.ToString()),
                X509SignatureGenerator.CreateForRSA(keypair, builder.RSASignaturePadding),
                builder.NotBefore,
                builder.NotAfter,
                GenerateSerialNumber()
            );

        cert = builder.KeyPair switch {
            RSA rsa => cert.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => cert.CopyWithPrivateKey(ecdsa),
            DSA dsa => cert.CopyWithPrivateKey(dsa),
            _ => cert
        };

        if (!String.IsNullOrEmpty(builder.FriendlyName) && Tools.IsWindows) {
            //CopyWithPrivateKey doesn't copy FriendlyName so it needs to be set here after the copy is made
            cert.FriendlyName = builder.FriendlyName;
        }

        return cert;
    }


    /// <summary>
    /// Builds an X509Certificate2 instance based on the parameters that have been set previously in the builder. Uses a combination of BouncyCastle and system .NET methods.
    /// </summary>
    /// <returns>An X509Certificate2 instance.</returns>
    [Obsolete("Use the Build method instead.")]
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    internal X509Certificate2 BouncyBuild()
    {
        Validate();

        var builder = KeyPair == null
            ? SetKeyPair(RSA.Create(KeyLength))
            : this;

        var issuerCert = (builder.Issuer != null)
            ? DotNetUtilities.FromX509Certificate(builder.Issuer)
            : null;

        var bouncyKeyPair = DotNetUtilities.GetKeyPair(builder.KeyPair);

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(new BigInteger(GenerateSerialNumber()));
        generator.SetIssuerDN(issuerCert?.SubjectDN ?? builder.Subject);
        generator.SetSubjectDN(builder.Subject);
        generator.SetPublicKey(bouncyKeyPair?.Public);
        generator.SetNotBefore(builder.NotBefore.DateTime);
        generator.SetNotAfter(builder.NotAfter.DateTime);

        if (issuerCert != null) {
            generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuerCert.GetPublicKey()));
        }

        foreach (var extension in BuildExtensions(builder)) {
            generator.AddExtension(extension.Oid?.Value, extension.Critical, extension.ConvertToBouncyCastle().GetParsedValue());
        }

        //Create certificate
        var algorithm = GetSignatureAlgorithm(builder).Id;
        var cert = builder.Issuer != null
            ? generator.Generate(new Asn1SignatureFactory(algorithm, builder.Issuer.GetBouncyCastleRsaKeyPair().Private, Tools.SecureRandom))
            : generator.Generate(new Asn1SignatureFactory(algorithm, bouncyKeyPair?.Private, Tools.SecureRandom));

        //Place the certificate and private-key into a PKCS12 store
        var store = new Pkcs12Store();
        var certEntry = new X509CertificateEntry(cert);
        store.SetCertificateEntry(cert.SerialNumber.ToString(), certEntry);
        store.SetKeyEntry(cert.SerialNumber.ToString(), new AsymmetricKeyEntry(bouncyKeyPair?.Private), new[] { certEntry });

        //Finally copy the PKCS12 store to a .NET X509Certificate2 structure to return
        using var pfxStream = new MemoryStream();
        var pwd = Tools.CreateRandomCharArray(20);
        store.Save(pfxStream, pwd, Tools.SecureRandom);
        pfxStream.Seek(0, SeekOrigin.Begin);
        var newCert = new X509Certificate2(pfxStream.ToArray(), new string(pwd), X509KeyStorageFlags.Exportable);
        if (!String.IsNullOrEmpty(builder.FriendlyName) && Tools.IsWindows) {
            newCert.FriendlyName = builder.FriendlyName;
        }

        return newCert;
    }


    private static ImmutableHashSet<X509Extension> BuildExtensions(CertificateBuilder builder)
    {
        //Setup default extensions based on selected certificate Usage
        var extensions = GetCommonExtensions(builder);
        extensions.AddRange(builder.Usage switch {
            null => new List<X509Extension>(),
            CertificateUsage.CA => GetCaExtensions(builder),
            CertificateUsage.Server => GetServerExtensions(builder),
            CertificateUsage.Client => GetClientExtensions(builder),
            CertificateUsage.CodeSign => GetCodeSigningExtensions(builder),
            CertificateUsage.SMime => GetSMimeExtensions(builder),
            _ => throw new NotImplementedException($"{builder.Usage} {nameof(Usage)} not yet implemented")
        });

        //Setup extension for Subject Alternative Name if necessary
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var dnsName in builder.DnsNames) {
            sanBuilder.AddDnsName(dnsName);
        }
        if (!String.IsNullOrEmpty(builder.Email)) {
            sanBuilder.AddEmailAddress(builder.Email);
        }
        if (builder.DnsNames.Any() || !String.IsNullOrEmpty(builder.Email)) {
            extensions.Add(sanBuilder.Build());
        }

        //Collate extensions; manually specified ones override those matching ones generated above (e.g. Usage, DnsNames, Email, etc.)
        return extensions.Any()
            ? builder.Extensions.Union(extensions)
            : builder.Extensions;
    }


    private static List<X509Extension> GetCommonExtensions(CertificateBuilder builder)
        => new() {
            new X509ExtensionBC(false, new DerOctetString(new SubjectKeyIdentifierStructure(DotNetUtilities.GetKeyPair(builder.KeyPair).Public)))
                .ConvertToDotNet(X509Extensions.SubjectKeyIdentifier)
        };


    private static List<X509Extension> GetCaExtensions(CertificateBuilder builder)
        => new() {
            new X509BasicConstraintsExtension(true, builder.PathLength.HasValue, builder.PathLength ?? 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true),
        };


    private static List<X509Extension> GetServerExtensions(CertificateBuilder builder)
        => new() {
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(KeyPurposeID.IdKPServerAuth.Id) }, false),
        };


    private static List<X509Extension> GetClientExtensions(CertificateBuilder builder)
        => new() {
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(KeyPurposeID.IdKPClientAuth.Id) }, false),
        };


    private static List<X509Extension> GetCodeSigningExtensions(CertificateBuilder builder)
        => new() {
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true),
            new X509EnhancedKeyUsageExtension(new OidCollection {
                new(KeyPurposeID.IdKPCodeSigning.Id),
                new(KeyPurposeID.IdKPTimeStamping.Id),
                new("1.3.6.1.4.1.311.10.3.13") //Used by Microsoft Authenticode to limit the signature's lifetime to the certificate's expiration
            }, false),
        };


    private static List<X509Extension> GetSMimeExtensions(CertificateBuilder builder)
        => new() {
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.NonRepudiation, true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(KeyPurposeID.IdKPEmailProtection.Id) }, false),
        };


    private static byte[] GenerateSerialNumber()
    {
        Span<byte> span = stackalloc byte[18];

        BinaryPrimitives.WriteInt16BigEndian(span[0..2], 0x4D58);
        BinaryPrimitives.WriteInt64BigEndian(span[2..10], DateTime.UtcNow.Ticks);
        BinaryPrimitives.WriteInt64BigEndian(span[10..18], Tools.SecureRandom.NextLong());
        return span.ToArray();
    }


    private static DerObjectIdentifier GetSignatureAlgorithm(CertificateBuilder builder)
        => builder.HashAlgorithm.Name switch {
            nameof(HashAlgorithmName.MD5) => PkcsObjectIdentifiers.MD5WithRsaEncryption,
            nameof(HashAlgorithmName.SHA1) => PkcsObjectIdentifiers.Sha1WithRsaEncryption,
            nameof(HashAlgorithmName.SHA256) => PkcsObjectIdentifiers.Sha256WithRsaEncryption,
            nameof(HashAlgorithmName.SHA384) => PkcsObjectIdentifiers.Sha384WithRsaEncryption,
            nameof(HashAlgorithmName.SHA512) => PkcsObjectIdentifiers.Sha512WithRsaEncryption,
            _ => throw new NotSupportedException($"Specified {nameof(HashAlgorithm)} {builder.HashAlgorithm} is not supported.")
        };


    private static readonly X509Name EmptyName = new X509NameBuilder();
    private static readonly X509ExtensionOidEqualityComparer X509ExtensionOidEqualityComparer = new();
}
