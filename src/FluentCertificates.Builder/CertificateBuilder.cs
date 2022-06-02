using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics;
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
using Org.BouncyCastle.Crypto;


namespace FluentCertificates;

public partial record CertificateBuilder
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


    /// <summary>
    /// Build a CertificateRequest based on the parameters that have been set previously in the builder.
    /// </summary>
    /// <returns>A CertificateRequest instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when the SetKeyPair(AsymmetricAlgorithm) method has not been called.</exception>
    public CertificateRequest ToCertificateRequest()
    {
        var dn = new X500DistinguishedName(Subject.ToString());

        var request = KeyPair switch {
            RSA rsa => new CertificateRequest(dn, rsa, HashAlgorithm, RSASignaturePadding),
            ECDsa ecdsa => new CertificateRequest(dn, ecdsa, HashAlgorithm),
            null => throw new ArgumentNullException(nameof(KeyPair), $"Call {nameof(SetKeyPair)}(...) first to provide a public/private keypair"),
            _ => throw new NotSupportedException($"Unsupported {nameof(KeyPair)} algorithm: {KeyPair.SignatureAlgorithm}")
        };

        foreach (var extension in BuildExtensions(this, request)) {
            request.CertificateExtensions.Add(extension);
        }

        if (Issuer != null) {
            request.CertificateExtensions.Add(new X509AuthorityKeyIdentifierExtension(Issuer, false));
        }

        return request;
    }


    /// <summary>
    /// Builds an X509Certificate2 instance based on the parameters that have been set previously in the builder.
    /// </summary>
    /// <returns>An X509Certificate2 instance.</returns>
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    public X509Certificate2 Build()
    {
        Validate();

        var builder = KeyPair == null
            ? SetKeyPair(RSA.Create(KeyLength))
            : this;

        Debug.Assert(builder.KeyPair != null);

        var request = builder.ToCertificateRequest();

        var cert = builder.Issuer != null
            ? request.Create(
                builder.Issuer,
                builder.NotBefore,
                builder.NotAfter,
                builder.GenerateSerialNumber()
            )
            : request.Create(
                new X500DistinguishedName(builder.Subject.ToString()),
                builder.CreateSignatureGenerator(),
                builder.NotBefore,
                builder.NotAfter,
                builder.GenerateSerialNumber()
            );

        cert = builder.KeyPair switch {
            DSA dsa => cert.CopyWithPrivateKey(dsa),
            RSA rsa => cert.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => cert.CopyWithPrivateKey(ecdsa),
            _ => cert
        };

        if (!String.IsNullOrEmpty(builder.FriendlyName) && Tools.IsWindows) {
            //CopyWithPrivateKey doesn't copy FriendlyName so it needs to be set here after the copy is made
            cert.FriendlyName = builder.FriendlyName;
        }

        return cert;
    }


    private byte[] GenerateSerialNumber()
    {
        Span<byte> span = stackalloc byte[18];
        BinaryPrimitives.WriteInt16BigEndian(span[0..2], 0x4D58);
        BinaryPrimitives.WriteInt64BigEndian(span[2..10], DateTime.UtcNow.Ticks);
        BinaryPrimitives.WriteInt64BigEndian(span[10..18], Tools.SecureRandom.NextLong());
        return span.ToArray();
    }


    private X509SignatureGenerator CreateSignatureGenerator()
        => KeyPair switch {
            DSA dsa => new DSAX509SignatureGenerator(dsa),
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            null => throw new ArgumentNullException(nameof(KeyPair), $"Call {nameof(SetKeyPair)}(...) first to provide a public/private keypair"),
            _ => throw new NotSupportedException($"Unsupported {nameof(KeyPair)} algorithm: {KeyPair.SignatureAlgorithm}")
        };


    private static ImmutableHashSet<X509Extension> BuildExtensions(CertificateBuilder builder, CertificateRequest? req)
    {
        //Setup default extensions based on selected certificate Usage
        var extensions = GetCommonExtensions(builder, req);
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


    private static List<X509Extension> GetCommonExtensions(CertificateBuilder builder, CertificateRequest? req)
        => new() {
            (req != null)
                ? new X509SubjectKeyIdentifierExtension(req.PublicKey, false)
                #if NET6_0_OR_GREATER
                : new X509SubjectKeyIdentifierExtension(new PublicKey(builder.KeyPair!), false)
                #else
                : new X509ExtensionBC(false, new DerOctetString(new SubjectKeyIdentifierStructure(DotNetUtilities.GetKeyPair(builder.KeyPair).Public)))
                    .ConvertToDotNet(X509Extensions.SubjectKeyIdentifier)
                #endif
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
