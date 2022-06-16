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
#if !NET6_0_OR_GREATER
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
#endif

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using X509ExtensionBC = Org.BouncyCastle.Asn1.X509.X509Extension;


namespace FluentCertificates;

public partial record CertificateBuilder
{
    public CertificateUsage? Usage { get; init; }
    public int? KeyLength { get; init; }
    public int? PathLength { get; init; }
    public DateTimeOffset NotBefore { get; init; } = DateTimeOffset.UtcNow.AddHours(-1);
    public DateTimeOffset NotAfter { get; init; } = DateTimeOffset.UtcNow.AddHours(1);
    public X500NameBuilder Subject { get; init; } = EmptyNameBuilder;
    public X509Certificate2? Issuer { get; init; }
    public string[] DnsNames { get; init; } = Array.Empty<string>();
    public string? FriendlyName { get; init; }
    public string? Email { get; init; }
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;
    public RSASignaturePadding RSASignaturePadding { get; init; } = RSASignaturePadding.Pkcs1;
    public ImmutableHashSet<X509Extension> Extensions { get; init; } = ImmutableHashSet<X509Extension>.Empty.WithComparer(X509ExtensionOidEqualityComparer);


    private AsymmetricAlgorithm? KeyPair { get; init; }


    /// <summary>
    /// Use this for a quick and easy way to set some appropriate default extensions for the 
    /// </summary>
    /// <param name="value">What the certificate's primary purpose will be.</param>
    /// <returns>A new instance of CertificateBuilder with the specified Usage set.</returns>
    public CertificateBuilder SetUsage(CertificateUsage value)
        => this with { Usage = value };

    /// <summary>
    /// Sets the KeyLength for generating new keys. Default is 4096 bits for RSA and is 2048 for DSA. KeyLength is ignored when generating ECDsa keys. 
    /// </summary>
    /// <param name="value"></param>
    /// <returns>A new instance of CertificateBuilder with the specified KeyLength set.</returns>
    public CertificateBuilder SetKeyLength(int? value)
        => this with { KeyLength = value };

    /// <summary>
    /// Sets the certificate's validity period to begin from the specified timestamp. Default value is 1 hour ago.
    /// </summary>
    /// <param name="value"></param>
    /// <returns>A new instance of CertificateBuilder with the specified NotBefore set.</returns>
    public CertificateBuilder SetNotBefore(DateTimeOffset value)
        => this with { NotBefore = value };

    /// <summary>
    /// Sets the certificate's validity period to end at the specified timestamp. Default value is 1 hour in the future.
    /// </summary>
    /// <param name="value"></param>
    /// <returns>A new instance of CertificateBuilder with the specified NotAfter set.</returns>
    public CertificateBuilder SetNotAfter(DateTimeOffset value)
        => this with { NotAfter = value };

    public CertificateBuilder SetSubject(X500NameBuilder value)
        => this with { Subject = value };

    public CertificateBuilder SetSubject(X509Name value)
        => this with { Subject = new X500NameBuilder(value) };

    public CertificateBuilder SetSubject(X500DistinguishedName value)
        => this with { Subject = new X500NameBuilder(value) };

    public CertificateBuilder SetSubject(string value)
        => this with { Subject = new X500NameBuilder(value) };

    public CertificateBuilder SetSubject(Func<X500NameBuilder, X500NameBuilder> func)
        => this with { Subject = func(Subject) };

    public CertificateBuilder SetIssuer(X509Certificate2? value)
        => this with { Issuer = value };

    public CertificateBuilder SetDnsNames(IEnumerable<string> values)
        => this with { DnsNames = values.ToArray() };

    public CertificateBuilder SetDnsNames(params string[] values)
        => this with { DnsNames = values.ToArray() };

    /// <summary>
    /// Use to set a FriendlyName for the certificate. This feature is only supported on Windows and will be ignored on all other platforms.
    /// </summary>
    /// <param name="value"></param>
    /// <returns>A new instance of CertificateBuilder with the specified FriendlyName set.</returns>
    public CertificateBuilder SetFriendlyName(string value)
        => this with { FriendlyName = value };

    public CertificateBuilder SetEmail(string value)
        => this with { Email = value };

    public CertificateBuilder SetPathLength(int? value)
        => this with { PathLength = value };

    /// <summary>
    /// Use to change the hashing algorithm. Default is SHA256.
    /// </summary>
    /// <param name="value"></param>
    /// <returns>A new instance of CertificateBuilder with the specified HashAlgorithm set.</returns>
    public CertificateBuilder SetHashAlgorithm(HashAlgorithmName value)
        => this with { HashAlgorithm = value };

    /// <summary>
    /// Use to change the the padding algorithm for RSA signatures. Default is PKCS1. This is ignored when using other key algorithms (ECDsa/DSA).
    /// </summary>
    /// <param name="value"></param>
    /// <returns>A new instance of CertificateBuilder with the specified RSASignaturePadding set.</returns>
    public CertificateBuilder SetRSASignaturePadding(RSASignaturePadding value)
        => this with { RSASignaturePadding = value };

    /// <summary>
    /// Use this to provide a key-pair to use when creating new certificates or certificate-requests.
    /// </summary>
    /// <param name="value">A public-private keypair. Supported algorithms currently include RSA, ECDsa and the deprecated DSA.</param>
    /// <returns>A new instance of CertificateBuilder with the specified key-pair set.</returns>
    public CertificateBuilder SetKeyPair(AsymmetricAlgorithm? value)
        => this with { KeyPair = value };

    /// <summary>
    /// Use this to generate a new key-pair to use when creating new certificates or certificate-requests.
    /// </summary>
    /// <param name="value">The type of algorithm to use for generating the keys. Supported algorithms currently include RSA, ECDsa and the deprecated DSA. The default is RSA.</param>
    /// <returns>A new instance of CertificateBuilder with the new key-pair set.</returns>
    public CertificateBuilder GenerateKeyPair(KeyAlgorithm value = KeyAlgorithm.RSA)
        => SetKeyPair(CreateKeyPair(value));

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
        var dn = Subject.Build();

        var request = KeyPair switch {
            RSA rsa => new CertificateRequest(dn, rsa, HashAlgorithm, RSASignaturePadding),
            ECDsa ecdsa => new CertificateRequest(dn, ecdsa, HashAlgorithm),
            #if NET6_0_OR_GREATER
            DSA dsa => new CertificateRequest(dn, new PublicKey(dsa), HashAlgorithm),
            #else
            DSA dsa => throw new NotImplementedException($"Support for DSA is not yet implemented on .NET 5 or earlier."),
            #endif
            null => throw new ArgumentNullException(nameof(KeyPair), $"Call {nameof(SetKeyPair)}(...) or {nameof(GenerateKeyPair)}() first to provide a public/private keypair"),
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
            ? GenerateKeyPair(KeyAlgorithm.RSA)
            : this;

        Debug.Assert(builder.KeyPair != null);

        var request = builder.ToCertificateRequest();

        var cert = builder.Issuer != null
            ? request.Create(
                builder.Issuer.SubjectName,
                builder.CreateSignatureGenerator(builder.Issuer.GetPrivateKey()),
                builder.NotBefore,
                builder.NotAfter,
                builder.GenerateSerialNumber()
            )
            : request.Create(
                builder.Subject.Build(),
                builder.CreateSignatureGenerator(builder.KeyPair),
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


    private AsymmetricAlgorithm CreateKeyPair(KeyAlgorithm algorithm)
        => algorithm switch {
            KeyAlgorithm.DSA => DSA.Create(KeyLength ?? 1024),
            KeyAlgorithm.RSA => RSA.Create(KeyLength ?? 4096),
            KeyAlgorithm.ECDsa => ECDsa.Create() ?? throw new NotSupportedException("Unsupported ECDSA algorithm"),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
        };


    private X509SignatureGenerator CreateSignatureGenerator(AsymmetricAlgorithm? keys)
        => keys switch {
            DSA dsa => new DSAX509SignatureGenerator(dsa),
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            null => throw new ArgumentNullException(nameof(keys), $"Call {nameof(SetKeyPair)}(...) or {nameof(GenerateKeyPair)}() first to provide a public/private keypair"),
            _ => throw new NotSupportedException($"Unsupported {nameof(KeyPair)} algorithm: {keys.SignatureAlgorithm}")
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


    private static readonly X500NameBuilder EmptyNameBuilder = new();
    private static readonly X509ExtensionOidEqualityComparer X509ExtensionOidEqualityComparer = new();
}
