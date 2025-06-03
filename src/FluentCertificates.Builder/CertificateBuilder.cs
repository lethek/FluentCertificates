using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;

public record CertificateBuilder
{
    public CertificateUsage? Usage { get; init; }
    public DateTimeOffset NotBefore { get; init; } = DateTimeOffset.UtcNow.AddHours(-1);
    public DateTimeOffset NotAfter { get; init; } = DateTimeOffset.UtcNow.AddHours(1);
    public X500NameBuilder Subject { get; init; } = EmptyNameBuilder;
    public X509Certificate2? Issuer { get; init; }
    public string? FriendlyName { get; init; }
    public int? PathLength { get; init; }
    public int? KeyLength { get; init; }
    public KeyAlgorithm KeyAlgorithm { get; init; } = KeyAlgorithm.RSA;
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;
    public RSASignaturePadding RSASignaturePadding { get; init; } = RSASignaturePadding.Pkcs1;
    public ImmutableHashSet<X509Extension> Extensions { get; init; } = ImmutableHashSet<X509Extension>.Empty.WithComparer(X509ExtensionOidEqualityComparer);
    public X509KeyStorageFlags KeyStorageFlags { get; init; }
    public ImmutableList<GeneralName>? SubjectAlternativeNames { get; init; }

    private PublicKey? PublicKey { get; init; }
    private AsymmetricAlgorithm? KeyPair { get; init; }


    /// <summary>
    /// Sets the primary usage of the certificate, which determines default extensions.
    /// </summary>
    /// <param name="value">The intended usage of the certificate.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified usage.</returns>
    public CertificateBuilder SetUsage(CertificateUsage value)
        => this with { Usage = value };

    /// <summary>
    /// Sets the certificate's validity period start time.
    /// </summary>
    /// <param name="value">The start time for certificate validity. If unspecified, the default is 1 hour ago.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified NotBefore value.</returns>
    public CertificateBuilder SetNotBefore(DateTimeOffset value)
        => this with { NotBefore = value };

    /// <summary>
    /// Sets the certificate's validity period end time.
    /// </summary>
    /// <param name="value">The end time for certificate validity. If unspecified, the default is 1 hour in the future.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified NotAfter value.</returns>
    public CertificateBuilder SetNotAfter(DateTimeOffset value)
        => this with { NotAfter = value };

    /// <summary>
    /// Sets the subject name using an <see cref="X500NameBuilder"/>.
    /// </summary>
    /// <param name="value">The subject name builder.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified subject.</returns>
    public CertificateBuilder SetSubject(X500NameBuilder value)
        => this with { Subject = value };

    /// <summary>
    /// Sets the subject name using an <see cref="X500DistinguishedName"/>.
    /// </summary>
    /// <param name="value">The distinguished name.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified subject.</returns>
    public CertificateBuilder SetSubject(X500DistinguishedName value)
        => this with { Subject = new X500NameBuilder(value) };

    /// <summary>
    /// Sets the subject name using a string representation.
    /// </summary>
    /// <param name="value">The subject name as a string.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified subject.</returns>
    public CertificateBuilder SetSubject(string value)
        => this with { Subject = new X500NameBuilder(value) };

    /// <summary>
    /// Sets the subject name using a function to configure the <see cref="X500NameBuilder"/>.
    /// </summary>
    /// <param name="func">A function to configure the subject name builder.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the configured subject.</returns>
    public CertificateBuilder SetSubject(Func<X500NameBuilder, X500NameBuilder> func)
        => this with { Subject = func(Subject) };

    /// <summary>
    /// Sets the issuer certificate.
    /// </summary>
    /// <param name="value">The issuer certificate.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified issuer.</returns>
    public CertificateBuilder SetIssuer(X509Certificate2? value)
        => this with { Issuer = value };

    /// <summary>
    /// Sets a friendly name for the certificate (Windows only; it'll be ignored on other platforms).
    /// </summary>
    /// <param name="value">The friendly name.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified friendly name.</returns>
    public CertificateBuilder SetFriendlyName(string value)
        => this with { FriendlyName = value };

    /// <summary>
    /// Sets the path length constraint for CA certificates.
    /// </summary>
    /// <param name="value">The path length constraint.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified path length.</returns>
    public CertificateBuilder SetPathLength(int? value)
        => this with { PathLength = value };

    /// <summary>
    /// Sets the key length for new key generation. Default is 4096 bits for RSA and is 2048 for DSA. KeyLength is ignored when generating ECDsa keys.
    /// </summary>
    /// <param name="value">The key length in bits.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified key length.</returns>
    public CertificateBuilder SetKeyLength(int? value)
        => this with { KeyLength = value };


    /// <summary>
    /// Sets the key pair to use for certificate creation or certificate-requests.
    /// </summary>
    /// <remarks>
    /// Keys provided through this method are NOT automatically disposed by the CertificateBuilder so it is the caller's responsibility to manage that.
    /// </remarks>
    /// <param name="value">The asymmetric key pair, or <see langword="null" /> to remove. Supported algorithms currently include RSA, ECDsa and the deprecated DSA.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified key pair.</returns>
    public CertificateBuilder SetKeyPair(AsymmetricAlgorithm? value)
        => this with {
            KeyAlgorithm = GetKeyAlgorithm(value) ?? KeyAlgorithm,
            PublicKey = value != null ? new PublicKey(value) : null,
            KeyPair = value
        };

    /// <summary>
    /// Sets the key algorithm for automatic key generation. This is mutually exclusive with the SetKeyPair method, so if a KeyPair
    /// was previously specified, setting the KeyAlgorithm will remove it from the builder. Whenever the build's Create() method is
    /// called, a new key-pair will be generated and immediately disposed upon return.
    /// </summary>
    /// <param name="value">The key algorithm to use. Supported algorithms currently include RSA, ECDsa and the deprecated DSA. If unspecified, the default is RSA.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified key algorithm.</returns>
    public CertificateBuilder SetKeyAlgorithm(KeyAlgorithm value)
        => this with {
            KeyAlgorithm = value,
            PublicKey = null,
            KeyPair = null
        };

    /// <summary>
    /// Sets the hash algorithm for signing.
    /// </summary>
    /// <param name="value">The hash algorithm.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified hash algorithm.</returns>
    public CertificateBuilder SetHashAlgorithm(HashAlgorithmName value)
        => this with { HashAlgorithm = value };


    /// <summary>
    /// Sets the RSA signature padding mode. If unspecified, the default is <see cref="RSASignaturePadding.Pkcs1"/>.
    /// This is ignored when using other key algorithms (ECDsa/DSA).
    /// </summary>
    /// <param name="value">The RSA signature padding.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified padding.</returns>
    public CertificateBuilder SetRSASignaturePadding(RSASignaturePadding value)
        => this with { RSASignaturePadding = value };
    

    /// <summary>
    /// Adds an extension to the certificate.
    /// </summary>
    /// <param name="extension">The extension to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extension added.</returns>
    public CertificateBuilder AddExtension(X509Extension extension)
        => this with { Extensions = Extensions.Add(extension) };

    /// <summary>
    /// Adds multiple extensions to the certificate.
    /// </summary>
    /// <param name="values">The extensions to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extensions added.</returns>
    public CertificateBuilder AddExtensions(params X509Extension[] values)
        => this with { Extensions = Extensions.Union(values) };

    /// <summary>
    /// Adds multiple extensions to the certificate.
    /// </summary>
    /// <param name="values">The extensions to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extensions added.</returns>
    public CertificateBuilder AddExtensions(IEnumerable<X509Extension> values)
        => this with { Extensions = Extensions.Union(values) };

    /// <summary>
    /// Sets the certificate extensions, replacing any existing ones.
    /// </summary>
    /// <param name="values">The extensions to set.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified extensions.</returns>
    public CertificateBuilder SetExtensions(params X509Extension[] values)
        => this with { Extensions = values.ToImmutableHashSet(X509ExtensionOidEqualityComparer) };

    /// <summary>
    /// Sets the certificate extensions, replacing any existing ones.
    /// </summary>
    /// <param name="values">The extensions to set.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified extensions.</returns>
    public CertificateBuilder SetExtensions(IEnumerable<X509Extension> values)
        => this with { Extensions = values.ToImmutableHashSet(X509ExtensionOidEqualityComparer) };

    
    /// <summary>
    /// Sets the key storage flags for the certificate.
    /// </summary>
    /// <param name="value">The key storage flags.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified flags.</returns>
    public CertificateBuilder SetKeyStorageFlags(X509KeyStorageFlags value)
        => this with { KeyStorageFlags = value };


    /// <summary>
    /// Sets the subject alternative names using a builder function.
    /// </summary>
    /// <param name="configureSan">A function to configure the SAN builder.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified SANs.</returns>
    public CertificateBuilder SetSubjectAlternativeNames(Func<GeneralNameListBuilder, GeneralNameListBuilder> configureSan)
        => SetSubjectAlternativeNames(configureSan(new GeneralNameListBuilder()).Create());


    /// <summary>
    /// Sets the subject alternative names.
    /// </summary>
    /// <param name="san">The subject alternative names.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified SANs.</returns>
    public CertificateBuilder SetSubjectAlternativeNames(IEnumerable<GeneralName> san)
        => this with { SubjectAlternativeNames = san.ToImmutableList() };


    /// <summary>
    /// Validates the current builder configuration and throws if invalid.
    /// </summary>
    public void Validate()
    {
        if (KeyLength <= 0 && KeyPair == null && KeyAlgorithm != KeyAlgorithm.ECDsa) {
            throw new ArgumentException($"{nameof(KeyLength)} must be greater than zero", nameof(KeyLength));
        }

        if (NotBefore >= NotAfter) {
            throw new ArgumentException($"{nameof(NotBefore)} cannot be later than or equal to {nameof(NotAfter)}", nameof(NotAfter));
        }
    }


    /// <summary>
    /// Creates a <see cref="CertificateRequest"/> based on the builder's parameters.
    /// </summary>
    /// <returns>A new <see cref="CertificateRequest"/> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown if no key pair is set. Make sure to call the <see cref="SetKeyPair"/> method as
    /// certificate requests require a manually specified key pair.</exception>
    public CertificateRequest CreateCertificateRequest()
    {
        if (PublicKey == null) {
            throw new ArgumentNullException($"Call {nameof(SetKeyPair)}(...) first to provide an asymmetric public/private keypair");
        }

        var dn = Subject.Create();

        var request = new CertificateRequest(dn, PublicKey, HashAlgorithm);

        foreach (var extension in BuildExtensions(this)) {
            request.CertificateExtensions.Add(extension);
        }

        if (Issuer != null) {
            request.CertificateExtensions.Add(new X509AuthorityKeyIdentifierExtension(Issuer, false));
        }

        return request;
    }


    /// <summary>
    /// Creates a <see cref="CertificateSigningRequest"/> based on the builder's parameters.
    /// </summary>
    /// <returns>A new <see cref="CertificateSigningRequest"/> instance.</returns>
    public CertificateSigningRequest CreateCertificateSigningRequest()
        => new(CreateCertificateRequest(), CreateSignatureGenerator(KeyPair));


    /// <summary>
    /// Builds an <see cref="X509Certificate2"/> instance based on the builder's parameters.
    /// </summary>
    /// <returns>A new <see cref="X509Certificate2"/> instance.</returns>
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    public X509Certificate2 Create()
    {
        Validate();

        bool disposeKeys = (KeyPair == null);

        var builder = KeyPair == null
            ? GenerateKeyPair()
            : this;

        try {
            if (builder.PublicKey == null) {
                throw new ArgumentNullException($"Call {nameof(SetKeyPair)}(...) or {nameof(SetKeyAlgorithm)}() first to provide a public/private keypair");
            }

            var request = builder.CreateCertificateRequest();

            var cert = builder.Issuer != null
                ? request.Create(
                    builder.Issuer.SubjectName,
                    builder.CreateSignatureGenerator(builder.Issuer.GetPrivateKey()),
                    builder.NotBefore,
                    builder.NotAfter,
                    builder.GenerateSerialNumber()
                )
                : request.Create(
                    builder.Subject.Create(),
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

            if (!String.IsNullOrEmpty(builder.FriendlyName) && OperatingSystem.IsWindows()) {
                //CopyWithPrivateKey doesn't copy FriendlyName so it needs to be set here after the copy is made
                cert.FriendlyName = builder.FriendlyName;
            }

            if (builder.KeyStorageFlags != X509KeyStorageFlags.DefaultKeySet) {
                //We have to create a new copy of the certificate to apply the KeyStorageFlags; there doesn't appear to be a better way to do it :(
                using (cert) {
                    return CertTools.LoadPkcs12(cert.Export(X509ContentType.Pkcs12), (string?)null, builder.KeyStorageFlags);
                }
            } else {
                return cert;
            }

        } finally {
            if (disposeKeys) {
                builder.KeyPair?.Clear();
            }
        }
    }


    private byte[] GenerateSerialNumber()
    {
        Span<byte> span = stackalloc byte[18];
        BinaryPrimitives.WriteInt16BigEndian(span[0..2], 0x4D58);
        BinaryPrimitives.WriteInt64BigEndian(span[2..10], DateTime.UtcNow.Ticks);
        RandomNumberGenerator.Fill(span[10..18]);
        return span.ToArray();
    }


    private X509SignatureGenerator CreateSignatureGenerator(AsymmetricAlgorithm? keys)
        => keys switch {
            DSA dsa => new DSAX509SignatureGenerator(dsa),
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            null => throw new ArgumentNullException(nameof(keys), $"Call {nameof(SetKeyPair)}(...) or {nameof(SetKeyAlgorithm)}() first to provide a public/private keypair"),
            _ => throw new NotSupportedException($"Unsupported algorithm: {keys.SignatureAlgorithm}")
        };


    private CertificateBuilder GenerateKeyPair()
        => SetKeyPair(
            KeyAlgorithm switch {
                KeyAlgorithm.ECDsa => ECDsa.Create() ?? throw new NotSupportedException("Unsupported ECDSA algorithm"),
                KeyAlgorithm.RSA => RSA.Create(KeyLength ?? 4096),
                KeyAlgorithm.DSA => DSA.Create(KeyLength ?? 1024),
                _ => throw new ArgumentOutOfRangeException(nameof(KeyAlgorithm), KeyAlgorithm, $"Unsupported {nameof(KeyAlgorithm)}")
            }
        );


    private static ImmutableHashSet<X509Extension> BuildExtensions(CertificateBuilder builder)
    {
        //Setup default extensions based on selected certificate Usage
        var extensions = GetCommonExtensions(builder);
        extensions.AddRange(builder.Usage switch {
            null => [],
            CertificateUsage.CA => GetCaExtensions(builder),
            CertificateUsage.Server => GetServerExtensions(builder),
            CertificateUsage.Client => GetClientExtensions(builder),
            CertificateUsage.CodeSign => GetCodeSigningExtensions(builder),
            CertificateUsage.SMime => GetSMimeExtensions(builder),
            _ => throw new NotImplementedException($"{builder.Usage} {nameof(Usage)} not yet implemented")
        });

        //Setup extension for Subject Alternative Name if necessary
        if (builder.SubjectAlternativeNames != null && builder.SubjectAlternativeNames.Any()) {
            //Extension must be marked critical if the Subject is empty, as per https://tools.ietf.org/html/rfc5280#section-4.1.2.6
            bool critical = !builder.Subject.RelativeDistinguishedNames.Any();
            extensions.Add(new X509SubjectAlternativeNameExtension(builder.SubjectAlternativeNames.Encode(), critical));
        }

        //Collate extensions; manually specified ones override those matching ones generated above (e.g. Usage, DnsNames, Email, etc.)
        return extensions.Any()
            ? builder.Extensions.Union(extensions)
            : builder.Extensions;
    }


    private static List<X509Extension> GetCommonExtensions(CertificateBuilder builder)
        => [new X509SubjectKeyIdentifierExtension(builder.PublicKey!, false)];


    private static List<X509Extension> GetCaExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(true, builder.PathLength.HasValue, builder.PathLength ?? 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true)
        ];


    private static List<X509Extension> GetServerExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.ServerAuthPurpose) }, false)
        ];


    private static List<X509Extension> GetClientExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.ClientAuthPurpose) }, false)
        ];


    private static List<X509Extension> GetCodeSigningExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true),
            new X509EnhancedKeyUsageExtension(new OidCollection {
                new(Oids.CodeSigningPurpose),
                new(Oids.TimeStampingPurpose),
                new(Oids.LifetimeSigningPurpose) //Used by Microsoft Authenticode to limit the signature's lifetime to the certificate's expiration
            }, false)
        ];


    private static List<X509Extension> GetSMimeExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.NonRepudiation, true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.EmailProtectionPurpose) }, false)
        ];


    private static KeyAlgorithm? GetKeyAlgorithm(AsymmetricAlgorithm? keys)
        => keys switch {
            ECDsa => KeyAlgorithm.ECDsa,
            RSA => KeyAlgorithm.RSA,
            DSA => KeyAlgorithm.DSA,
            null => null,
            _ => throw new NotSupportedException($"Unsupported AsymmetricAlgorithm: {keys.GetType()}")
        };


    private static readonly X500NameBuilder EmptyNameBuilder = new();
    private static readonly X509ExtensionOidEqualityComparer X509ExtensionOidEqualityComparer = new();
}
