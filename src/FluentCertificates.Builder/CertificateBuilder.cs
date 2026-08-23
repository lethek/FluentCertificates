using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;

/// <summary>
/// Provides a fluent API for building and creating X.509 certificates and certificate requests.
/// </summary>
/// <remarks>
/// The <c>CertificateBuilder</c> record allows configuration of certificate properties, key generation,
/// extensions, and other parameters. It supports both self-signed and CA-signed certificates,
/// and can generate Certificate Signing Requests (CSRs).
/// </remarks>
public record CertificateBuilder
{
    /// <summary>Gets the primary usage of the certificate, which determines default extensions.</summary>
    public CertificateUsage? Usage { get; init; }

    /// <summary>Gets the start time for certificate validity. Defaults to 1 hour ago (UTC).</summary>
    public DateTimeOffset NotBefore { get; init; } = DateTimeOffset.UtcNow.AddHours(-1);

    /// <summary>Gets the end time for certificate validity. Defaults to 1 hour in the future (UTC).</summary>
    public DateTimeOffset NotAfter { get; init; } = DateTimeOffset.UtcNow.AddHours(1);
    
    /// <summary>Gets the Subject Name Builder for the certificate.</summary>
    public X500NameBuilder Subject { get; init; } = EmptyNameBuilder;
    
    /// <summary>Gets the issuer certificate, or <see langword="null"/> for self-signed certificates.</summary>
    public X509Certificate2? Issuer { get; init; }
    
    /// <summary>Gets the friendly name for the certificate (Windows only; this property is ignored on other platforms).</summary>
    public string? FriendlyName { get; init; }
    
    /// <summary>Gets the path length constraint for CA certificates.</summary>
    public int? PathLength { get; init; }
    
    /// <summary>
    /// Gets the algorithm used for automatic key generation, including its key length, curve or parameter set.
    /// Defaults to RSA-4096.
    /// </summary>
    public KeyAlgorithm KeyAlgorithm { get; init; } = KeyAlgorithm.RSA();

    /// <summary>Gets the hash algorithm for signing.</summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;
    
    /// <summary>Gets the RSA signature padding mode. Ignored for non-RSA algorithms.</summary>
    public RSASignaturePadding RSASignaturePadding { get; init; } = RSASignaturePadding.Pkcs1;
    
    /// <summary>
    /// Gets the signature generator used to sign the certificate or certificate-request, or <see langword="null"/>
    /// to derive one from the signing key.
    /// </summary>
    public X509SignatureGenerator? SignatureGenerator { get; init; }

    /// <summary>Gets the key storage flags for the certificate.</summary>
    public X509KeyStorageFlags KeyStorageFlags { get; init; }
    
    /// <summary>Gets the custom serial number generator function for certificate creation.</summary>
    public Func<byte[]>? SerialNumberGenerator { get; init; }

    /// <summary>Gets the collection of certificate extensions.</summary>
    public IReadOnlyCollection<X509Extension> Extensions => _extensions;
    private ImmutableHashSet<X509Extension> _extensions { get; init; } = ImmutableHashSet<X509Extension>.Empty.WithComparer(X509ExtensionOidEqualityComparer);
    
    /// <summary>Gets the list of subject alternative names, or <see langword="null"/> if not set.</summary>
    public IReadOnlyList<GeneralName>? SubjectAlternativeNames => _subjectAlternativeNames;
    private ImmutableList<GeneralName>? _subjectAlternativeNames { get; init; }

    private PublicKey? PublicKey { get; init; }
    private CertificateKey? KeyPair { get; init; }


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
    /// Sets the certificate's validity period to run for <paramref name="duration"/> starting now (UTC).
    /// </summary>
    /// <remarks>
    /// Unlike the default <see cref="NotBefore"/>, this does not backdate the start time, so a certificate
    /// built this way is not valid on a verifier whose clock runs behind. Use the
    /// <see cref="SetValidity(DateTimeOffset,TimeSpan)"/> overload to allow for clock skew.
    /// </remarks>
    /// <param name="duration">How long the certificate remains valid. Must be greater than <see cref="TimeSpan.Zero"/>.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified validity period.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="duration"/> is zero or negative.</exception>
    public CertificateBuilder SetValidity(TimeSpan duration)
        => SetValidity(DateTimeOffset.UtcNow, duration);

    /// <summary>
    /// Sets the certificate's validity period to run for <paramref name="duration"/> starting at <paramref name="from"/>.
    /// </summary>
    /// <param name="from">The start time for certificate validity.</param>
    /// <param name="duration">How long the certificate remains valid. Must be greater than <see cref="TimeSpan.Zero"/>.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified validity period.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="duration"/> is zero or negative.</exception>
    public CertificateBuilder SetValidity(DateTimeOffset from, TimeSpan duration)
        => duration > TimeSpan.Zero
            ? this with { NotBefore = from, NotAfter = from + duration }
            : throw new ArgumentOutOfRangeException(nameof(duration), duration, $"{nameof(duration)} must be greater than zero");

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
            KeyPair = value == null ? null : new CertificateKey(value)
        };

    /// <summary>
    /// Sets the key pair to use for certificate creation or certificate-requests, from a key of any supported
    /// kind including the post-quantum ones.
    /// </summary>
    /// <remarks>
    /// Keys provided through this method are NOT automatically disposed by the CertificateBuilder so it is the
    /// caller's responsibility to manage that. A classical key converts implicitly, so
    /// <c>SetKeyPair(rsa)</c> continues to bind to the <see cref="AsymmetricAlgorithm"/> overload above.
    /// </remarks>
    /// <param name="value">The key pair, or <see langword="null" /> to remove.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified key pair.</returns>
    public CertificateBuilder SetKeyPair(CertificateKey? value)
        => this with {
            KeyAlgorithm = GetKeyAlgorithm(value) ?? KeyAlgorithm,
            PublicKey = CreatePublicKey(value),
            KeyPair = value
        };

    /// <summary>
    /// Sets the public key to certify, without supplying the matching private key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the counterpart to <see cref="SetSignatureGenerator"/> for keys this process cannot use
    /// directly, such as those held in an HSM, a TPM or a cloud KMS: the public key goes into the
    /// certificate while the private key never leaves the device.
    /// </para>
    /// <para>
    /// It is mutually exclusive with <see cref="SetKeyPair(AsymmetricAlgorithm)"/>, which it clears, and it suppresses the
    /// automatic key generation that would otherwise happen during <see cref="Create"/>. The resulting
    /// certificate has no private key attached.
    /// </para>
    /// <para>
    /// Self-signing a certificate this way also requires <see cref="SetSignatureGenerator"/>, since the
    /// builder holds no key it could sign with. Nothing checks that the generator actually corresponds to
    /// this public key; that pairing is the caller's to get right.
    /// </para>
    /// <para>
    /// <see cref="KeyAlgorithm"/> is updated to match the key where the algorithm is recognised, and left
    /// unchanged otherwise.
    /// </para>
    /// </remarks>
    /// <param name="value">The public key to certify, or <see langword="null"/> to remove it.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified public key.</returns>
    public CertificateBuilder SetPublicKey(PublicKey? value)
        => this with {
            KeyAlgorithm = KeepEcChoice(GetKeyAlgorithm(value)) ?? KeyAlgorithm,
            PublicKey = value,
            KeyPair = null
        };


    /// <summary>
    /// An EC public key reads back as <see cref="KeyAlgorithm.ECDsa()"/> whether it was made for signing or for
    /// key agreement, so that guess must not overwrite a caller who already said
    /// <see cref="KeyAlgorithm.ECDiffieHellman()"/>. Call <see cref="SetKeyAlgorithm"/> before
    /// <see cref="SetPublicKey"/> to certify an ECDH key held elsewhere.
    /// </summary>
    private KeyAlgorithm? KeepEcChoice(KeyAlgorithm? derived)
        => derived?.Family == KeyAlgorithmFamily.ECDsa && KeyAlgorithm.Family == KeyAlgorithmFamily.ECDiffieHellman
            ? KeyAlgorithm
            : derived;

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
    /// Sets a signature generator to sign with, instead of deriving one from the signing key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the extension point for keys this process cannot use directly, such as those held in an HSM,
    /// a TPM or a cloud KMS: implement <see cref="X509SignatureGenerator"/> against the remote key and the
    /// builder never needs the private key itself.
    /// </para>
    /// <para>
    /// The generator replaces whichever signature would otherwise have been produced. When
    /// <see cref="Issuer"/> is set that is the issuer's signature, and the issuer certificate no longer needs
    /// an attached private key. Otherwise it is the self-signature, which requires the matching key pair from
    /// <see cref="SetKeyPair(AsymmetricAlgorithm)"/> so the certificate's own public key agrees with the signature.
    /// </para>
    /// <para>
    /// <see cref="HashAlgorithm"/> and <see cref="RSASignaturePadding"/> are not applied to a supplied
    /// generator; it determines its own signature algorithm.
    /// </para>
    /// </remarks>
    /// <param name="value">The signature generator to sign with, or <see langword="null"/> to derive one from the signing key.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified signature generator.</returns>
    public CertificateBuilder SetSignatureGenerator(X509SignatureGenerator? value)
        => this with { SignatureGenerator = value };



    /// <summary>
    /// Adds an extension to the certificate.
    /// </summary>
    /// <param name="extension">The extension to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extension added.</returns>
    public CertificateBuilder AddExtension(X509Extension extension)
        => this with { _extensions = _extensions.Add(extension) };

    /// <summary>
    /// Adds multiple extensions to the certificate.
    /// </summary>
    /// <param name="values">The extensions to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extensions added.</returns>
    public CertificateBuilder AddExtensions(params X509Extension[] values)
        => this with { _extensions = _extensions.Union(values) };

    /// <summary>
    /// Adds multiple extensions to the certificate.
    /// </summary>
    /// <param name="values">The extensions to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extensions added.</returns>
    public CertificateBuilder AddExtensions(IEnumerable<X509Extension> values)
        => this with { _extensions = _extensions.Union(values) };

    /// <summary>
    /// Sets the certificate extensions, replacing any existing ones.
    /// </summary>
    /// <param name="values">The extensions to set.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified extensions.</returns>
    public CertificateBuilder SetExtensions(params X509Extension[] values)
        => this with { _extensions = values.ToImmutableHashSet(X509ExtensionOidEqualityComparer) };

    /// <summary>
    /// Sets the certificate extensions, replacing any existing ones.
    /// </summary>
    /// <param name="values">The extensions to set.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified extensions.</returns>
    public CertificateBuilder SetExtensions(IEnumerable<X509Extension> values)
        => this with { _extensions = values.ToImmutableHashSet(X509ExtensionOidEqualityComparer) };

    
    /// <summary>
    /// Sets the key storage flags for the certificate.
    /// </summary>
    /// <param name="value">The key storage flags.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified flags.</returns>
    public CertificateBuilder SetKeyStorageFlags(X509KeyStorageFlags value)
        => this with { KeyStorageFlags = value };


    /// <summary>
    /// Sets a custom serial number generator function for certificate creation.
    /// </summary>
    /// <param name="generator">A delegate that returns a <see cref="T:System.Byte[]"/> representing the serial number to use for the certificate.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified serial number generator.</returns>
    public CertificateBuilder SetSerialNumberGenerator(Func<byte[]> generator)
        => this with { SerialNumberGenerator = generator };


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
        => this with { _subjectAlternativeNames = [.. san]};


    /// <summary>
    /// Validates the current builder configuration and throws if invalid.
    /// </summary>
    public void Validate()
    {
        //A KeyAlgorithm carries its own key length, curve or parameter set, so there is no longer any
        //combination of those to police here: an invalid one cannot be constructed in the first place.

        if (NotBefore >= NotAfter) {
            throw new ArgumentException($"{nameof(NotBefore)} cannot be later than or equal to {nameof(NotAfter)}", nameof(NotAfter));
        }

        if (!KeyAlgorithm.CanSign) {
            //A key-agreement or key-encapsulation key has no signing operation at all, so it can sign
            //neither its own certificate nor anything beneath it.
            //A SignatureGenerator is no substitute here: with no Issuer the certificate is self-issued, so
            //the generator would sign it with a key unrelated to the subject key and the signature could
            //never verify against it.
            if (Issuer == null) {
                throw new ArgumentException($"{KeyAlgorithm.Name} cannot sign, so the certificate must be signed by someone else. Set an {nameof(Issuer)}", nameof(Issuer));
            }

            if (Usage is CertificateUsage.CA or CertificateUsage.CodeSign or CertificateUsage.OcspSigning or CertificateUsage.TimeStamping) {
                throw new ArgumentException($"{nameof(CertificateUsage)}.{Usage} needs a key that can sign, which {KeyAlgorithm.Name} cannot", nameof(Usage));
            }
        }

        //Self-signing means the subject key and the signing key are the same key, so with no KeyPair in hand
        //the caller has to describe both halves of it or neither: a public key to certify AND a generator to
        //sign with. Supplying only one half would pair a generated key with an unrelated signature, or leave
        //nothing able to sign at all.
        if (Issuer == null && KeyPair == null) {
            if (PublicKey == null && SignatureGenerator != null) {
                throw new ArgumentException($"{nameof(SignatureGenerator)} without an {nameof(Issuer)} signs the certificate with itself, so the key it signs with must also be supplied through {nameof(SetKeyPair)} or {nameof(SetPublicKey)}", nameof(SignatureGenerator));
            }

            if (PublicKey != null && SignatureGenerator == null) {
                throw new ArgumentException($"{nameof(SetPublicKey)} supplies no private key, so a self-signed certificate also needs a {nameof(SignatureGenerator)} to sign with, or an {nameof(Issuer)} to sign it", nameof(SignatureGenerator));
            }
        }
    }


    /// <summary>
    /// Creates a <see cref="CertificateRequest"/> based on the builder's parameters.
    /// </summary>
    /// <returns>A new <see cref="CertificateRequest"/> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown if no key pair is set. Make sure to call the <see cref="SetKeyPair(AsymmetricAlgorithm)"/> method as
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
    /// <exception cref="NotSupportedException">Thrown when the key to certify is an <see cref="System.Security.Cryptography.ECDiffieHellman"/>
    /// key, which cannot produce the proof-of-possession signature a PKCS#10 request is built around.</exception>
    public CertificateSigningRequest CreateCertificateSigningRequest()
    {
        //PKCS#10 proves possession by signing the request with the very key being certified. A supplied
        //SignatureGenerator signs with some other key, which proves nothing about this one.
        if (!KeyAlgorithm.CanSign || KeyPair?.CanSign == false) {
            throw new NotSupportedException($"A {KeyAlgorithm.Name} key cannot sign, so it cannot sign the request that asks for it to be certified");
        }

        return new(CreateCertificateRequest(), SignatureGenerator ?? CreateSignatureGenerator(KeyPair));
    }


    /// <summary>
    /// Builds an <see cref="X509Certificate2"/> instance based on the builder's parameters.
    /// </summary>
    /// <returns>A new <see cref="X509Certificate2"/> instance.</returns>
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    public X509Certificate2 Create()
    {
        Validate();

        //A public key supplied on its own is enough to certify, so only generate when nothing was provided
        bool generateKeys = KeyPair == null && PublicKey == null;

        var builder = generateKeys
            ? GenerateKeyPair()
            : this;

        try {
            if (builder.PublicKey == null) {
                throw new ArgumentNullException($"Call {nameof(SetKeyPair)}(...), {nameof(SetPublicKey)}(...) or {nameof(SetKeyAlgorithm)}() first to provide a key to certify");
            }

            var request = builder.CreateCertificateRequest();

            //GetPrivateKey hands back a fresh instance which is ours to release, unlike KeyPair, whose
            //lifetime belongs either to the caller or to the disposal in this method's finally block
            using var issuerKey = builder.SignatureGenerator == null && builder.Issuer != null
                ? builder.Issuer.GetPrivateKey()
                : null;

            //A supplied generator is used as-is, which also means an Issuer certificate with no attached
            //private key is enough: the key it stands for lives wherever the generator can reach it
            var generator = builder.SignatureGenerator
                ?? builder.CreateSignatureGenerator(issuerKey ?? builder.KeyPair);

            var cert = request.Create(
                builder.Issuer?.SubjectName ?? builder.Subject.Create(),
                generator,
                builder.NotBefore,
                builder.NotAfter,
                builder.GenerateSerialNumber()
            );

            //CopyToCertificate returns a separate certificate, leaving the keyless original ours to release
            if (builder.KeyPair != null) {
                var certWithKey = builder.KeyPair.CopyToCertificate(cert);
                cert.Dispose();
                cert = certWithKey;
            }

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
            //Only keys this method generated are ours to release; a caller-supplied key stays the caller's
            if (generateKeys) {
                builder.KeyPair?.Dispose();
            }
        }
    }


    private byte[] GenerateSerialNumber()
        => SerialNumberGenerator?.Invoke() ?? DefaultGenerateSerialNumber();

    
    private static byte[] DefaultGenerateSerialNumber()
    {
        Span<byte> span = stackalloc byte[18];
        BinaryPrimitives.WriteInt16BigEndian(span[0..2], 0x4D58);
        BinaryPrimitives.WriteInt64BigEndian(span[2..10], DateTime.UtcNow.Ticks);
        RandomNumberGenerator.Fill(span[10..18]);
        return [.. span];
    }


    private X509SignatureGenerator CreateSignatureGenerator(CertificateKey? keys)
    {
        if (keys == null) {
            throw new ArgumentNullException(nameof(keys), $"Call {nameof(SetKeyPair)}(...) or {nameof(SetKeyAlgorithm)}() first to provide a public/private keypair");
        }

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
#pragma warning disable FLUENTCERT001
        if (keys.AsMLDsa is { } mldsa) {
            return X509SignatureGenerator.CreateForMLDsa(mldsa);
        }

        if (keys.AsSlhDsa is { } slhdsa) {
            return X509SignatureGenerator.CreateForSlhDsa(slhdsa);
        }

        if (keys.AsCompositeMLDsa is { } composite) {
            return X509SignatureGenerator.CreateForCompositeMLDsa(composite);
        }
#pragma warning restore FLUENTCERT001
#pragma warning restore SYSLIB5006
#endif

        return keys.AsAsymmetricAlgorithm switch {
#pragma warning disable CS0618 // Type or member is obsolete
            DSA dsa => new DSAX509SignatureGenerator(dsa),
#pragma warning restore CS0618 // Type or member is obsolete
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            ECDiffieHellman => throw new NotSupportedException($"An {nameof(ECDiffieHellman)} key agrees on a shared secret and cannot sign. Set an {nameof(Issuer)} so the certificate is signed by a CA, or supply a {nameof(SignatureGenerator)}"),
            _ => throw new NotSupportedException($"Unsupported algorithm: {keys.Family}")
        };
    }


    private CertificateBuilder GenerateKeyPair()
    {
        PostQuantumSupport.ThrowIfUnsupported(KeyAlgorithm);

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
#pragma warning disable FLUENTCERT001
        switch (KeyAlgorithm.Family) {
            case KeyAlgorithmFamily.MLDsa:
                return SetKeyPair(new CertificateKey(MLDsa.GenerateKey(PostQuantumSupport.MLDsaAlgorithmFor(KeyAlgorithm))));
            case KeyAlgorithmFamily.SlhDsa:
                return SetKeyPair(new CertificateKey(SlhDsa.GenerateKey(PostQuantumSupport.SlhDsaAlgorithmFor(KeyAlgorithm))));
            case KeyAlgorithmFamily.CompositeMLDsa:
                return SetKeyPair(new CertificateKey(CompositeMLDsa.GenerateKey(PostQuantumSupport.CompositeAlgorithmFor(KeyAlgorithm))));
            case KeyAlgorithmFamily.MLKem:
                return SetKeyPair(new CertificateKey(MLKem.GenerateKey(PostQuantumSupport.MLKemAlgorithmFor(KeyAlgorithm))));
        }
#pragma warning restore FLUENTCERT001
#pragma warning restore SYSLIB5006
#endif

        return SetKeyPair(
            KeyAlgorithm.Family switch {
                KeyAlgorithmFamily.ECDsa => ECDsa.Create(KeyAlgorithm.Curve!.Value),
                KeyAlgorithmFamily.ECDiffieHellman => ECDiffieHellman.Create(KeyAlgorithm.Curve!.Value),
                KeyAlgorithmFamily.Rsa => RSA.Create(KeyAlgorithm.KeyLength!.Value),
#pragma warning disable CS0618 // Type or member is obsolete
                KeyAlgorithmFamily.Dsa => DSA.Create(KeyAlgorithm.KeyLength!.Value),
#pragma warning restore CS0618 // Type or member is obsolete
                _ => throw new ArgumentOutOfRangeException(nameof(KeyAlgorithm), KeyAlgorithm, $"Unsupported {nameof(KeyAlgorithm)}")
            }
        );
    }




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
            CertificateUsage.OcspSigning => GetOcspSigningExtensions(builder),
            CertificateUsage.TimeStamping => GetTimeStampingExtensions(builder),
            _ => throw new NotImplementedException($"{builder.Usage} {nameof(Usage)} not yet implemented")
        });

        //Setup extension for Subject Alternative Name if necessary
        if (builder.SubjectAlternativeNames != null && builder.SubjectAlternativeNames.Any()) {
            //Extension must be marked critical if the Subject is empty, as per https://tools.ietf.org/html/rfc5280#section-4.1.2.6
            bool critical = !builder.Subject.RelativeDistinguishedNames.Any();
            extensions.Add(new X509SubjectAlternativeNameExtension(builder.SubjectAlternativeNames.Encode(), critical));
        }

        //Collate extensions; manually specified ones in the `builder` may override matching generated ones above (e.g. Usage, DnsNames, Email, etc.)
        return extensions.Any()
            ? builder._extensions.Union(extensions)
            : builder._extensions;
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
            new X509KeyUsageExtension(SigningOrKeyAgreement(builder) | KeyEnciphermentIfSupported(builder), true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.ServerAuthPurpose) }, false)
        ];


    private static List<X509Extension> GetClientExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(SigningOrKeyAgreement(builder), true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.ClientAuthPurpose) }, false)
        ];


    private static List<X509Extension> GetCodeSigningExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.CodeSigningPurpose) }, false)
        ];


    private static List<X509Extension> GetSMimeExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(SigningOrKeyAgreement(builder) | X509KeyUsageFlags.NonRepudiation | KeyEnciphermentIfSupported(builder), true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.EmailProtectionPurpose) }, false)
        ];


    private static List<X509Extension> GetOcspSigningExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.OcspSigningPurpose) }, false)
        ];


    private static List<X509Extension> GetTimeStampingExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true),
            //RFC 3161 s2.3 requires a TSA certificate to carry id-kp-timeStamping as its only
            //extended key usage, and requires that extension to be marked critical
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.TimeStampingPurpose) }, true)
        ];


    /// <summary>
    /// Returns the key usage bit for the certificate's own key: <see cref="X509KeyUsageFlags.KeyAgreement"/>
    /// for an ECDH key, which derives a shared secret and cannot sign, and
    /// <see cref="X509KeyUsageFlags.DigitalSignature"/> otherwise. RFC 5280 s4.2.1.3 separates key transport
    /// from key agreement, and RFC 5480 s3 lists keyAgreement among the usages permitted for id-ecPublicKey.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="KeyEnciphermentIfSupported"/> this reads <see cref="KeyAlgorithm"/> rather than the
    /// public key, because it has to: an ECDH and an ECDsa public key are byte-identical in
    /// SubjectPublicKeyInfo, carrying the same algorithm OID and the same curve parameters.
    /// </remarks>
#pragma warning disable FLUENTCERT001 // Naming a post-quantum family to classify one is not experimental use
    private static X509KeyUsageFlags SigningOrKeyAgreement(CertificateBuilder builder)
        => builder.KeyAlgorithm.Family switch {
            //An ECDH key really does perform Diffie-Hellman key agreement
            KeyAlgorithmFamily.ECDiffieHellman => X509KeyUsageFlags.KeyAgreement,
            //ML-KEM does not. Encapsulation is key transport, so its bit is keyEncipherment, asserted by
            //KeyEnciphermentIfSupported; claiming keyAgreement as well would name an operation the key
            //has no equivalent of.
            KeyAlgorithmFamily.MLKem => X509KeyUsageFlags.None,
            _ => X509KeyUsageFlags.DigitalSignature
        };
#pragma warning restore FLUENTCERT001


    /// <summary>
    /// Returns <see cref="X509KeyUsageFlags.KeyEncipherment"/> only when the certificate's public key can
    /// actually perform key transport, which in practice means RSA. An EC key cannot encrypt key material
    /// (it uses key agreement instead, which is <see cref="X509KeyUsageFlags.KeyAgreement"/>), and DSA is
    /// signature-only, so asserting keyEncipherment for either claims a capability the key does not have.
    /// RFC 8813 s3 makes this a MUST NOT for id-ecPublicKey keys; the CA/Browser Forum TLS Baseline
    /// Requirements s7.1.2.7.11 list keyEncipherment as not permitted for ECC public keys, and the S/MIME
    /// Baseline Requirements s7.1.2.3 reach the same result via "Other bit positions SHALL NOT be set".
    /// </summary>
    private static X509KeyUsageFlags KeyEnciphermentIfSupported(CertificateBuilder builder)
        => builder.PublicKey?.Oid.Value switch {
            Oids.Rsa => X509KeyUsageFlags.KeyEncipherment,
            //ML-KEM is a key-encapsulation mechanism: encapsulating to the certified public key is
            //key transport, which is what keyEncipherment asserts. RFC 9629 s3 and the draft LAMPS
            //profile for ML-KEM certificates both put it here rather than under keyAgreement.
            Oids.MLKem512 or Oids.MLKem768 or Oids.MLKem1024 => X509KeyUsageFlags.KeyEncipherment,
            _ => X509KeyUsageFlags.None
        };


    /// <summary>
    /// Maps a public key's algorithm OID onto a <see cref="KeyAlgorithm"/>, or <see langword="null"/> when it is
    /// not one the builder knows how to generate. Unlike the key-pair overload an unrecognised algorithm is not
    /// an error here: the builder only has to put the key in the certificate, not produce one like it.
    /// </summary>
    /// <remarks>
    /// <see cref="Oids.EcPublicKey"/> maps to <see cref="KeyAlgorithm.ECDsa()"/> because an ECDH public key is
    /// indistinguishable from an ECDsa one: both carry that OID and the same curve parameters, so the intended
    /// use cannot be read back off the key. <see cref="SetPublicKey"/> keeps an explicit
    /// <see cref="KeyAlgorithm.ECDiffieHellman()"/> choice rather than overwriting it with this guess.
    /// </remarks>
    private static KeyAlgorithm? GetKeyAlgorithm(PublicKey? key)
    {
#pragma warning disable CS0618 // Type or member is obsolete
#pragma warning disable FLUENTCERT001 // Post-quantum support is experimental
        return key?.Oid.Value switch {
            Oids.Rsa => KeyAlgorithm.RSA(),
            Oids.EcPublicKey => KeyAlgorithm.ECDsa(),
            Oids.Dsa => KeyAlgorithm.DSA(),
            //A post-quantum OID names its parameter set exactly, so the lookup is unambiguous
            { } oid when KeyAlgorithm.PostQuantumAlgorithms.FirstOrDefault(x => x.Oid == oid) is { } pqc => pqc,
            _ => null
        };
#pragma warning restore FLUENTCERT001
#pragma warning restore CS0618 // Type or member is obsolete
    }


    /// <summary>
    /// Derives a <see cref="KeyAlgorithm"/> from a supplied key. The key's own parameters win over anything
    /// previously configured, since it is the key that will actually end up in the certificate.
    /// </summary>
    private static KeyAlgorithm? GetKeyAlgorithm(AsymmetricAlgorithm? keys)
    {
#pragma warning disable CS0618 // Type or member is obsolete
        return keys switch {
            ECDsa ecdsa => KeyAlgorithm.ECDsa(ecdsa.ExportParameters(false).Curve),
            ECDiffieHellman ecdh => KeyAlgorithm.ECDiffieHellman(ecdh.ExportParameters(false).Curve),
            RSA rsa => KeyAlgorithm.RSA(rsa.KeySize),
            DSA dsa => KeyAlgorithm.DSA(dsa.KeySize),
            null => null,
            _ => throw new NotSupportedException($"Unsupported AsymmetricAlgorithm: {keys.GetType()}")
        };
#pragma warning restore CS0618 // Type or member is obsolete
    }


    private static KeyAlgorithm? GetKeyAlgorithm(CertificateKey? keys)
    {
        if (keys == null) {
            return null;
        }

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
#pragma warning disable FLUENTCERT001
        //The BCL algorithm's Name matches the parameter-set name this library uses, so one lookup by
        //name covers all three post-quantum signature families
        var name = keys.AsMLDsa?.Algorithm.Name
            ?? keys.AsSlhDsa?.Algorithm.Name
            ?? keys.AsCompositeMLDsa?.Algorithm.Name
            ?? keys.AsMLKem?.Algorithm.Name;

        if (name != null) {
            return KeyAlgorithm.PostQuantumAlgorithms.FirstOrDefault(x => x.Name == name)
                ?? throw new NotSupportedException($"Unsupported post-quantum parameter set: {name}");
        }
#pragma warning restore FLUENTCERT001
#pragma warning restore SYSLIB5006
#endif

        return GetKeyAlgorithm(keys.AsAsymmetricAlgorithm);
    }


    /// <summary>
    /// Builds the <see cref="PublicKey"/> for a supplied key pair. The post-quantum types have their own
    /// <see cref="PublicKey"/> constructors rather than going through <see cref="AsymmetricAlgorithm"/>.
    /// </summary>
    private static PublicKey? CreatePublicKey(CertificateKey? keys)
    {
        if (keys == null) {
            return null;
        }

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
#pragma warning disable FLUENTCERT001
        if (keys.AsMLDsa is { } mldsa) {
            return new PublicKey(mldsa);
        }

        if (keys.AsSlhDsa is { } slhdsa) {
            return new PublicKey(slhdsa);
        }

        if (keys.AsCompositeMLDsa is { } composite) {
            return new PublicKey(composite);
        }

        if (keys.AsMLKem is { } mlkem) {
            return new PublicKey(mlkem);
        }
#pragma warning restore FLUENTCERT001
#pragma warning restore SYSLIB5006
#endif

        return keys.AsAsymmetricAlgorithm is { } key
            ? new PublicKey(key)
            : throw new NotSupportedException($"Cannot derive a public key from a {keys.Family} key on this target framework");
    }


    private static readonly X500NameBuilder EmptyNameBuilder = new();
    private static readonly X509ExtensionOidEqualityComparer X509ExtensionOidEqualityComparer = new();
}
