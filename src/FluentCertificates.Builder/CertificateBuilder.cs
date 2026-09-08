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
    private ImmutableHashSet<X509Extension> _extensions { get; init; } = EmptyExtensions;

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
    /// The counterpart to <see cref="SetSignatureGenerator"/> for a key this process cannot use directly,
    /// such as one held in an HSM, a TPM or a cloud KMS. It clears
    /// <see cref="SetKeyPair(AsymmetricAlgorithm)"/> and suppresses the automatic key generation
    /// <see cref="Create"/> would otherwise do, so the resulting certificate has no private key attached.
    /// <see cref="KeyAlgorithm"/> follows the key where the algorithm is recognised.
    /// </para>
    /// <para>
    /// Self-signing this way also needs <see cref="SetSignatureGenerator"/>, since the builder holds no key
    /// it could sign with. Nothing checks that the generator corresponds to this public key; that pairing is
    /// yours to get right.
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
    /// The extension point for a key this process cannot use directly, such as one held in an HSM, a TPM or
    /// a cloud KMS: implement <see cref="X509SignatureGenerator"/> against the remote key and the builder
    /// never needs the private key itself. The generator determines its own signature algorithm, so
    /// <see cref="HashAlgorithm"/> and <see cref="RSASignaturePadding"/> do not apply to it.
    /// </para>
    /// <para>
    /// It replaces whichever signature would otherwise have been produced. With an <see cref="Issuer"/> set
    /// that is the issuer's signature, and the issuer certificate no longer needs an attached private key.
    /// Otherwise it is the self-signature, which also needs the matching key pair from
    /// <see cref="SetKeyPair(AsymmetricAlgorithm)"/> so the certificate's own public key agrees with it.
    /// </para>
    /// </remarks>
    /// <param name="value">The signature generator to sign with, or <see langword="null"/> to derive one from the signing key.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified signature generator.</returns>
    public CertificateBuilder SetSignatureGenerator(X509SignatureGenerator? value)
        => this with { SignatureGenerator = value };



    /// <summary>
    /// Adds an extension to the certificate, replacing any extension already present under the same OID
    /// regardless of its runtime type.
    /// </summary>
    /// <param name="extension">The extension to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extension added.</returns>
    public CertificateBuilder AddExtension(X509Extension extension)
        => SetExtension(extension);

    /// <summary>
    /// Adds multiple extensions to the certificate, replacing any extension already present under the same
    /// OID regardless of its runtime type. Where <paramref name="values"/> itself carries two extensions
    /// under one OID, the last one replaces the others.
    /// </summary>
    /// <param name="values">The extensions to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extensions added.</returns>
    public CertificateBuilder AddExtensions(params IEnumerable<X509Extension> values)
        => values.Aggregate(this, (builder, extension) => builder.SetExtension(extension));

    /// <summary>
    /// Sets the certificate extensions, replacing any already on the builder. Where <paramref name="values"/>
    /// itself carries two extensions under one OID, the last one replaces the others.
    /// </summary>
    /// <param name="values">The extensions to set.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified extensions.</returns>
    public CertificateBuilder SetExtensions(params IEnumerable<X509Extension> values)
        => values.Aggregate(this with { _extensions = EmptyExtensions }, (builder, extension) => builder.SetExtension(extension));


    /// <summary>
    /// Sets the Authority Information Access extension, naming a single OCSP responder and a single
    /// CA Issuers location.
    /// </summary>
    /// <param name="ocspUri">The URI of the OCSP responder, or <see langword="null"/> to omit it.</param>
    /// <param name="caIssuersUri">The URI the issuer's certificate can be downloaded from, or <see langword="null"/> to omit it.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Authority Information Access extension.</returns>
    /// <exception cref="ArgumentException">Thrown when both URIs are omitted.</exception>
    /// <remarks>Passing the literal <c>null</c> for both arguments is ambiguous with the collection overload; cast at least one, e.g. <c>(string?)null</c>.</remarks>
    public CertificateBuilder SetAuthorityInformationAccess(string? ocspUri, string? caIssuersUri)
        => SetAuthorityInformationAccess(
            ocspUri == null ? null : [ocspUri],
            caIssuersUri == null ? null : [caIssuersUri]);

    /// <summary>
    /// Sets the Authority Information Access extension, naming where the issuer can be reached for
    /// revocation status and for its own certificate.
    /// </summary>
    /// <param name="ocspUris">The URIs of the OCSP responders, or <see langword="null"/> to omit them.</param>
    /// <param name="caIssuersUris">The URIs the issuer's certificate can be downloaded from, or <see langword="null"/> to omit them.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Authority Information Access extension.</returns>
    /// <exception cref="ArgumentException">Thrown when both collections are <see langword="null"/> or empty.</exception>
    /// <remarks>The extension is non-critical, and there is no option to change that: RFC 5280 s4.2.2.1 requires
    /// conforming CAs to mark it non-critical. A critical one supplied through <see cref="AddExtension"/> or accepted
    /// from a certificate signing request is issued non-critical anyway; see <see cref="CreateCertificateRequest"/>.</remarks>
    public CertificateBuilder SetAuthorityInformationAccess(IEnumerable<string>? ocspUris, IEnumerable<string>? caIssuersUris)
        => SetExtension(new X509AuthorityInformationAccessExtension(ocspUris, caIssuersUris));


    /// <summary>
    /// Sets the CRL Distribution Points extension, naming where the issuer publishes its revocation lists.
    /// </summary>
    /// <param name="uris">The URIs the CRL can be downloaded from. Must contain at least one URI, and each must be ASCII.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified CRL Distribution Points extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="uris"/> is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when a URI contains a character outside the 7-bit ASCII set.</exception>
    /// <remarks>The extension is non-critical; use the overload taking <c>critical</c> to change that.</remarks>
    public CertificateBuilder SetCrlDistributionPoints(params IEnumerable<string> uris)
        => SetCrlDistributionPoints(uris, false);

    /// <summary>
    /// Sets the CRL Distribution Points extension, naming where the issuer publishes its revocation lists.
    /// </summary>
    /// <param name="uris">The URIs the CRL can be downloaded from. Must contain at least one URI, and each must be ASCII.</param>
    /// <param name="critical">Whether to mark the extension critical. RFC 5280 s4.2.1.13 says it SHOULD be non-critical;
    /// the CA/Browser Forum Baseline Requirements certificate profiles (s7.1.2) require it non-critical.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified CRL Distribution Points extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="uris"/> is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when a URI contains a character outside the 7-bit ASCII set.</exception>
    public CertificateBuilder SetCrlDistributionPoints(IEnumerable<string> uris, bool critical)
        => SetExtension(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(uris, critical));


    /// <summary>
    /// Sets the Certificate Policies extension, naming the policies under which the certificate is issued.
    /// </summary>
    /// <param name="policyIdentifier">The OID of the first (or only) policy to assert.</param>
    /// <param name="morePolicyIdentifiers">The OIDs of any further policies to assert.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Certificate Policies extension.</returns>
    /// <remarks>The extension is non-critical; use an overload taking <c>critical</c> to change that.</remarks>
    public CertificateBuilder SetCertificatePolicies(string policyIdentifier, params IEnumerable<string> morePolicyIdentifiers)
        => SetCertificatePolicies([policyIdentifier, .. morePolicyIdentifiers]);

    /// <summary>
    /// Sets the Certificate Policies extension, naming the policies under which the certificate is issued.
    /// </summary>
    /// <param name="policyIdentifiers">The policies to assert. Must contain at least one.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Certificate Policies extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="policyIdentifiers"/> is empty.</exception>
    /// <exception cref="ArgumentException">Thrown when an <see cref="Oid"/> in <paramref name="policyIdentifiers"/> has no <see cref="Oid.Value"/>.</exception>
    /// <remarks>The extension is non-critical; use the overload taking <c>critical</c> to change that.</remarks>
    public CertificateBuilder SetCertificatePolicies(params IEnumerable<Oid> policyIdentifiers)
        => SetCertificatePolicies(policyIdentifiers, false);

    /// <summary>
    /// Sets the Certificate Policies extension, naming the policies under which the certificate is issued.
    /// </summary>
    /// <param name="policyIdentifiers">The policies to assert. Must contain at least one.</param>
    /// <param name="critical">Whether to mark the extension critical. A critical extension forces any relying party that cannot interpret the Certificate Policies extension to reject the certificate.
    /// The CA/Browser Forum Baseline Requirements certificate profiles (s7.1.2) require it non-critical.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Certificate Policies extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="policyIdentifiers"/> is empty.</exception>
    /// <exception cref="ArgumentException">Thrown when an <see cref="Oid"/> in <paramref name="policyIdentifiers"/> has no <see cref="Oid.Value"/>.</exception>
    public CertificateBuilder SetCertificatePolicies(IEnumerable<Oid> policyIdentifiers, bool critical)
        => SetCertificatePolicies((policyIdentifiers ?? throw new ArgumentNullException(nameof(policyIdentifiers)))
            .Select(x => x?.Value ?? throw new ArgumentException("Every Oid in policyIdentifiers must have a Value", nameof(policyIdentifiers))), critical);

    /// <summary>
    /// Sets the Certificate Policies extension, naming the policies under which the certificate is issued.
    /// </summary>
    /// <param name="policyIdentifiers">The OIDs of the policies to assert. Must contain at least one OID.</param>
    /// <param name="critical">Whether to mark the extension critical. A critical extension forces any relying party that cannot interpret the Certificate Policies extension to reject the certificate.
    /// The CA/Browser Forum Baseline Requirements certificate profiles (s7.1.2) require it non-critical.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Certificate Policies extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="policyIdentifiers"/> is empty.</exception>
    public CertificateBuilder SetCertificatePolicies(IEnumerable<string> policyIdentifiers, bool critical = false)
        => SetExtension(new X509CertificatePolicyExtension(policyIdentifiers, critical));


    /// <summary>
    /// Takes the subject name and the public key to certify out of a received certificate signing request,
    /// and nothing else. Everything a requester asked for beyond those two is discarded.
    /// </summary>
    /// <remarks>
    /// The CA half of a PKCS#10 exchange, and the counterpart to
    /// <see cref="CreateCertificateSigningRequest"/>. Issuer, validity, usage profile and extensions all stay
    /// yours, so one configured builder can issue from many requests. The private key stays with the
    /// requester, so the certificate has none attached and an <see cref="Issuer"/> or
    /// <see cref="SignatureGenerator"/> must sign it. Any subject, public key or key pair already on the
    /// builder is replaced, and <see cref="KeyAlgorithm"/> follows the request's key under
    /// <see cref="SetPublicKey"/>'s rules. Nothing here re-checks the request's signature; that is settled
    /// when it is parsed.
    /// </remarks>
    /// <param name="csr">The received certificate signing request.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the request's subject and public key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="csr"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the request's subject contains a multi-valued
    /// relative distinguished name, which <see cref="X500NameBuilder"/> cannot represent.</exception>
    public CertificateBuilder UseCertificateSigningRequest(CertificateSigningRequest csr)
    {
        ArgumentNullException.ThrowIfNull(csr);

        return SetSubject(csr.CertificateRequest.SubjectName)
            .SetPublicKey(csr.CertificateRequest.PublicKey);
    }


    /// <summary>
    /// Takes the subject name and the public key to certify out of a received certificate signing request,
    /// along with those of its requested extensions that <paramref name="accept"/> returns
    /// <see langword="true"/> for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An accepted extension counts as the CA's own: it replaces anything already present under the same OID
    /// and overrides what the <see cref="Usage"/> profile would have generated. Afterwards the last call
    /// wins, so <see cref="AddExtension"/> or a <c>Set*</c> helper writing that OID replaces it in turn.
    /// </para>
    /// <para>
    /// <b>Nothing in the request is screened here.</b> Not the subject name, not a Subject Key Identifier,
    /// and not what any other extension asserts. <see cref="CreateCertificateRequest"/> later measures the
    /// whole extension set against the <see cref="Issuer"/> and <see cref="Usage"/>, but accepting an
    /// extension is not itself what makes it safe. Only you know what your policy allows, so apply it in
    /// <paramref name="accept"/>, and call <see cref="SetSubject(X500NameBuilder)"/> afterwards to issue
    /// under a name you have verified.
    /// </para>
    /// <para>
    /// <b>Set a <see cref="Usage"/> before accepting anything.</b> The refusals
    /// <see cref="CreateCertificateRequest"/> describes are the only check on what an accepted extension
    /// asserts, and a builder with no <see cref="Usage"/> makes none of them: a request can then carry
    /// <c>cA=TRUE</c> and <c>keyCertSign</c> and issue a certificate that signs others chaining to your
    /// issuer.
    /// </para>
    /// <para>
    /// Accepted extensions stay on the builder this returns, so issue each further request from the builder
    /// as it stood before this call. A request parsed without
    /// <see cref="CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions"/> carries no extensions, so
    /// <paramref name="accept"/> is never called.
    /// </para>
    /// </remarks>
    /// <param name="csr">The received certificate signing request.</param>
    /// <param name="accept">Decides, per requested extension, whether the CA honours it.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the request's subject, public key and accepted extensions.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="csr"/> or <paramref name="accept"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the request's subject contains a multi-valued
    /// relative distinguished name, which <see cref="X500NameBuilder"/> cannot represent.</exception>
    public CertificateBuilder UseCertificateSigningRequest(CertificateSigningRequest csr, Func<X509Extension, bool> accept)
    {
        ArgumentNullException.ThrowIfNull(csr);
        ArgumentNullException.ThrowIfNull(accept);

        var builder = UseCertificateSigningRequest(csr);
        foreach (var extension in csr.CertificateRequest.CertificateExtensions.Where(accept)) {
            builder = builder.SetExtension(extension);
        }
        return builder;
    }


    /// <summary>
    /// Refuses an Authority Key Identifier naming a key other than the issuer's, whoever supplied it. RFC
    /// 5280 s4.2.1.2 makes the issuer's Subject Key Identifier the value that MUST appear there, so setting
    /// an <see cref="Issuer"/> settles what belongs in it.
    /// </summary>
    /// <remarks>
    /// A Subject Key Identifier is deliberately not checked: s4.2.1.2 only recommends deriving one from the
    /// key, allowing "other methods of generating unique numbers", so no comparison tells a conforming label
    /// from a careless one.
    /// </remarks>
    private static void CheckKeyIdentifierIsGenuine(CertificateBuilder builder, IEnumerable<X509Extension> extensions)
    {
        var extension = extensions.FirstOrDefault(x => x.Oid?.Value == Oids.AuthorityKeyIdentifier);
        if (extension == null || builder.Issuer == null) {
            return;
        }

        //Comparing whole encodings would refuse a conforming extension for also carrying authorityCertIssuer
        //and authorityCertSerialNumber, which s4.2.1.1 permits alongside the keyIdentifier.
        var supplied = ReadKeyIdentifier(extension);

        //s4.2.1.1 requires the keyIdentifier field in every certificate a conforming CA generates, and this
        //extension displaces the one the builder would otherwise write.
        if (supplied == null) {
            throw new InvalidOperationException("An authority key identifier carries no readable key identifier, so it names no signing key and would replace the one generated for the issuer. Remove it to have the correct one generated, or leave the certificate no issuer to identify");
        }

        if (!supplied.Value.Span.SequenceEqual(GetSubjectKeyIdentifier(builder.Issuer).Span)) {
            throw new InvalidOperationException("An authority key identifier does not identify the issuer's own key, which describes a signer that did not sign this certificate. Remove it; the correct value is generated automatically");
        }
    }


    private static ReadOnlyMemory<byte>? ReadKeyIdentifier(X509Extension extension)
    {
        try {
            return new X509AuthorityKeyIdentifierExtension(extension.RawData, extension.Critical).KeyIdentifier;
        } catch (CryptographicException) {
            return null;
        }
    }


    //Adding over an extension already under this OID would keep the one already there, since that is how
    //ImmutableHashSet resolves a collision, so removing first is what makes this a replacement. Remove reads
    //the set's own comparer, which matches on the OID alone.
    private CertificateBuilder SetExtension(X509Extension extension)
        => this with { _extensions = _extensions.Remove(extension).Add(extension) };


    //For a caller holding an OID but no extension to hand Remove
    private CertificateBuilder RemoveExtensionsByOidValue(string? oid)
        => this with {
            _extensions = _extensions
                .Where(x => !String.Equals(x.Oid?.Value, oid))
                .ToImmutableHashSet(X509ExtensionOidEqualityComparer)
        };


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
    /// <param name="generator">A delegate that returns a <see cref="byte"/> array representing the serial number to use for the certificate.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified serial number generator.</returns>
    public CertificateBuilder SetSerialNumberGenerator(Func<byte[]> generator)
        => this with { SerialNumberGenerator = generator };


    /// <summary>
    /// Sets the subject alternative names, discarding any Subject Alternative Name extension already on the
    /// builder.
    /// </summary>
    /// <param name="configureSan">A function to configure the SAN builder.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified SANs.</returns>
    public CertificateBuilder SetSubjectAlternativeNames(Func<GeneralNameListBuilder, GeneralNameListBuilder> configureSan)
        => SetSubjectAlternativeNames(configureSan(new GeneralNameListBuilder()).Create());


    /// <summary>
    /// Sets the subject alternative names, discarding any Subject Alternative Name extension already on the
    /// builder.
    /// </summary>
    /// <remarks>
    /// These names are encoded into their extension at issuance, alongside the ones the <see cref="Usage"/>
    /// profile generates, and an extension added under that OID would otherwise take precedence over the
    /// whole generated set. Discarding it here is what makes this call the last word on which names the
    /// certificate carries, whether the extension it displaces came from <see cref="AddExtension"/> or was
    /// accepted out of a signing request. Call it before
    /// <see cref="UseCertificateSigningRequest(CertificateSigningRequest,Func{X509Extension,bool})"/> to let
    /// an accepted Subject Alternative Name win instead.
    /// </remarks>
    /// <param name="san">The subject alternative names. An empty sequence leaves the certificate with no
    /// Subject Alternative Name extension at all, discarding any already present.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified SANs.</returns>
    public CertificateBuilder SetSubjectAlternativeNames(IEnumerable<GeneralName> san)
        => RemoveExtensionsByOidValue(Oids.SubjectAltName) with { _subjectAlternativeNames = [.. san] };


    /// <summary>
    /// Validates the current builder configuration and throws if invalid.
    /// </summary>
    public void Validate()
    {
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
    /// Returns the criticality RFC 5280 demands of this extension, or <see langword="null"/> where it
    /// leaves the choice open. Every rule here is a MUST about the flag beside the extension rather than
    /// the value inside it, so a violation can be corrected without altering what the extension says.
    /// </summary>
    private static bool? IsRequiredCriticality(X509Extension extension, CertificateBuilder builder, IEnumerable<X509Extension> extensions)
        => extension.Oid?.Value switch {
            //s4.2.1.1, s4.2.1.2, s4.2.1.8, s4.2.1.15, s4.2.2.1 and s4.2.2.2: MUST be non-critical.
            Oids.AuthorityKeyIdentifier or Oids.SubjectKeyIdentifier or Oids.SubjectDirectoryAttributes
                or Oids.FreshestCrl or Oids.AuthorityInformationAccess or Oids.SubjectInformationAccess
                => false,
            //s4.2.1.10, s4.2.1.11 and s4.2.1.14: MUST be critical. Left non-critical, a relying party that
            //does not implement the extension ignores the restriction instead of refusing the certificate.
            Oids.NameConstraints or Oids.CertPolicyConstraints or Oids.InhibitAnyPolicyExtension
                => true,
            //s4.2.1.9: MUST be critical in a CA certificate whose key validates signatures on certificates.
            //That same sentence leaves the choice open for a CA certificate whose key does not, naming an
            //indirect CRL issuer as the example, and for an end-entity certificate. A value that will not
            //decode has no cA bit to read, so it goes out as supplied.
            Oids.BasicConstraints2 when IsCertificateAuthority(extension) == true && MayValidateCertificateSignatures(extensions)
                => true,
            //s4.2.1.6: MUST be critical when the subject is empty, being then the only name in the certificate.
            Oids.SubjectAltName when builder.Subject.RelativeDistinguishedNames.IsEmpty
                => true,
            _ => null
        };


    private static bool? IsCertificateAuthority(X509Extension extension)
    {
        try {
            return new X509BasicConstraintsExtension(extension, extension.Critical).CertificateAuthority;
        } catch (CryptographicException) {
            return null;
        }
    }


    /// <summary>
    /// Whether the certified key may be used to validate signatures on certificates, which is the condition
    /// RFC 5280 s4.2.1.9 attaches to its criticality MUST. Only a key usage extension that reads back and
    /// omits <see cref="X509KeyUsageFlags.KeyCertSign"/> settles that it may not: with none present the key
    /// is unrestricted, and one this builder cannot read establishes no restriction either.
    /// </summary>
    private static bool MayValidateCertificateSignatures(IEnumerable<X509Extension> extensions)
    {
        var keyUsage = extensions.FirstOrDefault(x => String.Equals(x.Oid?.Value, Oids.KeyUsage));
        if (keyUsage == null) {
            return true;
        }

        try {
            return new X509KeyUsageExtension(keyUsage, keyUsage.Critical).KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign);
        } catch (CryptographicException) {
            return true;
        }
    }


    private static X509Extension ConformCriticality(X509Extension extension, CertificateBuilder builder, IEnumerable<X509Extension> extensions)
    {
        //Correcting on the way out rather than on the way in keeps Extensions a faithful record of what the
        //builder was handed, and is the only point at which the empty-subject rule can be settled, since
        //the subject can still change after an extension is added. Criticality is encoded beside the
        //extension rather than within it, so the corrected copy carries the value that was asked for.
        var required = IsRequiredCriticality(extension, builder, extensions);
        return required == null || required == extension.Critical
            ? extension
            : new X509Extension(extension.Oid!, extension.RawData, required.Value);
    }


    private static void CheckExtensionsAgreeWithUsage(CertificateBuilder builder, IEnumerable<X509Extension> extensions)
    {
        //A supplied extension normally replaces whatever the Usage profile generated under the same OID,
        //which is the point: a CA refines its own profile. These two contradict it instead, and what is
        //wrong is in the value, so criticality conformance cannot reach it. cRLSign is deliberately not
        //checked: an indirect CRL issuer is conventionally an end-entity certificate asserting exactly that.
        //Without a Usage there is no profile to measure against, so the check is skipped entirely, leaving
        //such a request to its accept predicate alone.
        if (builder.Usage == null) {
            return;
        }

        bool profileIsCa = builder.Usage == CertificateUsage.CA;

        foreach (var extension in extensions) {
            switch (extension.Oid?.Value) {
                case Oids.BasicConstraints2:
                    var constraints = Decode(extension, x => new X509BasicConstraintsExtension(x, x.Critical), x => new X509BasicConstraintsExtension(x.CertificateAuthority, x.HasPathLengthConstraint, x.PathLengthConstraint, extension.Critical))
                        ?? throw UnreadableValue(extension, "basic constraints");
                    if (constraints.CertificateAuthority != profileIsCa) {
                        throw new InvalidOperationException(constraints.CertificateAuthority
                            ? $"A basic constraints extension asserting cA=TRUE contradicts {nameof(CertificateUsage)}.{builder.Usage}, which issues end-entity certificates. Reject it, or set {nameof(CertificateUsage)}.{nameof(CertificateUsage.CA)}"
                            : $"A basic constraints extension asserting cA=FALSE contradicts {nameof(CertificateUsage)}.{nameof(CertificateUsage.CA)}. Reject it, or choose an end-entity {nameof(CertificateUsage)}");
                    }
                    break;

                case Oids.KeyUsage:
                    var usages = Decode(extension, x => new X509KeyUsageExtension(x, x.Critical), x => new X509KeyUsageExtension(x.KeyUsages, extension.Critical))
                        ?.KeyUsages ?? throw UnreadableValue(extension, "key usage");
                    if (!profileIsCa && usages.HasFlag(X509KeyUsageFlags.KeyCertSign)) {
                        throw new InvalidOperationException($"A key usage extension asserting {nameof(X509KeyUsageFlags.KeyCertSign)} contradicts {nameof(CertificateUsage)}.{builder.Usage}, which issues end-entity certificates. Reject it, or set {nameof(CertificateUsage)}.{nameof(CertificateUsage.CA)}");
                    }
                    if (profileIsCa && !usages.HasFlag(X509KeyUsageFlags.KeyCertSign)) {
                        throw new InvalidOperationException($"A key usage extension that does not assert {nameof(X509KeyUsageFlags.KeyCertSign)} contradicts {nameof(CertificateUsage)}.{nameof(CertificateUsage.CA)}, whose certificates exist to sign other certificates. Reject it, or choose an end-entity {nameof(CertificateUsage)}");
                    }
                    break;
            }
        }
    }


    private static void CheckSubjectAgreesWithUsage(CertificateBuilder builder, X500DistinguishedName subject)
    {
        if (builder.Usage is null) {
            return;
        }

        if (builder.Issuer == null) {
            //With no Issuer the certificate is written self-issued, so there is no separate name to collide
            //with -- but only when the key signing it is the subject's own. A generator holding some other
            //key mints a certificate under a name of the requester's choosing that a relying party can still
            //build a path for, since the signature verifies against whoever does own that key. Java will then
            //accept it as a certificate revocation list issuer for the name it bears, cA=FALSE and all. The CA
            //profile is no exemption from this: there it certifies a foreign key under the signing authority's
            //own name, with cA=TRUE and keyCertSign, which is that authority impersonated outright.
            if (builder.SignatureGenerator != null && !IsSubjectsOwnKey(builder)) {
                throw new InvalidOperationException($"The certificate would be self-issued, naming itself as its own issuer, yet signed by a key that is not its own. A relying party reads that as the named issuer vouching for this subject. Set an {nameof(Issuer)} so the certificate names the authority that really signed it, or sign with the subject's own key");
            }
            return;
        }

        //A certificate under the issuer's own name is ordinarily key rollover, but only when the issuer
        //genuinely signed it. A SignatureGenerator holding some other key mints one that a relying party
        //doing the RFC 5280 s6.3.3 name match reads as the issuer's successor -- the same impersonation the
        //no-Issuer case refuses, reached by borrowing a real issuer's name instead of leaving Issuer unset.
        //Whether some other name would also be read as the issuer's is the caller's to judge, so the names
        //are compared as encoded rather than folded. With no SignatureGenerator supplied, Create() signs
        //with Issuer's own private key, so there is nothing to check.
        if (builder.SignatureGenerator != null
            && subject.RawData.AsSpan().SequenceEqual(builder.Issuer.SubjectName.RawData)
            && !IsIssuersOwnKey(builder)) {
            throw new InvalidOperationException($"The certificate would be issued under the issuer's own name, which is ordinarily key rollover, yet signed by a key that is not the issuer's own. A relying party reads that as the issuer vouching for a successor certificate it never signed. Sign with the issuer's own key, or issue under a different subject");
        }
    }


    private static bool IsSubjectsOwnKey(CertificateBuilder builder)
        => builder.PublicKey != null
        && builder.SignatureGenerator!.PublicKey.ExportSubjectPublicKeyInfo()
            .AsSpan().SequenceEqual(builder.PublicKey.ExportSubjectPublicKeyInfo());


    private static bool IsIssuersOwnKey(CertificateBuilder builder)
        => builder.SignatureGenerator!.PublicKey.ExportSubjectPublicKeyInfo()
            .AsSpan().SequenceEqual(builder.Issuer!.PublicKey.ExportSubjectPublicKeyInfo());


    private static T? Decode<T>(X509Extension extension, Func<X509Extension, T> decode, Func<T, X509Extension> encode) where T : class
    {
        //Answers only if the value re-encodes to the very bytes it came from. .NET's decoder is stricter
        //than the ones that will later read the certificate: bytes it rejects, such as a well-formed
        //SEQUENCE with a trailing NULL after it, are read by OpenSSL and Windows CryptoAPI as whatever the
        //well-formed part says, letting a requester assert what the caller's check failed to see.
        try {
            var decoded = decode(extension);

            //Re-encoding is also what forces the decode: the BCL types parse lazily, on first read of a
            //decoded property, so this is where a bad value throws. The two halves throw differently, the
            //decoder CryptographicException and this constructor ArgumentException for a field it parsed
            //but cannot represent, such as a negative pathLenConstraint.
            return encode(decoded).RawData.AsSpan().SequenceEqual(extension.RawData)
                ? decoded
                : null;
        } catch (Exception ex) when (ex is CryptographicException or ArgumentException) {
            return null;
        }
    }


    private static InvalidOperationException UnreadableValue(X509Extension extension, string name)
    {
        //Quoted so a caller can find the offending extension among everything they accepted, truncated
        //because a requester chooses how long it is. Not every refusal is malformed DER: a pathLenConstraint
        //too large for an Int32 is well-formed and conforming, and is refused only for being unreadable.
        var quoted = Convert.ToHexString(extension.RawData.AsSpan(0, Math.Min(extension.RawData.Length, QuotedValueLimit)));
        var ellipsis = extension.RawData.Length > QuotedValueLimit ? "..." : "";
        return new InvalidOperationException($"A {name} extension's value does not read back as the bytes it was supplied as, so what it asserts to a validator cannot be established here and may not agree with {nameof(CertificateUsage)}. Reject it, or supply one this builder can read. Value: {quoted}{ellipsis}");
    }


    private const int QuotedValueLimit = 128;


    /// <summary>
    /// Creates a <see cref="CertificateRequest"/> based on the builder's parameters.
    /// </summary>
    /// <remarks>
    /// <para>An <see cref="Issuer"/> contributes an Authority Key Identifier extension unless one was
    /// already supplied, in which case the supplied extension stands, provided it identifies the
    /// <see cref="Issuer"/>'s own key.</para>
    /// <para>
    /// Where RFC 5280 states a criticality MUST for an extension, it is written with that criticality. The
    /// value is untouched and <see cref="Extensions"/> still reports whatever it was given, so this changes
    /// only what is issued. The README lists which extensions and which sections.
    /// </para>
    /// <para>
    /// A basic constraints or key usage extension is refused rather than corrected, because what is wrong
    /// with it is in the value: one disagreeing with the <see cref="Usage"/> profile about whether this is a
    /// certificate authority or may sign certificates, or one whose value does not read back as the bytes it
    /// was supplied as. Neither is checked without a <see cref="Usage"/>. What extensions a profile permits,
    /// and whether a subject is entitled to the name it asks for, are yours to decide.
    /// </para>
    /// </remarks>
    /// <returns>A new <see cref="CertificateRequest"/> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown if no key pair is set. Make sure to call the <see cref="SetKeyPair(AsymmetricAlgorithm)"/> method as
    /// certificate requests require a manually specified key pair.</exception>
    /// <exception cref="InvalidOperationException">Thrown when an extension's value contradicts the
    /// <see cref="Usage"/> profile, when the certificate would be signed by a key that is not the one it
    /// names as its issuer, or when an Authority Key Identifier does not identify the <see cref="Issuer"/>'s
    /// own key.</exception>
    public CertificateRequest CreateCertificateRequest()
    {
        if (PublicKey == null) {
            throw new ArgumentNullException($"Call {nameof(SetKeyPair)}(...) first to provide an asymmetric public/private keypair");
        }

        var dn = Subject.Create();

        CheckSubjectAgreesWithUsage(this, dn);

        var request = new CertificateRequest(dn, PublicKey, HashAlgorithm);

        var extensions = BuildExtensions(this);

        CheckExtensionsAgreeWithUsage(this, extensions);
        CheckKeyIdentifierIsGenuine(this, extensions);

        foreach (var extension in extensions) {
            request.CertificateExtensions.Add(ConformCriticality(extension, this, extensions));
        }

        //Added straight to the request rather than through BuildExtensions, so nothing lets a supplied
        //extension replace it and adding both would make CertificateRequest throw: hence the guard. The
        //false is RFC 5280 s4.2.1.1's non-critical, already conforming, so ConformCriticality is not needed.
        if (Issuer != null && !extensions.Any(x => String.Equals(x.Oid?.Value, Oids.AuthorityKeyIdentifier))) {
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(GetSubjectKeyIdentifier(Issuer).Span));
        }

        return request;
    }


    /// <summary>
    /// The key identifier naming a certificate authority: the one it publishes in its own Subject Key
    /// Identifier, or one derived from its public key where it publishes none.
    /// </summary>
    /// <remarks>
    /// Deriving it, rather than naming such a CA by issuer and serial number, follows RFC 5280 s4.2.1.1: the
    /// keyIdentifier field is required in every certificate a conforming CA generates, and those two fields
    /// are permitted alongside it rather than in place of it.
    /// </remarks>
    private static ReadOnlyMemory<byte> GetSubjectKeyIdentifier(X509Certificate2 ca)
        => ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault() is { } published
            ? published.SubjectKeyIdentifierBytes
            : new X509SubjectKeyIdentifierExtension(ca.PublicKey, false).SubjectKeyIdentifierBytes;


    /// <summary>
    /// Creates a <see cref="CertificateSigningRequest"/> based on the builder's parameters.
    /// </summary>
    /// <returns>A new <see cref="CertificateSigningRequest"/> instance.</returns>
    /// <exception cref="NotSupportedException">Thrown when the key to certify is an <see cref="System.Security.Cryptography.ECDiffieHellman"/>
    /// key, which cannot produce the proof-of-possession signature a PKCS#10 request is built around.</exception>
    /// <exception cref="InvalidOperationException">Thrown when an extension's value contradicts the
    /// <see cref="Usage"/> profile, when the certificate would be signed by a key that is not the one it
    /// names as its issuer, or when an Authority Key Identifier does not identify the <see cref="Issuer"/>'s
    /// own key.</exception>
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
    /// <exception cref="InvalidOperationException">Thrown when an extension's value contradicts the
    /// <see cref="Usage"/> profile, when the certificate would be signed by a key that is not the one it
    /// names as its issuer, or when an Authority Key Identifier does not identify the <see cref="Issuer"/>'s
    /// own key.</exception>
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
            bool critical = builder.Subject.RelativeDistinguishedNames.IsEmpty;
            extensions.Add(new X509SubjectAlternativeNameExtension(builder.SubjectAlternativeNames.Encode(), critical));
        }

        //Collate extensions; manually specified ones in the `builder` may override matching generated ones above (e.g. Usage, DnsNames, Email, etc.)
        return extensions.Count > 0
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
            new X509KeyUsageExtension(EndEntityKeyUsage(builder, SigningOrKeyAgreement(builder) | KeyEnciphermentIfSupported(builder)), true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.ServerAuthPurpose) }, false)
        ];


    private static List<X509Extension> GetClientExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(EndEntityKeyUsage(builder, SigningOrKeyAgreement(builder)), true),
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
            new X509KeyUsageExtension(EndEntityKeyUsage(builder, SigningOrKeyAgreement(builder) | NonRepudiationIfSigning(builder) | KeyEnciphermentIfSupported(builder)), true),
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
    /// Applies RFC 9935 s5 to an end-entity certificate's key usage: an ML-KEM certificate asserts
    /// <see cref="X509KeyUsageFlags.KeyEncipherment"/> and nothing else, whatever the usage profile would
    /// otherwise have composed. Every other algorithm keeps the profile's own flags.
    /// </summary>
    /// <remarks>
    /// The rule is applied here rather than left to each profile's own OR-expression because it is a
    /// prohibition, not a contribution: "keyEncipherement MUST be the only key usage set". A profile that
    /// omitted the bit would emit an empty keyUsage, which RFC 5280 s4.2.1.3 forbids, and one that added a
    /// second bit would break the "only". Signing usages never reach here, since <see cref="Validate"/>
    /// rejects them for a key that cannot sign.
    /// </remarks>
    private static X509KeyUsageFlags EndEntityKeyUsage(CertificateBuilder builder, X509KeyUsageFlags flags)
        => builder.PublicKey?.Oid.Value is Oids.MLKem512 or Oids.MLKem768 or Oids.MLKem1024
            ? X509KeyUsageFlags.KeyEncipherment
            : flags;


    /// <summary>
    /// Returns <see cref="X509KeyUsageFlags.NonRepudiation"/> only for a key that can sign. The bit claims the
    /// subject cannot later deny having signed something, so it means nothing for a key-agreement or
    /// key-encapsulation key, which has no signing operation to deny.
    /// </summary>
    private static X509KeyUsageFlags NonRepudiationIfSigning(CertificateBuilder builder)
        => builder.KeyAlgorithm.CanSign
            ? X509KeyUsageFlags.NonRepudiation
            : X509KeyUsageFlags.None;


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
#pragma warning disable FLUENTCERT001 // Classifying a family is not use of the experimental surface
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
            //key transport, which is what keyEncipherment asserts. RFC 9629 s3 and RFC 9935 s5 both
            //put it here rather than under keyAgreement.
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
    private static readonly ImmutableHashSet<X509Extension> EmptyExtensions = ImmutableHashSet<X509Extension>.Empty.WithComparer(X509ExtensionOidEqualityComparer);
}
