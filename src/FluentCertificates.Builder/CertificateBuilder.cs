using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;

/// <summary>Provides a fluent API for building and creating X.509 certificates and certificate requests.</summary>
public record CertificateBuilder
{
    /// <summary>Gets the primary usage of the certificate, which determines default extensions.</summary>
    /// <remarks>Setting this discards any extension already on the builder that the profile generates
    /// itself. The rule lives here rather than in <see cref="SetUsage"/> so that a <c>with</c> expression,
    /// which writes the property directly, cannot state a usage the setter would have stated differently.</remarks>
    public CertificateUsage? Usage {
        get;
        init {
            field = value;
            //No profile applies when the usage is cleared, so there is nothing that profile owns to discard
            if (value != null) {
                _extensions = GetExtensionsWithoutOids(_extensions, GetOidsGeneratedByProfile(value.Value));
            }
        }
    }

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
    /// <remarks>Setting this discards any basic constraints extension already on the builder when the
    /// <see cref="Usage"/> is <see cref="CertificateUsage.CA"/>, for the reason given on <see cref="Usage"/>.
    /// Where it is anything else the value reaches no generated extension, so discarding would delete one and
    /// put nothing in its place. Setting both in one <c>with</c> expression gives the same result whichever
    /// order they are written in, since every profile discards basic constraints anyway.</remarks>
    public int? PathLength {
        get;
        init {
            field = value;
            if (Usage == CertificateUsage.CA) {
                _extensions = GetExtensionsWithoutOid(_extensions, Oids.BasicConstraints2);
            }
        }
    }

    /// <summary>Gets the algorithm used for automatic key generation, including its key length, curve or parameter set. Defaults to RSA-4096.</summary>
    /// <remarks>Set through <see cref="SetKeyAlgorithm"/> rather than an initializer. That call also clears
    /// any key already set and discards a Subject Key Identifier describing it, which an <c>init</c> accessor
    /// cannot do without also firing on the key <see cref="Create"/> generates for itself.</remarks>
    public KeyAlgorithm KeyAlgorithm => _keyAlgorithm;
    private KeyAlgorithm _keyAlgorithm { get; init; } = KeyAlgorithm.RSA();

    /// <summary>Gets the hash algorithm for signing.</summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;
    
    /// <summary>Gets the RSA signature padding mode. Ignored for non-RSA algorithms.</summary>
    public RSASignaturePadding RSASignaturePadding { get; init; } = RSASignaturePadding.Pkcs1;
    
    /// <summary>Gets the signature generator used to sign the certificate or certificate-request, or <see langword="null"/> to derive one from the signing key.</summary>
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

    private PublicKey? PublicKey {
        get;
        init {
            field = value;
            //Export the SubjectPublicKeyInfo once, when the key is set, so equality and hashing never
            //re-encode it. This init runs exactly when PublicKey is assigned, so a `with` that leaves the
            //key alone copies the cached bytes untouched, and one that changes it recomputes them.
            _publicKeySpki = value?.ExportSubjectPublicKeyInfo();
        }
    }
    private CertificateKey? KeyPair { get; init; }

    //The cached SubjectPublicKeyInfo of PublicKey, which is the key's identity for equality; see PublicKey's init.
    private byte[]? _publicKeySpki { get; init; }


    /// <summary>Sets the primary usage of the certificate, which determines default extensions, discarding
    /// any extension already on the builder that the profile generates itself.</summary>
    /// <remarks>Discarding those is what makes this call the last word on the profile; call it before
    /// <see cref="UseCertificateSigningRequest(CertificateSigningRequest,Func{X509Extension,bool})"/>
    /// to let an accepted basic constraints, key usage or extended key usage win instead.</remarks>
    /// <param name="value">The intended usage of the certificate.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified usage.</returns>
    public CertificateBuilder SetUsage(CertificateUsage value)
        => this with { Usage = value };

    /// <summary>Sets the certificate's validity period start time.</summary>
    /// <param name="value">The start time for certificate validity. If unspecified, the default is 1 hour ago.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified NotBefore value.</returns>
    public CertificateBuilder SetNotBefore(DateTimeOffset value)
        => this with { NotBefore = value };

    /// <summary>Sets the certificate's validity period end time.</summary>
    /// <param name="value">The end time for certificate validity. If unspecified, the default is 1 hour in the future.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified NotAfter value.</returns>
    public CertificateBuilder SetNotAfter(DateTimeOffset value)
        => this with { NotAfter = value };

    /// <summary>Sets the certificate's validity period to run for <paramref name="duration"/> starting now (UTC).</summary>
    /// <remarks>Unlike the default <see cref="NotBefore"/>, this does not backdate the start time, so the
    /// certificate is not yet valid on a verifier whose clock runs behind.</remarks>
    /// <param name="duration">How long the certificate remains valid. Must be greater than <see cref="TimeSpan.Zero"/>.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified validity period.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="duration"/> is zero or negative.</exception>
    public CertificateBuilder SetValidity(TimeSpan duration)
        => SetValidity(DateTimeOffset.UtcNow, duration);

    /// <summary>Sets the certificate's validity period to run for <paramref name="duration"/> starting at <paramref name="from"/>.</summary>
    /// <param name="from">The start time for certificate validity.</param>
    /// <param name="duration">How long the certificate remains valid. Must be greater than <see cref="TimeSpan.Zero"/>.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified validity period.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="duration"/> is zero or negative.</exception>
    public CertificateBuilder SetValidity(DateTimeOffset from, TimeSpan duration)
        => duration > TimeSpan.Zero
            ? this with { NotBefore = from, NotAfter = from + duration }
            : throw new ArgumentOutOfRangeException(nameof(duration), duration, $"{nameof(duration)} must be greater than zero");

    /// <summary>Sets the subject name using an <see cref="X500NameBuilder"/>.</summary>
    /// <param name="value">The subject name builder.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified subject.</returns>
    public CertificateBuilder SetSubject(X500NameBuilder value)
        => this with { Subject = value };

    /// <summary>Sets the subject name using an <see cref="X500DistinguishedName"/>.</summary>
    /// <param name="value">The distinguished name.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified subject.</returns>
    public CertificateBuilder SetSubject(X500DistinguishedName value)
        => this with { Subject = new X500NameBuilder(value) };

    /// <summary>Sets the subject name using a string representation.</summary>
    /// <param name="value">The subject name as a string.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified subject.</returns>
    public CertificateBuilder SetSubject(string value)
        => this with { Subject = new X500NameBuilder(value) };

    /// <summary>Sets the subject name using a function to configure the <see cref="X500NameBuilder"/>.</summary>
    /// <param name="func">A function to configure the subject name builder.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the configured subject.</returns>
    public CertificateBuilder SetSubject(Func<X500NameBuilder, X500NameBuilder> func)
        => this with { Subject = func(Subject) };

    /// <summary>Sets the issuer certificate.</summary>
    /// <param name="value">The issuer certificate.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified issuer.</returns>
    public CertificateBuilder SetIssuer(X509Certificate2? value)
        => this with { Issuer = value };

    /// <summary>Sets a friendly name for the certificate (Windows only; it'll be ignored on other platforms).</summary>
    /// <param name="value">The friendly name.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified friendly name.</returns>
    public CertificateBuilder SetFriendlyName(string value)
        => this with { FriendlyName = value };

    /// <summary>Sets the path length constraint for CA certificates, discarding any basic constraints
    /// extension already on the builder.</summary>
    /// <remarks>Under <see cref="CertificateUsage.CA"/> this value reaches the generated basic constraints,
    /// so discarding that extension is what makes this call the last word; call it before
    /// <see cref="UseCertificateSigningRequest(CertificateSigningRequest,Func{X509Extension,bool})"/>
    /// to let an accepted basic constraints win instead. Under any other profile the value reaches nothing,
    /// so nothing is discarded either.</remarks>
    /// <param name="value">The path length constraint.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified path length.</returns>
    public CertificateBuilder SetPathLength(int? value)
        => this with { PathLength = value };

    /// <summary>Sets the key pair to use for certificate creation or certificate-requests, discarding any
    /// Subject Key Identifier extension already on the builder.</summary>
    /// <remarks>Keys supplied here are never disposed by the builder; their lifetime stays the caller's.
    /// Discarding that extension keeps the certificate from naming a key other than the one it certifies;
    /// add or accept a Subject Key Identifier afterwards to carry a different value.</remarks>
    /// <param name="value">The asymmetric key pair, or <see langword="null" /> to remove. Supported algorithms currently include RSA, ECDsa and the deprecated DSA.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified key pair.</returns>
    public CertificateBuilder SetKeyPair(AsymmetricAlgorithm? value)
        => RemoveExtensionsByOidValue(Oids.SubjectKeyIdentifier).WithKeyPair(value);


    /// <summary>Sets the key pair to use for certificate creation or certificate-requests, from a key of any supported kind including the post-quantum ones, discarding any Subject Key Identifier extension already on the builder.</summary>
    /// <param name="value">The key pair, or <see langword="null" /> to remove.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified key pair.</returns>
    public CertificateBuilder SetKeyPair(CertificateKey? value)
        => RemoveExtensionsByOidValue(Oids.SubjectKeyIdentifier).WithKeyPair(value);


    /// <summary>
    /// Assigns the key without discarding a Subject Key Identifier, which is what <see cref="GenerateKeyPair"/>
    /// needs: filling in a key the caller never named is not a caller's call and must not outrank one.
    /// </summary>
    /// <remarks>Identical in signature to <see cref="SetKeyPair(AsymmetricAlgorithm)"/>, so calling the wrong
    /// one compiles. Nothing but the name says which is which.</remarks>
    private CertificateBuilder WithKeyPair(AsymmetricAlgorithm? value)
        => this with {
            _keyAlgorithm = GetKeyAlgorithm(value) ?? KeyAlgorithm,
            PublicKey = value != null ? new PublicKey(value) : null,
            KeyPair = value == null ? null : new CertificateKey(value)
        };


    /// <inheritdoc cref="WithKeyPair(AsymmetricAlgorithm)"/>
    private CertificateBuilder WithKeyPair(CertificateKey? value)
        => this with {
            _keyAlgorithm = GetKeyAlgorithm(value) ?? KeyAlgorithm,
            PublicKey = CreatePublicKey(value),
            KeyPair = value
        };

    /// <summary>Sets the public key to certify, without supplying the matching private key, discarding any
    /// Subject Key Identifier extension already on the builder.</summary>
    /// <remarks>Clears any key pair and suppresses the automatic key generation <see cref="Create"/> would do,
    /// so the certificate has no private key attached. Self-signing this way also needs
    /// <see cref="SetSignatureGenerator"/>, and nothing checks that the generator matches this public key.</remarks>
    /// <param name="value">The public key to certify, or <see langword="null"/> to remove it.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified public key.</returns>
    public CertificateBuilder SetPublicKey(PublicKey? value)
        => RemoveExtensionsByOidValue(Oids.SubjectKeyIdentifier) with {
            _keyAlgorithm = KeepEcChoice(GetKeyAlgorithm(value)) ?? KeyAlgorithm,
            PublicKey = value,
            KeyPair = null
        };


    /// <summary>
    /// An EC public key reads back as <see cref="KeyAlgorithm.ECDsa()"/> whether it was made for signing or key
    /// agreement, so that guess must not overwrite an explicit <see cref="KeyAlgorithm.ECDiffieHellman()"/>.
    /// </summary>
    private KeyAlgorithm? KeepEcChoice(KeyAlgorithm? derived)
        => derived?.Family == KeyAlgorithmFamily.ECDsa && KeyAlgorithm.Family == KeyAlgorithmFamily.ECDiffieHellman
            ? KeyAlgorithm
            : derived;

    /// <summary>Sets the key algorithm for automatic key generation, removing any key pair previously set and
    /// discarding any Subject Key Identifier extension already on the builder.</summary>
    /// <remarks>Each <see cref="Create"/> call generates a key pair and disposes it on return.</remarks>
    /// <param name="value">The key algorithm to use. Supported algorithms currently include RSA, ECDsa and the deprecated DSA. If unspecified, the default is RSA.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified key algorithm.</returns>
    public CertificateBuilder SetKeyAlgorithm(KeyAlgorithm value)
        => RemoveExtensionsByOidValue(Oids.SubjectKeyIdentifier) with {
            _keyAlgorithm = value,
            PublicKey = null,
            KeyPair = null
        };

    /// <summary>Sets the hash algorithm for signing.</summary>
    /// <param name="value">The hash algorithm.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified hash algorithm.</returns>
    public CertificateBuilder SetHashAlgorithm(HashAlgorithmName value)
        => this with { HashAlgorithm = value };


    /// <summary>Sets the RSA signature padding mode, which is ignored for other key algorithms.</summary>
    /// <param name="value">The RSA signature padding.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified padding.</returns>
    public CertificateBuilder SetRSASignaturePadding(RSASignaturePadding value)
        => this with { RSASignaturePadding = value };


    /// <summary>Sets a signature generator to sign with, instead of deriving one from the signing key.</summary>
    /// <remarks>The generator determines its own signature algorithm, so <see cref="HashAlgorithm"/> and
    /// <see cref="RSASignaturePadding"/> do not apply to it. With an <see cref="Issuer"/> set it replaces the
    /// issuer's signature, and that certificate then needs no attached private key.</remarks>
    /// <param name="value">The signature generator to sign with, or <see langword="null"/> to derive one from the signing key.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified signature generator.</returns>
    public CertificateBuilder SetSignatureGenerator(X509SignatureGenerator? value)
        => this with { SignatureGenerator = value };



    /// <summary>Adds an extension, replacing any already present under the same OID regardless of its runtime type.</summary>
    /// <param name="extension">The extension to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extension added.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="extension"/> is <see langword="null"/>.</exception>
    public CertificateBuilder AddExtension(X509Extension extension)
    {
        ArgumentNullException.ThrowIfNull(extension);

        return SetExtension(extension);
    }

    /// <summary>Adds multiple extensions, replacing any already present under the same OID. Where
    /// <paramref name="values"/> repeats an OID, the last one wins.</summary>
    /// <param name="values">The extensions to add.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the extensions added.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="values"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="values"/> holds a <see langword="null"/>.</exception>
    public CertificateBuilder AddExtensions(params IEnumerable<X509Extension> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return values.Aggregate(this, (builder, extension) => builder.SetExtension(EnsureNotNull(extension, nameof(values))));
    }

    /// <summary>Sets the certificate extensions, replacing any already on the builder. Where
    /// <paramref name="values"/> repeats an OID, the last one wins.</summary>
    /// <param name="values">The extensions to set.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified extensions.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="values"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="values"/> holds a <see langword="null"/>.</exception>
    public CertificateBuilder SetExtensions(params IEnumerable<X509Extension> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return values.Aggregate(this with { _extensions = EmptyExtensions }, (builder, extension) => builder.SetExtension(EnsureNotNull(extension, nameof(values))));
    }

    /// <summary>Sets the Authority Information Access extension, naming a single OCSP responder and a single CA Issuers location.</summary>
    /// <param name="ocspUri">The URI of the OCSP responder, or <see langword="null"/> to omit it.</param>
    /// <param name="caIssuersUri">The URI the issuer's certificate can be downloaded from, or <see langword="null"/> to omit it.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Authority Information Access extension.</returns>
    /// <exception cref="ArgumentException">Thrown when both URIs are omitted.</exception>
    /// <remarks>Passing the literal <c>null</c> for both arguments is ambiguous with the collection overload; cast at least one, e.g. <c>(string?)null</c>.</remarks>
    public CertificateBuilder SetAuthorityInformationAccess(string? ocspUri, string? caIssuersUri)
        => SetAuthorityInformationAccess(
            ocspUri == null ? null : [ocspUri],
            caIssuersUri == null ? null : [caIssuersUri]);

    /// <summary>Sets the Authority Information Access extension, naming where the issuer can be reached for revocation status and for its own certificate.</summary>
    /// <param name="ocspUris">The URIs of the OCSP responders, or <see langword="null"/> to omit them.</param>
    /// <param name="caIssuersUris">The URIs the issuer's certificate can be downloaded from, or <see langword="null"/> to omit them.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Authority Information Access extension.</returns>
    /// <exception cref="ArgumentException">Thrown when both collections are <see langword="null"/> or empty.</exception>
    /// <remarks>Always non-critical: RFC 5280 s4.2.2.1 requires conforming CAs to mark it so, and a critical one
    /// supplied elsewhere is issued non-critical anyway.</remarks>
    public CertificateBuilder SetAuthorityInformationAccess(IEnumerable<string>? ocspUris, IEnumerable<string>? caIssuersUris)
        => SetExtension(new X509AuthorityInformationAccessExtension(ocspUris, caIssuersUris));


    /// <summary>Sets the CRL Distribution Points extension, naming where the issuer publishes its revocation lists.</summary>
    /// <param name="uris">The URIs the CRL can be downloaded from. Must contain at least one URI, and each must be ASCII.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified CRL Distribution Points extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="uris"/> is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when a URI contains a character outside the 7-bit ASCII set.</exception>
    public CertificateBuilder SetCrlDistributionPoints(params IEnumerable<string> uris)
        => SetCrlDistributionPoints(uris, false);

    /// <summary>Sets the CRL Distribution Points extension, naming where the issuer publishes its revocation lists.</summary>
    /// <param name="uris">The URIs the CRL can be downloaded from. Must contain at least one URI, and each must be ASCII.</param>
    /// <param name="critical">Whether to mark the extension critical. RFC 5280 s4.2.1.13 says it SHOULD be non-critical.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified CRL Distribution Points extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="uris"/> is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when a URI contains a character outside the 7-bit ASCII set.</exception>
    public CertificateBuilder SetCrlDistributionPoints(IEnumerable<string> uris, bool critical)
        => SetExtension(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(uris, critical));


    /// <summary>Sets the Certificate Policies extension, naming the policies under which the certificate is issued.</summary>
    /// <param name="policyIdentifier">The OID of the first (or only) policy to assert.</param>
    /// <param name="morePolicyIdentifiers">The OIDs of any further policies to assert.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Certificate Policies extension.</returns>
    public CertificateBuilder SetCertificatePolicies(string policyIdentifier, params IEnumerable<string> morePolicyIdentifiers)
        => SetCertificatePolicies([policyIdentifier, .. morePolicyIdentifiers]);

    /// <summary>Sets the Certificate Policies extension, naming the policies under which the certificate is issued.</summary>
    /// <param name="policyIdentifiers">The policies to assert. Must contain at least one.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Certificate Policies extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="policyIdentifiers"/> is empty.</exception>
    /// <exception cref="ArgumentException">Thrown when an <see cref="Oid"/> in <paramref name="policyIdentifiers"/> has no <see cref="Oid.Value"/>.</exception>
    public CertificateBuilder SetCertificatePolicies(params IEnumerable<Oid> policyIdentifiers)
        => SetCertificatePolicies(policyIdentifiers, false);

    /// <summary>Sets the Certificate Policies extension, naming the policies under which the certificate is issued.</summary>
    /// <param name="policyIdentifiers">The policies to assert. Must contain at least one.</param>
    /// <param name="critical">Whether to mark the extension critical, which forces a relying party that cannot interpret it to reject the certificate.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Certificate Policies extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="policyIdentifiers"/> is empty.</exception>
    /// <exception cref="ArgumentException">Thrown when an <see cref="Oid"/> in <paramref name="policyIdentifiers"/> has no <see cref="Oid.Value"/>.</exception>
    public CertificateBuilder SetCertificatePolicies(IEnumerable<Oid> policyIdentifiers, bool critical)
        => SetCertificatePolicies((policyIdentifiers ?? throw new ArgumentNullException(nameof(policyIdentifiers)))
            .Select(x => x?.Value ?? throw new ArgumentException("Every Oid in policyIdentifiers must have a Value", nameof(policyIdentifiers))), critical);

    /// <summary>Sets the Certificate Policies extension, naming the policies under which the certificate is issued.</summary>
    /// <param name="policyIdentifiers">The OIDs of the policies to assert. Must contain at least one OID.</param>
    /// <param name="critical">Whether to mark the extension critical, which forces a relying party that cannot interpret it to reject the certificate.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified Certificate Policies extension.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="policyIdentifiers"/> is empty.</exception>
    public CertificateBuilder SetCertificatePolicies(IEnumerable<string> policyIdentifiers, bool critical = false)
        => SetExtension(new X509CertificatePolicyExtension(policyIdentifiers, critical));


    /// <summary>Takes the subject name and the public key to certify out of a received certificate signing
    /// request, discarding everything else the requester asked for.</summary>
    /// <remarks>The certificate has no private key attached, so an <see cref="Issuer"/> or
    /// <see cref="SignatureGenerator"/> must sign it. Nothing here re-checks the request's signature.</remarks>
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


    /// <summary>Takes the subject name and the public key to certify out of a received certificate signing
    /// request, along with those requested extensions that <paramref name="accept"/> returns
    /// <see langword="true"/> for.</summary>
    /// <remarks>
    /// An accepted extension replaces anything already present under the same OID, and the last call wins
    /// thereafter. <b>Nothing in the request is screened here</b>: apply your policy in
    /// <paramref name="accept"/>, and set a <see cref="Usage"/> first, or none of
    /// <see cref="CreateCertificateRequest"/>'s refusals apply to what an accepted extension asserts.
    /// <para>
    /// Two hazards a permissive <paramref name="accept"/> would not think to screen for:
    /// </para>
    /// <list type="bullet">
    /// <item><description>A requested <c>certificatePolicies</c> extension asserting anyPolicy
    /// (<c>2.5.29.32.0</c>) inherits every policy the issuing CA holds (RFC 5280 s6.1.5(g)). Accepting it
    /// on a permissive predicate hands the requester every policy the CA asserts, whether or not the CA
    /// intended that.</description></item>
    /// <item><description>A requested CRL Distribution Points extension names where revocation is checked
    /// for the certificate the CA is about to issue. The requester chooses that location, and RFC 5280
    /// does not require the extension at all, so its absence is equally the requester's choice. The
    /// issuing CA certificate's own CRLDP and AIA values describe its parent's endpoints, not the ones an
    /// issued certificate should carry, so they are not a value to screen a requested one against.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="csr">The received certificate signing request.</param>
    /// <param name="accept">Decides, per requested extension, whether the CA honours it.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the request's subject, public key and accepted extensions.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="csr"/> or <paramref name="accept"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="csr"/>'s extension collection holds a <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the request's subject contains a multi-valued
    /// relative distinguished name, which <see cref="X500NameBuilder"/> cannot represent.</exception>
    public CertificateBuilder UseCertificateSigningRequest(CertificateSigningRequest csr, Func<X509Extension, bool> accept)
    {
        ArgumentNullException.ThrowIfNull(csr);
        ArgumentNullException.ThrowIfNull(accept);

        var builder = UseCertificateSigningRequest(csr);
        foreach (var extension in csr.CertificateRequest.CertificateExtensions) {
            //Refused before accept sees it, so the predicate is never handed a null either. Only a caller
            //who has added one to the parsed request's own collection can get here.
            if (accept(EnsureNotNull(extension, nameof(csr)))) {
                builder = builder.SetExtension(extension);
            }
        }
        return builder;
    }


    /// <summary>
    /// Adds an extension, replacing any already present under the same OID.
    /// </summary>
    /// <remarks><see cref="ImmutableHashSet{T}"/> keeps the entry already there on a collision, so removing
    /// first is what makes this a replacement. Remove reads the set's own comparer, which matches on the OID
    /// alone.</remarks>
    private CertificateBuilder SetExtension(X509Extension extension)
        => this with { _extensions = _extensions.Remove(extension).Add(extension) };


    private CertificateBuilder RemoveExtensionsByOidValue(string? oid)
        => this with { _extensions = GetExtensionsWithoutOid(_extensions, oid) };


    /// <summary>
    /// Refuses a null inside a sequence of extensions, which is an <see cref="ArgumentException"/> against
    /// the sequence rather than an <see cref="ArgumentNullException"/>, since the sequence itself is not null.
    /// </summary>
    /// <remarks><see cref="ImmutableHashSet{T}"/> null-guards its own hashing, so a null never reaches
    /// <see cref="X509ExtensionOidEqualityComparer"/> and would otherwise sit in the set until
    /// <see cref="Create"/> dereferenced it, far from the call that supplied it.</remarks>
    private static X509Extension EnsureNotNull(X509Extension extension, string paramName)
        => extension ?? throw new ArgumentException("An extension in the sequence is null", paramName);


    /// <summary>
    /// The set with any extension under <paramref name="oid"/> removed. Static so an <c>init</c> accessor,
    /// which has no whole builder to return, can share the rule with the setter that calls it.
    /// </summary>
    private static ImmutableHashSet<X509Extension> GetExtensionsWithoutOid(ImmutableHashSet<X509Extension> extensions, string? oid)
        => extensions
            .Where(x => !String.Equals(x.Oid?.Value, oid))
            .ToImmutableHashSet(X509ExtensionOidEqualityComparer);


    /// <summary>The set with every extension under any of <paramref name="oids"/> removed.</summary>
    private static ImmutableHashSet<X509Extension> GetExtensionsWithoutOids(ImmutableHashSet<X509Extension> extensions, ImmutableHashSet<string> oids)
        => extensions
            .Where(x => x.Oid?.Value is not { } oid || !oids.Contains(oid))
            .ToImmutableHashSet(X509ExtensionOidEqualityComparer);


    /// <summary>
    /// The OIDs each <see cref="CertificateUsage"/> profile generates in <see cref="BuildExtensions"/>, which
    /// <see cref="Usage"/> discards so that setting a profile is the last word on them.
    /// </summary>
    /// <remarks>Listed rather than derived from the generators, which need a public key
    /// <see cref="Usage"/> may not have been given yet. The tests
    /// <c>SetUsage_DiscardsEveryExtensionItsOwnProfileGenerates</c> and
    /// <c>SetUsage_KeepsAnExtendedKeyUsageWhenItsProfileGeneratesNone</c> pin the two together in both
    /// directions: listing an OID the profile does not generate would delete the caller's extension with
    /// nothing put back. The subject key identifier is common to every profile and owned by none, so it is
    /// not here.</remarks>
    private static ImmutableHashSet<string> GetOidsGeneratedByProfile(CertificateUsage usage)
        => usage switch {
            CertificateUsage.CA or CertificateUsage.CrlSigning => [Oids.BasicConstraints2, Oids.KeyUsage],
            _ => [Oids.BasicConstraints2, Oids.KeyUsage, Oids.EnhancedKeyUsage]
        };


    /// <summary>Sets the key storage flags for the certificate.</summary>
    /// <param name="value">The key storage flags.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified flags.</returns>
    public CertificateBuilder SetKeyStorageFlags(X509KeyStorageFlags value)
        => this with { KeyStorageFlags = value };


    /// <summary>Sets a custom serial number generator function for certificate creation.</summary>
    /// <param name="generator">A delegate that returns a <see cref="byte"/> array representing the serial number to use for the certificate.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified serial number generator.</returns>
    public CertificateBuilder SetSerialNumberGenerator(Func<byte[]> generator)
        => this with { SerialNumberGenerator = generator };


    /// <summary>Sets the subject alternative names, discarding any Subject Alternative Name extension already on the builder.</summary>
    /// <param name="configureSan">A function to configure the SAN builder.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified SANs.</returns>
    public CertificateBuilder SetSubjectAlternativeNames(Func<GeneralNameListBuilder, GeneralNameListBuilder> configureSan)
        => SetSubjectAlternativeNames(configureSan(new GeneralNameListBuilder()).Create());


    /// <summary>Sets the subject alternative names, discarding any Subject Alternative Name extension already on the builder.</summary>
    /// <remarks>Discarding that extension is what makes this call the last word on the certificate's names; call
    /// it before <see cref="UseCertificateSigningRequest(CertificateSigningRequest,Func{X509Extension,bool})"/>
    /// to let an accepted Subject Alternative Name win instead.</remarks>
    /// <param name="san">The subject alternative names. An empty sequence leaves the certificate with no Subject Alternative Name extension at all.</param>
    /// <returns>A new instance of <see cref="CertificateBuilder"/> with the specified SANs.</returns>
    public CertificateBuilder SetSubjectAlternativeNames(IEnumerable<GeneralName> san)
        => RemoveExtensionsByOidValue(Oids.SubjectAltName) with { _subjectAlternativeNames = [.. san] };


    /// <summary>Validates the current builder configuration and throws if invalid.</summary>
    /// <remarks><see cref="CreateCertificateSigningRequest"/> deliberately does not call this: a requester
    /// leaving its name to the authority is a normal thing to ask for, and the empty-subject rule applied
    /// here binds whoever issues the certificate.</remarks>
    /// <exception cref="InvalidOperationException">Thrown when the builder describes a certificate that
    /// cannot be built: an inverted validity period, a key that cannot sign and no <see cref="Issuer"/> to
    /// sign for it, a <see cref="Usage"/> profile that signs on a key that cannot, a self-signed certificate
    /// with no key to sign it, or an empty <see cref="Subject"/> with no subject alternative name.</exception>
    public void Validate()
    {
        if (NotBefore >= NotAfter) {
            throw new InvalidOperationException($"{nameof(NotBefore)} cannot be later than or equal to {nameof(NotAfter)}");
        }

        //A SignatureGenerator is no substitute: with no Issuer the certificate is self-issued, so it
        //would be signed by a key unrelated to the subject key and could never verify against it.
        if (!KeyAlgorithm.CanSign && Issuer == null) {
            throw new InvalidOperationException($"{KeyAlgorithm.Name} cannot sign, so the certificate must be signed by someone else. Set an {nameof(Issuer)}");
        }

        CheckKeyAgreesWithUsage(this);

        if (Issuer == null && KeyPair == null) {
            if (PublicKey == null && SignatureGenerator != null) {
                throw new InvalidOperationException($"{nameof(SignatureGenerator)} without an {nameof(Issuer)} signs the certificate with itself, so the key it signs with must also be supplied through {nameof(SetKeyPair)} or {nameof(SetPublicKey)}");
            }

            if (PublicKey != null && SignatureGenerator == null) {
                throw new InvalidOperationException($"{nameof(SetPublicKey)} supplies no private key, so a self-signed certificate also needs a {nameof(SignatureGenerator)} to sign with, or an {nameof(Issuer)} to sign it");
            }
        }

        //RFC 5280 s4.2.1.6: a certificate whose subject is an empty sequence MUST carry a subject
        //alternative name, that extension being the only name it then has. Refusing is the only answer
        //available, since a name is not something the builder can invent.
        if (Subject.RelativeDistinguishedNames.IsEmpty && !HasSubjectAlternativeName()) {
            throw new InvalidOperationException($"A certificate with an empty {nameof(Subject)} carries no name at all unless it has a subject alternative name, which RFC 5280 s4.2.1.6 requires of it. Set a {nameof(Subject)}, or call {nameof(SetSubjectAlternativeNames)}");
        }
    }


    /// <summary>Creates a <see cref="CertificateRequest"/> based on the builder's parameters.</summary>
    /// <remarks>An <see cref="Issuer"/> contributes an Authority Key Identifier unless one was already
    /// supplied. Where RFC 5280 states a criticality MUST, the extension is written with that criticality;
    /// its value is untouched and <see cref="Extensions"/> still reports what it was given.</remarks>
    /// <returns>A new <see cref="CertificateRequest"/> instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no key pair is set, when an extension's value
    /// contradicts the <see cref="Usage"/> profile, when the <see cref="Usage"/> profile signs but the
    /// certified key cannot, when an Authority Key Identifier does not identify the issuer's own key, when the
    /// <see cref="Issuer"/> publishes a Subject Key Identifier whose value does not decode, or when a
    /// subject alternative name extension carries no entries or does not decode.</exception>
    public CertificateRequest CreateCertificateRequest()
    {
        if (PublicKey == null) {
            throw new InvalidOperationException($"Call {nameof(SetKeyPair)}(...) first to provide an asymmetric public/private keypair");
        }

        var dn = Subject.Create();

        CheckKeyAgreesWithUsage(this);

        var request = new CertificateRequest(dn, PublicKey, HashAlgorithm);

        var extensions = BuildExtensions(this);

        CheckExtensionsAgreeWithUsage(this, extensions);
        CheckKeyIdentifierIsGenuine(this, extensions);
        CheckSubjectAlternativeNameIsPopulated(extensions);

        foreach (var extension in extensions) {
            request.CertificateExtensions.Add(ConformCriticality(extension, this, extensions));
        }

        //Added straight to the request rather than through BuildExtensions, so adding both would make
        //CertificateRequest throw: hence the guard. It is already non-critical per RFC 5280 s4.2.1.1.
        if (Issuer != null && !extensions.Any(x => Oids.AuthorityKeyIdentifierOid.ValueEquals(x.Oid))) {
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(GetSubjectKeyIdentifier(Issuer).Span));
        }

        return request;
    }


    /// <summary>Creates a <see cref="CertificateSigningRequest"/> based on the builder's parameters.</summary>
    /// <returns>A new <see cref="CertificateSigningRequest"/> instance.</returns>
    /// <exception cref="NotSupportedException">Thrown when the key to certify cannot sign, so cannot produce the proof-of-possession signature.</exception>
    /// <exception cref="InvalidOperationException">Thrown when an extension's value contradicts the
    /// <see cref="Usage"/> profile, when the request would be signed by a key that is not the one it
    /// certifies, or when a subject alternative name extension carries no entries or does not decode.
    /// Nothing here depends on the <see cref="Issuer"/>, which this member discards.</exception>
    public CertificateSigningRequest CreateCertificateSigningRequest()
    {
        //PKCS#10 proves possession by signing the request with the very key being certified
        if (!KeyAlgorithm.CanSign || KeyPair?.CanSign == false) {
            throw new NotSupportedException($"A {KeyAlgorithm.Name} key cannot sign, so it cannot sign the request that asks for it to be certified");
        }

        //Nothing signs a request but the key it certifies, so an Issuer set for later issuance has no
        //bearing here and must not contribute an Authority Key Identifier the requester cannot know.
        var builder = Issuer != null ? this with { Issuer = null } : this;

        var request = builder.CreateCertificateRequest();

        //Proof of possession is the whole point of the signature on a PKCS#10 request: it is only evidence
        //that the requester holds the private key for the public key being certified if that same key signs.
        //Only a caller-supplied SignatureGenerator can hold some other key; the one derived from KeyPair is
        //that key by construction, so it is trusted rather than re-encoded and compared, which DSA's generator
        //spells differently from the key's own SubjectPublicKeyInfo. PublicKey is non-null here, since
        //CreateCertificateRequest above throws otherwise.
        if (SignatureGenerator != null
            && !SignatureGenerator.PublicKey.ExportSubjectPublicKeyInfo().AsSpan()
                .SequenceEqual(PublicKey!.ExportSubjectPublicKeyInfo())) {
            throw new InvalidOperationException($"A certificate signing request must be signed by the very key it certifies, to prove the requester holds it, but the {nameof(SignatureGenerator)} holds a different key. Sign with the subject's own key, or clear the {nameof(SignatureGenerator)} so the key pair signs the request");
        }

        return new(request, SignatureGenerator ?? CreateSignatureGenerator(KeyPair));
    }


    /// <summary>Builds an <see cref="X509Certificate2"/> instance based on the builder's parameters.</summary>
    /// <returns>A new <see cref="X509Certificate2"/> instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when an extension's value contradicts the
    /// <see cref="Usage"/> profile, when an Authority Key Identifier does not identify the issuer's own key,
    /// when the <see cref="Issuer"/> publishes a Subject Key Identifier whose value does not decode, or when a
    /// subject alternative name extension carries no entries or does not decode. <see cref="Validate"/>,
    /// which this member calls, adds its own: among those, a certificate with an empty
    /// <see cref="Subject"/> and no subject alternative name is refused.</exception>
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    public X509Certificate2 Create()
    {
        Validate();

        bool generateKeys = KeyPair == null && PublicKey == null;

        var builder = generateKeys
            ? GenerateKeyPair()
            : this;

        try {
            if (builder.PublicKey == null) {
                throw new InvalidOperationException($"Call {nameof(SetKeyPair)}(...), {nameof(SetPublicKey)}(...) or {nameof(SetKeyAlgorithm)}() first to provide a key to certify");
            }

            var request = builder.CreateCertificateRequest();

            //GetPrivateKey hands back a fresh instance which is ours to release, unlike KeyPair
            using var issuerKey = builder.SignatureGenerator == null && builder.Issuer != null
                ? builder.Issuer.GetPrivateKey()
                : null;

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


    /// <summary>Whether a subject alternative name will reach the certificate, from either source.</summary>
    /// <remarks>Presence is all that is asked. An extension holding an empty <c>GeneralNames</c> passes,
    /// which only hand-written bytes can produce: <see cref="SetSubjectAlternativeNames(IEnumerable{GeneralName})"/>
    /// given an empty sequence adds no extension at all.</remarks>
    private bool HasSubjectAlternativeName()
        => _subjectAlternativeNames?.Count > 0
           || _extensions.Any(x => Oids.SubjectAltNameOid.ValueEquals(x.Oid));


    private byte[] GenerateSerialNumber()
        => SerialNumberGenerator?.Invoke() ?? GenerateDefaultSerialNumber();


    private static byte[] GenerateDefaultSerialNumber()
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
            throw new InvalidOperationException($"Call {nameof(SetKeyPair)}(...) or {nameof(SetKeyAlgorithm)}() first to provide a public/private keypair");
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
                return WithKeyPair(new CertificateKey(MLDsa.GenerateKey(PostQuantumSupport.GetMLDsaAlgorithmFor(KeyAlgorithm))));
            case KeyAlgorithmFamily.SlhDsa:
                return WithKeyPair(new CertificateKey(SlhDsa.GenerateKey(PostQuantumSupport.SlhDsaAlgorithmFor(KeyAlgorithm))));
            case KeyAlgorithmFamily.CompositeMLDsa:
                return WithKeyPair(new CertificateKey(CompositeMLDsa.GenerateKey(PostQuantumSupport.GetCompositeAlgorithmFor(KeyAlgorithm))));
            case KeyAlgorithmFamily.MLKem:
                return WithKeyPair(new CertificateKey(MLKem.GenerateKey(PostQuantumSupport.GetMLKemAlgorithmFor(KeyAlgorithm))));
        }
#pragma warning restore FLUENTCERT001
#pragma warning restore SYSLIB5006
#endif

        return WithKeyPair(
            KeyAlgorithm.Family switch {
                KeyAlgorithmFamily.ECDsa => ECDsa.Create(KeyAlgorithm.Curve!.Value),
                KeyAlgorithmFamily.ECDiffieHellman => ECDiffieHellman.Create(KeyAlgorithm.Curve!.Value),
                KeyAlgorithmFamily.Rsa => RSA.Create(KeyAlgorithm.KeyLength!.Value),
#pragma warning disable CS0618 // Type or member is obsolete
                KeyAlgorithmFamily.Dsa => DSA.Create(KeyAlgorithm.KeyLength!.Value),
#pragma warning restore CS0618 // Type or member is obsolete
                //Unreachable, so no test kills this: ThrowIfUnsupported rejects a post-quantum family the
                //target framework cannot generate, and the switch above takes the ones it can
                _ => throw new InvalidOperationException($"Unsupported {nameof(KeyAlgorithm)}: {KeyAlgorithm.Name}")
            }
        );
    }


    /// <summary>
    /// Returns the criticality RFC 5280 demands of this extension, or <see langword="null"/> where it leaves
    /// the choice open. Every rule here is a MUST about the flag rather than the value inside it.
    /// </summary>
    private static bool? IsRequiredCriticality(X509Extension extension, CertificateBuilder builder, IEnumerable<X509Extension> extensions)
        => extension.Oid?.Value switch {
            //s4.2.1.1, s4.2.1.2, s4.2.1.8, s4.2.1.15, s4.2.2.1 and s4.2.2.2: MUST be non-critical.
            Oids.AuthorityKeyIdentifier or Oids.SubjectKeyIdentifier or Oids.SubjectDirectoryAttributes
                or Oids.FreshestCrl or Oids.AuthorityInformationAccess or Oids.SubjectInformationAccess
                => false,
            //s4.2.1.10, s4.2.1.11 and s4.2.1.14: MUST be critical.
            Oids.NameConstraints or Oids.CertPolicyConstraints or Oids.InhibitAnyPolicyExtension
                => true,
            //s4.2.1.9: MUST be critical in a CA certificate whose key validates certificate signatures. A
            //value that will not decode has no cA bit to read, so it goes out as supplied.
            Oids.BasicConstraints2 when IsCertificateAuthority(extension) == true && MayValidateCertificateSignatures(extensions)
                => true,
            //s4.2.1.6: MUST be critical when the subject is empty.
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
    /// Refuses an Authority Key Identifier naming a key other than the issuer's: RFC 5280 s4.2.1.2 makes the
    /// issuer's Subject Key Identifier the value that MUST appear there. A Subject Key Identifier is
    /// deliberately not checked, since s4.2.1.2 permits "other methods of generating unique numbers".
    /// </summary>
    private static void CheckKeyIdentifierIsGenuine(CertificateBuilder builder, IEnumerable<X509Extension> extensions)
    {
        var extension = extensions.FirstOrDefault(x => Oids.AuthorityKeyIdentifierOid.ValueEquals(x.Oid));
        if (extension == null || builder.Issuer == null) {
            return;
        }

        //Comparing whole encodings would refuse a conforming extension for also carrying authorityCertIssuer
        //and authorityCertSerialNumber, which s4.2.1.1 permits alongside the keyIdentifier.
        var supplied = ReadKeyIdentifier(extension);

        //s4.2.1.1 requires the keyIdentifier field in every certificate a conforming CA generates
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


    /// <summary>
    /// Refuses a subject alternative name extension that carries no entries. RFC 5280 s4.2.1.6 requires at
    /// least one when the extension is present, and a validator has nothing else to name the certificate by
    /// when it is also the one <see cref="ConformCriticality"/> marks critical over an empty subject.
    /// </summary>
    /// <remarks>Read with the same extent rule FC-86 applies elsewhere: bytes after the SAN's single encoded
    /// value are what one reader skips and another might not, so a value that does not decode cleanly to its
    /// own end is refused the same as one that decodes to zero entries, rather than left for whatever reads
    /// it next to disagree about.</remarks>
    private static void CheckSubjectAlternativeNameIsPopulated(IEnumerable<X509Extension> extensions)
    {
        var san = extensions.FirstOrDefault(x => Oids.SubjectAltNameOid.ValueEquals(x.Oid));
        if (san == null) {
            return;
        }

        try {
            AsnDecoder.ReadSequence(san.RawData, AsnEncodingRules.BER, out _, out int contentLength, out int consumed);
            if (consumed != san.RawData.Length) {
                throw CreateUnreadableValueException(san, "subject alternative name");
            }

            if (contentLength == 0) {
                throw new InvalidOperationException("A subject alternative name extension carries no entries, so it names nobody. RFC 5280 s4.2.1.6 requires at least one. Reject it, or supply one naming somebody");
            }
        } catch (AsnContentException) {
            throw CreateUnreadableValueException(san, "subject alternative name");
        }
    }


    /// <summary>
    /// Whether the certified key may validate signatures on certificates, the condition RFC 5280 s4.2.1.9
    /// attaches to its criticality MUST. Only a key usage extension that reads back and omits
    /// <see cref="X509KeyUsageFlags.KeyCertSign"/> settles that it may not.
    /// </summary>
    private static bool MayValidateCertificateSignatures(IEnumerable<X509Extension> extensions)
    {
        var keyUsage = extensions.FirstOrDefault(x => Oids.KeyUsageOid.ValueEquals(x.Oid));
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
        //Correcting on the way out keeps Extensions a faithful record of what the builder was handed, and is
        //the only point at which the empty-subject rule can be settled, since the subject can still change.
        var required = IsRequiredCriticality(extension, builder, extensions);
        return required == null || required == extension.Critical
            ? extension
            : new X509Extension(extension.Oid!, extension.RawData, required.Value);
    }


    /// <summary>
    /// Refuses a profile whose certificate exists to sign, on a key that cannot sign. Those profiles assert
    /// a key usage describing an operation the certified key can never perform, and for ML-KEM specifically
    /// RFC 9935 s5 permits no bit but <see cref="X509KeyUsageFlags.KeyEncipherment"/>.
    /// </summary>
    /// <remarks>Checked here rather than in each profile's extensions, so that it refuses rather than
    /// silently substituting a key usage the caller did not ask for.</remarks>
    private static void CheckKeyAgreesWithUsage(CertificateBuilder builder)
    {
        if (builder.KeyAlgorithm.CanSign) {
            return;
        }

        if (builder.Usage is CertificateUsage.CA or CertificateUsage.CodeSign or CertificateUsage.OcspSigning or CertificateUsage.TimeStamping or CertificateUsage.CrlSigning) {
            throw new InvalidOperationException($"{nameof(CertificateUsage)}.{builder.Usage} asserts a key usage the certified key can never perform, since a {builder.KeyAlgorithm.Name} key cannot sign. Choose a {nameof(CertificateUsage)} whose key does not sign, or certify a signing key");
        }
    }


    private static void CheckExtensionsAgreeWithUsage(CertificateBuilder builder, IEnumerable<X509Extension> extensions)
    {
        if (builder.Usage == null) {
            return;
        }

        bool profileIsCa = builder.Usage == CertificateUsage.CA;

        foreach (var extension in extensions) {
            switch (extension.Oid?.Value) {
                case Oids.BasicConstraints2:
                    var isCa = Decode(extension, x => new X509BasicConstraintsExtension(x, x.Critical), x => x.CertificateAuthority)
                        ?? throw CreateUnreadableValueException(extension, "basic constraints");
                    if (isCa != profileIsCa) {
                        throw new InvalidOperationException(isCa
                            ? $"A basic constraints extension asserting cA=TRUE contradicts {nameof(CertificateUsage)}.{builder.Usage}, which issues end-entity certificates. Reject it, or set {nameof(CertificateUsage)}.{nameof(CertificateUsage.CA)}"
                            : $"A basic constraints extension asserting cA=FALSE contradicts {nameof(CertificateUsage)}.{nameof(CertificateUsage.CA)}. Reject it, or choose an end-entity {nameof(CertificateUsage)}");
                    }
                    break;

                //cRLSign is deliberately not checked: an indirect CRL issuer is conventionally an end-entity
                //certificate asserting exactly that.
                case Oids.KeyUsage:
                    var usages = Decode(extension, x => new X509KeyUsageExtension(x, x.Critical), x => x.KeyUsages)
                        ?? throw CreateUnreadableValueException(extension, "key usage");
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


    /// <summary>
    /// What <paramref name="read"/> makes of the extension's value, or <see langword="null"/> where the
    /// value is one this builder cannot answer for.
    /// </summary>
    /// <remarks>
    /// Two things are asked, and canonical DER is not one of them. Every non-canonical spelling the decoder
    /// accepts, such as a DEFAULT written out or a bit string carrying a spare byte, denotes the same value
    /// to any reader, and real certificates carry them.
    /// <para>The value must decode, and it must be a single encoded value with nothing after it. Bytes past
    /// the first value are what one reader skips and another reads: an empty SEQUENCE followed by a stray
    /// <c>cA=TRUE</c> is read here as cA=FALSE, while OpenSSL and CryptoAPI read the well-formed part and
    /// honour the authority. .NET 10's decoder refuses those bytes itself, .NET 8 and 9 do not, so the
    /// extent is measured here rather than left to the framework.</para>
    /// </remarks>
    private static TValue? Decode<TExtension, TValue>(X509Extension extension, Func<X509Extension, TExtension> decode, Func<TExtension, TValue> read) where TValue : struct
    {
        try {
            //BER, so that only the extent is judged here and the spelling is left to the decoder below
            AsnDecoder.ReadEncodedValue(extension.RawData, AsnEncodingRules.BER, out _, out _, out int consumed);
            if (consumed != extension.RawData.Length) {
                return null;
            }

            //Reading is also what forces the decode, since the BCL types parse lazily
            return read(decode(extension));
        } catch (Exception ex) when (ex is CryptographicException or AsnContentException) {
            return null;
        }
    }


    private static InvalidOperationException CreateUnreadableValueException(X509Extension extension, string name)
    {
        const int quotedValueLimit = 128;

        //Truncated because a requester chooses how long the value is
        var quoted = Convert.ToHexString(extension.RawData.AsSpan(0, Math.Min(extension.RawData.Length, quotedValueLimit)));
        var ellipsis = extension.RawData.Length > quotedValueLimit ? "..." : "";
        return new InvalidOperationException($"A {name} extension's value cannot be read, so what it asserts to a validator cannot be established here and may not agree with {nameof(CertificateUsage)}. Reject it, or supply one this builder can read. Value: {quoted}{ellipsis}");
    }


    /// <summary>
    /// The key identifier naming a certificate authority: the one it publishes in its own Subject Key
    /// Identifier, or one derived from its public key where it publishes none.
    /// </summary>
    /// <remarks>A published identifier that will not decode is refused rather than replaced by a derived
    /// one. Deriving would name a key identifier the authority does not publish, which nothing chaining by
    /// key identifier could match, and no error would say why.</remarks>
    /// <exception cref="InvalidOperationException">Thrown when the authority publishes a Subject Key
    /// Identifier whose value does not decode.</exception>
    private static ReadOnlyMemory<byte> GetSubjectKeyIdentifier(X509Certificate2 ca)
    {
        if (ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault() is not { } published) {
            return new X509SubjectKeyIdentifierExtension(ca.PublicKey, false).SubjectKeyIdentifierBytes;
        }

        try {
            return published.SubjectKeyIdentifierBytes;
        } catch (CryptographicException ex) {
            throw new InvalidOperationException("The issuer publishes a subject key identifier whose value cannot be decoded, so there is nothing to name it by. Re-issue the issuer with a well-formed subject key identifier, or with none at all to have one derived from its public key", ex);
        }
    }


    private static ImmutableHashSet<X509Extension> BuildExtensions(CertificateBuilder builder)
    {
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
            CertificateUsage.CrlSigning => GetCrlSigningExtensions(builder),
            _ => throw new NotImplementedException($"{builder.Usage} {nameof(Usage)} not yet implemented")
        });

        if (builder.SubjectAlternativeNames != null && builder.SubjectAlternativeNames.Any()) {
            //RFC 5280 s4.1.2.6: must be marked critical when the Subject is empty
            bool critical = builder.Subject.RelativeDistinguishedNames.IsEmpty;
            extensions.Add(new X509SubjectAlternativeNameExtension(builder.SubjectAlternativeNames.Encode(), critical));
        }

        //Extensions on the builder override the generated ones under the same OID
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
            new X509KeyUsageExtension(GetEndEntityKeyUsage(builder, GetSigningOrKeyAgreement(builder) | GetKeyEnciphermentIfSupported(builder)), true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.ServerAuthPurpose) }, false)
        ];


    private static List<X509Extension> GetClientExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(GetEndEntityKeyUsage(builder, GetSigningOrKeyAgreement(builder)), true),
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
            new X509KeyUsageExtension(GetEndEntityKeyUsage(builder, GetSigningOrKeyAgreement(builder) | GetNonRepudiationIfSigning(builder) | GetKeyEnciphermentIfSupported(builder)), true),
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
            //RFC 3161 s2.3: id-kp-timeStamping must be a TSA certificate's only EKU, marked critical
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.TimeStampingPurpose) }, true)
        ];


    //RFC 5280 defines no extended key usage for CRL signing, so this profile has no EKU
    private static List<X509Extension> GetCrlSigningExtensions(CertificateBuilder builder)
        => [
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign, true)
        ];


    /// <summary>
    /// RFC 9935 s5: an ML-KEM certificate asserts <see cref="X509KeyUsageFlags.KeyEncipherment"/> and nothing
    /// else. Applied here rather than in each profile because it is a prohibition: omitting the bit would
    /// emit an empty keyUsage, which RFC 5280 s4.2.1.3 forbids, and adding a second breaks the "only".
    /// </summary>
    private static X509KeyUsageFlags GetEndEntityKeyUsage(CertificateBuilder builder, X509KeyUsageFlags flags)
        => builder.PublicKey?.Oid.Value is Oids.MLKem512 or Oids.MLKem768 or Oids.MLKem1024
            ? X509KeyUsageFlags.KeyEncipherment
            : flags;


    /// <summary>
    /// Returns <see cref="X509KeyUsageFlags.NonRepudiation"/> only for a key that can sign, since the bit
    /// means nothing for a key-agreement or key-encapsulation key.
    /// </summary>
    private static X509KeyUsageFlags GetNonRepudiationIfSigning(CertificateBuilder builder)
        => builder.KeyAlgorithm.CanSign
            ? X509KeyUsageFlags.NonRepudiation
            : X509KeyUsageFlags.None;


#pragma warning disable FLUENTCERT001 // Classifying a family is not use of the experimental surface
    /// <summary>
    /// Returns <see cref="X509KeyUsageFlags.KeyAgreement"/> for an ECDH key and
    /// <see cref="X509KeyUsageFlags.DigitalSignature"/> otherwise; RFC 5480 s3 permits keyAgreement for
    /// id-ecPublicKey. It must read <see cref="KeyAlgorithm"/> rather than the public key, because an ECDH
    /// and an ECDsa public key are byte-identical in SubjectPublicKeyInfo.
    /// </summary>
    private static X509KeyUsageFlags GetSigningOrKeyAgreement(CertificateBuilder builder)
        => builder.KeyAlgorithm.Family switch {
            KeyAlgorithmFamily.ECDiffieHellman => X509KeyUsageFlags.KeyAgreement,
            //ML-KEM encapsulation is key transport, so its bit is keyEncipherment, asserted by
            //GetKeyEnciphermentIfSupported; keyAgreement would name an operation the key has no equivalent of.
            KeyAlgorithmFamily.MLKem => X509KeyUsageFlags.None,
            _ => X509KeyUsageFlags.DigitalSignature
        };
#pragma warning restore FLUENTCERT001


    /// <summary>
    /// Returns <see cref="X509KeyUsageFlags.KeyEncipherment"/> only for a public key that can perform key
    /// transport. RFC 8813 s3 makes it a MUST NOT for id-ecPublicKey keys, and DSA is signature-only.
    /// </summary>
    private static X509KeyUsageFlags GetKeyEnciphermentIfSupported(CertificateBuilder builder)
        => builder.PublicKey?.Oid.Value switch {
            Oids.Rsa => X509KeyUsageFlags.KeyEncipherment,
            //RFC 9629 s3 and RFC 9935 s5 put ML-KEM encapsulation here rather than under keyAgreement
            Oids.MLKem512 or Oids.MLKem768 or Oids.MLKem1024 => X509KeyUsageFlags.KeyEncipherment,
            _ => X509KeyUsageFlags.None
        };


#pragma warning disable CS0618 // Type or member is obsolete
#pragma warning disable FLUENTCERT001 // Post-quantum support is experimental
    /// <summary>
    /// Maps a public key's algorithm OID onto a <see cref="KeyAlgorithm"/>, or <see langword="null"/> when it
    /// is not one the builder knows how to generate, which is not an error here.
    /// </summary>
    private static KeyAlgorithm? GetKeyAlgorithm(PublicKey? key)
        => key?.Oid.Value switch {
            Oids.Rsa => KeyAlgorithm.RSA(),
            Oids.EcPublicKey => KeyAlgorithm.ECDsa(),
            Oids.Dsa => KeyAlgorithm.DSA(),
            { } oid when KeyAlgorithm.PostQuantumAlgorithms.FirstOrDefault(x => x.Oid == oid) is { } pqc => pqc,
            _ => null
        };
#pragma warning restore FLUENTCERT001
#pragma warning restore CS0618 // Type or member is obsolete


#pragma warning disable CS0618 // Type or member is obsolete
    /// <summary>Derives a <see cref="KeyAlgorithm"/> from a supplied key, whose own parameters win over anything previously configured.</summary>
    private static KeyAlgorithm? GetKeyAlgorithm(AsymmetricAlgorithm? keys)
        => keys switch {
            ECDsa ecdsa => KeyAlgorithm.ECDsa(ecdsa.ExportParameters(false).Curve),
            ECDiffieHellman ecdh => KeyAlgorithm.ECDiffieHellman(ecdh.ExportParameters(false).Curve),
            RSA rsa => KeyAlgorithm.RSA(rsa.KeySize),
            DSA dsa => KeyAlgorithm.DSA(dsa.KeySize),
            null => null,
            _ => throw new NotSupportedException($"Unsupported AsymmetricAlgorithm: {keys.GetType()}")
        };
#pragma warning restore CS0618 // Type or member is obsolete


    private static KeyAlgorithm? GetKeyAlgorithm(CertificateKey? keys)
    {
        if (keys == null) {
            return null;
        }

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
#pragma warning disable FLUENTCERT001
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


    /// <summary>Builds the <see cref="PublicKey"/> for a supplied key pair.</summary>
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


    /// <summary>Determines whether another builder is configured identically to this one.</summary>
    /// <param name="other">The other builder to compare.</param>
    /// <returns>True if the two builders describe the same certificate configuration; otherwise, false.</returns>
    /// <remarks>This is the record's value equality, so the immutable-collection fields are compared by their
    /// contents rather than by reference. The key is compared by its public SubjectPublicKeyInfo, so a builder
    /// holding only a public key equals one holding the matching pair, and a non-exportable HSM/TPM key is
    /// compared by that public half alone. A <see cref="SignatureGenerator"/> and a
    /// <see cref="SerialNumberGenerator"/> have no value equality, so each is compared by reference.</remarks>
    public virtual bool Equals(CertificateBuilder? other)
    {
        if (other is null || other.GetType() != GetType()) {
            return false;
        }
        if (ReferenceEquals(this, other)) {
            return true;
        }

        return Usage == other.Usage
            && NotBefore == other.NotBefore
            && NotAfter == other.NotAfter
            && FriendlyName == other.FriendlyName
            && PathLength == other.PathLength
            && _keyAlgorithm == other._keyAlgorithm
            && HashAlgorithm == other.HashAlgorithm
            && RSASignaturePadding.Equals(other.RSASignaturePadding)
            && KeyStorageFlags == other.KeyStorageFlags
            && ReferenceEquals(SignatureGenerator, other.SignatureGenerator)
            && ReferenceEquals(SerialNumberGenerator, other.SerialNumberGenerator)
            && Subject.Equals(other.Subject)
            && HasSameKey(other)
            && HasSameIssuer(other)
            && HasSameExtensions(other)
            && HasSameSubjectAlternativeNames(other);
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Usage);
        hash.Add(NotBefore);
        hash.Add(NotAfter);
        hash.Add(FriendlyName);
        hash.Add(PathLength);
        hash.Add(_keyAlgorithm);
        hash.Add(HashAlgorithm);
        hash.Add(RSASignaturePadding);
        hash.Add(KeyStorageFlags);
        hash.Add(Subject);
        if (_publicKeySpki is not null) {
            hash.AddBytes(_publicKeySpki);
        }
        if (Issuer is not null) {
            hash.Add(Issuer);
        }

        //The extension set is order-independent, so a commutative sum keeps two equal sets hashing alike
        var extensionsHash = 0;
        foreach (var extension in _extensions) {
            var perExtension = new HashCode();
            perExtension.Add(extension.Oid?.Value);
            perExtension.Add(extension.Critical);
            perExtension.AddBytes(extension.RawData);
            extensionsHash += perExtension.ToHashCode();
        }
        hash.Add(extensionsHash);

        if (_subjectAlternativeNames is not null) {
            foreach (var name in _subjectAlternativeNames) {
                hash.Add(name);
            }
        }

        //SignatureGenerator and SerialNumberGenerator are compared by reference and left out here: unequal
        //objects are allowed to share a hash, and equal ones still match on every member folded above.
        return hash.ToHashCode();
    }


    private bool HasSameKey(CertificateBuilder other)
        => _publicKeySpki is null
            ? other._publicKeySpki is null
            : other._publicKeySpki is not null && _publicKeySpki.AsSpan().SequenceEqual(other._publicKeySpki);


    private bool HasSameIssuer(CertificateBuilder other)
        => Issuer is null
            ? other.Issuer is null
            : other.Issuer is not null && Issuer.RawData.AsSpan().SequenceEqual(other.Issuer.RawData);


    private bool HasSameExtensions(CertificateBuilder other)
    {
        if (_extensions.Count != other._extensions.Count) {
            return false;
        }

        //The set keys on OID alone, so TryGetValue finds the counterpart under the same OID; comparing then
        //settles what the OID does not, its criticality and its encoded value.
        foreach (var extension in _extensions) {
            if (!other._extensions.TryGetValue(extension, out var counterpart)
                || counterpart.Critical != extension.Critical
                || !counterpart.RawData.AsSpan().SequenceEqual(extension.RawData)) {
                return false;
            }
        }
        return true;
    }


    private bool HasSameSubjectAlternativeNames(CertificateBuilder other)
        => _subjectAlternativeNames is null
            ? other._subjectAlternativeNames is null
            : other._subjectAlternativeNames is not null && _subjectAlternativeNames.SequenceEqual(other._subjectAlternativeNames);


    private static readonly X500NameBuilder EmptyNameBuilder = new();
    private static readonly X509ExtensionOidEqualityComparer X509ExtensionOidEqualityComparer = new();
    private static readonly ImmutableHashSet<X509Extension> EmptyExtensions = ImmutableHashSet<X509Extension>.Empty.WithComparer(X509ExtensionOidEqualityComparer);
}
