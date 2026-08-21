using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;


namespace FluentCertificates;

/// <summary>
/// Represents a digital signature algorithm, including the key algorithm family it applies to, its hash
/// algorithm and padding where it has them, and its OID. Provides static instances for common algorithms and
/// lookup methods by OID.
/// </summary>
/// <remarks>
/// A classical signature algorithm pairs a key algorithm with a hash. A post-quantum one does not: ML-DSA and
/// its relatives absorb the message directly and their OID names the parameter set rather than a
/// key-plus-hash combination. <see cref="HashAlgorithm"/> is therefore <see langword="null"/> for those, which
/// is the reason it is nullable at all.
/// </remarks>
public sealed record SignatureAlgorithm
{
    // ReSharper disable InconsistentNaming
    /// <summary>SHA-1 with DSA signature algorithm.</summary>
    [Obsolete("Obsolete")]
    public static readonly SignatureAlgorithm SHA1DSA = new(KeyAlgorithmFamily.Dsa, HashAlgorithmName.SHA1, null, Oids.DsaWithSha1);

    /// <summary>SHA-256 with DSA signature algorithm.</summary>
    [Obsolete("Obsolete")]
    public static readonly SignatureAlgorithm SHA256DSA = new(KeyAlgorithmFamily.Dsa, HashAlgorithmName.SHA256, null, Oids.DsaWithSha256);

    /// <summary>SHA-1 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA1ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA1, null, Oids.ECDsaWithSha1);

    /// <summary>SHA-256 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA256ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA256, null, Oids.ECDsaWithSha256);

    /// <summary>SHA-384 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA384ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA384, null, Oids.ECDsaWithSha384);

    /// <summary>SHA-512 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA512ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA512, null, Oids.ECDsaWithSha512);

    /// <summary>MD5 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm MD5RSA = new(KeyAlgorithmFamily.Rsa, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Md5);

    /// <summary>SHA-1 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA1RSA = new(KeyAlgorithmFamily.Rsa, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha1);

    /// <summary>SHA-256 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA256RSA = new(KeyAlgorithmFamily.Rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha256);

    /// <summary>SHA-384 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA384RSA = new(KeyAlgorithmFamily.Rsa, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha384);

    /// <summary>SHA-512 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA512RSA = new(KeyAlgorithmFamily.Rsa, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha512);

    /// <summary>ML-DSA-44 (FIPS 204). Takes no separate hash algorithm.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly SignatureAlgorithm MLDsa44 = new(KeyAlgorithmFamily.MLDsa, null, null, Oids.MLDsa44);

    /// <summary>ML-DSA-65 (FIPS 204). Takes no separate hash algorithm.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly SignatureAlgorithm MLDsa65 = new(KeyAlgorithmFamily.MLDsa, null, null, Oids.MLDsa65);

    /// <summary>ML-DSA-87 (FIPS 204). Takes no separate hash algorithm.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly SignatureAlgorithm MLDsa87 = new(KeyAlgorithmFamily.MLDsa, null, null, Oids.MLDsa87);
    // ReSharper restore InconsistentNaming


    /// <summary>
    /// The signature algorithm matching a post-quantum key algorithm.
    /// </summary>
    /// <remarks>
    /// For the post-quantum families the key algorithm and the signature algorithm share an OID, since the
    /// parameter set fixes both and there is no separate hash to name. That correspondence is what lets this
    /// be derived rather than listed: SLH-DSA alone would otherwise need twelve members and Composite ML-DSA
    /// eighteen, each duplicating an OID already declared on <see cref="KeyAlgorithm"/>.
    /// </remarks>
    /// <param name="algorithm">A post-quantum signing algorithm.</param>
    /// <exception cref="ArgumentException">Thrown if the algorithm is not a post-quantum signing one.</exception>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static SignatureAlgorithm ForPostQuantum(KeyAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(algorithm);

        if (!algorithm.IsPostQuantum || !algorithm.CanSign) {
            throw new ArgumentException($"{algorithm.Name} is not a post-quantum signature algorithm", nameof(algorithm));
        }

        return new SignatureAlgorithm(algorithm.Family, null, null, algorithm.Oid);
    }


    /// <summary>
    /// Gets the family of key this signature algorithm applies to.
    /// </summary>
    /// <remarks>
    /// A family rather than a full <see cref="KeyAlgorithm"/>, because a classical signature algorithm says
    /// nothing about key size: <see cref="SHA256RSA"/> describes RSA signatures at every key length. Where the
    /// parameter set does matter, as it does for the post-quantum algorithms, <see cref="Oid"/> pins it.
    /// </remarks>
    public KeyAlgorithmFamily Family { get; init; }


    /// <summary>
    /// Gets the hash algorithm used by this signature algorithm, or <see langword="null"/> for an algorithm
    /// that takes no separate hash.
    /// </summary>
    public HashAlgorithmName? HashAlgorithm { get; init; }


    /// <summary>
    /// Gets the RSA signature padding, if applicable.
    /// </summary>
    public RSASignaturePadding? RSASignaturePadding { get; init; }


    /// <summary>
    /// Gets the OID string representing this signature algorithm.
    /// </summary>
    public string Oid { get; init; }


    /// <summary>
    /// Looks up a <see cref="SignatureAlgorithm"/> by its OID value string.
    /// </summary>
    /// <param name="oidValue">The OID value as a string.</param>
    /// <returns>The matching <see cref="SignatureAlgorithm"/>.</returns>
    /// <exception cref="NotSupportedException">Thrown if the OID is not supported.</exception>
    public static SignatureAlgorithm FromOidValue(string? oidValue)
        => oidValue != null && InstanceLookup.TryGetValue(oidValue, out var algorithm)
            ? algorithm
            : throw new NotSupportedException($"Unsupported signature algorithm: {oidValue}");


    /// <summary>
    /// Looks up a <see cref="SignatureAlgorithm"/> by an <see cref="Oid"/> object.
    /// </summary>
    /// <param name="oid">The <see cref="Oid"/> instance.</param>
    /// <returns>The matching <see cref="SignatureAlgorithm"/>.</returns>
    /// <exception cref="NotSupportedException">Thrown if the OID is not supported.</exception>
    public static SignatureAlgorithm FromOid(Oid oid)
        => oid.Value != null && InstanceLookup.TryGetValue(oid.Value, out var algorithm)
            ? algorithm
            : throw new NotSupportedException($"Unsupported signature algorithm: {oid.Value} ({oid.FriendlyName})");


    /// <summary>
    /// Creates a <see cref="SignatureAlgorithm"/> for RSA-PSS with the specified signature and hash OIDs.
    /// </summary>
    /// <param name="signatureOid">The signature OID.</param>
    /// <param name="hashOid">The hash algorithm OID.</param>
    /// <returns>A new <see cref="SignatureAlgorithm"/> instance for RSA-PSS.</returns>
    internal static SignatureAlgorithm ForRsaSsaPss(string signatureOid, string hashOid)
        => new(KeyAlgorithmFamily.Rsa, HashAlgorithmName.FromOid(hashOid), RSASignaturePadding.Pss, Oids.RsaPss);


    /// <summary>
    /// Initializes a new instance of the <see cref="SignatureAlgorithm"/> record.
    /// </summary>
    /// <param name="family">The key algorithm family.</param>
    /// <param name="hashAlgorithm">The hash algorithm, or <see langword="null"/> if the algorithm takes none.</param>
    /// <param name="padding">The RSA signature padding, if any.</param>
    /// <param name="oid">The OID string.</param>
    private SignatureAlgorithm(KeyAlgorithmFamily family, HashAlgorithmName? hashAlgorithm, RSASignaturePadding? padding, string oid)
    {
        Family = family;
        HashAlgorithm = hashAlgorithm;
        RSASignaturePadding = padding;
        Oid = oid;
    }


    /// <summary>
    /// Immutable lookup dictionary mapping OID strings to <see cref="SignatureAlgorithm"/> instances.
    /// </summary>
#pragma warning disable CS0618 // Type or member is obsolete
#pragma warning disable FLUENTCERT001 // Post-quantum support is experimental
    private static readonly ImmutableDictionary<string, SignatureAlgorithm> InstanceLookup = BuildLookup();


    private static ImmutableDictionary<string, SignatureAlgorithm> BuildLookup()
    {
        var classical = new Dictionary<string, SignatureAlgorithm> {
        [SHA1DSA.Oid] = SHA1DSA,
        [SHA256DSA.Oid] = SHA256DSA,
        [SHA1ECDSA.Oid] = SHA1ECDSA,
        [SHA256ECDSA.Oid] = SHA256ECDSA,
        [SHA384ECDSA.Oid] = SHA384ECDSA,
        [SHA512ECDSA.Oid] = SHA512ECDSA,
        [MD5RSA.Oid] = MD5RSA,
        [SHA1RSA.Oid] = SHA1RSA,
        [SHA256RSA.Oid] = SHA256RSA,
        [SHA384RSA.Oid] = SHA384RSA,
            [SHA512RSA.Oid] = SHA512RSA
        };

        //Every post-quantum signing parameter set resolves through its own OID. Derived from the one
        //list on KeyAlgorithm so a new parameter set cannot be added there and forgotten here.
        foreach (var algorithm in KeyAlgorithm.PostQuantumAlgorithms.Where(x => x.CanSign)) {
            classical[algorithm.Oid] = ForPostQuantum(algorithm);
        }

        return classical.ToImmutableDictionary();
    }
#pragma warning restore FLUENTCERT001
#pragma warning restore CS0618 // Type or member is obsolete
}
