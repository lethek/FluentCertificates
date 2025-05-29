using System.Collections.Immutable;
using System.Security.Cryptography;


namespace FluentCertificates;

/// <summary>
/// Represents a digital signature algorithm, including its key algorithm, hash algorithm, padding, and OID.
/// Provides static instances for common algorithms and lookup methods by OID.
/// </summary>
public sealed record SignatureAlgorithm
{
    // ReSharper disable InconsistentNaming
    /// <summary>SHA-1 with DSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA1DSA = new(KeyAlgorithm.DSA, HashAlgorithmName.SHA1, null, Oids.DsaWithSha1);

    /// <summary>SHA-256 with DSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA256DSA = new(KeyAlgorithm.DSA, HashAlgorithmName.SHA256, null, Oids.DsaWithSha256);

    /// <summary>SHA-1 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA1ECDSA = new(KeyAlgorithm.ECDsa, HashAlgorithmName.SHA1, null, Oids.ECDsaWithSha1);

    /// <summary>SHA-256 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA256ECDSA = new(KeyAlgorithm.ECDsa, HashAlgorithmName.SHA256, null, Oids.ECDsaWithSha256);

    /// <summary>SHA-384 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA384ECDSA = new(KeyAlgorithm.ECDsa, HashAlgorithmName.SHA384, null, Oids.ECDsaWithSha384);

    /// <summary>SHA-512 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA512ECDSA = new(KeyAlgorithm.ECDsa, HashAlgorithmName.SHA512, null, Oids.ECDsaWithSha512);

    /// <summary>MD5 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm MD5RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Md5);

    /// <summary>SHA-1 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA1RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha1);

    /// <summary>SHA-256 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA256RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha256);

    /// <summary>SHA-384 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA384RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha384);

    /// <summary>SHA-512 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA512RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha512);
    // ReSharper restore InconsistentNaming


    /// <summary>
    /// Gets the key algorithm used by this signature algorithm.
    /// </summary>
    public KeyAlgorithm KeyAlgorithm { get; init; }


    /// <summary>
    /// Gets the hash algorithm used by this signature algorithm.
    /// </summary>
    public HashAlgorithmName HashAlgorithm { get; init; }


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
        => new(KeyAlgorithm.RSA, HashAlgorithmName.FromOid(hashOid), RSASignaturePadding.Pss, Oids.RsaPss);

   
    /// <summary>
    /// Initializes a new instance of the <see cref="SignatureAlgorithm"/> record.
    /// </summary>
    /// <param name="keyAlgorithm">The key algorithm.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="padding">The RSA signature padding, if any.</param>
    /// <param name="oid">The OID string.</param>
    private SignatureAlgorithm(KeyAlgorithm keyAlgorithm, HashAlgorithmName hashAlgorithm, RSASignaturePadding? padding, string oid)
    {
        KeyAlgorithm = keyAlgorithm;
        HashAlgorithm = hashAlgorithm;
        RSASignaturePadding = padding;
        Oid = oid;
    }

    
    /// <summary>
    /// Immutable lookup dictionary mapping OID strings to <see cref="SignatureAlgorithm"/> instances.
    /// </summary>
    private static readonly ImmutableDictionary<string, SignatureAlgorithm> InstanceLookup = new Dictionary<string, SignatureAlgorithm> {
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
    }.ToImmutableDictionary();
}
