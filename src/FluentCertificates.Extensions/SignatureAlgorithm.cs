using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
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
    [Obsolete("DSA is deprecated for certificate use. Consider using ECDsa, RSA or ML-DSA instead.")]
    public static readonly SignatureAlgorithm SHA1DSA = new(KeyAlgorithmFamily.Dsa, HashAlgorithmName.SHA1, null, Oids.DsaWithSha1);

    /// <summary>SHA-256 with DSA signature algorithm.</summary>
    [Obsolete("DSA is deprecated for certificate use. Consider using ECDsa, RSA or ML-DSA instead.")]
    public static readonly SignatureAlgorithm SHA256DSA = new(KeyAlgorithmFamily.Dsa, HashAlgorithmName.SHA256, null, Oids.DsaWithSha256);

    /// <summary>SHA-384 with DSA signature algorithm.</summary>
    [Obsolete("DSA is deprecated for certificate use. Consider using ECDsa, RSA or ML-DSA instead.")]
    public static readonly SignatureAlgorithm SHA384DSA = new(KeyAlgorithmFamily.Dsa, HashAlgorithmName.SHA384, null, Oids.DsaWithSha384);

    /// <summary>SHA-512 with DSA signature algorithm.</summary>
    [Obsolete("DSA is deprecated for certificate use. Consider using ECDsa, RSA or ML-DSA instead.")]
    public static readonly SignatureAlgorithm SHA512DSA = new(KeyAlgorithmFamily.Dsa, HashAlgorithmName.SHA512, null, Oids.DsaWithSha512);

    /// <summary>SHA-1 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA1ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA1, null, Oids.ECDsaWithSha1);

    /// <summary>SHA-256 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA256ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA256, null, Oids.ECDsaWithSha256);

    /// <summary>SHA-384 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA384ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA384, null, Oids.ECDsaWithSha384);

    /// <summary>SHA-512 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA512ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA512, null, Oids.ECDsaWithSha512);

    /// <summary>SHA3-256 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA3_256ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA3_256, null, Oids.ECDsaWithSha3_256);

    /// <summary>SHA3-384 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA3_384ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA3_384, null, Oids.ECDsaWithSha3_384);

    /// <summary>SHA3-512 with ECDSA signature algorithm.</summary>
    public static readonly SignatureAlgorithm SHA3_512ECDSA = new(KeyAlgorithmFamily.ECDsa, HashAlgorithmName.SHA3_512, null, Oids.ECDsaWithSha3_512);

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

    /// <summary>SHA3-256 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA3_256RSA = new(KeyAlgorithmFamily.Rsa, HashAlgorithmName.SHA3_256, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha3_256);

    /// <summary>SHA3-384 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA3_384RSA = new(KeyAlgorithmFamily.Rsa, HashAlgorithmName.SHA3_384, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha3_384);

    /// <summary>SHA3-512 with RSA signature algorithm (PKCS#1 v1.5 padding).</summary>
    public static readonly SignatureAlgorithm SHA3_512RSA = new(KeyAlgorithmFamily.Rsa, HashAlgorithmName.SHA3_512, RSASignaturePadding.Pkcs1, Oids.RsaPkcs1Sha3_512);

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
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="algorithm"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown if the algorithm is not a post-quantum signing one.</exception>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static SignatureAlgorithm CreateForPostQuantum(KeyAlgorithm algorithm)
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
    /// Reads the algorithm from an encoded <c>AlgorithmIdentifier</c>, taking an RSA-PSS hash from its parameters.
    /// </summary>
    /// <param name="algorithmIdentifier">The encoded <c>AlgorithmIdentifier</c> SEQUENCE.</param>
    /// <returns>The matching <see cref="SignatureAlgorithm"/>.</returns>
    /// <exception cref="NotSupportedException">Thrown if the signature algorithm is not recognised.</exception>
    internal static SignatureAlgorithm FromAlgorithmIdentifier(ReadOnlyMemory<byte> algorithmIdentifier)
    {
        var reader = new AsnReader(algorithmIdentifier, AsnEncodingRules.BER).ReadSequence(Asn1Tag.Sequence);
        var algorithm = reader.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
        if (algorithm == Oids.RsaPss) {
            try {
                //RFC 4055 s3.1: the parameters MUST be present in a signature's algorithm identifier, as
                //RSASSA-PSS-params, so an absent or NULL one is refused. Within them every field has a default,
                //and the hash is SHA-1 where hashAlgorithm is left out.
                var parameters = reader.ReadSequence(Asn1Tag.Sequence);
                var hashTag = new Asn1Tag(TagClass.ContextSpecific, 0);
                var hashAlgorithm = parameters.HasData && parameters.PeekTag().HasSameClassAndValue(hashTag)
                    ? parameters.ReadSequence(hashTag).ReadSequence(Asn1Tag.Sequence).ReadObjectIdentifier(Asn1Tag.ObjectIdentifier)
                    : Oids.Sha1;
                return CreateForRsaSsaPss(algorithm, hashAlgorithm);
            } catch (AsnContentException ex) {
                throw new NotSupportedException("The RSASSA-PSS parameters are not in a form that can be read.", ex);
            } catch (Exception ex) when (ex is CryptographicException or ArgumentException) {
                //HashAlgorithmName.FromOid refuses a hash it does not know
                throw new NotSupportedException("The RSASSA-PSS hash algorithm is not supported.", ex);
            }
        }
        return FromOidValue(algorithm);
    }


    /// <summary>
    /// Refuses an RSASSA-PSS identifier whose parameters are not the ones .NET verifies with, and does nothing for
    /// any other algorithm.
    /// </summary>
    /// <remarks>.NET verifies PSS with MGF1 over the same hash, a salt as long as the hash, and trailer field 1.
    /// Verifying a signature that declares anything else with those settings would reject a valid signature,
    /// or accept one that is inconsistent with what it declares.</remarks>
    /// <param name="algorithmIdentifier">The encoded <c>AlgorithmIdentifier</c> SEQUENCE.</param>
    /// <exception cref="NotSupportedException">The parameters are not readable or are not the ones .NET verifies with.</exception>
    internal static void ThrowIfPssParametersNotVerifiable(ReadOnlyMemory<byte> algorithmIdentifier)
    {
        var reader = new AsnReader(algorithmIdentifier, AsnEncodingRules.BER).ReadSequence(Asn1Tag.Sequence);
        if (reader.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier) != Oids.RsaPss) {
            return;
        }

        try {
            var parameters = reader.ReadSequence(Asn1Tag.Sequence);
            string hash = Oids.Sha1, maskHash = Oids.Sha1;
            System.Numerics.BigInteger saltLength = 20, trailer = 1;

            while (parameters.HasData) {
                var tag = parameters.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific) {
                    throw new AsnContentException("Unexpected field in the RSASSA-PSS parameters.");
                }

                var field = parameters.ReadSequence(tag);
                switch (tag.TagValue) {
                    case 0:
                        hash = field.ReadSequence(Asn1Tag.Sequence).ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
                        break;
                    case 1:
                        var maskGenerator = field.ReadSequence(Asn1Tag.Sequence);
                        if (maskGenerator.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier) != Oids.Mgf1) {
                            throw new NotSupportedException("The RSASSA-PSS mask generation function is not MGF1.");
                        }
                        maskHash = maskGenerator.ReadSequence(Asn1Tag.Sequence).ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
                        break;
                    case 2:
                        saltLength = field.ReadInteger();
                        break;
                    case 3:
                        trailer = field.ReadInteger();
                        break;
                    default:
                        throw new AsnContentException("Unexpected field in the RSASSA-PSS parameters.");
                }
            }

            var hashSize = hash switch {
                Oids.Sha1 => 20,
                Oids.Sha256 or Oids.Sha3_256 => 32,
                Oids.Sha384 or Oids.Sha3_384 => 48,
                Oids.Sha512 or Oids.Sha3_512 => 64,
                _ => throw new NotSupportedException($"The RSASSA-PSS hash {hash} is not supported.")
            };
            if (maskHash != hash || saltLength != hashSize || trailer != 1) {
                throw new NotSupportedException("The RSASSA-PSS parameters are not the ones that can be verified: MGF1 over the same hash, a salt as long as the hash, and trailer field 1.");
            }
        } catch (AsnContentException ex) {
            throw new NotSupportedException("The RSASSA-PSS parameters are not in a form that can be read.", ex);
        }
    }


    /// <summary>
    /// Creates a <see cref="SignatureAlgorithm"/> for RSA-PSS with the specified signature and hash OIDs.
    /// </summary>
    /// <param name="signatureOid">Unused. The signature OID is always <see cref="Oids.RsaPss"/>.</param>
    /// <param name="hashOid">The hash algorithm OID.</param>
    /// <returns>A new <see cref="SignatureAlgorithm"/> instance for RSA-PSS.</returns>
    internal static SignatureAlgorithm CreateForRsaSsaPss(string signatureOid, string hashOid)
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
    /// Frozen lookup dictionary mapping OID strings to <see cref="SignatureAlgorithm"/> instances.
    /// </summary>
#pragma warning disable CS0618 // Type or member is obsolete
#pragma warning disable FLUENTCERT001 // Post-quantum support is experimental
    private static readonly FrozenDictionary<string, SignatureAlgorithm> InstanceLookup = BuildLookup();


    private static FrozenDictionary<string, SignatureAlgorithm> BuildLookup()
    {
        var classical = new Dictionary<string, SignatureAlgorithm> {
            [SHA1DSA.Oid] = SHA1DSA,
            [SHA256DSA.Oid] = SHA256DSA,
            [SHA384DSA.Oid] = SHA384DSA,
            [SHA512DSA.Oid] = SHA512DSA,
            [SHA1ECDSA.Oid] = SHA1ECDSA,
            [SHA256ECDSA.Oid] = SHA256ECDSA,
            [SHA384ECDSA.Oid] = SHA384ECDSA,
            [SHA512ECDSA.Oid] = SHA512ECDSA,
            [SHA3_256ECDSA.Oid] = SHA3_256ECDSA,
            [SHA3_384ECDSA.Oid] = SHA3_384ECDSA,
            [SHA3_512ECDSA.Oid] = SHA3_512ECDSA,
            [MD5RSA.Oid] = MD5RSA,
            [SHA1RSA.Oid] = SHA1RSA,
            [SHA256RSA.Oid] = SHA256RSA,
            [SHA384RSA.Oid] = SHA384RSA,
            [SHA512RSA.Oid] = SHA512RSA,
            [SHA3_256RSA.Oid] = SHA3_256RSA,
            [SHA3_384RSA.Oid] = SHA3_384RSA,
            [SHA3_512RSA.Oid] = SHA3_512RSA
        };

        //Every post-quantum signing parameter set resolves through its own OID. Derived from the one
        //list on KeyAlgorithm so a new parameter set cannot be added there and forgotten here.
        foreach (var algorithm in KeyAlgorithm.PostQuantumAlgorithms.Where(x => x.CanSign)) {
            classical[algorithm.Oid] = CreateForPostQuantum(algorithm);
        }

        return classical.ToFrozenDictionary();
    }
#pragma warning restore FLUENTCERT001
#pragma warning restore CS0618 // Type or member is obsolete
}
