using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using ECCurveType = System.Security.Cryptography.ECCurve;


namespace FluentCertificates;

/// <summary>
/// Describes a key algorithm together with the parameters that make it concrete: a key length for RSA and DSA,
/// a curve for the elliptic-curve algorithms, or a parameter set for the post-quantum ones.
/// </summary>
/// <remarks>
/// <para>
/// Every instance is a complete, valid choice of algorithm. There is no way to name RSA without a key length or
/// ML-DSA without a parameter set, and no way to attach a curve to RSA, so the combinations that used to be
/// rejected at build time cannot be expressed at all.
/// </para>
/// <para>
/// Fixed parameter sets are exposed as static fields (<see cref="MLDsa65"/>); families that take a parameter are
/// exposed as static methods (<see cref="RSA(int)"/>). Each family's default matches what the builder generated
/// before this type existed: RSA 4096, DSA 1024, and nistP256 for both elliptic-curve algorithms.
/// </para>
/// <para>
/// The post-quantum members exist on every target framework so that the public surface does not vary by TFM.
/// Generating one requires .NET 10 or later and platform support for that algorithm; see
/// <see cref="IsSupported"/>.
/// </para>
/// </remarks>
public sealed record KeyAlgorithm
{
    /// <summary>RSA with the default key length of 4096 bits.</summary>
    public static KeyAlgorithm RSA() => RSA(4096);

    /// <summary>RSA with the specified key length.</summary>
    /// <param name="keyLength">The key length in bits.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="keyLength"/> is not positive.</exception>
    public static KeyAlgorithm RSA(int keyLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keyLength);
        return new KeyAlgorithm(KeyAlgorithmFamily.Rsa, $"RSA-{keyLength}", Oids.Rsa, canSign: true) { KeyLength = keyLength };
    }

    /// <summary>DSA with the default key length of 1024 bits.</summary>
    [Obsolete("DSA is deprecated for certificate use. Consider using ECDsa, RSA or ML-DSA instead.")]
    public static KeyAlgorithm DSA() => DSA(1024);

    /// <summary>DSA with the specified key length.</summary>
    /// <param name="keyLength">The key length in bits.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="keyLength"/> is not positive.</exception>
    [Obsolete("DSA is deprecated for certificate use. Consider using ECDsa, RSA or ML-DSA instead.")]
    public static KeyAlgorithm DSA(int keyLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keyLength);
#pragma warning disable CS0618 // Type or member is obsolete
        return new KeyAlgorithm(KeyAlgorithmFamily.Dsa, $"DSA-{keyLength}", Oids.Dsa, canSign: true) { KeyLength = keyLength };
#pragma warning restore CS0618 // Type or member is obsolete
    }

    /// <summary>ECDsa on the default curve, nistP256.</summary>
    public static KeyAlgorithm ECDsa() => ECDsa(ECCurveType.NamedCurves.nistP256);

    /// <summary>ECDsa on the specified curve.</summary>
    /// <param name="curve">The elliptic curve to generate the key on.</param>
    public static KeyAlgorithm ECDsa(ECCurveType curve)
        => new(KeyAlgorithmFamily.ECDsa, $"ECDsa-{DescribeCurve(curve)}", Oids.EcPublicKey, canSign: true) { Curve = curve };

    /// <summary>ECDH key agreement on the default curve, nistP256.</summary>
    public static KeyAlgorithm ECDiffieHellman() => ECDiffieHellman(ECCurveType.NamedCurves.nistP256);

    /// <summary>
    /// ECDH key agreement on the specified curve. An ECDH key cannot sign, so a certificate for one must be
    /// issued by a CA and cannot itself be a CA or a code-signing, OCSP-signing or time-stamping certificate.
    /// </summary>
    /// <param name="curve">The elliptic curve to generate the key on.</param>
    public static KeyAlgorithm ECDiffieHellman(ECCurveType curve)
        => new(KeyAlgorithmFamily.ECDiffieHellman, $"ECDH-{DescribeCurve(curve)}", Oids.EcPublicKey, canSign: false) { Curve = curve };


    /// <summary>
    /// The default algorithm for a family, for callers that hold a <see cref="KeyAlgorithmFamily"/> rather
    /// than a full algorithm: a family is an enum and so can appear in an attribute, a switch label or a
    /// configuration value, where an algorithm cannot.
    /// </summary>
    /// <param name="family">The family to take the default of.</param>
    /// <returns>
    /// RSA-4096, DSA-1024, nistP256 for either elliptic-curve family, or the middle parameter set for a
    /// post-quantum family.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the family has no default.</exception>
    public static KeyAlgorithm Default(KeyAlgorithmFamily family)
    {
#pragma warning disable CS0618 // Type or member is obsolete
#pragma warning disable FLUENTCERT001 // Post-quantum support is experimental
        return family switch {
            KeyAlgorithmFamily.Rsa => RSA(),
            KeyAlgorithmFamily.Dsa => DSA(),
            KeyAlgorithmFamily.ECDsa => ECDsa(),
            KeyAlgorithmFamily.ECDiffieHellman => ECDiffieHellman(),
            KeyAlgorithmFamily.MLDsa => MLDsa65,
            _ => throw new ArgumentOutOfRangeException(nameof(family), family, $"No default algorithm for {family}")
        };
#pragma warning restore FLUENTCERT001
#pragma warning restore CS0618 // Type or member is obsolete
    }


    /// <summary>ML-DSA-44 (FIPS 204), the smallest of the three parameter sets.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa44 = new(KeyAlgorithmFamily.MLDsa, "ML-DSA-44", Oids.MLDsa44, canSign: true);

    /// <summary>ML-DSA-65 (FIPS 204).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa65 = new(KeyAlgorithmFamily.MLDsa, "ML-DSA-65", Oids.MLDsa65, canSign: true);

    /// <summary>ML-DSA-87 (FIPS 204), the largest of the three parameter sets.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa87 = new(KeyAlgorithmFamily.MLDsa, "ML-DSA-87", Oids.MLDsa87, canSign: true);


    /// <summary>Gets the family this algorithm belongs to.</summary>
    public KeyAlgorithmFamily Family { get; }

    /// <summary>
    /// Gets the algorithm's name, which for a post-quantum algorithm is its FIPS parameter-set name.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the OID that identifies this algorithm in a certificate's SubjectPublicKeyInfo.
    /// </summary>
    /// <remarks>
    /// This does not identify the algorithm uniquely for every family: ECDsa and ECDiffieHellman share
    /// <see cref="Oids.EcPublicKey"/>, and RSA of any key length carries <see cref="Oids.Rsa"/>. The
    /// post-quantum OIDs do identify their parameter set exactly.
    /// </remarks>
    public string Oid { get; }

    /// <summary>Gets the key length in bits for RSA and DSA, or <see langword="null"/> for every other family.</summary>
    public int? KeyLength { get; private init; }

    /// <summary>Gets the curve for the elliptic-curve families, or <see langword="null"/> for every other family.</summary>
    public ECCurveType? Curve { get; private init; }

    /// <summary>
    /// Gets whether keys of this algorithm can produce signatures. This is <see langword="false"/> for the
    /// key-agreement and key-encapsulation families, which cannot self-sign, cannot act as a CA, and cannot
    /// produce a PKCS#10 certificate-signing request.
    /// </summary>
    public bool CanSign { get; }

    /// <summary>Gets whether this algorithm is an elliptic-curve one, and so takes a <see cref="Curve"/>.</summary>
    public bool IsEllipticCurve => Family is KeyAlgorithmFamily.ECDsa or KeyAlgorithmFamily.ECDiffieHellman;

    /// <summary>Gets whether this algorithm is a post-quantum one.</summary>
    public bool IsPostQuantum
        => Family is KeyAlgorithmFamily.MLDsa or KeyAlgorithmFamily.SlhDsa
            or KeyAlgorithmFamily.CompositeMLDsa or KeyAlgorithmFamily.MLKem;

    /// <summary>
    /// Gets whether keys of this algorithm can be generated on the current runtime and platform.
    /// </summary>
    /// <remarks>
    /// The classical families are always supported. A post-quantum family requires .NET 10 or later, and
    /// further requires the platform's cryptographic provider to implement it: SLH-DSA in particular is
    /// unavailable on Windows, and Composite ML-DSA support varies by parameter set. Availability is a runtime
    /// capability rather than a property of the operating system, so test it rather than inferring it.
    /// </remarks>
    public bool IsSupported => !IsPostQuantum || PostQuantumSupport.IsSupported(this);


    /// <summary>Returns the algorithm's <see cref="Name"/>.</summary>
    public override string ToString() => Name;


    /// <inheritdoc/>
    public bool Equals(KeyAlgorithm? other)
        => other != null
            && Family == other.Family
            && Name == other.Name
            && KeyLength == other.KeyLength
            && CurveKey(Curve) == CurveKey(other.Curve);

    /// <inheritdoc/>
    public override int GetHashCode()
        => HashCode.Combine(Family, Name, KeyLength, CurveKey(Curve));


    private KeyAlgorithm(KeyAlgorithmFamily family, string name, string oid, bool canSign)
    {
        Family = family;
        Name = name;
        Oid = oid;
        CanSign = canSign;
    }


    /// <summary>
    /// An <see cref="ECCurveType"/> is a struct whose default equality is reflective and compares its byte
    /// arrays by reference, so record equality cannot use it directly. A named curve is identified by its OID;
    /// an explicit one has to be identified by its actual parameters, since two unrelated explicit curves
    /// would otherwise compare equal.
    /// </summary>
    private static string? CurveKey(ECCurveType? curve)
    {
        if (curve == null) {
            return null;
        }

        var value = curve.Value;
        if (value.IsNamed) {
            return $"named:{value.Oid.Value ?? value.Oid.FriendlyName}";
        }

        return "explicit:" + String.Join(
            '|',
            Convert.ToHexString(value.A ?? []),
            Convert.ToHexString(value.B ?? []),
            Convert.ToHexString(value.G.X ?? []),
            Convert.ToHexString(value.G.Y ?? []),
            Convert.ToHexString(value.Order ?? []),
            Convert.ToHexString(value.Cofactor ?? []),
            Convert.ToHexString(value.Prime ?? []),
            Convert.ToHexString(value.Polynomial ?? []),
            Convert.ToHexString(value.Seed ?? []),
            value.CurveType
        );
    }


    /// <summary>
    /// A short label for <see cref="Name"/>. Unlike <see cref="CurveKey"/> this need not be unique: it is for
    /// humans, and equality never consults it for an explicit curve.
    /// </summary>
    private static string DescribeCurve(ECCurveType curve)
        => curve.IsNamed
            ? curve.Oid.FriendlyName ?? curve.Oid.Value ?? "named"
            : "explicit";
}
