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
            KeyAlgorithmFamily.SlhDsa => SlhDsaSha2_128f,
            KeyAlgorithmFamily.CompositeMLDsa => MLDsa65WithECDsaP256,
            KeyAlgorithmFamily.MLKem => MLKem768,
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


    /// <summary>SLH-DSA-SHA2-128s (FIPS 205). The <c>s</c> sets favour signature size over signing speed.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaSha2_128s = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHA2-128s", Oids.SlhDsaSha2_128s, canSign: true);

    /// <summary>SLH-DSA-SHA2-128f (FIPS 205). The <c>f</c> sets favour signing speed over signature size.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaSha2_128f = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHA2-128f", Oids.SlhDsaSha2_128f, canSign: true);

    /// <summary>SLH-DSA-SHA2-192s (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaSha2_192s = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHA2-192s", Oids.SlhDsaSha2_192s, canSign: true);

    /// <summary>SLH-DSA-SHA2-192f (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaSha2_192f = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHA2-192f", Oids.SlhDsaSha2_192f, canSign: true);

    /// <summary>SLH-DSA-SHA2-256s (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaSha2_256s = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHA2-256s", Oids.SlhDsaSha2_256s, canSign: true);

    /// <summary>SLH-DSA-SHA2-256f (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaSha2_256f = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHA2-256f", Oids.SlhDsaSha2_256f, canSign: true);

    /// <summary>SLH-DSA-SHAKE-128s (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaShake128s = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHAKE-128s", Oids.SlhDsaShake128s, canSign: true);

    /// <summary>SLH-DSA-SHAKE-128f (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaShake128f = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHAKE-128f", Oids.SlhDsaShake128f, canSign: true);

    /// <summary>SLH-DSA-SHAKE-192s (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaShake192s = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHAKE-192s", Oids.SlhDsaShake192s, canSign: true);

    /// <summary>SLH-DSA-SHAKE-192f (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaShake192f = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHAKE-192f", Oids.SlhDsaShake192f, canSign: true);

    /// <summary>SLH-DSA-SHAKE-256s (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaShake256s = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHAKE-256s", Oids.SlhDsaShake256s, canSign: true);

    /// <summary>SLH-DSA-SHAKE-256f (FIPS 205).</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm SlhDsaShake256f = new(KeyAlgorithmFamily.SlhDsa, "SLH-DSA-SHAKE-256f", Oids.SlhDsaShake256f, canSign: true);


    /// <summary>MLDSA44-RSA2048-PSS-SHA256, pairing ML-DSA-44 with RSA-2048 PSS.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa44WithRSA2048Pss = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA44-RSA2048-PSS-SHA256", Oids.MLDsa44WithRSA2048Pss, canSign: true);

    /// <summary>MLDSA44-RSA2048-PKCS15-SHA256, pairing ML-DSA-44 with RSA-2048 PKCS#1 v1.5.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa44WithRSA2048Pkcs15 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA44-RSA2048-PKCS15-SHA256", Oids.MLDsa44WithRSA2048Pkcs15, canSign: true);

    /// <summary>MLDSA44-Ed25519-SHA512, pairing ML-DSA-44 with Ed25519.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa44WithEd25519 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA44-Ed25519-SHA512", Oids.MLDsa44WithEd25519, canSign: true);

    /// <summary>MLDSA44-ECDSA-P256-SHA256, pairing ML-DSA-44 with ECDSA on P-256.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa44WithECDsaP256 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA44-ECDSA-P256-SHA256", Oids.MLDsa44WithECDsaP256, canSign: true);

    /// <summary>MLDSA65-RSA3072-PSS-SHA512, pairing ML-DSA-65 with RSA-3072 PSS.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa65WithRSA3072Pss = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA65-RSA3072-PSS-SHA512", Oids.MLDsa65WithRSA3072Pss, canSign: true);

    /// <summary>MLDSA65-RSA3072-PKCS15-SHA512, pairing ML-DSA-65 with RSA-3072 PKCS#1 v1.5.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa65WithRSA3072Pkcs15 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA65-RSA3072-PKCS15-SHA512", Oids.MLDsa65WithRSA3072Pkcs15, canSign: true);

    /// <summary>MLDSA65-RSA4096-PSS-SHA512, pairing ML-DSA-65 with RSA-4096 PSS.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa65WithRSA4096Pss = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA65-RSA4096-PSS-SHA512", Oids.MLDsa65WithRSA4096Pss, canSign: true);

    /// <summary>MLDSA65-RSA4096-PKCS15-SHA512, pairing ML-DSA-65 with RSA-4096 PKCS#1 v1.5.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa65WithRSA4096Pkcs15 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA65-RSA4096-PKCS15-SHA512", Oids.MLDsa65WithRSA4096Pkcs15, canSign: true);

    /// <summary>MLDSA65-ECDSA-P256-SHA512, pairing ML-DSA-65 with ECDSA on P-256.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa65WithECDsaP256 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA65-ECDSA-P256-SHA512", Oids.MLDsa65WithECDsaP256, canSign: true);

    /// <summary>MLDSA65-ECDSA-P384-SHA512, pairing ML-DSA-65 with ECDSA on P-384.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa65WithECDsaP384 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA65-ECDSA-P384-SHA512", Oids.MLDsa65WithECDsaP384, canSign: true);

    /// <summary>MLDSA65-ECDSA-brainpoolP256r1-SHA512, pairing ML-DSA-65 with ECDSA on brainpoolP256r1.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa65WithECDsaBrainpoolP256r1 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA65-ECDSA-brainpoolP256r1-SHA512", Oids.MLDsa65WithECDsaBrainpoolP256r1, canSign: true);

    /// <summary>MLDSA65-Ed25519-SHA512, pairing ML-DSA-65 with Ed25519.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa65WithEd25519 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA65-Ed25519-SHA512", Oids.MLDsa65WithEd25519, canSign: true);

    /// <summary>MLDSA87-ECDSA-P384-SHA512, pairing ML-DSA-87 with ECDSA on P-384.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa87WithECDsaP384 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA87-ECDSA-P384-SHA512", Oids.MLDsa87WithECDsaP384, canSign: true);

    /// <summary>MLDSA87-ECDSA-brainpoolP384r1-SHA512, pairing ML-DSA-87 with ECDSA on brainpoolP384r1.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa87WithECDsaBrainpoolP384r1 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA87-ECDSA-brainpoolP384r1-SHA512", Oids.MLDsa87WithECDsaBrainpoolP384r1, canSign: true);

    /// <summary>MLDSA87-Ed448-SHAKE256, pairing ML-DSA-87 with Ed448.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa87WithEd448 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA87-Ed448-SHAKE256", Oids.MLDsa87WithEd448, canSign: true);

    /// <summary>MLDSA87-RSA3072-PSS-SHA512, pairing ML-DSA-87 with RSA-3072 PSS.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa87WithRSA3072Pss = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA87-RSA3072-PSS-SHA512", Oids.MLDsa87WithRSA3072Pss, canSign: true);

    /// <summary>MLDSA87-RSA4096-PSS-SHA512, pairing ML-DSA-87 with RSA-4096 PSS.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa87WithRSA4096Pss = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA87-RSA4096-PSS-SHA512", Oids.MLDsa87WithRSA4096Pss, canSign: true);

    /// <summary>MLDSA87-ECDSA-P521-SHA512, pairing ML-DSA-87 with ECDSA on P-521.</summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLDsa87WithECDsaP521 = new(KeyAlgorithmFamily.CompositeMLDsa, "MLDSA87-ECDSA-P521-SHA512", Oids.MLDsa87WithECDsaP521, canSign: true);


    /// <summary>
    /// ML-KEM-512 (FIPS 203) key encapsulation. Cannot sign, so a certificate for one must be issued by a
    /// CA and cannot itself be a CA or a code-signing, OCSP-signing or time-stamping certificate.
    /// </summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLKem512 = new(KeyAlgorithmFamily.MLKem, "ML-KEM-512", Oids.MLKem512, canSign: false);

    /// <summary>
    /// ML-KEM-768 (FIPS 203) key encapsulation. Cannot sign, so a certificate for one must be issued by a
    /// CA and cannot itself be a CA or a code-signing, OCSP-signing or time-stamping certificate.
    /// </summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLKem768 = new(KeyAlgorithmFamily.MLKem, "ML-KEM-768", Oids.MLKem768, canSign: false);

    /// <summary>
    /// ML-KEM-1024 (FIPS 203) key encapsulation. Cannot sign, so a certificate for one must be issued by a
    /// CA and cannot itself be a CA or a code-signing, OCSP-signing or time-stamping certificate.
    /// </summary>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static readonly KeyAlgorithm MLKem1024 = new(KeyAlgorithmFamily.MLKem, "ML-KEM-1024", Oids.MLKem1024, canSign: false);


    /// <summary>
    /// Every post-quantum algorithm this library knows, whether or not the current platform supports it.
    /// </summary>
    /// <remarks>
    /// Useful for enumerating parameter sets in tests and diagnostics. Filter with
    /// <see cref="IsSupported"/> before trying to generate a key from one.
    /// </remarks>
    [Experimental(Experiments.PostQuantumCryptography)]
    public static IReadOnlyList<KeyAlgorithm> PostQuantumAlgorithms { get; } = [
        MLDsa44, MLDsa65, MLDsa87,
        SlhDsaSha2_128s, SlhDsaSha2_128f, SlhDsaSha2_192s, SlhDsaSha2_192f, SlhDsaSha2_256s, SlhDsaSha2_256f,
        SlhDsaShake128s, SlhDsaShake128f, SlhDsaShake192s, SlhDsaShake192f, SlhDsaShake256s, SlhDsaShake256f,
        MLDsa44WithRSA2048Pss, MLDsa44WithRSA2048Pkcs15, MLDsa44WithEd25519, MLDsa44WithECDsaP256,
        MLDsa65WithRSA3072Pss, MLDsa65WithRSA3072Pkcs15, MLDsa65WithRSA4096Pss, MLDsa65WithRSA4096Pkcs15,
        MLDsa65WithECDsaP256, MLDsa65WithECDsaP384, MLDsa65WithECDsaBrainpoolP256r1, MLDsa65WithEd25519,
        MLDsa87WithECDsaP384, MLDsa87WithECDsaBrainpoolP384r1, MLDsa87WithEd448,
        MLDsa87WithRSA3072Pss, MLDsa87WithRSA4096Pss, MLDsa87WithECDsaP521,
        MLKem512, MLKem768, MLKem1024
    ];


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
#pragma warning disable FLUENTCERT001 // Classifying a family is not use of the experimental surface
    public bool IsPostQuantum
        => Family is KeyAlgorithmFamily.MLDsa or KeyAlgorithmFamily.SlhDsa
            or KeyAlgorithmFamily.CompositeMLDsa or KeyAlgorithmFamily.MLKem;
#pragma warning restore FLUENTCERT001

    /// <summary>
    /// Gets whether this algorithm can be used to build a certificate on the current runtime and platform.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The classical families are always supported. A post-quantum family requires .NET 10 or later and the
    /// platform's cryptographic provider to implement it. Availability is a runtime capability rather than a
    /// property of the operating system, so test it rather than inferring it from the OS.
    /// </para>
    /// <para>
    /// Known gaps as of .NET 10: SLH-DSA is unavailable on Windows; Composite ML-DSA is unavailable
    /// everywhere for certificate use, because although composite keys generate, no platform can yet build
    /// an <c>X509SignatureGenerator</c> from one; and four Composite parameter sets do not generate at all.
    /// </para>
    /// <para>
    /// This reports certificate usability, not merely key generation, since a certificate is what this
    /// library builds. An algorithm reporting <see langword="true"/> here will not fail in
    /// <c>CertificateBuilder.Create()</c> for want of platform support.
    /// </para>
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
