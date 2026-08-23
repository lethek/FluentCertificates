using System.Security.Cryptography;

namespace FluentCertificates;

public class KeyAlgorithmTests
{
    [Test]
    [Arguments(1024)]
    [Arguments(2048)]
    [Arguments(4096)]
    public async Task RSA_CarriesItsKeyLengthAndName(int keyLength)
    {
        var algorithm = KeyAlgorithm.RSA(keyLength);

        await Assert.That(algorithm.Family).IsEqualTo(KeyAlgorithmFamily.Rsa);
        await Assert.That(algorithm.KeyLength).IsEqualTo(keyLength);
        await Assert.That(algorithm.Name).IsEqualTo($"RSA-{keyLength}");
        await Assert.That(algorithm.ToString()).IsEqualTo($"RSA-{keyLength}");
        await Assert.That(algorithm.CanSign).IsTrue();
        await Assert.That(algorithm.IsEllipticCurve).IsFalse();
        await Assert.That(algorithm.IsPostQuantum).IsFalse();
        await Assert.That(algorithm.IsSupported).IsTrue();
    }


    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    public async Task RSA_NonPositiveKeyLength_Throws(int keyLength)
        => await Assert.That(() => KeyAlgorithm.RSA(keyLength)).ThrowsExactly<ArgumentOutOfRangeException>();


    [Test]
    public async Task Defaults_MatchTheDocumentedValues()
    {
        await Assert.That(KeyAlgorithm.RSA()).IsEqualTo(KeyAlgorithm.RSA(4096));
        await Assert.That(KeyAlgorithm.Default(KeyAlgorithmFamily.Rsa)).IsEqualTo(KeyAlgorithm.RSA(4096));
        await Assert.That(KeyAlgorithm.Default(KeyAlgorithmFamily.ECDsa)).IsEqualTo(KeyAlgorithm.ECDsa());
        await Assert.That(KeyAlgorithm.Default(KeyAlgorithmFamily.ECDiffieHellman)).IsEqualTo(KeyAlgorithm.ECDiffieHellman());
    }


    [Test]
    public async Task Default_UnknownFamily_Throws()
        => await Assert.That(() => KeyAlgorithm.Default((KeyAlgorithmFamily)999))
            .ThrowsExactly<ArgumentOutOfRangeException>();


    [Test]
    public async Task ECDiffieHellman_CannotSign()
    {
        var algorithm = KeyAlgorithm.ECDiffieHellman();

        await Assert.That(algorithm.CanSign).IsFalse();
        await Assert.That(algorithm.IsEllipticCurve).IsTrue();
        await Assert.That(algorithm.Curve).IsNotNull();
    }


    [Test]
    public async Task ECDsa_NamedCurve_IsDescribedByItsCurve()
    {
        var algorithm = KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384);

        await Assert.That(algorithm.Family).IsEqualTo(KeyAlgorithmFamily.ECDsa);
        await Assert.That(algorithm.IsEllipticCurve).IsTrue();
        await Assert.That(algorithm.KeyLength).IsNull();

        //The label comes from the curve's own identity, so a different curve gives a different name
        await Assert.That(algorithm.Name).IsNotEqualTo(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP521).Name);
        await Assert.That(algorithm.Name).StartsWith("ECDsa-");
        await Assert.That(algorithm.Name).DoesNotContain("explicit");
    }


    [Test]
    public async Task ECDsa_SameNamedCurve_AreEqual()
    {
        var a = KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP256);
        var b = KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP256);

        await Assert.That(a).IsEqualTo(b);
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
    }


    [Test]
    public async Task ECDsa_DifferentNamedCurves_AreNotEqual()
        => await Assert.That(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP256))
            .IsNotEqualTo(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384));


    /// <summary>
    /// An explicit curve carries no OID, so identity has to come from its actual parameters. Two explicit
    /// curves differing in a single field must not compare equal, and an explicit curve must never compare
    /// equal to a named one.
    /// </summary>
    [Test]
    public async Task ECDsa_ExplicitCurves_CompareByTheirParameters()
    {
        var first = KeyAlgorithm.ECDsa(ExplicitPrimeCurve());
        var same = KeyAlgorithm.ECDsa(ExplicitPrimeCurve());
        var different = KeyAlgorithm.ECDsa(ExplicitPrimeCurve(seed: [0x09]));

        await Assert.That(first).IsEqualTo(same);
        await Assert.That(first.GetHashCode()).IsEqualTo(same.GetHashCode());
        await Assert.That(first).IsNotEqualTo(different);
        await Assert.That(first).IsNotEqualTo(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP256));
    }


    [Test]
    public async Task ECDsa_ExplicitCurve_IsNamedExplicit()
        => await Assert.That(KeyAlgorithm.ECDsa(ExplicitPrimeCurve()).Name).IsEqualTo("ECDsa-explicit");


    [Test]
    public async Task ECDiffieHellman_ExplicitCurve_IsNamedExplicit()
        => await Assert.That(KeyAlgorithm.ECDiffieHellman(ExplicitPrimeCurve()).Name).IsEqualTo("ECDH-explicit");


    /// <summary>
    /// Every field of an explicit curve contributes to identity, so changing any one of them alone must
    /// change equality. A field left out of the key would let two unrelated curves collide.
    /// </summary>
    [Test]
    [Arguments("a")]
    [Arguments("b")]
    [Arguments("gx")]
    [Arguments("gy")]
    [Arguments("order")]
    [Arguments("cofactor")]
    [Arguments("prime")]
    [Arguments("polynomial")]
    [Arguments("seed")]
    public async Task ECDsa_ExplicitCurve_EveryFieldAffectsEquality(string field)
    {
        var baseline = KeyAlgorithm.ECDsa(ExplicitPrimeCurve());
        var altered = KeyAlgorithm.ECDsa(Alter(field));

        await Assert.That(baseline).IsNotEqualTo(altered);
    }


    /// <summary>
    /// Every byte-array field of an explicit curve is optional. A curve that leaves them all unset must
    /// still produce a key rather than dereferencing a null array.
    /// </summary>
    [Test]
    public async Task ECDsa_ExplicitCurveWithNoParameters_StillCompares()
    {
        var bare = KeyAlgorithm.ECDsa(new ECCurve { CurveType = ECCurve.ECCurveType.PrimeShortWeierstrass });
        var alsoBare = KeyAlgorithm.ECDsa(new ECCurve { CurveType = ECCurve.ECCurveType.PrimeShortWeierstrass });

        await Assert.That(bare).IsEqualTo(alsoBare);
        await Assert.That(bare).IsNotEqualTo(KeyAlgorithm.ECDsa(ExplicitPrimeCurve()));
        await Assert.That(bare.Name).IsEqualTo("ECDsa-explicit");
    }


    /// <summary>
    /// A named curve is keyed by its OID value where it has one, and falls back to the friendly name, so two
    /// curves naming the same thing in different ways stay distinguishable.
    /// </summary>
    [Test]
    public async Task ECDsa_NamedCurveWithoutOidValue_FallsBackToTheFriendlyName()
    {
        var byFriendlyName = KeyAlgorithm.ECDsa(ECCurve.CreateFromFriendlyName("nistP256"));

        await Assert.That(byFriendlyName.Name).IsNotEqualTo("ECDsa-named");
        await Assert.That(byFriendlyName.Name).IsNotEqualTo("ECDsa-explicit");
        await Assert.That(byFriendlyName).IsEqualTo(KeyAlgorithm.ECDsa(ECCurve.CreateFromFriendlyName("nistP256")));
    }


    /// <summary>
    /// An object initialiser is the one way to make a named curve with no OID, and it is not a usable
    /// identity: the curve cannot be named or compared. It has to be refused by name rather than failing
    /// with a <see cref="NullReferenceException"/> from inside the library.
    /// </summary>
    [Test]
    public async Task ECDsa_NamedCurveWithoutAnOid_Throws()
    {
        var ex = await Assert
            .That(() => KeyAlgorithm.ECDsa(new ECCurve { CurveType = ECCurve.ECCurveType.Named }))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("named elliptic curve must carry an OID");
        await Assert.That(ex.ParamName).IsEqualTo("curve");
    }


    [Test]
    public async Task ECDiffieHellman_NamedCurveWithoutAnOid_Throws()
        => await Assert
            .That(() => KeyAlgorithm.ECDiffieHellman(new ECCurve { CurveType = ECCurve.ECCurveType.Named }))
            .ThrowsExactly<ArgumentException>();


    /// <summary>
    /// An explicit curve has no OID by definition, so the guard must not catch it.
    /// </summary>
    [Test]
    public async Task ECDsa_ExplicitCurveWithoutAnOid_IsAccepted()
        => await Assert.That(() => KeyAlgorithm.ECDsa(ExplicitPrimeCurve())).ThrowsNothing();


    /// <summary>
    /// Every <see cref="ECCurve"/> factory fills in both halves of a named curve's OID, whichever half it was
    /// given, so the label is the friendly name in each case.
    /// </summary>
    [Test]
    public async Task ECDsa_NamedCurve_IsLabelledByItsFriendlyNameWhicheverFactoryBuiltIt()
    {
        await Assert.That(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP256).Name).IsEqualTo("ECDsa-nistP256");
        await Assert.That(KeyAlgorithm.ECDsa(ECCurve.CreateFromFriendlyName("nistP256")).Name)
            .IsEqualTo("ECDsa-nistP256");

        //CreateFromValue resolves a friendly name of its own, so the label is that rather than the OID
        var fromValue = KeyAlgorithm.ECDsa(ECCurve.CreateFromValue("1.2.840.10045.3.1.7"));
        await Assert.That(fromValue.Name).StartsWith("ECDsa-");
        await Assert.That(fromValue.Name).IsNotEqualTo("ECDsa-explicit");
    }


    [Test]
    public async Task Default_UnknownFamily_MessageNamesTheFamily()
    {
        var ex = await Assert.That(() => KeyAlgorithm.Default((KeyAlgorithmFamily)999))
            .ThrowsExactly<ArgumentOutOfRangeException>();

        await Assert.That(ex!.Message).Contains("999");
        await Assert.That(ex.ParamName).IsEqualTo("family");
    }


    [Test]
    public async Task Equals_NullAndOtherTypes_IsFalse()
    {
        var algorithm = KeyAlgorithm.RSA(2048);

        await Assert.That(algorithm.Equals(null)).IsFalse();
        await Assert.That(algorithm).IsNotEqualTo(KeyAlgorithm.RSA(3072));
    }


    /// <summary>
    /// A minimal but structurally complete explicit prime curve. It is never used to generate a key, only
    /// to exercise the parameter-based identity, so the values need not describe a usable curve.
    /// </summary>
    private static ECCurve ExplicitPrimeCurve(
        byte[]? a = null, byte[]? b = null, byte[]? gx = null, byte[]? gy = null,
        byte[]? order = null, byte[]? cofactor = null, byte[]? prime = null, byte[]? seed = null,
        byte[]? polynomial = null)
        => new() {
            CurveType = ECCurve.ECCurveType.PrimeShortWeierstrass,
            A = a ?? [0x01],
            B = b ?? [0x02],
            G = new ECPoint { X = gx ?? [0x03], Y = gy ?? [0x04] },
            Order = order ?? [0x05],
            Cofactor = cofactor ?? [0x06],
            Prime = prime ?? [0x07],
            Polynomial = polynomial ?? [0x09],
            Seed = seed ?? [0x08]
        };


    private static ECCurve Alter(string field)
        => field switch {
            "a" => ExplicitPrimeCurve(a: [0x7F]),
            "b" => ExplicitPrimeCurve(b: [0x7F]),
            "gx" => ExplicitPrimeCurve(gx: [0x7F]),
            "gy" => ExplicitPrimeCurve(gy: [0x7F]),
            "order" => ExplicitPrimeCurve(order: [0x7F]),
            "cofactor" => ExplicitPrimeCurve(cofactor: [0x7F]),
            "prime" => ExplicitPrimeCurve(prime: [0x7F]),
            "polynomial" => ExplicitPrimeCurve(polynomial: [0x7F]),
            "seed" => ExplicitPrimeCurve(seed: [0x7F]),
            _ => throw new ArgumentOutOfRangeException(nameof(field), field, null)
        };
}
