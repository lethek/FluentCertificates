using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

using TUnit.Assertions.Enums;

namespace FluentCertificates;

public class X500NameComparerTests
{
    /// <summary>
    /// Every fold-dependent test gates on this probe, so a run claiming it can fold has to actually fold.
    /// Its value is not asserted: a globalization-invariant run reports false, which is a correct answer
    /// rather than a failure, and has to answer rather than throw.
    /// </summary>
    [Test]
    public async Task CanFold_PredictsWhetherThisRuntimeFolds()
    {
        var esszett = Utf8Name(("2.5.4.3", "Große"));
        var doubleS = Utf8Name(("2.5.4.3", "Grosse"));

        if (X500NameComparer.CanFold) {
            await Assert.That(X500NameComparer.Folded.Equals(esszett, doubleS)).IsTrue();
        } else {
            await Assert.That(() => X500NameComparer.Folded.Equals(esszett, doubleS)).ThrowsNothing();
        }
    }


    [Test]
    [MethodDataSource(nameof(AllComparers))]
    public async Task Equals_BothNull_IsTrue(X500NameComparer comparer)
        => await Assert.That(comparer.Equals(null, null)).IsTrue();


    [Test]
    [MethodDataSource(nameof(AllComparers))]
    public async Task Equals_OneSideNull_IsFalse(X500NameComparer comparer)
    {
        var name = Utf8Name(("2.5.4.3", "Example"));

        await Assert.That(comparer.Equals(name, null)).IsFalse();
        await Assert.That(comparer.Equals(null, name)).IsFalse();
    }


    [Test]
    [MethodDataSource(nameof(AllComparers))]
    public async Task GetHashCode_Null_Throws(X500NameComparer comparer)
        => await Assert.That(() => comparer.GetHashCode(null!)).ThrowsExactly<ArgumentNullException>();


    /// <summary>A comparer is an equality, so every name has to equal itself under every member, including
    /// one whose bytes never decode.</summary>
    [Test]
    [MethodDataSource(nameof(AllComparers))]
    public async Task Equals_AnyNameAgainstItself_IsTrue(X500NameComparer comparer)
    {
        var name = Utf8Name(("2.5.4.3", "Example"));
        var undecodable = UndecodableName();

        await Assert.That(comparer.Equals(name, Utf8Name(("2.5.4.3", "Example")))).IsTrue();
        await Assert.That(comparer.Equals(undecodable, UndecodableName())).IsTrue();
        await Assert.That(comparer.GetHashCode(undecodable)).IsEqualTo(comparer.GetHashCode(UndecodableName()));
    }


    [Test]
    [MethodDataSource(nameof(AllComparers))]
    public async Task Equals_UndecodableAgainstDifferentUndecodable_IsFalse(X500NameComparer comparer)
        => await Assert.That(comparer.Equals(UndecodableName(), UndecodableName(0x01))).IsFalse();


    [Test]
    [MethodDataSource(nameof(AllComparers))]
    public async Task Equals_DifferentNames_IsFalse(X500NameComparer comparer)
        => await Assert
            .That(comparer.Equals(Utf8Name(("2.5.4.3", "Alpha")), Utf8Name(("2.5.4.3", "Beta"))))
            .IsFalse();


    [Test]
    public async Task Exact_SameCharactersDifferentStringType_IsFalse()
    {
        //RFC 5280 s4.1.2.4 lets a conforming CA choose either, so this reaches real certificates
        await Assert
            .That(X500NameComparer.Exact.Equals(
                Utf8Name(("2.5.4.3", "Example")),
                PrintableName(("2.5.4.3", "Example"))))
            .IsFalse();
    }


    [Test]
    [MethodDataSource(nameof(DecodingComparers))]
    public async Task Decoding_SameCharactersDifferentStringType_IsTrue(X500NameComparer comparer)
    {
        var utf8 = Utf8Name(("2.5.4.3", "Example"));
        var printable = PrintableName(("2.5.4.3", "Example"));

        await Assert.That(comparer.Equals(utf8, printable)).IsTrue();
        await Assert.That(comparer.GetHashCode(utf8)).IsEqualTo(comparer.GetHashCode(printable));
    }


    [Test]
    public async Task Values_DifferentCase_IsFalse()
        => await Assert
            .That(X500NameComparer.Values.Equals(Utf8Name(("2.5.4.3", "Example")), Utf8Name(("2.5.4.3", "EXAMPLE"))))
            .IsFalse();


    [Test]
    public async Task Folded_DifferentCase_IsTrue()
    {
        var lower = Utf8Name(("2.5.4.3", "Example"));
        var upper = Utf8Name(("2.5.4.3", "EXAMPLE"));

        await Assert.That(X500NameComparer.Folded.Equals(lower, upper)).IsTrue();
        await Assert.That(X500NameComparer.Folded.GetHashCode(lower)).IsEqualTo(X500NameComparer.Folded.GetHashCode(upper));
    }


    [Test]
    public async Task Folded_DifferentWhitespaceRuns_IsTrue()
    {
        var single = Utf8Name(("2.5.4.3", "Exam ple"));
        var doubled = Utf8Name(("2.5.4.3", "Exam  ple"));

        await Assert.That(X500NameComparer.Folded.Equals(single, doubled)).IsTrue();
        await Assert.That(X500NameComparer.Folded.GetHashCode(single)).IsEqualTo(X500NameComparer.Folded.GetHashCode(doubled));
    }


    [Test]
    public async Task Values_DifferentWhitespaceRuns_IsFalse()
        => await Assert
            .That(X500NameComparer.Values.Equals(Utf8Name(("2.5.4.3", "Exam ple")), Utf8Name(("2.5.4.3", "Exam  ple"))))
            .IsFalse();


    [Test]
    public async Task Folded_DotlessIAgainstI_IsTrue()
    {
        Skip.Unless(X500NameComparer.CanFold, "Folding is unavailable in this run's globalization mode");

        //The upper-then-lower round trip carries a dotless i (U+0131) onto an i, as Java's X500Principal does
        await Assert
            .That(X500NameComparer.Folded.Equals(Utf8Name(("2.5.4.3", "kız")), Utf8Name(("2.5.4.3", "kiz"))))
            .IsTrue();
    }


    [Test]
    [MethodDataSource(nameof(OrderSignificantComparers))]
    public async Task OrderSignificant_RelativeNamesInAnotherOrder_IsFalse(X500NameComparer comparer)
        => await Assert
            .That(comparer.Equals(
                Utf8Name(("2.5.4.3", "Leaf"), ("2.5.4.10", "Acme")),
                Utf8Name(("2.5.4.10", "Acme"), ("2.5.4.3", "Leaf"))))
            .IsFalse();


    [Test]
    [MethodDataSource(nameof(AnyOrderComparers))]
    public async Task AnyOrder_RelativeNamesInAnotherOrder_IsTrue(X500NameComparer comparer)
    {
        var forwards = Utf8Name(("2.5.4.3", "Leaf"), ("2.5.4.10", "Acme"));
        var backwards = Utf8Name(("2.5.4.10", "Acme"), ("2.5.4.3", "Leaf"));

        await Assert.That(comparer.Equals(forwards, backwards)).IsTrue();
        await Assert.That(comparer.GetHashCode(forwards)).IsEqualTo(comparer.GetHashCode(backwards));
    }


    [Test]
    [MethodDataSource(nameof(AllComparers))]
    public async Task Equals_DifferentNumberOfRelativeNames_IsFalse(X500NameComparer comparer)
        => await Assert
            .That(comparer.Equals(
                Utf8Name(("2.5.4.3", "Leaf")),
                Utf8Name(("2.5.4.3", "Leaf"), ("2.5.4.10", "Acme"))))
            .IsFalse();


    /// <summary>
    /// A relative distinguished name is an ASN.1 SET, and RFC 5280 s7.1 matches one as a set: same number of
    /// attributes, each with a match in the other. DER orders a SET by its members' encodings, so two names
    /// carrying the same attributes under different string types present them in different orders, which is
    /// what this pins down.
    /// </summary>
    [Test]
    [MethodDataSource(nameof(DecodingComparers))]
    public async Task Decoding_MultiValuedRelativeName_MatchesAsASetDespiteEncodedOrder(X500NameComparer comparer)
    {
        //DER sorts a SET by its members' whole encodings, so the values have to be the same length for the
        //string type to decide the order: UTF8String (0x0C) then sorts ahead of PrintableString (0x13)
        var first = MultiValuedName(
            ("2.5.4.11", "Alpha", UniversalTagNumber.PrintableString),
            ("2.5.4.11", "Bravo", UniversalTagNumber.UTF8String));

        var second = MultiValuedName(
            ("2.5.4.11", "Alpha", UniversalTagNumber.UTF8String),
            ("2.5.4.11", "Bravo", UniversalTagNumber.PrintableString));

        //Pinned rather than merely asserted different, so a change in DER's ordering shows up here
        await Assert.That(EncodedOrderOf(first)).IsEquivalentTo(["Bravo", "Alpha"], CollectionOrdering.Matching);
        await Assert.That(EncodedOrderOf(second)).IsEquivalentTo(["Alpha", "Bravo"], CollectionOrdering.Matching);

        await Assert.That(comparer.Equals(first, second)).IsTrue();
        await Assert.That(comparer.GetHashCode(first)).IsEqualTo(comparer.GetHashCode(second));
    }


    [Test]
    [MethodDataSource(nameof(DecodingComparers))]
    public async Task Decoding_MultiValuedRelativeNameWithADifferentValue_IsFalse(X500NameComparer comparer)
        => await Assert
            .That(comparer.Equals(
                MultiValuedName(("2.5.4.11", "Alpha", UniversalTagNumber.UTF8String), ("2.5.4.11", "Beta", UniversalTagNumber.UTF8String)),
                MultiValuedName(("2.5.4.11", "Alpha", UniversalTagNumber.UTF8String), ("2.5.4.11", "Gamma", UniversalTagNumber.UTF8String))))
            .IsFalse();


    /// <summary>
    /// A value that does not decode is carried as bytes rather than as text spelling out those bytes, so no
    /// text value can impersonate one.
    /// </summary>
    [Test]
    [MethodDataSource(nameof(DecodingComparers))]
    public async Task Decoding_TextSpellingOutAnUndecodableValue_DoesNotMatchIt(X500NameComparer comparer)
    {
        //An OCTET STRING attribute value: a universal tag the DirectoryString readers do not accept
        byte[] raw = [0x04, 0x03, 0x30, 0x06, 0x45];
        var binary = RawValuedName("2.5.4.3", raw);
        var spelledOut = Utf8Name(("2.5.4.3", Convert.ToHexString(raw)));

        await Assert.That(comparer.Equals(binary, spelledOut)).IsFalse();
    }


    [Test]
    [MethodDataSource(nameof(DecodingComparers))]
    public async Task Decoding_SameUndecodableValue_IsTrue(X500NameComparer comparer)
    {
        byte[] raw = [0x04, 0x03, 0x30, 0x06, 0x45];

        await Assert.That(comparer.Equals(RawValuedName("2.5.4.3", raw), RawValuedName("2.5.4.3", raw))).IsTrue();
        await Assert
            .That(comparer.GetHashCode(RawValuedName("2.5.4.3", raw)))
            .IsEqualTo(comparer.GetHashCode(RawValuedName("2.5.4.3", raw)));
    }


    [Test]
    [MethodDataSource(nameof(AllComparers))]
    public async Task Comparer_KeysADictionary(X500NameComparer comparer)
    {
        var names = new Dictionary<X500DistinguishedName, string>(comparer) {
            [Utf8Name(("2.5.4.3", "Example"))] = "first"
        };

        names[Utf8Name(("2.5.4.3", "Example"))] = "second";

        await Assert.That(names.Count).IsEqualTo(1);
        await Assert.That(names.Values.Single()).IsEqualTo("second");
    }


    [Test]
    public async Task Comparer_IsSubclassable()
    {
        var comparer = new AlwaysTheSameName();

        await Assert
            .That(comparer.Equals(Utf8Name(("2.5.4.3", "Alpha")), Utf8Name(("2.5.4.3", "Beta"))))
            .IsTrue();
    }


    private sealed class AlwaysTheSameName : X500NameComparer
    {
        protected override bool EqualsName(X500DistinguishedName x, X500DistinguishedName y) => true;

        protected override int GetHashCodeOfName(X500DistinguishedName name) => 0;
    }


    public static IEnumerable<Func<X500NameComparer>> AllComparers()
    {
        yield return () => X500NameComparer.Exact;
        yield return () => X500NameComparer.Values;
        yield return () => X500NameComparer.ValuesAnyOrder;
        yield return () => X500NameComparer.Folded;
        yield return () => X500NameComparer.FoldedAnyOrder;
    }


    public static IEnumerable<Func<X500NameComparer>> DecodingComparers()
    {
        yield return () => X500NameComparer.Values;
        yield return () => X500NameComparer.ValuesAnyOrder;
        yield return () => X500NameComparer.Folded;
        yield return () => X500NameComparer.FoldedAnyOrder;
    }


    public static IEnumerable<Func<X500NameComparer>> OrderSignificantComparers()
    {
        yield return () => X500NameComparer.Exact;
        yield return () => X500NameComparer.Values;
        yield return () => X500NameComparer.Folded;
    }


    public static IEnumerable<Func<X500NameComparer>> AnyOrderComparers()
    {
        yield return () => X500NameComparer.ValuesAnyOrder;
        yield return () => X500NameComparer.FoldedAnyOrder;
    }


    private static X500DistinguishedName Utf8Name(params (string Oid, string Value)[] rdns)
        => BuildName(rdns.Select(x => new[] { (x.Oid, x.Value, UniversalTagNumber.UTF8String) }).ToArray());


    private static X500DistinguishedName PrintableName(params (string Oid, string Value)[] rdns)
        => BuildName(rdns.Select(x => new[] { (x.Oid, x.Value, UniversalTagNumber.PrintableString) }).ToArray());


    /// <summary>One relative distinguished name carrying every attribute given.</summary>
    private static X500DistinguishedName MultiValuedName(params (string Oid, string Value, UniversalTagNumber Encoding)[] attributes)
        => BuildName([attributes]);


    private static X500DistinguishedName BuildName((string Oid, string Value, UniversalTagNumber Encoding)[][] rdns)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            foreach (var rdn in rdns) {
                using (writer.PushSetOf()) {
                    foreach (var (oid, value, encoding) in rdn) {
                        using (writer.PushSequence()) {
                            writer.WriteObjectIdentifier(oid);
                            writer.WriteCharacterString(encoding, value);
                        }
                    }
                }
            }
        }
        return new X500DistinguishedName(writer.Encode());
    }


    /// <summary>A name whose single attribute value carries <paramref name="raw"/> verbatim, so it reaches
    /// no DirectoryString reader.</summary>
    private static X500DistinguishedName RawValuedName(string oid, byte[] raw)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            using (writer.PushSetOf()) {
                using (writer.PushSequence()) {
                    writer.WriteObjectIdentifier(oid);
                    writer.WriteEncodedValue(raw);
                }
            }
        }
        return new X500DistinguishedName(writer.Encode());
    }


    /// <summary>The attribute values in the order the encoding presents them, to pin how two names differ in it.</summary>
    private static List<string> EncodedOrderOf(X500DistinguishedName name)
    {
        var values = new List<string>();
        var rdns = new AsnReader(name.RawData, AsnEncodingRules.DER).ReadSequence();
        while (rdns.HasData) {
            var attributes = rdns.ReadSetOf();
            while (attributes.HasData) {
                var attribute = attributes.ReadSequence();
                attribute.ReadObjectIdentifier();
                values.Add(attribute.ReadCharacterString((UniversalTagNumber)attribute.PeekTag().TagValue));
            }
        }
        return values;
    }


    //A SEQUENCE containing an INTEGER: valid DER, but not shaped like a sequence of relative distinguished names
    private static X500DistinguishedName UndecodableName(byte value = 0x00)
        => new([0x30, 0x03, 0x02, 0x01, value]);
}
