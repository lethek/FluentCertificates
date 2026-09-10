using System.Globalization;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// Settles the assumption <c>X500NameComparer.MatchesAsMultiset</c> rests on. It pairs members off by first
/// fit, which decides multiset matching correctly only where the match relation is an equivalence relation:
/// otherwise taking one partner can strand a later member that had no other, and the answer turns on the
/// order DER happened to put the attributes in.
/// </summary>
/// <remarks>
/// These assert a property rather than specific outcomes, so they hold whatever a given ICU version decides
/// two strings mean. Nothing here pins which values fold together; the claim is only that whatever the
/// folding says, it says it consistently.
/// </remarks>
public class X500NameComparerFoldRelationTests
{
    /// <summary>
    /// Strings chosen to stress the composition <c>Folded</c> applies: compatibility normalisation, a
    /// whitespace collapse, an upper-then-lower case round trip, then collation ignoring case and accents.
    /// Case pairs, compatibility singletons, decomposed and precomposed spellings, invisible characters,
    /// non-ASCII digits and non-BMP case pairs are all represented, since those are where the steps disagree.
    /// </summary>
    public static IEnumerable<string> Alphabet()
        => [
            //ASCII baselines
            "", " ", "a", "A", "abc", "ABC", "a b", "a  b", " a ", "\ta\t",
            //Dotted and dotless i, which the case round trip exists to handle
            "i", "I", "ı", "İ", "i̇",
            //Sharp s against its expansion, including the capital form
            "ß", "ss", "SS", "ẞ", "straße", "STRASSE", "Strasse",
            //Ligatures against the letters they decompose to
            "ﬁ", "fi", "FI", "ﬀ", "ff", "ﬃ", "ffi",
            //Precomposed against decomposed, and the singletons that normalise onto them
            "é", "é", "É", "É", "e",
            "Å", "Å", "å", "å",
            "K", "K", "k", "Ω", "Ω", "ω",
            "µ", "μ", "Μ",
            //Greek final sigma against the medial form
            "σ", "ς", "Σ",
            //Long s, which folds onto an ordinary s
            "ſ", "s", "S",
            //Fullwidth and other compatibility forms
            "ａ", "Ａ", "０", "0",
            "²", "2", "₁", "1", "Ⅰ", "ⅰ",
            "①", "㎡", "㎒",
            //Invisible and format characters
            "a​b", "ab", "a‍b", "a­b", "‏a", "‎a", "a﻿b",
            //Space variants a collapse may or may not treat alike
            "a b", "a b", "a b", "a　b", "a\nb", "ab",
            //Non-ASCII digits, which normalisation maps onto ASCII only for some scripts
            "٣", "3", "۳", "१",
            //Hangul, where composition and decomposition are algorithmic
            "가", "가", "하나",
            //Non-BMP: a mathematical alphanumeric singleton and a Deseret case pair
            "𝐀", "𐐀", "𐐨",
            //Combining marks in different orders, which canonical ordering is meant to settle
            "q́̈", "q̈́",
            //Han and kana compatibility
            "カ", "ｶ", "か",
            //Cherokee, whose case mapping was added late and is not round-trip stable everywhere
            "Ꭰ", "ꭰ",
            //Turkish and Azeri spellings that only differ by the dot
            "TITLE", "title", "TİTLE", "tıtle"
        ];


    private static readonly List<string> Values = [.. Alphabet()];


    private static List<X500DistinguishedName> BuildCommonNames()
        => [.. Values.Select(value => new X500NameBuilder().Add(Oids.CommonNameOid, value).Create())];


    /// <summary>
    /// The whole point. A relation is an equivalence relation exactly when it is the "same block" relation of
    /// some partition, so the blocks are built by first fit and then every pair is checked against them. A
    /// pass means reflexivity, symmetry and transitivity all hold over this alphabet at once; a failure names
    /// the two values that break it.
    /// </summary>
    [Test]
    [MethodDataSource(nameof(Comparers))]
    public async Task FoldedMatching_IsAnEquivalenceRelation(string label, X500NameComparer comparer, bool folds)
    {
        var names = BuildCommonNames();
        var blockOf = new int[names.Count];

        for (var i = 0; i < names.Count; i++) {
            blockOf[i] = -1;
            for (var j = 0; j < i && blockOf[i] < 0; j++) {
                if (comparer.Equals(names[i], names[j])) {
                    blockOf[i] = blockOf[j];
                }
            }
            if (blockOf[i] < 0) {
                blockOf[i] = i;
            }
        }

        for (var i = 0; i < names.Count; i++) {
            for (var j = 0; j < names.Count; j++) {
                var matches = comparer.Equals(names[i], names[j]);
                var sameBlock = blockOf[i] == blockOf[j];

                await Assert
                    .That(matches)
                    .IsEqualTo(sameBlock)
                    .Because($"{label}: {Describe(Values[i])} and {Describe(Values[j])} "
                        + $"{(matches ? "match but land in different blocks" : "do not match but share a block")}, "
                        + "so the relation is not transitive and first-fit matching cannot be trusted");
            }
        }

        //An alphabet where nothing matches anything else satisfies the property above for free, so the
        //folding comparers are held to actually folding some of it together
        if (folds) {
            await Assert
                .That(blockOf.Distinct().Count())
                .IsLessThan(names.Count)
                .Because($"{label} put every value in its own block, so the check above proved nothing");
        }
    }


    public static IEnumerable<(string, X500NameComparer, bool)> Comparers()
    {
        yield return ("Folded", X500NameComparer.Folded, true);
        yield return ("FoldedAnyOrder", X500NameComparer.FoldedAnyOrder, true);
        yield return ("Values", X500NameComparer.Values, false);
        yield return ("ValuesAnyOrder", X500NameComparer.ValuesAnyOrder, false);
    }


    /// <summary>
    /// The structural reason the above holds, checked directly. Collation equality is equality of a sort key,
    /// and a relation of the form "f(x) equals f(y)" is an equivalence relation whatever f does. Confirming
    /// the two agree is what carries the result beyond the alphabet above.
    /// </summary>
    [Test]
    public async Task CollationEquality_IsSortKeyEquality()
    {
        var compare = CultureInfo.InvariantCulture.CompareInfo;
        const CompareOptions options = CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace;

        var values = Values;
        var keys = values.Select(x => compare.GetSortKey(x, options).KeyData).ToList();

        for (var i = 0; i < values.Count; i++) {
            for (var j = 0; j < values.Count; j++) {
                await Assert
                    .That(compare.Compare(values[i], values[j], options) == 0)
                    .IsEqualTo(keys[i].AsSpan().SequenceEqual(keys[j]))
                    .Because($"{Describe(values[i])} and {Describe(values[j])} compare and sort-key differently, "
                        + "so collation equality here is not equality of a sort key and nothing guarantees it is transitive");
            }
        }
    }


    /// <summary>
    /// The hash side of the same contract: <c>GetHashCodeOfAttribute</c> hashes through the same collation, so
    /// two values that match must hash alike or a dictionary keyed on these names loses entries.
    /// </summary>
    [Test]
    public async Task MatchingNames_HashAlike()
    {
        var names = BuildCommonNames();

        foreach (var (label, comparer, _) in Comparers()) {
            for (var i = 0; i < names.Count; i++) {
                for (var j = 0; j < i; j++) {
                    if (comparer.Equals(names[i], names[j])) {
                        await Assert
                            .That(comparer.GetHashCode(names[i]))
                            .IsEqualTo(comparer.GetHashCode(names[j]))
                            .Because($"{label}: {Describe(Values[i])} and {Describe(Values[j])} "
                                + "match but hash differently");
                    }
                }
            }
        }
    }


    /// <summary>
    /// First fit, exercised where it actually has a choice to make. Every relative distinguished name here
    /// carries a value that folds onto the same thing, so any of them can pair with any other and a greedy
    /// pick that stranded a later member would show up as a permutation comparing unequal.
    /// </summary>
    [Test]
    public async Task FoldedAnyOrder_MatchesWhicheverOrderTheParticipantsArriveIn()
    {
        //Three values folding alike and one that does not, so a wrong pairing has somewhere to go wrong
        string[] values = ["straße", "STRASSE", "Strasse", "other"];

        var subject = Build(values);

        foreach (var permutation in Permute(values)) {
            await Assert
                .That(X500NameComparer.FoldedAnyOrder.Equals(subject, Build(permutation)))
                .IsTrue()
                .Because($"the same relative distinguished names in the order [{String.Join(", ", permutation)}] "
                    + "compare unequal, so the multiset matching depends on the order they arrived in");
        }
    }


    private static X500DistinguishedName Build(IReadOnlyList<string> commonNames)
    {
        var builder = new X500NameBuilder();
        foreach (var name in commonNames) {
            builder = builder.Add(Oids.CommonNameOid, name);
        }
        return builder.Create();
    }


    private static IEnumerable<string[]> Permute(string[] values)
    {
        var order = Enumerable.Range(0, values.Length).ToArray();
        do {
            yield return [.. order.Select(i => values[i])];
        } while (NextPermutation(order));
    }


    private static bool NextPermutation(int[] order)
    {
        var pivot = order.Length - 2;
        while (pivot >= 0 && order[pivot] >= order[pivot + 1]) {
            pivot--;
        }
        if (pivot < 0) {
            return false;
        }

        var swap = order.Length - 1;
        while (order[swap] <= order[pivot]) {
            swap--;
        }
        (order[pivot], order[swap]) = (order[swap], order[pivot]);
        Array.Reverse(order, pivot + 1, order.Length - pivot - 1);
        return true;
    }


    /// <summary>Names a value by its code points, since the interesting ones are invisible or look identical.</summary>
    private static string Describe(string value)
        => value.Length == 0
            ? "<empty>"
            : String.Join(" ", value.Select(c => $"U+{(int)c:X4}"));
}
