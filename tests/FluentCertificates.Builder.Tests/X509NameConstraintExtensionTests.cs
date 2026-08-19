using System.Formats.Asn1;

namespace FluentCertificates;

public class X509NameConstraintExtensionTests
{
    [Test]
    public async Task Extension_HasNameConstraintsOidAndIsCritical()
    {
        var ext = new X509NameConstraintExtension(Dns("example.com"), null);

        //RFC 5280 s4.2.1.10: conforming CAs MUST mark this extension critical
        await Assert.That(ext.Oid?.Value).IsEqualTo("2.5.29.30");
        await Assert.That(ext.Critical).IsTrue();
    }


    [Test]
    public async Task Encode_PermittedSubtreesOnly_UsesContextTagZero()
    {
        var ext = new X509NameConstraintExtension(Dns("permitted.example.com"), null);
        var outer = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();

        await Assert.That(ReadSubtreeDnsNames(outer, 0)).IsEquivalentTo(["permitted.example.com"]);
        await Assert.That(outer.HasData).IsFalse().Because("no excludedSubtrees were supplied");
    }


    [Test]
    public async Task Encode_ExcludedSubtreesOnly_UsesContextTagOne()
    {
        var ext = new X509NameConstraintExtension(null, Dns("excluded.example.com"));
        var outer = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();

        //With no permitted subtrees the [0] element is absent entirely, not empty
        await Assert.That(outer.PeekTag()).IsEqualTo(new Asn1Tag(TagClass.ContextSpecific, 1, true));
        await Assert.That(ReadSubtreeDnsNames(outer, 1)).IsEquivalentTo(["excluded.example.com"]);
    }


    [Test]
    public async Task Encode_BothSubtrees_WritesPermittedBeforeExcluded()
    {
        var ext = new X509NameConstraintExtension(
            Dns("a.permitted.com", "b.permitted.com"),
            Dns("a.excluded.com"));

        var outer = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();

        await Assert.That(ReadSubtreeDnsNames(outer, 0)).IsEquivalentTo(["a.permitted.com", "b.permitted.com"]);
        await Assert.That(ReadSubtreeDnsNames(outer, 1)).IsEquivalentTo(["a.excluded.com"]);
        await Assert.That(outer.HasData).IsFalse();
    }


    [Test]
    public async Task Encode_NoSubtrees_ProducesAnEmptySequence()
    {
        var ext = new X509NameConstraintExtension(null, null);
        var outer = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();

        await Assert.That(outer.HasData).IsFalse();
    }


    private static IEnumerable<GeneralName> Dns(params string[] names)
        => new GeneralNameListBuilder().AddDnsNames(names).Create();


    private static List<string> ReadSubtreeDnsNames(AsnReader outer, int contextTag)
    {
        var subtrees = outer.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, contextTag, true));
        var names = new List<string>();
        while (subtrees.HasData) {
            var subtree = subtrees.ReadSequence();
            names.Add(subtree.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 2)));
        }
        return names;
    }
}
