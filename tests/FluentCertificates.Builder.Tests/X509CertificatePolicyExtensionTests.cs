using System.Formats.Asn1;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class X509CertificatePolicyExtensionTests
{
    [Test]
    public async Task Extension_HasCertificatePoliciesOidAndIsNotCritical()
    {
        var ext = new X509CertificatePolicyExtension([PolicyA]);

        //RFC 5280 s4.2.1.4: conforming CAs SHOULD mark this extension as non-critical
        await Assert.That(ext.Oid?.Value).IsEqualTo("2.5.29.32");
        await Assert.That(ext.Critical).IsFalse();
    }


    [Test]
    public async Task Encode_SinglePolicy_WritesOnePolicyInformation()
    {
        var ext = new X509CertificatePolicyExtension([PolicyA]);

        await Assert.That(ReadPolicyIdentifiers(ext)).IsEquivalentTo([PolicyA]);
    }


    [Test]
    public async Task Encode_SeveralPolicies_PreservesTheOrderGiven()
    {
        var ext = new X509CertificatePolicyExtension([PolicyB, PolicyA, Oids.AnyCertPolicy]);

        await Assert.That(ReadPolicyIdentifiers(ext)).IsEquivalentTo([PolicyB, PolicyA, Oids.AnyCertPolicy], CollectionOrdering.Matching);
    }


    [Test]
    public async Task Encode_NoPolicies_Throws()
    {
        //RFC 5280 s4.2.1.4 declares certificatePolicies as SEQUENCE SIZE (1..MAX), so an empty
        //extension cannot be represented at all
        await Assert.That(() => new X509CertificatePolicyExtension([])).Throws<ArgumentException>();
    }


    [Test]
    public async Task Encode_MalformedOid_Throws()
    {
        await Assert.That(() => new X509CertificatePolicyExtension(["not an oid"])).ThrowsException();
    }


    private const string PolicyA = "1.3.6.1.4.1.99999.1.1";
    private const string PolicyB = "1.3.6.1.4.1.99999.1.2";


    private static List<string> ReadPolicyIdentifiers(X509CertificatePolicyExtension ext)
    {
        var policies = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();
        var identifiers = new List<string>();
        while (policies.HasData) {
            identifiers.Add(policies.ReadSequence().ReadObjectIdentifier());
        }
        return identifiers;
    }
}
