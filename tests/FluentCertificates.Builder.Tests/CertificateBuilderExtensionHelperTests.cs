using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

/// <summary>
/// Covers the fluent helpers for the Authority Information Access, CRL Distribution Points and
/// Certificate Policies extensions. Assertions decode the DER the certificate actually carries rather
/// than comparing against the encoder that produced it.
/// </summary>
public class CertificateBuilderExtensionHelperTests
{
    [Test]
    public async Task SetAuthorityInformationAccess_SingleUris_CarriesBothLocations()
    {
        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetAuthorityInformationAccess_SingleUris_CarriesBothLocations)))
            .SetAuthorityInformationAccess(OcspUri, CaIssuersUri)
            .Create();

        var ext = FindExtension(cert, Oids.AuthorityInformationAccess);

        await Assert.That(ext.Critical).IsFalse();
        await Assert.That(ReadAccessLocations(ext, Oids.OcspEndpoint)).IsEquivalentTo([OcspUri]);
        await Assert.That(ReadAccessLocations(ext, Oids.CertificateAuthorityIssuers)).IsEquivalentTo([CaIssuersUri]);
    }


    [Test]
    public async Task SetAuthorityInformationAccess_OcspOnly_OmitsCaIssuers()
    {
        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetAuthorityInformationAccess_OcspOnly_OmitsCaIssuers)))
            .SetAuthorityInformationAccess(OcspUri, null)
            .Create();

        var ext = FindExtension(cert, Oids.AuthorityInformationAccess);

        await Assert.That(ReadAccessLocations(ext, Oids.OcspEndpoint)).IsEquivalentTo([OcspUri]);
        await Assert.That(ReadAccessLocations(ext, Oids.CertificateAuthorityIssuers)).IsEmpty();
    }


    [Test]
    public async Task SetAuthorityInformationAccess_Collections_CarriesEveryUri()
    {
        var ocspUris = new[] { OcspUri, "http://ocsp2.example.com/" }; // DevSkim: ignore DS137138

        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetAuthorityInformationAccess_Collections_CarriesEveryUri)))
            .SetAuthorityInformationAccess(ocspUris, [CaIssuersUri])
            .Create();

        var ext = FindExtension(cert, Oids.AuthorityInformationAccess);

        await Assert.That(ReadAccessLocations(ext, Oids.OcspEndpoint)).IsEquivalentTo(ocspUris);
        await Assert.That(ReadAccessLocations(ext, Oids.CertificateAuthorityIssuers)).IsEquivalentTo([CaIssuersUri]);
    }


    [Test]
    public async Task SetAuthorityInformationAccess_NoUris_Throws()
    {
        await Assert.That(() => new CertificateBuilder().SetAuthorityInformationAccess(null, (string?)null))
            .Throws<ArgumentException>();
    }


    [Test]
    public async Task SetAuthorityInformationAccess_CalledTwice_KeepsOnlyTheLastCall()
    {
        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetAuthorityInformationAccess_CalledTwice_KeepsOnlyTheLastCall)))
            .SetAuthorityInformationAccess("http://discarded.example.com/", null) // DevSkim: ignore DS137138
            .SetAuthorityInformationAccess(OcspUri, null)
            .Create();

        await Assert.That(CountExtensions(cert, Oids.AuthorityInformationAccess)).IsEqualTo(1);
        await Assert.That(ReadAccessLocations(FindExtension(cert, Oids.AuthorityInformationAccess), Oids.OcspEndpoint))
            .IsEquivalentTo([OcspUri]);
    }


    [Test]
    public async Task SetCrlDistributionPoints_Uris_CarriesEveryDistributionPoint()
    {
        var uris = new[] { CrlUri, "http://crl2.example.com/other.crl" }; // DevSkim: ignore DS137138

        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetCrlDistributionPoints_Uris_CarriesEveryDistributionPoint)))
            .SetCrlDistributionPoints(uris)
            .Create();

        var ext = FindExtension(cert, Oids.CrlDistributionPoints);

        //RFC 5280 s4.2.1.13: conforming CAs SHOULD mark this extension as non-critical
        await Assert.That(ext.Critical).IsFalse();
        await Assert.That(ReadCrlDistributionPointUris(ext)).IsEquivalentTo(uris);
    }


    [Test]
    public async Task SetCrlDistributionPoints_ParamsAndEnumerable_ProduceTheSameExtension()
    {
        var fromParams = new CertificateBuilder().SetCrlDistributionPoints(CrlUri);
        var fromEnumerable = new CertificateBuilder().SetCrlDistributionPoints(new List<string> { CrlUri });

        await Assert.That(fromParams.Extensions.Single().RawData)
            .IsEquivalentTo(fromEnumerable.Extensions.Single().RawData);
    }


    [Test]
    public async Task SetCrlDistributionPoints_NoUris_Throws()
    {
        await Assert.That(() => new CertificateBuilder().SetCrlDistributionPoints()).Throws<ArgumentException>();
    }


    [Test]
    public async Task SetCrlDistributionPoints_NonAsciiUri_Throws()
    {
        await Assert.That(() => new CertificateBuilder().SetCrlDistributionPoints("http://crl.exámple.com/")) // DevSkim: ignore DS137138
            .Throws<CryptographicException>();
    }


    [Test]
    public async Task SetCrlDistributionPoints_CalledTwice_KeepsOnlyTheLastCall()
    {
        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetCrlDistributionPoints_CalledTwice_KeepsOnlyTheLastCall)))
            .SetCrlDistributionPoints("http://discarded.example.com/discarded.crl") // DevSkim: ignore DS137138
            .SetCrlDistributionPoints(CrlUri)
            .Create();

        await Assert.That(CountExtensions(cert, Oids.CrlDistributionPoints)).IsEqualTo(1);
        await Assert.That(ReadCrlDistributionPointUris(FindExtension(cert, Oids.CrlDistributionPoints)))
            .IsEquivalentTo([CrlUri]);
    }


    [Test]
    public async Task SetCertificatePolicies_Oids_CarriesEveryPolicy()
    {
        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetCertificatePolicies_Oids_CarriesEveryPolicy)))
            .SetCertificatePolicies(new Oid(PolicyOid), new Oid(Oids.AnyCertPolicy))
            .Create();

        var ext = FindExtension(cert, Oids.CertPolicies);

        await Assert.That(ext.Critical).IsFalse();
        await Assert.That(ReadPolicyIdentifiers(ext)).IsEquivalentTo([PolicyOid, Oids.AnyCertPolicy]);
    }


    [Test]
    public async Task SetCertificatePolicies_OidParamsAndOidEnumerable_ProduceTheSameExtension()
    {
        var fromParams = new CertificateBuilder().SetCertificatePolicies(new Oid(PolicyOid));
        var fromEnumerable = new CertificateBuilder().SetCertificatePolicies(new List<Oid> { new(PolicyOid) });

        await Assert.That(fromParams.Extensions.Single().RawData)
            .IsEquivalentTo(fromEnumerable.Extensions.Single().RawData);
    }


    [Test]
    public async Task SetCertificatePolicies_OidAndEquivalentString_ProduceTheSameExtension()
    {
        var fromOid = new CertificateBuilder().SetCertificatePolicies(new Oid(PolicyOid));
        var fromString = new CertificateBuilder().SetCertificatePolicies(PolicyOid);

        await Assert.That(fromOid.Extensions.Single().RawData)
            .IsEquivalentTo(fromString.Extensions.Single().RawData);
    }


    [Test]
    public async Task SetCertificatePolicies_SingleStringAndEnumerable_ProduceTheSameExtension()
    {
        var fromSingle = new CertificateBuilder().SetCertificatePolicies(PolicyOid);
        var fromEnumerable = new CertificateBuilder().SetCertificatePolicies(new List<string> { PolicyOid });

        await Assert.That(fromSingle.Extensions.Single().RawData)
            .IsEquivalentTo(fromEnumerable.Extensions.Single().RawData);
    }


    [Test]
    public async Task SetCertificatePolicies_MultipleRawStrings_CarriesEveryPolicy()
    {
        var builder = new CertificateBuilder().SetCertificatePolicies(PolicyOid, Oids.AnyCertPolicy);

        await Assert.That(builder.Extensions.Single().RawData)
            .IsEquivalentTo(new CertificateBuilder().SetCertificatePolicies(new Oid(PolicyOid), new Oid(Oids.AnyCertPolicy)).Extensions.Single().RawData);
    }


    [Test]
    public async Task SetCertificatePolicies_OidWithNoValue_ThrowsNamingThePolicyIdentifiersParameter()
    {
        var ex = await Assert.That(() => new CertificateBuilder().SetCertificatePolicies(new Oid { FriendlyName = "no value" }))
            .Throws<ArgumentException>();

        await Assert.That(ex!.ParamName).IsEqualTo("policyIdentifiers");
    }


    [Test]
    public async Task SetCertificatePolicies_DuplicateOid_Throws()
    {
        await Assert.That(() => new CertificateBuilder().SetCertificatePolicies(PolicyOid, PolicyOid))
            .Throws<ArgumentException>();
    }


    [Test]
    public async Task SetCertificatePolicies_NoOids_Throws()
    {
        //With no params string[] overload to compete with params Oid[], a bare call resolves to the
        //Oid overload with zero elements -- still an empty policy list, so it still throws
        await Assert.That(() => new CertificateBuilder().SetCertificatePolicies()).Throws<ArgumentException>();
    }


    [Test]
    public async Task SetCertificatePolicies_CalledTwice_KeepsOnlyTheLastCall()
    {
        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetCertificatePolicies_CalledTwice_KeepsOnlyTheLastCall)))
            .SetCertificatePolicies("1.3.6.1.4.1.99999.9.9")
            .SetCertificatePolicies(PolicyOid)
            .Create();

        await Assert.That(CountExtensions(cert, Oids.CertPolicies)).IsEqualTo(1);
        await Assert.That(ReadPolicyIdentifiers(FindExtension(cert, Oids.CertPolicies))).IsEquivalentTo([PolicyOid]);
    }


    [Test]
    public async Task SetCertificatePolicies_ReplacesAnExistingExtensionOfADifferentRuntimeType()
    {
        //A certificate policies extension read back off a real certificate decodes as a plain X509Extension,
        //not X509CertificatePolicyExtension -- the ordinary re-issue/copy-extensions path
        using var existing = new CertificateBuilder().SetCertificatePolicies("1.3.6.1.4.1.99999.9.9").Create();
        var priorPolicyExtension = existing.Extensions[Oids.CertPolicies]!;

        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetCertificatePolicies_ReplacesAnExistingExtensionOfADifferentRuntimeType)))
            .AddExtension(priorPolicyExtension)
            .SetCertificatePolicies(PolicyOid)
            .Create();

        await Assert.That(CountExtensions(cert, Oids.CertPolicies)).IsEqualTo(1);
        await Assert.That(ReadPolicyIdentifiers(FindExtension(cert, Oids.CertPolicies))).IsEquivalentTo([PolicyOid]);
    }


    [Test]
    public async Task SetAuthorityInformationAccess_ReplacesAnExistingExtensionOfADifferentRuntimeType()
    {
        var rawAia = new X509Extension(Oids.AuthorityInformationAccess, new X509AuthorityInformationAccessExtension(["http://discarded.example.com/"], null).RawData, false); // DevSkim: ignore DS137138

        using var cert = new CertificateBuilder()
            .SetSubject(x => x.SetCommonName(nameof(SetAuthorityInformationAccess_ReplacesAnExistingExtensionOfADifferentRuntimeType)))
            .AddExtension(rawAia)
            .SetAuthorityInformationAccess(OcspUri, null)
            .Create();

        await Assert.That(CountExtensions(cert, Oids.AuthorityInformationAccess)).IsEqualTo(1);
        await Assert.That(ReadAccessLocations(FindExtension(cert, Oids.AuthorityInformationAccess), Oids.OcspEndpoint)).IsEquivalentTo([OcspUri]);
    }


    [Test]
    public async Task Helpers_AreIndependent_AndCoexistOnOneCertificate()
    {
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject(x => x.SetCommonName(nameof(Helpers_AreIndependent_AndCoexistOnOneCertificate)))
            .SetAuthorityInformationAccess(OcspUri, CaIssuersUri)
            .SetCrlDistributionPoints(CrlUri)
            .SetCertificatePolicies(PolicyOid)
            .Create();

        await Assert.That(ReadAccessLocations(FindExtension(cert, Oids.AuthorityInformationAccess), Oids.OcspEndpoint)).IsEquivalentTo([OcspUri]);
        await Assert.That(ReadCrlDistributionPointUris(FindExtension(cert, Oids.CrlDistributionPoints))).IsEquivalentTo([CrlUri]);
        await Assert.That(ReadPolicyIdentifiers(FindExtension(cert, Oids.CertPolicies))).IsEquivalentTo([PolicyOid]);

        //The CA usage's own extensions are untouched by any of them
        await Assert.That(cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority).IsTrue();
    }


    private const string OcspUri = "http://ocsp.example.com/"; // DevSkim: ignore DS137138
    private const string CaIssuersUri = "http://pki.example.com/issuer.cer"; // DevSkim: ignore DS137138
    private const string CrlUri = "http://crl.example.com/root.crl"; // DevSkim: ignore DS137138
    private const string PolicyOid = "1.3.6.1.4.1.99999.1.1";

    private static readonly Asn1Tag UriTag = new(TagClass.ContextSpecific, 6);
    private static readonly Asn1Tag ContextZero = new(TagClass.ContextSpecific, 0, true);


    private static X509Extension FindExtension(X509Certificate2 cert, string oid)
        => cert.Extensions.Single(x => x.Oid?.Value == oid);


    private static int CountExtensions(X509Certificate2 cert, string oid)
        => cert.Extensions.Count(x => x.Oid?.Value == oid);


    /// <summary>
    /// Reads the accessLocation URIs of every AccessDescription matching <paramref name="accessMethodOid"/>.
    /// AuthorityInfoAccessSyntax is a SEQUENCE OF AccessDescription { accessMethod OID, accessLocation GeneralName }.
    /// </summary>
    private static List<string> ReadAccessLocations(X509Extension ext, string accessMethodOid)
    {
        var descriptions = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();
        var uris = new List<string>();
        while (descriptions.HasData) {
            var description = descriptions.ReadSequence();
            var method = description.ReadObjectIdentifier();
            var location = description.ReadCharacterString(UniversalTagNumber.IA5String, UriTag);
            if (method == accessMethodOid) {
                uris.Add(location);
            }
        }
        return uris;
    }


    /// <summary>
    /// Reads the fullName URIs of every DistributionPoint. CRLDistributionPoints is a SEQUENCE OF
    /// DistributionPoint { distributionPoint [0] { fullName [0] GeneralNames } }.
    /// </summary>
    private static List<string> ReadCrlDistributionPointUris(X509Extension ext)
    {
        var points = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();
        var uris = new List<string>();
        while (points.HasData) {
            var fullName = points.ReadSequence().ReadSequence(ContextZero).ReadSequence(ContextZero);
            while (fullName.HasData) {
                uris.Add(fullName.ReadCharacterString(UniversalTagNumber.IA5String, UriTag));
            }
        }
        return uris;
    }


    /// <summary>
    /// Reads the policyIdentifier of every PolicyInformation. certificatePolicies is a SEQUENCE OF
    /// PolicyInformation { policyIdentifier OID, policyQualifiers OPTIONAL }.
    /// </summary>
    private static List<string> ReadPolicyIdentifiers(X509Extension ext)
    {
        var policies = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();
        var identifiers = new List<string>();
        while (policies.HasData) {
            identifiers.Add(policies.ReadSequence().ReadObjectIdentifier());
        }
        return identifiers;
    }
}
