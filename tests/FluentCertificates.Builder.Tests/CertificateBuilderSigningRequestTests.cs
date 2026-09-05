using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using TUnit.Assertions.Enums;

using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

/// <summary>
/// Covers issuing a certificate from a received CSR. The builder takes the subject and public key out of
/// the request; everything else stays the CA's decision, and a requested extension only reaches the
/// certificate when the accept predicate says so.
/// </summary>
public class CertificateBuilderSigningRequestTests
{
    [Test]
    public async Task UseCertificateSigningRequest_TakesTheSubjectAndPublicKeyFromTheRequest()
    {
        //More than a bare CN, so the round trip has attribute order and several encodings to preserve
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = BuildRequest("CN=Requesting Party, OU=Sales, O=Acme, C=AU", requesterKeys);

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .SetSubject("CN=Overwritten By The Request")
            .UseCertificateSigningRequest(csr)
            .Create();

        //Compared as encoded bytes, not as a decoded string: the name makes a full round trip through
        //X500NameBuilder, and Subject would normalise away a difference in encoding or attribute order
        await Assert.That(issued.SubjectName.RawData)
            .IsEquivalentTo(csr.CertificateRequest.SubjectName.RawData, CollectionOrdering.Matching);
        await Assert.That(issued.PublicKey.ExportSubjectPublicKeyInfo())
            .IsEquivalentTo(csr.CertificateRequest.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_PreservesTheSubjectsValueEncoding()
    {
        //The subject is carried across as an X500DistinguishedName. Routing it through the string form
        //instead would re-encode BMPString as whatever X500DistinguishedName's parser prefers, changing the
        //bytes a relying party matches the name on while the displayed subject looks identical.
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = new CertificateBuilder()
            .SetSubject(new X500NameBuilder().Add(Oids.CommonNameOid, UniversalTagNumber.BMPString, "Bmp Encoded"))
            .SetKeyPair(requesterKeys)
            .CreateCertificateSigningRequest();

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr)
            .Create();

        await Assert.That(issued.SubjectName.RawData)
            .IsEquivalentTo(csr.CertificateRequest.SubjectName.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_IssuesACertificateSignedByTheIssuerWithNoPrivateKey()
    {
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = BuildRequest("CN=No Key Of Its Own", requesterKeys);

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr)
            .Create();

        //The requester keeps the private key, so nothing on this side could attach one
        await Assert.That(issued.HasPrivateKey).IsFalse();
        await Assert.That(issued.IsIssuedBy(ca, true)).IsTrue();
    }


    [Test]
    public async Task UseCertificateSigningRequest_DiscardsEveryRequestedExtension()
    {
        //A requester asking to become a CA is the pitfall this API exists to avoid
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Would Be A CA"));

        //Naming the OIDs rather than asserting non-emptiness: the checks below are all absence checks, and
        //would pass vacuously if the request stopped carrying what it is supposed to be asking for
        await Assert.That(csr.CertificateRequest.CertificateExtensions.Select(x => x.Oid!.Value!))
            .Contains(Oids.BasicConstraints2).And.Contains(Oids.EnhancedKeyUsage).And.Contains(Oids.SubjectAltName);

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr)
            .Create();

        await Assert.That(issued.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority).IsFalse();
        await Assert.That(ReadEnhancedKeyUsages(issued)).IsEquivalentTo([Oids.ServerAuthPurpose]);
        await Assert.That(issued.Extensions.Any(x => x.Oid?.Value == Oids.SubjectAltName)).IsFalse();
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AppliesOnlyTheAcceptedExtensions()
    {
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Partly Honoured"));

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.SubjectAltName)
            .Create();

        //The SAN it asked for is honoured
        await Assert.That(ReadDnsNames(issued)).IsEquivalentTo([RequestedDnsName]);

        //The CA bit and the client-auth EKU it also asked for are not
        await Assert.That(issued.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority).IsFalse();
        await Assert.That(ReadEnhancedKeyUsages(issued)).IsEquivalentTo([Oids.ServerAuthPurpose]);

        //Still the requester's key being certified, not a freshly generated one
        await Assert.That(issued.PublicKey.ExportSubjectPublicKeyInfo())
            .IsEquivalentTo(csr.CertificateRequest.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AppliesEveryAcceptedExtensionNotJustTheFirst()
    {
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Two Honoured"));

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value is Oids.SubjectAltName or Oids.EnhancedKeyUsage)
            .Create();

        await Assert.That(ReadDnsNames(issued)).IsEquivalentTo([RequestedDnsName]);
        await Assert.That(ReadEnhancedKeyUsages(issued)).IsEquivalentTo([Oids.ClientAuthPurpose]);

        //The CA bit was not accepted, so the profile's own still stands
        await Assert.That(issued.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority).IsFalse();
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_KeepsTheCriticalityTheRequestAskedFor()
    {
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Critical Eku")
            .SetKeyPair(requesterKeys)
            .AddExtension(new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.ClientAuthPurpose) }, true))
            .CreateCertificateSigningRequest());

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.EnhancedKeyUsage)
            .Create();

        await Assert.That(FindExtension(issued, Oids.EnhancedKeyUsage).Critical).IsTrue();
        await Assert.That(ReadEnhancedKeyUsages(issued)).IsEquivalentTo([Oids.ClientAuthPurpose]);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AnAcceptedSanBeatsTheCasOwnInEitherOrder()
    {
        //An accepted extension goes into the same set a manually added one does, and that set beats anything
        //generated, so SetSubjectAlternativeNames loses even when it is called afterwards. SAN decides which
        //hostnames the certificate is trusted for, so this is pinned rather than left to be discovered.
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Requester San Wins"));

        using var ca = BuildCa();
        using var acceptedLast = new CertificateBuilder()
            .SetIssuer(ca)
            .SetSubjectAlternativeNames(x => x.AddDnsName("ca-pinned.example.com"))
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.SubjectAltName)
            .Create();

        using var acceptedFirst = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.SubjectAltName)
            .SetSubjectAlternativeNames(x => x.AddDnsName("ca-pinned.example.com"))
            .Create();

        await Assert.That(ReadDnsNames(acceptedLast)).IsEquivalentTo([RequestedDnsName]);
        await Assert.That(ReadDnsNames(acceptedFirst)).IsEquivalentTo([RequestedDnsName]);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AnAcceptedExtensionOverridesTheUsageProfile()
    {
        //Accepting an extension means accepting it over the profile's own: the CA said yes to this OID
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Profile Overridden"));

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.EnhancedKeyUsage)
            .Create();

        await Assert.That(CountExtensions(issued, Oids.EnhancedKeyUsage)).IsEqualTo(1);
        await Assert.That(ReadEnhancedKeyUsages(issued)).IsEquivalentTo([Oids.ClientAuthPurpose]);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AnAcceptedExtensionReplacesOneOfADifferentRuntimeType()
    {
        //An extension read back off a certificate decodes as a plain X509Extension, which the builder's
        //OID-plus-type equality treats as distinct. Both reaching CertificateRequest would throw.
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Replaces A Raw Extension"));
        var rawEku = new X509Extension(
            Oids.EnhancedKeyUsage,
            new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.CodeSigningPurpose) }, false).RawData,
            false);

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .AddExtension(rawEku)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.EnhancedKeyUsage)
            .Create();

        await Assert.That(CountExtensions(issued, Oids.EnhancedKeyUsage)).IsEqualTo(1);
        await Assert.That(ReadEnhancedKeyUsages(issued)).IsEquivalentTo([Oids.ClientAuthPurpose]);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_OnARequestParsedWithoutExtensions_NeverConsultsAccept()
    {
        //FromDer discards requested extensions unless UnsafeLoadCertificateExtensions is passed, so a CA that
        //forgot that option honours nothing rather than silently honouring everything
        var csr = CertificateSigningRequest.FromDer(BuildAmbitiousRequest("CN=Nothing To Accept").RawData);
        var consulted = false;

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, _ => { consulted = true; return true; })
            .Create();

        await Assert.That(consulted).IsFalse();
        await Assert.That(issued.Subject).IsEqualTo("CN=Nothing To Accept");
        await Assert.That(ReadEnhancedKeyUsages(issued)).IsEquivalentTo([Oids.ServerAuthPurpose]);
    }


    [Test]
    public async Task UseCertificateSigningRequest_StillCarriesTheIssuersAuthorityKeyIdentifier()
    {
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = BuildRequest("CN=Gets The Issuers Aki", requesterKeys);

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr)
            .Create();

        await Assert.That(CountExtensions(issued, Oids.AuthorityKeyIdentifier)).IsEqualTo(1);
        await Assert.That(FindExtension(issued, Oids.AuthorityKeyIdentifier).RawData)
            .IsEquivalentTo(new X509AuthorityKeyIdentifierExtension(ca, false).RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AnAcceptedAuthorityKeyIdentifierReplacesTheIssuers()
    {
        //The issuer's own AKI is added straight to the CertificateRequest rather than through the extension
        //set, so without a guard a request that asked for one would make CertificateRequest throw
        using var otherKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Some Other CA")
            .SetKeyPair(otherKeys)
            .Create();

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var requested = new X509AuthorityKeyIdentifierExtension(other, false);
        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Asked For An Aki")
            .SetKeyPair(requesterKeys)
            .AddExtension(requested)
            .CreateCertificateSigningRequest());

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.AuthorityKeyIdentifier)
            .Create();

        await Assert.That(CountExtensions(issued, Oids.AuthorityKeyIdentifier)).IsEqualTo(1);
        await Assert.That(FindExtension(issued, Oids.AuthorityKeyIdentifier).RawData)
            .IsEquivalentTo(requested.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_ReplacesAKeyPairAlreadyOnTheBuilder()
    {
        using var caKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var csr = BuildRequest("CN=Requester Key Wins", requesterKeys);

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .SetKeyPair(caKeys)
            .UseCertificateSigningRequest(csr)
            .Create();

        await Assert.That(issued.HasPrivateKey).IsFalse();
        await Assert.That(issued.PublicKey.ExportSubjectPublicKeyInfo())
            .IsEquivalentTo(csr.CertificateRequest.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_TheRequestsKeyDecidesTheProfilesKeyUsage()
    {
        //KeyEnciphermentIfSupported reads the public key's algorithm OID: the bit is emitted for an RSA key
        //and withheld for an EC one, so it shows the request's key, not the builder's default, reached the
        //profile. The builder's default is RSA, so it is the EC half that could not pass by accident.
        using var rsaKeys = RSA.Create(2048);
        using var ecKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var ca = BuildCa();
        var template = new CertificateBuilder().SetUsage(CertificateUsage.Server).SetIssuer(ca);

        using var fromRsa = template.UseCertificateSigningRequest(BuildRequest("CN=Rsa Requester", rsaKeys)).Create();
        using var fromEc = template.UseCertificateSigningRequest(BuildRequest("CN=Ec Requester", ecKeys)).Create();

        await Assert.That(KeyUsagesOf(fromRsa).HasFlag(X509KeyUsageFlags.KeyEncipherment)).IsTrue();
        await Assert.That(KeyUsagesOf(fromEc).HasFlag(X509KeyUsageFlags.KeyEncipherment)).IsFalse();
    }


    [Test]
    public async Task UseCertificateSigningRequest_OneConfiguredBuilderIssuesFromManyRequests()
    {
        using var firstKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var secondKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var firstCsr = BuildRequest("CN=First Requester", firstKeys);
        var secondCsr = BuildRequest("CN=Second Requester", secondKeys);

        using var ca = BuildCa();
        var template = new CertificateBuilder()
            .SetUsage(CertificateUsage.Server)
            .SetIssuer(ca)
            .SetValidity(TimeSpan.FromDays(90));

        using var first = template.UseCertificateSigningRequest(firstCsr).Create();
        using var second = template.UseCertificateSigningRequest(secondCsr).Create();

        await Assert.That(first.Subject).IsEqualTo("CN=First Requester");
        await Assert.That(second.Subject).IsEqualTo("CN=Second Requester");

        //Each certificate against its own request, not merely against each other: two freshly generated keys
        //would differ from one another too, and prove nothing about where either came from
        await Assert.That(first.PublicKey.ExportSubjectPublicKeyInfo())
            .IsEquivalentTo(firstCsr.CertificateRequest.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
        await Assert.That(second.PublicKey.ExportSubjectPublicKeyInfo())
            .IsEquivalentTo(secondCsr.CertificateRequest.PublicKey.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
        await Assert.That(first.IsIssuedBy(ca, true)).IsTrue();
        await Assert.That(second.IsIssuedBy(ca, true)).IsTrue();
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_LeavesTheBuilderItWasCalledOnUntouched()
    {
        //Accepted extensions land on the returned builder, so issuing the next request from that result
        //would hand the next requester this one's extensions. Reusing the configured builder does not.
        var first = LoadWithExtensions(BuildAmbitiousRequest("CN=First Requester"));

        using var secondKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var second = BuildRequest("CN=Second Requester", secondKeys);

        using var ca = BuildCa();
        var template = new CertificateBuilder().SetUsage(CertificateUsage.Server).SetIssuer(ca);

        using var issuedFirst = template.UseCertificateSigningRequest(first, _ => true).Create();
        using var issuedSecond = template.UseCertificateSigningRequest(second).Create();

        await Assert.That(ReadDnsNames(issuedFirst)).IsEquivalentTo([RequestedDnsName]);

        //None of the first requester's extensions reached the second certificate
        await Assert.That(issuedSecond.Extensions.Any(x => x.Oid?.Value == Oids.SubjectAltName)).IsFalse();
        await Assert.That(issuedSecond.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority).IsFalse();
        await Assert.That(ReadEnhancedKeyUsages(issuedSecond)).IsEquivalentTo([Oids.ServerAuthPurpose]);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithNullArguments_ThrowsNamingTheOffendingParameter()
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = BuildRequest("CN=Null Arguments", keys);

        //Naming the parameter matters here: Enumerable.Where throws ArgumentNullException for a null
        //predicate all by itself, so asserting only the type would pass with no guard at all
        await Assert.That(() => new CertificateBuilder().UseCertificateSigningRequest(null!))
            .Throws<ArgumentNullException>().WithParameterName("csr");
        await Assert.That(() => new CertificateBuilder().UseCertificateSigningRequest(null!, _ => true))
            .Throws<ArgumentNullException>().WithParameterName("csr");
        await Assert.That(() => new CertificateBuilder().UseCertificateSigningRequest(csr, null!))
            .Throws<ArgumentNullException>().WithParameterName("accept");
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAMultiValuedRelativeDistinguishedName_Throws()
    {
        //X500NameBuilder models a name as a flat list of single-valued RDNs, so it cannot represent
        //"CN=Multi Valued+OU=Sales" and its constructor rejects one. The subject of a received request is
        //peer-supplied, so a CA has to expect this rather than meet it as an unhandled fault.
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=Multi Valued+OU=Sales, O=Acme"),
            keys,
            HashAlgorithmName.SHA256);
        var csr = CertificateSigningRequest.FromDer(request.CreateSigningRequest());

        await Assert.That(() => new CertificateBuilder().UseCertificateSigningRequest(csr))
            .Throws<InvalidOperationException>();
    }


    private const string RequestedDnsName = "requested.example.com";


    private static CertificateSigningRequest BuildRequest(string subject, AsymmetricAlgorithm keys)
        => new CertificateBuilder()
            .SetSubject(subject)
            .SetKeyPair(keys)
            .CreateCertificateSigningRequest();


    /// <summary>
    /// Builds a request asking for everything a requester should not be handed unchallenged: the CA bit, an
    /// EKU the issuing profile would not grant, and a SAN of its own choosing.
    /// </summary>
    private static CertificateSigningRequest BuildAmbitiousRequest(string subject)
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateBuilder()
            .SetSubject(subject)
            .SetKeyPair(keys)
            .AddExtension(new X509BasicConstraintsExtension(true, false, 0, true))
            .AddExtension(new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.ClientAuthPurpose) }, false))
            .SetSubjectAlternativeNames(x => x.AddDnsName(RequestedDnsName))
            .CreateCertificateSigningRequest();
    }


    private static CertificateSigningRequest LoadWithExtensions(CertificateSigningRequest csr)
        => CertificateSigningRequest.FromDer(csr.RawData, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);


    private static X509Certificate2 BuildCa()
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Issuing CA")
            .SetKeyPair(keys)
            .SetValidity(TimeSpan.FromDays(2))
            .Create();
    }


    private static int CountExtensions(X509Certificate2 cert, string oid)
        => cert.Extensions.Count(x => x.Oid?.Value == oid);


    private static X509Extension FindExtension(X509Certificate2 cert, string oid)
        => cert.Extensions.Single(x => x.Oid?.Value == oid);


    private static List<string> ReadEnhancedKeyUsages(X509Certificate2 cert)
        => cert.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(x => x.EnhancedKeyUsages.OfType<Oid>())
            .Select(x => x.Value!)
            .ToList();


    private static List<string> ReadDnsNames(X509Certificate2 cert)
        => cert.Extensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(x => x.EnumerateDnsNames())
            .ToList();


    private static X509KeyUsageFlags KeyUsagesOf(X509Certificate2 cert)
        => cert.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages;
}
