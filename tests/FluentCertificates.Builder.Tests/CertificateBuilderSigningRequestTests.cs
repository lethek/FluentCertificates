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
    public async Task UseCertificateSigningRequest_WithAccept_TheLastSubjectAlternativeNameCallWins()
    {
        //SAN decides which hostnames the certificate is trusted for, so which of the two calls wins is worth
        //pinning: whichever came last. A CA that accepts the requester's names and then pins the ones it
        //actually verified gets its own, and one that pins first and then accepts has said yes to theirs.
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=San Precedence"));

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
        await Assert.That(ReadDnsNames(acceptedFirst)).IsEquivalentTo(["ca-pinned.example.com"]);
        await Assert.That(CountExtensions(acceptedFirst, Oids.SubjectAltName)).IsEqualTo(1);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AnEmptySubjectAlternativeNameCallDiscardsTheAcceptedOne()
    {
        //Setting no names at all is still the caller's last word, so the accepted extension goes with it
        //rather than surviving as the only SAN in the certificate.
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=San Discarded"));

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.SubjectAltName)
            .SetSubjectAlternativeNames([])
            .Create();

        await Assert.That(CountExtensions(issued, Oids.SubjectAltName)).IsEqualTo(0);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_TheLastPathLengthCallWins()
    {
        //SetPathLength feeds the basic constraints the CA profile generates rather than being an extension
        //itself, so without a clear it loses to an accepted one however late it is called.
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Path Length Precedence"));

        using var ca = BuildCa();
        var template = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetIssuer(ca);

        using var pathLengthLast = template
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.BasicConstraints2)
            .SetPathLength(2)
            .Create();

        using var acceptedLast = template
            .SetPathLength(2)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.BasicConstraints2)
            .Create();

        await Assert.That(CountExtensions(pathLengthLast, Oids.BasicConstraints2)).IsEqualTo(1);
        await Assert.That(BasicConstraintsOf(pathLengthLast).HasPathLengthConstraint).IsTrue();
        await Assert.That(BasicConstraintsOf(pathLengthLast).PathLengthConstraint).IsEqualTo(2);

        //The request's own basic constraints assert no path length, and saying yes to them last means
        //saying yes to that too
        await Assert.That(BasicConstraintsOf(acceptedLast).HasPathLengthConstraint).IsFalse();
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_TheLastUsageCallWins()
    {
        //A profile generates the extended key usage rather than storing one, so an accepted extension
        //displaces it. Setting the profile afterwards has to be the CA's last word.
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Usage Precedence"));

        using var ca = BuildCa();
        using var usageLast = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.EnhancedKeyUsage)
            .SetUsage(CertificateUsage.Server)
            .Create();

        await Assert.That(CountExtensions(usageLast, Oids.EnhancedKeyUsage)).IsEqualTo(1);
        await Assert.That(ReadEnhancedKeyUsages(usageLast)).IsEquivalentTo([Oids.ServerAuthPurpose]);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_ASucceedingUsageAlsoReclaimsBasicConstraintsAndKeyUsage()
    {
        //The profile owns every extension it generates, not just the one under test above, so all of them
        //go back to the profile when it is set last. cA=TRUE would otherwise contradict Server and throw.
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Whole Profile Reclaimed"));

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, _ => true)
            .SetUsage(CertificateUsage.Server)
            .Create();

        await Assert.That(BasicConstraintsOf(issued).CertificateAuthority).IsFalse();
        await Assert.That(KeyUsagesOf(issued).HasFlag(X509KeyUsageFlags.KeyCertSign)).IsFalse();

        //The subject alternative name is not part of any profile, so accepting it still stands
        await Assert.That(ReadDnsNames(issued)).IsEquivalentTo([RequestedDnsName]);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_ANullInTheRequestsExtensions_ThrowsBeforeAcceptSeesIt()
    {
        //Only reachable by adding one to the parsed request's own collection, but it is the same defect as
        //a null passed to AddExtension: it would sit in the set until Create dereferenced it.
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = LoadWithExtensions(BuildRequest("CN=Null Extension", keys));
        //First, so that reaching the predicate at all would mean the guard ran too late
        csr.CertificateRequest.CertificateExtensions.Insert(0, null!);

        var sawExtension = false;

        await Assert.That(() => new CertificateBuilder().UseCertificateSigningRequest(csr, _ => { sawExtension = true; return true; }))
            .Throws<ArgumentException>().WithParameterName("csr");

        //The predicate is the caller's own code, so handing it a null would only move the fault
        await Assert.That(sawExtension).IsFalse();
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_TheLastKeyCallWins()
    {
        //The subject key identifier names the key being certified, so a key set after an accepted one has
        //to take it back. Otherwise the certificate names a key it does not contain.
        var csr = LoadWithExtensions(BuildAmbitiousRequest("CN=Key Precedence"));

        using var ca = BuildCa();
        using var ownKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var template = new CertificateBuilder().SetIssuer(ca);

        using var keyLast = template
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.SubjectKeyIdentifier)
            .SetKeyPair(ownKeys)
            .Create();

        using var acceptedLast = template
            .SetKeyPair(ownKeys)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.SubjectKeyIdentifier)
            .Create();

        await Assert.That(CountExtensions(keyLast, Oids.SubjectKeyIdentifier)).IsEqualTo(1);
        await Assert.That(SubjectKeyIdentifierOf(keyLast)).IsEqualTo(DerivedKeyIdentifier(new PublicKey(ownKeys)));

        //Accepting last means accepting the requester's own identifier, and its key with it
        await Assert.That(SubjectKeyIdentifierOf(acceptedLast)).IsEqualTo(DerivedKeyIdentifier(csr.CertificateRequest.PublicKey));
    }


    [Test]
    public async Task Create_WithAKeySetAfterASubjectKeyIdentifierWasAdded_NamesTheKeyItCertifies()
    {
        //Same rule off the signing-request path: AddExtension then a key means the key had the last word.
        using var stale = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var actual = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Key Set Last")
            .AddExtension(new X509SubjectKeyIdentifierExtension(new PublicKey(stale), false))
            .SetKeyPair(actual)
            .Create();

        await Assert.That(CountExtensions(cert, Oids.SubjectKeyIdentifier)).IsEqualTo(1);
        await Assert.That(SubjectKeyIdentifierOf(cert)).IsEqualTo(DerivedKeyIdentifier(new PublicKey(actual)));
    }


    [Test]
    public async Task Create_WithNoKeySetAndASubjectKeyIdentifierAdded_KeepsTheAddedOne()
    {
        //Create generates a key pair when the caller named none, and that fill-in must not outrank a
        //Subject Key Identifier the caller did add. It routes around the public setter for that reason.
        var supplied = new X509SubjectKeyIdentifierExtension("0102030405060708090A", critical: false);

        using var cert = new CertificateBuilder()
            .SetSubject("CN=Generated Key")
            .AddExtension(supplied)
            .Create();

        await Assert.That(FindExtension(cert, Oids.SubjectKeyIdentifier).RawData)
            .IsEquivalentTo(supplied.RawData, CollectionOrdering.Matching);
    }


    public static IEnumerable<CertificateUsage> AllUsages()
        => Enum.GetValues<CertificateUsage>();


    [Test]
    [MethodDataSource(nameof(AllUsages))]
    public async Task SetUsage_DiscardsEveryExtensionItsOwnProfileGenerates(CertificateUsage usage)
    {
        //SetUsage clears a listed set of OIDs, which has to stay in step with what the profiles actually
        //generate. Rather than restate that list, this builds the profile's certificate first and feeds
        //every extension it produced back through a request, so a profile gaining an OID the list does not
        //cover fails here instead of silently letting a requester keep that extension.
        using var ca = BuildCa();
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var fromProfileAlone = new CertificateBuilder()
            .SetUsage(usage)
            .SetIssuer(ca)
            .SetSubject($"CN={usage} Profile")
            .SetKeyPair(keys)
            .Create();

        //The subject and authority key identifiers come from the keys rather than the profile, so no
        //profile owns them and neither is expected to be reclaimed
        var generated = fromProfileAlone.Extensions
            .Where(x => x.Oid?.Value is not (Oids.SubjectKeyIdentifier or Oids.AuthorityKeyIdentifier))
            .ToList();

        var request = new CertificateRequest(new X500DistinguishedName($"CN={usage} Profile"), keys, HashAlgorithmName.SHA256);
        foreach (var extension in generated) {
            request.CertificateExtensions.Add(extension);
        }
        var csr = CertificateSigningRequest.FromDer(request.CreateSigningRequest(), CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        var profileSetLast = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, _ => true)
            .SetUsage(usage);

        //Asserted on the builder rather than the issued certificate on purpose. A requester's copy of a
        //generated extension can be byte-identical to the profile's, so comparing the certificate cannot
        //tell which one won: the CA profile's basic constraints are exactly that case, since RFC 5280
        //s4.2.1.9 makes them critical either way. Only the builder's own set shows the OID was reclaimed.
        foreach (var extension in generated) {
            await Assert.That(profileSetLast.Extensions.Any(x => x.Oid?.Value == extension.Oid?.Value)).IsFalse();
        }
    }


    [Test]
    [Arguments(CertificateUsage.CA)]
    [Arguments(CertificateUsage.CrlSigning)]
    public async Task SetUsage_KeepsAnExtendedKeyUsageWhenItsProfileGeneratesNone(CertificateUsage usage)
    {
        //The converse of the test above, which only pins that everything generated is discarded. A profile
        //generating no extended key usage has no word on that OID, so discarding one the caller set would
        //delete it with nothing put back.
        var builder = new CertificateBuilder()
            .AddExtension(new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.OcspSigningPurpose) }, false))
            .SetUsage(usage);

        await Assert.That(builder.Extensions.Any(x => x.Oid?.Value == Oids.EnhancedKeyUsage)).IsTrue();
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
            .IsEquivalentTo(KeyIdentifierAkiFor(ca).RawData, CollectionOrdering.Matching);
    }


    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task UseCertificateSigningRequest_WithAccept_AnAuthorityKeyIdentifierNamingAnotherCa_ThrowsRegardlessOfCallOrder(bool issuerSetFirst)
    {
        //Checked at issuance rather than where the extension was accepted, so call order cannot decide
        //whether the check runs at all.
        using var otherKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Some Other CA")
            .SetKeyPair(otherKeys)
            .Create();

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var requested = KeyIdentifierAkiFor(other);
        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Asked For An Aki")
            .SetKeyPair(requesterKeys)
            .AddExtension(requested)
            .CreateCertificateSigningRequest());

        using var ca = BuildCa();
        var builder = issuerSetFirst
            ? new CertificateBuilder().SetIssuer(ca).UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.AuthorityKeyIdentifier)
            : new CertificateBuilder().UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.AuthorityKeyIdentifier).SetIssuer(ca);

        var ex = await Assert.That(() => builder.CreateCertificateRequest())
            .Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("does not identify the issuer's own key");
    }


    [Test]
    public async Task Create_WithAnAuthorityKeyIdentifierNamingAnotherCaAddedDirectly_Throws()
    {
        //The check measures what would be issued, not where the value came from: a CA's own extension is
        //refused on the same terms as an accepted one. Naming some other key deliberately needs no Issuer.
        using var otherKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Some Other CA")
            .SetKeyPair(otherKeys)
            .Create();

        using var subjectKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = BuildCa();

        var builder = new CertificateBuilder()
            .SetSubject("CN=Aki Added By The Ca Itself")
            .SetKeyPair(subjectKeys)
            .SetIssuer(ca)
            .AddExtension(new X509Extension(KeyIdentifierAkiFor(other), false));

        var ex = await Assert.That(() => builder.Create()).Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("does not identify the issuer's own key");
    }


    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task UseCertificateSigningRequest_WithAccept_AnAuthorityKeyIdentifierNoLongerBeingIssued_IsNotRefused(bool discardedBySetExtensions)
    {
        //Clearing the set leaves the builder to generate the issuer's own identifier, and writing a correct
        //one over the top is the value the check wants anyway. Neither is refused.
        using var otherKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Some Other CA")
            .SetKeyPair(otherKeys)
            .Create();

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Aki Then Written Over")
            .SetKeyPair(requesterKeys)
            .AddExtension(new X509Extension(KeyIdentifierAkiFor(other), false))
            .CreateCertificateSigningRequest());

        using var ca = BuildCa();
        var accepted = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.AuthorityKeyIdentifier);

        var builder = discardedBySetExtensions
            ? accepted.SetExtensions(new X509EnhancedKeyUsageExtension(new OidCollection { new(Oids.ClientAuthPurpose) }, false))
            : accepted.AddExtension(new X509Extension(KeyIdentifierAkiFor(ca), false));

        using var issued = builder.Create();

        var aki = new X509AuthorityKeyIdentifierExtension(FindExtension(issued, Oids.AuthorityKeyIdentifier).RawData, false);
        var caSki = ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().First();

        await Assert.That(aki.KeyIdentifier).IsNotNull();
        await Assert.That(aki.KeyIdentifier!.Value.ToArray())
            .IsEquivalentTo(caSki.SubjectKeyIdentifierBytes.ToArray(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AnAuthorityKeyIdentifierMatchingTheIssuer_IsIssued()
    {
        //Pins that the check above turns on the value, not on merely accepting the OID: a request that
        //happens to supply the correct Authority Key Identifier is issued normally.
        using var ca = BuildCa();

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var requested = KeyIdentifierAkiFor(ca);
        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Asked For The Right Aki")
            .SetKeyPair(requesterKeys)
            .AddExtension(requested)
            .CreateCertificateSigningRequest());

        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.AuthorityKeyIdentifier)
            .Create();

        await Assert.That(CountExtensions(issued, Oids.AuthorityKeyIdentifier)).IsEqualTo(1);
        await Assert.That(FindExtension(issued, Oids.AuthorityKeyIdentifier).RawData)
            .IsEquivalentTo(requested.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_UnderAnIssuerWithNoSubjectKeyIdentifier_DerivesTheKeyIdentifierFromItsPublicKey()
    {
        //RFC 5280 s4.2.1.1 requires the keyIdentifier field in every certificate a conforming CA generates,
        //bar a self-signed one, so there is always a value to write. This issuer publishes no Subject Key
        //Identifier to copy, and that section's own advice is that the value "SHOULD be derived from the
        //public key used to verify the certificate's signature". Naming the issuer by issuer and serial
        //number instead would leave out the very field the requirement names.
        using var ca = BuildCaWithoutSubjectKeyIdentifier();

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = BuildRequest("CN=Issued By A Ca Without A Ski", requesterKeys);

        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr)
            .Create();

        var aki = new X509AuthorityKeyIdentifierExtension(FindExtension(issued, Oids.AuthorityKeyIdentifier).RawData, false);
        var derived = new X509SubjectKeyIdentifierExtension(ca.PublicKey, false);

        await Assert.That(aki.KeyIdentifier).IsNotNull();
        await Assert.That(aki.KeyIdentifier!.Value.ToArray())
            .IsEquivalentTo(derived.SubjectKeyIdentifierBytes.ToArray(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AnAuthorityKeyIdentifierCarryingIssuerAndSerial_IsIssued()
    {
        //RFC 5280 s4.2.1.1 makes authorityCertIssuer and authorityCertSerialNumber optional alongside the
        //keyIdentifier, so an extension carrying all three conforms. Only the keyIdentifier is compared, so
        //the extra fields do not make a correct identifier look wrong.
        using var ca = BuildCa();
        var requested = new X509Extension(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, includeKeyIdentifier: true, includeIssuerAndSerial: true),
            false);

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Aki With Issuer And Serial")
            .SetKeyPair(requesterKeys)
            .AddExtension(requested)
            .CreateCertificateSigningRequest());

        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.AuthorityKeyIdentifier)
            .Create();

        await Assert.That(FindExtension(issued, Oids.AuthorityKeyIdentifier).RawData)
            .IsEquivalentTo(requested.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_AnAuthorityKeyIdentifierUnderAnIssuerWithNoSubjectKeyIdentifier_IsCheckedAgainstTheDerivedValue()
    {
        //An issuer publishing no Subject Key Identifier still has an expected value, since one is derived
        //from its public key, so a requested identifier is measured against that rather than waved through.
        using var ca = BuildCaWithoutSubjectKeyIdentifier();

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var derived = new X509SubjectKeyIdentifierExtension(ca.PublicKey, false);
        var matching = new X509Extension(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(derived.SubjectKeyIdentifierBytes.Span), false);

        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Aki Matching A Derived Identifier")
            .SetKeyPair(requesterKeys)
            .AddExtension(matching)
            .CreateCertificateSigningRequest());

        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.AuthorityKeyIdentifier)
            .Create();

        await Assert.That(FindExtension(issued, Oids.AuthorityKeyIdentifier).RawData)
            .IsEquivalentTo(matching.RawData, CollectionOrdering.Matching);

        using var unrelatedKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var unrelated = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Unrelated CA")
            .SetKeyPair(unrelatedKeys)
            .Create();
        var wrong = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Aki Naming Another Key")
            .SetKeyPair(requesterKeys)
            .AddExtension(new X509Extension(KeyIdentifierAkiFor(unrelated), false))
            .CreateCertificateSigningRequest());

        var builder = new CertificateBuilder().SetIssuer(ca)
            .UseCertificateSigningRequest(wrong, x => x.Oid?.Value == Oids.AuthorityKeyIdentifier);
        var ex = await Assert.That(() => builder.CreateCertificateRequest())
            .Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("does not identify the issuer's own key");
    }


    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task UseCertificateSigningRequest_WithAccept_AnAuthorityKeyIdentifierWithNoReadableKeyIdentifier_Throws(bool decodable)
    {
        //RFC 5280 s4.2.1.1 requires the keyIdentifier field in every certificate a conforming CA generates.
        //An accepted extension without one names no signing key, and it displaces the extension the builder
        //would have contributed, so the certificate would identify its issuer by nothing at all. The
        //undecodable case is the same outcome by a different route: what it asserts cannot be established.
        using var ca = BuildCa();
        var value = decodable
            //Well-formed, but carrying only authorityCertIssuer and authorityCertSerialNumber
            ? X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, includeKeyIdentifier: false, includeIssuerAndSerial: true).RawData
            : [0x30, 0x03, 0x81, 0x01, 0x41];

        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Aki Naming No Key")
            .SetKeyPair(requesterKeys)
            .AddExtension(new X509Extension(Oids.AuthorityKeyIdentifier, value, critical: false))
            .CreateCertificateSigningRequest());

        var builder = new CertificateBuilder().SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.AuthorityKeyIdentifier);

        var ex = await Assert.That(() => builder.CreateCertificateRequest())
            .Throws<InvalidOperationException>();

        await Assert.That(ex!.Message).Contains("carries no readable key identifier");
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_ATruncatedSubjectKeyIdentifier_IsIssuedAsAsked()
    {
        //RFC 5280 s4.2.1.2's second common derivation: the four-bit type field 0100, then the least
        //significant 60 bits of the same SHA-1 hash the first derivation uses whole. It labels the certified
        //key exactly as well as the 20-byte form, so comparing against the 20-byte form would refuse it.
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var requested = new X509SubjectKeyIdentifierExtension(TruncatedKeyIdentifier(new PublicKey(requesterKeys)), false);
        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Short Ski")
            .SetKeyPair(requesterKeys)
            .AddExtension(requested)
            .CreateCertificateSigningRequest());

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.SubjectKeyIdentifier)
            .Create();

        await Assert.That(FindExtension(issued, Oids.SubjectKeyIdentifier).RawData)
            .IsEquivalentTo(requested.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task UseCertificateSigningRequest_WithAccept_ASubjectKeyIdentifierNotMatchingTheCertifiedKey_IsIssuedAsAsked()
    {
        //A label need not be derived from the key at all, since that section allows "other methods of
        //generating unique numbers" besides the two it describes. Nothing here can tell a conforming label
        //from a careless one, so whether to honour this one is the CA's policy and belongs to the predicate.
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var unrelatedKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var requested = new X509SubjectKeyIdentifierExtension(new PublicKey(unrelatedKeys), false);
        var csr = LoadWithExtensions(new CertificateBuilder()
            .SetSubject("CN=Unrelated Ski")
            .SetKeyPair(requesterKeys)
            .AddExtension(requested)
            .CreateCertificateSigningRequest());

        using var ca = BuildCa();
        using var issued = new CertificateBuilder()
            .SetIssuer(ca)
            .UseCertificateSigningRequest(csr, x => x.Oid?.Value == Oids.SubjectKeyIdentifier)
            .Create();

        await Assert.That(CountExtensions(issued, Oids.SubjectKeyIdentifier)).IsEqualTo(1);
        await Assert.That(FindExtension(issued, Oids.SubjectKeyIdentifier).RawData)
            .IsEquivalentTo(requested.RawData, CollectionOrdering.Matching);
    }


    //RFC 5280 s4.2.1.2 method (2), over the same BIT STRING subjectPublicKey contents method (1) hashes
    private static byte[] TruncatedKeyIdentifier(PublicKey publicKey)
    {
        var identifier = SHA1.HashData(publicKey.EncodedKeyValue.RawData)[^8..];
        identifier[0] = (byte)(0x40 | (identifier[0] & 0x0F));
        return identifier;
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
        //GetKeyEnciphermentIfSupported reads the public key's algorithm OID: the bit is emitted for an RSA key
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

        //Everything except the request's cA=TRUE basic constraints, which contradicts the Server profile and
        //is refused outright rather than issued
        using var issuedFirst = template.UseCertificateSigningRequest(first, x => x.Oid?.Value != Oids.BasicConstraints2).Create();
        using var issuedSecond = template.UseCertificateSigningRequest(second).Create();

        await Assert.That(ReadDnsNames(issuedFirst)).IsEquivalentTo([RequestedDnsName]);

        //None of the first requester's extensions reached the second certificate. Its basic constraints are
        //not worth asserting on: the predicate above never accepts that OID, so the Server profile's own
        //cA=FALSE stands whether anything leaks or not.
        await Assert.That(issuedSecond.Extensions.Any(x => x.Oid?.Value == Oids.SubjectAltName)).IsFalse();
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
        var request = new CertificateRequest(MultiValuedSubject(), keys, HashAlgorithmName.SHA256);
        var csr = CertificateSigningRequest.FromDer(request.CreateSigningRequest());

        await Assert.That(() => new CertificateBuilder().UseCertificateSigningRequest(csr))
            .Throws<InvalidOperationException>();
    }


    /// <summary>
    /// Encodes "CN=Multi Valued+OU=Sales, O=Acme" as DER: two relative distinguished names, the second of
    /// which holds two attributes.
    /// </summary>
    /// <remarks>
    /// Only Windows honours the '+' multi-value separator in the string constructor of
    /// <see cref="X500DistinguishedName"/>. Elsewhere "Multi Valued+OU=Sales" parses as one common name
    /// value, so a string here would build a single-valued name and silently test nothing.
    /// </remarks>
    private static X500DistinguishedName MultiValuedSubject()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            using (writer.PushSetOf()) {
                WriteAttribute(Oids.Organization, "Acme");
            }
            using (writer.PushSetOf()) {
                WriteAttribute(Oids.CommonName, "Multi Valued");
                WriteAttribute(Oids.OrganizationalUnit, "Sales");
            }
        }
        return new X500DistinguishedName(writer.Encode());

        void WriteAttribute(string oid, string value)
        {
            using (writer.PushSequence()) {
                writer.WriteObjectIdentifier(oid);
                writer.WriteCharacterString(UniversalTagNumber.PrintableString, value);
            }
        }
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


    //RFC 5280 s4.2.1.2 requires a CA certificate to carry a Subject Key Identifier and CertificateBuilder
    //always writes one, so one lacking it has to be built through CertificateRequest directly.
    private static X509Certificate2 BuildCaWithoutSubjectKeyIdentifier()
    {
        using var keys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=CA Without A Ski", keys, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(2));
    }


    //Every CA these tests build carries a Subject Key Identifier, so the keyIdentifier-only form is available
    private static X509AuthorityKeyIdentifierExtension KeyIdentifierAkiFor(X509Certificate2 ca)
        => X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, includeKeyIdentifier: true, includeIssuerAndSerial: false);


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


    private static X509BasicConstraintsExtension BasicConstraintsOf(X509Certificate2 cert)
        => cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();


    private static string SubjectKeyIdentifierOf(X509Certificate2 cert)
        => cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single().SubjectKeyIdentifier!;


    private static string DerivedKeyIdentifier(PublicKey publicKey)
        => new X509SubjectKeyIdentifierExtension(publicKey, false).SubjectKeyIdentifier!;
}
