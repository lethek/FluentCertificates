using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

using TUnit.Assertions.Enums;

using BcX509Crl =Org.BouncyCastle.X509.X509Crl;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;


namespace FluentCertificates;

public class X509CrlBuilderTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 3, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Next = Now.AddDays(7);


    private static X509Certificate2 CreateCa(string name = "CN=Test CA", CertificateUsage usage = CertificateUsage.CA)
        => new CertificateBuilder()
            .SetUsage(usage)
            .SetSubject(name)
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
            .SetValidity(TimeSpan.FromDays(30))
            .Create();


    private static X509CrlBuilder NewBuilder(X509Certificate2 issuer, long number = 1)
        => new X509CrlBuilder()
            .SetIssuer(issuer)
            .SetCrlNumber(number)
            .SetThisUpdate(Now)
            .SetNextUpdate(Next);


    private static RevokedCertificate Revoked(byte serial, X509RevocationReason? reason = null)
        => new(new byte[] { serial }, Now.AddHours(-1), reason);


    private static BcX509Crl ParseWithBouncyCastle(CertificateRevocationList crl)
        => new X509CrlParser().ReadCrl(crl.RawData.ToArray());


    private static bool HasBouncyCastleExtension(BcX509Crl crl, string oid)
        => crl.GetExtensionValue(new DerObjectIdentifier(oid)) != null;


    private static IssuingDistributionPoint GetIssuingDistributionPoint(BcX509Crl crl)
        => IssuingDistributionPoint.GetInstance(Asn1Object.FromByteArray(crl.GetExtensionValue(new DerObjectIdentifier(Oids.IssuingDistributionPoint)).GetOctets()));


    [Test]
    public async Task Create_FullCrl_CarriesWhatWasSetAndVerifiesAgainstTheIssuer()
    {
        using var ca = CreateCa();
        var revocationDate = Now.AddHours(-3);
        var invalidity = Now.AddDays(-2);

        var crl = NewBuilder(ca, 42)
            .AddRevokedCertificate(new RevokedCertificate(new byte[] { 0x01, 0x02 }, revocationDate, X509RevocationReason.KeyCompromise, invalidity))
            .AddRevokedCertificate(Revoked(0x7F))
            .Create();

        await Assert.That(crl.Issuer.RawData.AsSpan().SequenceEqual(ca.SubjectName.RawData)).IsTrue();
        await Assert.That(crl.CrlNumber).IsEqualTo((BigInteger?)42);
        await Assert.That(crl.ThisUpdate).IsEqualTo(Now);
        await Assert.That(crl.NextUpdate).IsEqualTo((DateTimeOffset?)Next);
        await Assert.That(crl.BaseCrlNumber).IsNull();
        await Assert.That(crl.DistributionPoint).IsNull();
        await Assert.That(crl.VerifySignature(ca)).IsTrue();

        var entries = crl.RevokedCertificates.ToList();
        await Assert.That(entries.Count).IsEqualTo(2);
        await Assert.That(Convert.ToHexString(entries[0].SerialNumber.Span)).IsEqualTo("0102");
        await Assert.That(entries[0].RevocationDate).IsEqualTo(revocationDate);
        await Assert.That(entries[0].Reason).IsEqualTo((X509RevocationReason?)X509RevocationReason.KeyCompromise);
        await Assert.That(entries[0].InvalidityDate).IsEqualTo((DateTimeOffset?)invalidity);
        await Assert.That(entries[1].Reason).IsNull();
    }


    [Test]
    public async Task Create_ParsesInDotNetsOwnLoaderAndInBouncyCastle()
    {
        using var ca = CreateCa();
        var crl = NewBuilder(ca)
            .AddRevokedCertificates(Revoked(1, X509RevocationReason.Superseded), Revoked(2))
            .Create();

        //.NET's loader keeps entries, and fails on a structure it cannot read
        var number = BigInteger.Zero;
        var bcl = CertificateRevocationListBuilder.Load(crl.RawData.ToArray(), out number);
        await Assert.That(number).IsEqualTo((BigInteger)1);
        await Assert.That(bcl.Build(ca, number + 1, Next, HashAlgorithmName.SHA256).Length).IsGreaterThan(0);

        var bc = ParseWithBouncyCastle(crl);
        await Assert.That(bc.GetRevokedCertificates().Count).IsEqualTo(2);
        bc.Verify(PublicKeyFactory.CreateKey(ca.PublicKey.ExportSubjectPublicKeyInfo()));
        await Assert.That(HasBouncyCastleExtension(bc, Oids.AuthorityKeyIdentifier)).IsTrue();
    }


    [Test]
    public async Task Create_WithCrlSigningIssuer_IsAccepted()
    {
        //.NET's own builder refuses this issuer, which is not a certificate authority
        using var signer = CreateCa("CN=CRL Signer", CertificateUsage.CrlSigning);

        var crl = NewBuilder(signer).AddRevokedCertificate(Revoked(9)).Create();

        await Assert.That(crl.VerifySignature(signer)).IsTrue();
    }


    [Test]
    public async Task Create_IssuerKeyUsageWithoutCrlSign_Throws()
    {
        using var client = new CertificateBuilder()
            .SetUsage(CertificateUsage.Client)
            .SetSubject("CN=Not a CRL signer")
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
            .SetValidity(TimeSpan.FromDays(1))
            .Create();

        await Assert.That(() => NewBuilder(client).Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_WithNameAndGenerator_WritesTheKeyIdentifierAndSigns()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = X509SignatureGenerator.CreateForECDsa(key);
        var keyId = new byte[] { 1, 2, 3, 4 };

        var crl = new X509CrlBuilder()
            .SetIssuer(new X500DistinguishedName("CN=HSM CA"), generator, keyId)
            .SetCrlNumber(5)
            .SetNextUpdate(DateTimeOffset.UtcNow.AddDays(1))
            .Create();

        var aki = AuthorityKeyIdentifier.GetInstance(Asn1Object.FromByteArray(
            ParseWithBouncyCastle(crl).GetExtensionValue(new DerObjectIdentifier(Oids.AuthorityKeyIdentifier)).GetOctets()));
        await Assert.That(aki.KeyIdentifier.GetOctets().AsSpan().SequenceEqual(keyId)).IsTrue();

        using var holder = new CertificateRequest("CN=HSM CA", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        await Assert.That(crl.VerifySignature(holder)).IsTrue();
    }


    [Test]
    public async Task SetIssuer_ACertificateAfterANameAndGenerator_SignsWithTheCertificatesKey()
    {
        using var ca = CreateCa();
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var crl = new X509CrlBuilder()
            .SetIssuer(new X500DistinguishedName("CN=Somebody Else"), X509SignatureGenerator.CreateForECDsa(otherKey))
            .SetIssuer(ca)
            .SetCrlNumber(1)
            .SetNextUpdate(Next)
            .Create();

        await Assert.That(crl.VerifySignature(ca)).IsTrue();
    }


    [Test]
    public async Task Create_WithoutAnIssuerNumberOrNextUpdate_Throws()
    {
        using var ca = CreateCa();

        await Assert.That(() => new X509CrlBuilder().SetCrlNumber(1).SetNextUpdate(Next).Create()).Throws<InvalidOperationException>();
        await Assert.That(() => new X509CrlBuilder().SetIssuer(ca).SetNextUpdate(Next).Create()).Throws<InvalidOperationException>();
        await Assert.That(() => new X509CrlBuilder().SetIssuer(ca).SetCrlNumber(1).Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_NextUpdateBeforeThisUpdate_Throws()
    {
        using var ca = CreateCa();

        await Assert.That(() => NewBuilder(ca).SetNextUpdate(Now.AddSeconds(-1)).Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task SetCrlNumber_Negative_Throws()
    {
        await Assert.That(() => new X509CrlBuilder().SetCrlNumber(-1)).Throws<ArgumentOutOfRangeException>();
    }


    [Test]
    public async Task Create_DatesFrom2050_AreWrittenAsGeneralizedTime()
    {
        using var ca = CreateCa();
        var far = new DateTimeOffset(2055, 1, 2, 3, 4, 5, TimeSpan.Zero);

        var crl = NewBuilder(ca).SetNextUpdate(far).AddRevokedCertificate(new RevokedCertificate(new byte[] { 1 }, far.AddDays(-1))).Create();

        await Assert.That(crl.NextUpdate).IsEqualTo((DateTimeOffset?)far);
        await Assert.That(crl.RevokedCertificates.Single().RevocationDate).IsEqualTo(far.AddDays(-1));
    }


    [Test]
    public async Task Create_DatesBefore1950_AreWrittenAsGeneralizedTime()
    {
        using var ca = CreateCa();
        var early = new DateTimeOffset(1940, 6, 7, 8, 9, 10, TimeSpan.Zero);

        var crl = NewBuilder(ca).SetThisUpdate(early).SetNextUpdate(Now)
            .AddRevokedCertificate(new RevokedCertificate(new byte[] { 1 }, early)).Create();

        await Assert.That(crl.ThisUpdate).IsEqualTo(early);
        await Assert.That(crl.RevokedCertificates.Single().RevocationDate).IsEqualTo(early);
    }


    [Test]
    [Arguments(CrlCoverage.AllCertificates, false, false)]
    [Arguments(CrlCoverage.EndEntityCertificates, true, false)]
    [Arguments(CrlCoverage.CACertificates, false, true)]
    public async Task SetDistributionPoint_WritesAnAddressAndCoverage(CrlCoverage covers, bool onlyUser, bool onlyCa)
    {
        using var ca = CreateCa();
        var point = new CrlDistributionPoint("http://crl.test/a.crl", "http://crl2.test/a.crl") { Covers = covers };

        var crl = NewBuilder(ca).SetDistributionPoint(point).Create();

        var bc = GetIssuingDistributionPoint(ParseWithBouncyCastle(crl));
        await Assert.That(bc.OnlyContainsUserCerts).IsEqualTo(onlyUser);
        await Assert.That(bc.OnlyContainsCACerts).IsEqualTo(onlyCa);
        await Assert.That(bc.IsIndirectCrl).IsFalse();
        await Assert.That(bc.DistributionPoint.ToString()).Contains("http://crl.test/a.crl");

        await Assert.That(crl.DistributionPoint!.Covers).IsEqualTo(covers);
        await Assert.That(crl.DistributionPoint.Uris).IsEquivalentTo(["http://crl.test/a.crl", "http://crl2.test/a.crl"]);
        await Assert.That(crl.Extensions.Select(x => x.Oid?.Value)).DoesNotContain(Oids.IssuingDistributionPoint);
    }


    [Test]
    public async Task SetDistributionPoint_IssuingDistributionPointIsCritical()
    {
        using var ca = CreateCa();

        var crl = NewBuilder(ca).SetDistributionPoint(new CrlDistributionPoint("http://crl.test/a.crl")).Create();

        var critical = ParseWithBouncyCastle(crl).GetCriticalExtensionOids().Select(x => x.ToString());
        await Assert.That(critical).Contains(Oids.IssuingDistributionPoint);
    }


    [Test]
    public async Task SetDistributionPoint_NonAsciiAddress_Throws()
    {
        await Assert.That(() => new X509CrlBuilder().SetDistributionPoint(new CrlDistributionPoint("http://crl.test/é.crl")))
            .Throws<ArgumentException>();
        await Assert.That(() => new X509CrlBuilder().SetDistributionPoint(new CrlDistributionPoint("http://crl.test/a.crl") { DeltaUris = ["é"] }))
            .Throws<ArgumentException>();
    }


    [Test]
    public async Task SetDistributionPoint_StatingNothing_Throws()
    {
        await Assert.That(() => new X509CrlBuilder().SetDistributionPoint(new CrlDistributionPoint())).Throws<ArgumentException>();

        //Narrowing the coverage, or naming a CRL issuer, is a statement
        var narrowed = new X509CrlBuilder().SetDistributionPoint(new CrlDistributionPoint { Covers = CrlCoverage.CACertificates });
        await Assert.That(narrowed.DistributionPoint).IsNotNull();
    }


    [Test]
    public async Task SetDistributionPoint_DeltaUris_AreAFreshestCrlOnAFullCrlAndNothingOnADelta()
    {
        using var ca = CreateCa();
        var point = new CrlDistributionPoint("http://crl.test/a.crl") { DeltaUris = ["http://crl.test/a-delta.crl"] };

        var full = NewBuilder(ca, 10).SetDistributionPoint(point).Create();
        var delta = NewBuilder(ca, 11).SetDistributionPoint(point).SetDeltaOf(full).Create();

        await Assert.That(HasBouncyCastleExtension(ParseWithBouncyCastle(full), Oids.FreshestCrl)).IsTrue();
        await Assert.That(full.DistributionPoint!.DeltaUris).IsEquivalentTo(["http://crl.test/a-delta.crl"]);
        await Assert.That(HasBouncyCastleExtension(ParseWithBouncyCastle(delta), Oids.FreshestCrl)).IsFalse();
        await Assert.That(delta.DistributionPoint!.DeltaUris).IsEmpty();
    }


    [Test]
    public async Task SetDeltaOf_WritesACriticalDeltaIndicatorNamingTheBase()
    {
        using var ca = CreateCa();

        var delta = NewBuilder(ca, 8).SetDeltaOf(7).Create();

        await Assert.That(delta.BaseCrlNumber).IsEqualTo((BigInteger?)7);
        await Assert.That(ParseWithBouncyCastle(delta).GetCriticalExtensionOids().Select(x => x.ToString())).Contains(Oids.DeltaCrlIndicator);
    }


    [Test]
    public async Task SetDeltaOf_NumberNotAboveTheBase_Throws()
    {
        using var ca = CreateCa();

        await Assert.That(() => NewBuilder(ca, 7).SetDeltaOf(7).Create()).Throws<InvalidOperationException>();
        await Assert.That(() => NewBuilder(ca, 6).SetDeltaOf(7).Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task SetDeltaOf_ADeltaCrl_Throws()
    {
        using var ca = CreateCa();
        var delta = NewBuilder(ca, 8).SetDeltaOf(7).Create();

        await Assert.That(() => new X509CrlBuilder().SetDeltaOf(delta)).Throws<ArgumentException>();
        await Assert.That(() => new X509CrlBuilder().SetDeltaOf(-1)).Throws<ArgumentOutOfRangeException>();
    }


    [Test]
    public async Task SetDeltaOf_ACrlOfADifferentScope_Throws()
    {
        using var ca = CreateCa();
        var full = NewBuilder(ca, 1).SetDistributionPoint(new CrlDistributionPoint("http://crl.test/ee.crl") { Covers = CrlCoverage.EndEntityCertificates }).Create();

        var other = new CrlDistributionPoint("http://crl.test/ca.crl") { Covers = CrlCoverage.CACertificates };
        await Assert.That(() => NewBuilder(ca, 2).SetDeltaOf(full).SetDistributionPoint(other).Create()).Throws<InvalidOperationException>();
        await Assert.That(() => NewBuilder(ca, 2).SetDeltaOf(full).Create()).Throws<InvalidOperationException>();

        var same = new CrlDistributionPoint("http://crl.test/ee.crl") { Covers = CrlCoverage.EndEntityCertificates };
        await Assert.That(NewBuilder(ca, 2).SetDeltaOf(full).SetDistributionPoint(same).Create().BaseCrlNumber).IsEqualTo((BigInteger?)1);
    }


    [Test]
    public async Task Create_RemoveFromCrl_IsRefusedInAFullCrlAndAllowedInADelta()
    {
        using var ca = CreateCa();
        var release = Revoked(3, X509RevocationReason.RemoveFromCrl);

        await Assert.That(() => NewBuilder(ca, 2).AddRevokedCertificate(release).Create()).Throws<InvalidOperationException>();
        await Assert.That(NewBuilder(ca, 2).SetDeltaOf(1).AddRevokedCertificate(release).Create().RevokedCertificates.Single().Reason)
            .IsEqualTo((X509RevocationReason?)X509RevocationReason.RemoveFromCrl);
    }


    [Test]
    public async Task Create_ExactRepeatOfAnEntry_IsWrittenOnce()
    {
        using var ca = CreateCa();

        var crl = NewBuilder(ca)
            .AddRevokedCertificates(Revoked(5, X509RevocationReason.KeyCompromise), Revoked(5, X509RevocationReason.KeyCompromise), Revoked(6))
            .Create();

        await Assert.That(crl.RevokedCertificates.Count()).IsEqualTo(2);
    }


    [Test]
    public async Task Create_SameSerialWithDifferentDetails_Throws()
    {
        using var ca = CreateCa();

        await Assert.That(() => NewBuilder(ca).AddRevokedCertificates(Revoked(5, X509RevocationReason.KeyCompromise), Revoked(5, X509RevocationReason.Superseded)).Create())
            .Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_SerialWithLeadingZero_IsTheSameCertificate()
    {
        using var ca = CreateCa();

        var crl = NewBuilder(ca)
            .AddRevokedCertificates(new RevokedCertificate(new byte[] { 0, 5 }, Now), new RevokedCertificate(new byte[] { 5 }, Now))
            .Create();

        await Assert.That(crl.RevokedCertificates.Count()).IsEqualTo(1);
    }


    [Test]
    public async Task Create_SerialWithHighBit_IsWrittenAsAPositiveInteger()
    {
        using var ca = CreateCa();

        var crl = NewBuilder(ca).AddRevokedCertificate(new RevokedCertificate(new byte[] { 0xFF, 0x01 }, Now)).Create();

        await Assert.That(Convert.ToHexString(crl.RevokedCertificates.Single().SerialNumber.Span)).IsEqualTo("FF01");
        await Assert.That(ParseWithBouncyCastle(crl).GetRevokedCertificates().Single().SerialNumber.IntValue).IsEqualTo(0xFF01);
    }


    [Test]
    public async Task AddRevokedCertificate_FromACertificate_UsesItsSerialAndIssuer()
    {
        using var ca = CreateCa();
        using var leaf = new CertificateBuilder().SetIssuer(ca).SetSubject("CN=leaf").SetKeyAlgorithm(KeyAlgorithm.ECDsa()).SetValidity(TimeSpan.FromDays(1)).Create();

        var crl = NewBuilder(ca).AddRevokedCertificate(RevokedCertificate.From(leaf, Now, X509RevocationReason.CessationOfOperation)).Create();

        var entry = crl.RevokedCertificates.Single();
        await Assert.That(entry.SerialNumber.Span.SequenceEqual(leaf.SerialNumberBytes.Span)).IsTrue();
        await Assert.That(entry.CertificateIssuer).IsNull();
    }


    [Test]
    public async Task Create_IndirectCrl_WritesCertificateIssuerOnlyWhereItChanges()
    {
        using var signer = CreateCa("CN=CRL Signer", CertificateUsage.CrlSigning);
        var caA = new X500DistinguishedName("CN=CA A");
        var caB = new X500DistinguishedName("CN=CA B");
        var point = new CrlDistributionPoint("http://crl.test/all.crl") { CrlIssuer = signer.SubjectName };

        var crl = NewBuilder(signer)
            .SetDistributionPoint(point)
            .AddRevokedCertificates(
                new RevokedCertificate(new byte[] { 1 }, Now, CertificateIssuer: caA),
                new RevokedCertificate(new byte[] { 2 }, Now, CertificateIssuer: caA),
                new RevokedCertificate(new byte[] { 3 }, Now, CertificateIssuer: caB),
                new RevokedCertificate(new byte[] { 1 }, Now, CertificateIssuer: caB),
                new RevokedCertificate(new byte[] { 4 }, Now))
            .Create();

        await Assert.That(GetIssuingDistributionPoint(ParseWithBouncyCastle(crl)).IsIndirectCrl).IsTrue();
        await Assert.That(crl.DistributionPoint!.CrlIssuer).IsNotNull();

        var entries = crl.RevokedCertificates.ToList();
        await Assert.That(entries.Select(x => x.CertificateIssuer!.Name)).IsEquivalentTo(["CN=CA A", "CN=CA A", "CN=CA B", "CN=CA B", "CN=CRL Signer"]);

        //Written where the issuer changes, the 1st, 3rd and 5th entries, and held in CertificateIssuer once read
        var oid = new byte[] { 0x06, 0x03, 0x55, 0x1D, 0x1D };
        var count = 0;
        for (var rest = crl.RawData.Span; rest.IndexOf(oid) is var at and >= 0; rest = rest[(at + oid.Length)..]) {
            count++;
        }
        await Assert.That(count).IsEqualTo(3);
        await Assert.That(entries.SelectMany(x => x.Extensions)).IsEmpty();
        await Assert.That(crl.VerifySignature(signer)).IsTrue();
    }


    [Test]
    public async Task Create_EntriesReadFromAnIndirectCrl_CanBeAddedToTheNextOne()
    {
        using var signer = CreateCa("CN=CRL Signer", CertificateUsage.CrlSigning);
        var point = new CrlDistributionPoint("http://crl.test/all.crl") { CrlIssuer = signer.SubjectName };
        var previous = NewBuilder(signer, 1)
            .SetDistributionPoint(point)
            .AddRevokedCertificates(
                new RevokedCertificate(new byte[] { 1 }, Now, CertificateIssuer: new X500DistinguishedName("CN=CA A")),
                new RevokedCertificate(new byte[] { 2 }, Now, CertificateIssuer: new X500DistinguishedName("CN=CA B")))
            .Create();

        var next = NewBuilder(signer, 2).SetDistributionPoint(point).AddRevokedCertificates(previous.RevokedCertificates).Create();

        await Assert.That(next.RevokedCertificates.Select(x => x.CertificateIssuer!.Name)).IsEquivalentTo(["CN=CA A", "CN=CA B"], CollectionOrdering.Matching);
    }


    [Test]
    public async Task Create_AnotherIssuersCertificateInANonIndirectCrl_Throws()
    {
        using var ca = CreateCa();

        await Assert.That(() => NewBuilder(ca)
            .AddRevokedCertificate(new RevokedCertificate(new byte[] { 1 }, Now, CertificateIssuer: new X500DistinguishedName("CN=Other CA")))
            .Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task Create_CrlIssuerThatIsNotTheSigner_Throws()
    {
        using var ca = CreateCa();
        var point = new CrlDistributionPoint("http://crl.test/a.crl") { CrlIssuer = new X500DistinguishedName("CN=Somebody Else") };

        await Assert.That(() => NewBuilder(ca).SetDistributionPoint(point).Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task AddExtension_OneTheBuilderWritesItself_Throws()
    {
        var number = new X509Extension(Oids.CrlNumber, new byte[] { 2, 1, 1 }, false);

        await Assert.That(() => new X509CrlBuilder().AddExtension(number)).Throws<ArgumentException>();
    }


    [Test]
    public async Task AddExtension_ACustomOne_IsWrittenAndReadBack()
    {
        using var ca = CreateCa();
        var custom = new X509Extension("1.2.3.4.5", new byte[] { 0x05, 0x00 }, false);

        var crl = NewBuilder(ca).AddExtension(custom).Create();

        var read = crl.Extensions.Single(x => x.Oid?.Value == "1.2.3.4.5");
        await Assert.That(read.Oid?.Value).IsEqualTo("1.2.3.4.5");
        await Assert.That(read.RawData).IsEquivalentTo(new byte[] { 0x05, 0x00 });
        await Assert.That(() => NewBuilder(ca).AddExtension(custom).AddExtension(custom)).Throws<ArgumentException>();
    }


    [Test]
    public async Task Create_EntryExtensions_AreWrittenAndReadBack()
    {
        using var ca = CreateCa();
        var custom = new X509Extension("1.2.3.4.6", new byte[] { 0x05, 0x00 }, false);

        var crl = NewBuilder(ca).AddRevokedCertificate(Revoked(1) with { Extensions = [custom] }).Create();

        await Assert.That(crl.RevokedCertificates.Single().Extensions.Single().Oid?.Value).IsEqualTo("1.2.3.4.6");
    }


    [Test]
    public async Task Create_EntryExtensionTheBuilderWritesItself_Throws()
    {
        using var ca = CreateCa();
        var reason = new X509Extension(Oids.CrlReasons, new byte[] { 0x0A, 0x01, 0x01 }, false);

        await Assert.That(() => NewBuilder(ca).AddRevokedCertificate(Revoked(1) with { Extensions = [reason] }).Create()).Throws<InvalidOperationException>();
    }


    [Test]
    public async Task SetCrlDistributionPoints_OnACertificate_WritesTheSameAddressesAsTheCrl()
    {
        using var ca = CreateCa();
        var point = new CrlDistributionPoint("http://crl.test/a.crl") { DeltaUris = ["http://crl.test/a-delta.crl"] };

        using var leaf = new CertificateBuilder()
            .SetIssuer(ca)
            .SetSubject("CN=leaf")
            .SetKeyAlgorithm(KeyAlgorithm.ECDsa())
            .SetValidity(TimeSpan.FromDays(1))
            .SetCrlDistributionPoints(point)
            .Create();

        var dps = CrlDistPoint.GetInstance(Asn1Object.FromByteArray(
            leaf.Extensions[Oids.CrlDistributionPoints]!.RawData)).GetDistributionPoints();
        await Assert.That(dps.Length).IsEqualTo(1);
        await Assert.That(dps[0].DistributionPointName.ToString()).Contains("http://crl.test/a.crl");

        var freshest = CrlDistPoint.GetInstance(Asn1Object.FromByteArray(leaf.Extensions[Oids.FreshestCrl]!.RawData)).GetDistributionPoints();
        await Assert.That(freshest[0].DistributionPointName.ToString()).Contains("http://crl.test/a-delta.crl");
    }


    [Test]
    public async Task SetCrlDistributionPoints_WithoutDeltaAddresses_RemovesAnEarlierFreshestCrl()
    {
        var builder = new CertificateBuilder()
            .SetCrlDistributionPoints(new CrlDistributionPoint("http://crl.test/a.crl") { DeltaUris = ["http://crl.test/a-delta.crl"] });
        await Assert.That(builder.Extensions.Any(x => x.Oid?.Value == Oids.FreshestCrl)).IsTrue();

        builder = builder.SetCrlDistributionPoints(new CrlDistributionPoint("http://crl.test/a.crl"));

        await Assert.That(builder.Extensions.Any(x => x.Oid?.Value == Oids.FreshestCrl)).IsFalse();
        await Assert.That(builder.Extensions.Any(x => x.Oid?.Value == Oids.CrlDistributionPoints)).IsTrue();
    }


    [Test]
    public async Task SetCrlDistributionPoints_WithCrlIssuer_WritesTheIssuerName()
    {
        using var ca = CreateCa();
        var point = new CrlDistributionPoint("http://crl.test/a.crl") { CrlIssuer = new X500DistinguishedName("CN=CRL Signer") };

        using var leaf = new CertificateBuilder().SetIssuer(ca).SetSubject("CN=leaf").SetKeyAlgorithm(KeyAlgorithm.ECDsa()).SetValidity(TimeSpan.FromDays(1))
            .SetCrlDistributionPoints(point).Create();

        var dp = CrlDistPoint.GetInstance(Asn1Object.FromByteArray(leaf.Extensions[Oids.CrlDistributionPoints]!.RawData)).GetDistributionPoints()[0];
        await Assert.That(dp.CrlIssuer.ToString()).Contains("CRL Signer");
    }


    [Test]
    public async Task SetCrlDistributionPoints_NoPointsOrAnEmptyPoint_Throws()
    {
        await Assert.That(() => new CertificateBuilder().SetCrlDistributionPoints(Array.Empty<CrlDistributionPoint>(), false)).Throws<ArgumentException>();
        await Assert.That(() => new CertificateBuilder().SetCrlDistributionPoints(new CrlDistributionPoint())).Throws<ArgumentException>();
    }
}
