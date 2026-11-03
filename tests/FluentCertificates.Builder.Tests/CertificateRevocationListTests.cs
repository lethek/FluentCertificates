using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

public class CertificateRevocationListTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 3, 0, 0, 0, TimeSpan.Zero);


    private static X509Certificate2 CreateCa(KeyAlgorithm? algorithm = null)
        => new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Test CA")
            .SetKeyAlgorithm(algorithm ?? KeyAlgorithm.ECDsa())
            .SetValidity(TimeSpan.FromDays(30))
            .Create();


    private static CertificateRevocationList CreateCrl(X509Certificate2 ca)
        => new X509CrlBuilder()
            .SetIssuer(ca)
            .SetCrlNumber(3)
            .SetThisUpdate(Now)
            .SetNextUpdate(Now.AddDays(1))
            .AddRevokedCertificate(new RevokedCertificate(new byte[] { 9 }, Now, X509RevocationReason.Superseded))
            .Create();


    /// <summary>A CRL signed by <paramref name="key"/> whose CRL-wide extensions are exactly the ones given.</summary>
    private static byte[] BuildCrlWithExtensions(ECDsa key, params (string Oid, bool Critical, byte[] Value)[] extensions)
        => BuildCrl(key, null, extensions);


    /// <summary>As <see cref="BuildCrlWithExtensions"/>, with the encoded <c>revokedCertificates</c> SEQUENCE given.</summary>
    private static byte[] BuildCrl(ECDsa key, byte[]? revokedCertificates, (string Oid, bool Critical, byte[] Value)[] extensions, byte[]? algorithmIdentifier = null)
    {
        var generator = X509SignatureGenerator.CreateForECDsa(key);
        var algorithm = algorithmIdentifier ?? generator.GetSignatureAlgorithmIdentifier(HashAlgorithmName.SHA256);

        var tbs = new AsnWriter(AsnEncodingRules.DER);
        using (tbs.PushSequence()) {
            tbs.WriteInteger(1);
            tbs.WriteEncodedValue(algorithm);
            tbs.WriteEncodedValue(new X500DistinguishedName("CN=Hand Made").RawData);
            tbs.WriteUtcTime(Now);
            tbs.WriteUtcTime(Now.AddDays(1));
            if (revokedCertificates != null) {
                tbs.WriteEncodedValue(revokedCertificates);
            }
            using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            using (tbs.PushSequence()) {
                foreach (var (oid, critical, value) in extensions) {
                    using (tbs.PushSequence()) {
                        tbs.WriteObjectIdentifier(oid);
                        if (critical) {
                            tbs.WriteBoolean(true);
                        }
                        tbs.WriteOctetString(value);
                    }
                }
            }
        }

        var toBeSigned = tbs.Encode();
        var crl = new AsnWriter(AsnEncodingRules.DER);
        using (crl.PushSequence()) {
            crl.WriteEncodedValue(toBeSigned);
            crl.WriteEncodedValue(algorithm);
            crl.WriteBitString(generator.SignData(toBeSigned, HashAlgorithmName.SHA256));
        }
        return crl.Encode();
    }


    [Test]
    public async Task Load_ACrlFromDotNetsOwnBuilder_ReadsItsEntries()
    {
        using var ca = CreateCa();
        var builder = new CertificateRevocationListBuilder();
        builder.AddEntry(new byte[] { 0x0A, 0x0B }, Now, X509RevocationReason.CACompromise);
        var der = builder.Build(ca, 12, Now.AddDays(2), HashAlgorithmName.SHA256);

        var crl = CertificateRevocationList.Load(der);

        await Assert.That(crl.CrlNumber).IsEqualTo((BigInteger?)12);
        await Assert.That(crl.DistributionPoint).IsNull();
        await Assert.That(crl.VerifySignature(ca)).IsTrue();
        var entry = crl.RevokedCertificates.Single();
        await Assert.That(Convert.ToHexString(entry.SerialNumber.Span)).IsEqualTo("0A0B");
        await Assert.That(entry.Reason).IsEqualTo((X509RevocationReason?)X509RevocationReason.CACompromise);
    }


    [Test]
    public async Task Load_KeepsTheEncodingExactlyAsReceived()
    {
        using var ca = CreateCa();
        var der = CreateCrl(ca).RawData.ToArray();

        var crl = CertificateRevocationList.Load(der);

        await Assert.That(crl.RawData.ToArray()).IsEquivalentTo(der);
    }


    [Test]
    public async Task Load_BerWithAnIndefiniteOuterLength_StillVerifies()
    {
        using var ca = CreateCa();
        var der = CreateCrl(ca).RawData.Span;
        AsnDecoder.ReadEncodedValue(der, AsnEncodingRules.DER, out var contentOffset, out var contentLength, out _);

        //SEQUENCE, indefinite length, the same content, then the end-of-contents marker
        byte[] ber = [0x30, 0x80, .. der.Slice(contentOffset, contentLength), 0x00, 0x00];
        var crl = CertificateRevocationList.Load(ber);

        await Assert.That(crl.CrlNumber).IsEqualTo((BigInteger?)3);
        await Assert.That(crl.VerifySignature(ca)).IsTrue();
        await Assert.That(crl.RawData.ToArray()).IsEquivalentTo(ber);
    }


    [Test]
    public async Task Load_NotACrl_ThrowsCryptographicException()
    {
        using var ca = CreateCa();
        var truncated = CreateCrl(ca).RawData.Span[..40].ToArray();

        await Assert.That(() => CertificateRevocationList.Load([])).Throws<CryptographicException>();
        await Assert.That(() => CertificateRevocationList.Load([1, 2, 3])).Throws<CryptographicException>();
        await Assert.That(() => CertificateRevocationList.Load(truncated)).Throws<CryptographicException>();
        await Assert.That(() => CertificateRevocationList.Load(ca.RawData)).Throws<CryptographicException>();
    }


    [Test]
    public async Task Load_OuterAlgorithmDiffersFromTheSignedOne_ThrowsCryptographicException()
    {
        using var ca = CreateCa();
        using var key = ECDsa.Create();
        var sha384 = X509SignatureGenerator.CreateForECDsa(key).GetSignatureAlgorithmIdentifier(HashAlgorithmName.SHA384);

        var reader = new AsnReader(CreateCrl(ca).RawData, AsnEncodingRules.DER).ReadSequence();
        var tbs = reader.ReadEncodedValue();
        reader.ReadEncodedValue();
        var signature = reader.ReadBitString(out _);

        var rewritten = new AsnWriter(AsnEncodingRules.DER);
        using (rewritten.PushSequence()) {
            rewritten.WriteEncodedValue(tbs.Span);
            rewritten.WriteEncodedValue(sha384);
            rewritten.WriteBitString(signature);
        }

        await Assert.That(() => CertificateRevocationList.Load(rewritten.Encode())).Throws<CryptographicException>();
    }


    [Test]
    public async Task Load_TrailingBytes_ThrowsCryptographicException()
    {
        using var ca = CreateCa();
        byte[] padded = [.. CreateCrl(ca).RawData.Span, 0x00];

        await Assert.That(() => CertificateRevocationList.Load(padded)).Throws<CryptographicException>();
    }


    [Test]
    public async Task LoadPem_RoundTripsThroughToPemString()
    {
        using var ca = CreateCa();
        var crl = CreateCrl(ca);

        var pem = crl.ToPemString();
        var loaded = CertificateRevocationList.LoadPem(pem);

        await Assert.That(pem).StartsWith("-----BEGIN X509 CRL-----");
        await Assert.That(loaded.RawData.ToArray()).IsEquivalentTo(crl.RawData.ToArray());
    }


    [Test]
    public async Task LoadPem_SkipsBlocksOfOtherLabels()
    {
        using var ca = CreateCa();
        var crl = CreateCrl(ca);

        var loaded = CertificateRevocationList.LoadPem(ca.ExportCertificatePem() + "\n" + crl.ToPemString());

        await Assert.That(loaded.CrlNumber).IsEqualTo((BigInteger?)3);
    }


    [Test]
    public async Task LoadPem_NoCrlBlock_ThrowsCryptographicException()
    {
        using var ca = CreateCa();

        await Assert.That(() => CertificateRevocationList.LoadPem("")).Throws<CryptographicException>();
        await Assert.That(() => CertificateRevocationList.LoadPem(ca.ExportCertificatePem())).Throws<CryptographicException>();
        await Assert.That(() => CertificateRevocationList.LoadPem("-----BEGIN X509 CRL-----\n!!!\n-----END X509 CRL-----")).Throws<CryptographicException>();
    }


    [Test]
    public async Task LoadPem_Null_ThrowsArgumentNullException()
    {
        await Assert.That(() => CertificateRevocationList.LoadPem(null!)).Throws<ArgumentNullException>();
    }


    [Test]
    public async Task VerifySignature_AnotherIssuersCertificate_ReturnsFalse()
    {
        using var ca = CreateCa();
        using var other = CreateCa();
        using var rsa = CreateCa(KeyAlgorithm.RSA(2048));
        var crl = CreateCrl(ca);

        await Assert.That(crl.VerifySignature(ca)).IsTrue();
        await Assert.That(crl.VerifySignature(other)).IsFalse();
        //A key of another kind is a mismatch, not an error
        await Assert.That(crl.VerifySignature(rsa)).IsFalse();
    }


    [Test]
    [Arguments("SHA256")]
    [Arguments("SHA384")]
    [Arguments("SHA512")]
    public async Task VerifySignature_RsaPss_VerifiesTheCrlTheBuilderSigned(string hash)
    {
        using var ca = CreateCa(KeyAlgorithm.RSA(2048));
        using var other = CreateCa(KeyAlgorithm.RSA(2048));

        var crl = new X509CrlBuilder()
            .SetIssuer(ca)
            .SetRSASignaturePadding(RSASignaturePadding.Pss)
            .SetHashAlgorithm(new HashAlgorithmName(hash))
            .SetCrlNumber(1)
            .SetNextUpdate(Now.AddDays(1))
            .Create();

        await Assert.That(crl.VerifySignature(ca)).IsTrue();
        await Assert.That(crl.VerifySignature(other)).IsFalse();
    }


    [Test]
    public async Task VerifySignature_RsaPssWithAnEmptyParameterSequence_UsesTheDefaults()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = CreateCa(KeyAlgorithm.RSA(2048));

        //Every field of RSASSA-PSS-params has a default, so an empty SEQUENCE is the SHA-1 parameters
        var identifier = new AsnWriter(AsnEncodingRules.DER);
        using (identifier.PushSequence()) {
            identifier.WriteObjectIdentifier(Oids.RsaPss);
            using (identifier.PushSequence()) { }
        }
        var crl = CertificateRevocationList.Load(BuildCrl(key, null, [], identifier.Encode()));

        await Assert.That(crl.VerifySignature(rsa)).IsFalse();
    }


    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task VerifySignature_RsaPssWithAbsentOrNullParameters_ThrowsNotSupported(bool explicitNull)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = CreateCa(KeyAlgorithm.RSA(2048));

        //RFC 4055 s3.1: a signature's parameters MUST be present, as RSASSA-PSS-params
        var identifier = new AsnWriter(AsnEncodingRules.DER);
        using (identifier.PushSequence()) {
            identifier.WriteObjectIdentifier(Oids.RsaPss);
            if (explicitNull) {
                identifier.WriteNull();
            }
        }
        var crl = CertificateRevocationList.Load(BuildCrl(key, null, [], identifier.Encode()));

        await Assert.That(() => crl.VerifySignature(rsa)).Throws<NotSupportedException>();
    }


    [Test]
    [Arguments(0, 32, 1, "different salt length")]
    [Arguments(1, 20, 1, "salt shorter than the hash")]
    [Arguments(2, 32, 2, "trailer field other than 1")]
    [Arguments(3, 32, 1, "MGF1 over a different hash")]
    public async Task VerifySignature_RsaPssWithParametersDotNetCannotVerifyWith_ThrowsNotSupported(int variant, int salt, int trailer, string reason)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = CreateCa(KeyAlgorithm.RSA(2048));
        _ = reason;

        //SHA-256, MGF1 over SHA-256 unless the variant says otherwise, then the given salt length and trailer
        var maskHash = variant == 3 ? Oids.Sha1 : Oids.Sha256;
        var identifier = new AsnWriter(AsnEncodingRules.DER);
        using (identifier.PushSequence()) {
            identifier.WriteObjectIdentifier(Oids.RsaPss);
            using (identifier.PushSequence()) {
                using (identifier.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                using (identifier.PushSequence()) {
                    identifier.WriteObjectIdentifier(Oids.Sha256);
                }
                using (identifier.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
                using (identifier.PushSequence()) {
                    identifier.WriteObjectIdentifier(Oids.Mgf1);
                    using (identifier.PushSequence()) {
                        identifier.WriteObjectIdentifier(maskHash);
                    }
                }
                using (identifier.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2))) {
                    identifier.WriteInteger(variant == 0 ? 0 : salt);
                }
                using (identifier.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3))) {
                    identifier.WriteInteger(trailer);
                }
            }
        }
        var crl = CertificateRevocationList.Load(BuildCrl(key, null, [], identifier.Encode()));

        await Assert.That(() => crl.VerifySignature(rsa)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task VerifySignature_RsaPssWithAnUnknownHash_ThrowsNotSupported()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = CreateCa(KeyAlgorithm.RSA(2048));

        var identifier = new AsnWriter(AsnEncodingRules.DER);
        using (identifier.PushSequence()) {
            identifier.WriteObjectIdentifier(Oids.RsaPss);
            using (identifier.PushSequence())
            using (identifier.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            using (identifier.PushSequence()) {
                identifier.WriteObjectIdentifier("1.2.3.4.5");
            }
        }
        var crl = CertificateRevocationList.Load(BuildCrl(key, null, [], identifier.Encode()));

        await Assert.That(() => crl.VerifySignature(rsa)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task VerifySignature_RsaPssWithUnreadableParameters_ThrowsNotSupported()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = CreateCa(KeyAlgorithm.RSA(2048));

        var identifier = new AsnWriter(AsnEncodingRules.DER);
        using (identifier.PushSequence()) {
            identifier.WriteObjectIdentifier(Oids.RsaPss);
            identifier.WriteInteger(1);
        }
        var crl = CertificateRevocationList.Load(BuildCrl(key, null, [], identifier.Encode()));

        await Assert.That(() => crl.VerifySignature(rsa)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task VerifySignature_ATamperedCrl_ReturnsFalse()
    {
        using var ca = CreateCa();
        var der = CreateCrl(ca).RawData.ToArray();

        //Flip a bit in nextUpdate, the second UTCTime, which the signature covers
        var index = der.AsSpan().IndexOf(new byte[] { 0x17, 0x0D });
        index = der.AsSpan(index + 2).IndexOf(new byte[] { 0x17, 0x0D }) + index + 2;
        der[index + 5] ^= 0x01;
        var tampered = CertificateRevocationList.Load(der);

        await Assert.That(tampered.VerifySignature(ca)).IsFalse();
    }


    [Test]
    public async Task VerifySignature_Null_ThrowsArgumentNullException()
    {
        using var ca = CreateCa();

        await Assert.That(() => CreateCrl(ca).VerifySignature(null!)).Throws<ArgumentNullException>();
    }


    [Test]
    public async Task Load_AScopeItCannotExpress_LeavesDistributionPointNullAndKeepsTheExtension()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //IssuingDistributionPoint { onlySomeReasons [3] keyCompromise }
        var idp = new AsnWriter(AsnEncodingRules.DER);
        using (idp.PushSequence()) {
            idp.WriteBitString([0x40], 6, new Asn1Tag(TagClass.ContextSpecific, 3));
        }
        var der = BuildCrlWithExtensions(key, (Oids.IssuingDistributionPoint, true, idp.Encode()));

        var crl = CertificateRevocationList.Load(der);

        await Assert.That(crl.DistributionPoint).IsNull();
        await Assert.That(crl.Extensions.Single().Oid?.Value).IsEqualTo(Oids.IssuingDistributionPoint);
        await Assert.That(crl.Extensions.Single().Critical).IsTrue();
    }


    [Test]
    public async Task SetDeltaOf_ABaseWithAScopeItCannotExpress_Throws()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var idp = new AsnWriter(AsnEncodingRules.DER);
        using (idp.PushSequence()) {
            idp.WriteBitString([0x40], 6, new Asn1Tag(TagClass.ContextSpecific, 3));
        }
        var number = new AsnWriter(AsnEncodingRules.DER);
        number.WriteInteger(5);
        var baseCrl = CertificateRevocationList.Load(BuildCrlWithExtensions(key,
            (Oids.CrlNumber, false, number.Encode()),
            (Oids.IssuingDistributionPoint, true, idp.Encode())));

        await Assert.That(() => new X509CrlBuilder().SetDeltaOf(baseCrl)).Throws<ArgumentException>();
    }


    [Test]
    public async Task Load_AnIndirectScope_NamesTheCrlIssuerAsTheCrlIssuer()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //IssuingDistributionPoint { indirectCRL [4] TRUE }
        var idp = new AsnWriter(AsnEncodingRules.DER);
        using (idp.PushSequence()) {
            idp.WriteBoolean(true, new Asn1Tag(TagClass.ContextSpecific, 4));
        }
        var der = BuildCrlWithExtensions(key, (Oids.IssuingDistributionPoint, true, idp.Encode()));

        var crl = CertificateRevocationList.Load(der);

        await Assert.That(crl.DistributionPoint!.CrlIssuer!.Name).IsEqualTo("CN=Hand Made");
        await Assert.That(crl.DistributionPoint.Covers).IsEqualTo(CrlCoverage.AllCertificates);
        await Assert.That(crl.DistributionPoint.Uris).IsEmpty();
    }


    [Test]
    [Arguments(7)]
    [Arguments(11)]
    [Arguments(99)]
    public async Task Load_AReasonCodeOutsideTheKnownValues_StillLoadsTheCrl(int code)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var entries = new AsnWriter(AsnEncodingRules.DER);
        using (entries.PushSequence()) {
            foreach (var serial in new[] { 1, 2 }) {
                using (entries.PushSequence()) {
                    entries.WriteInteger(serial);
                    entries.WriteUtcTime(Now);
                    using (entries.PushSequence())
                    using (entries.PushSequence()) {
                        entries.WriteObjectIdentifier(Oids.CrlReasons);
                        entries.WriteOctetString(serial == 1 ? [0x0A, 0x01, (byte)code] : [0x0A, 0x01, 0x01]);
                    }
                }
            }
        }

        var crl = CertificateRevocationList.Load(BuildCrl(key, entries.Encode(), []));

        var read = crl.RevokedCertificates.ToList();
        await Assert.That(read.Count).IsEqualTo(2);
        await Assert.That(read[0].Reason).IsEqualTo((X509RevocationReason?)(X509RevocationReason)code);
        await Assert.That(read[1].Reason).IsEqualTo((X509RevocationReason?)X509RevocationReason.KeyCompromise);
    }


    [Test]
    public async Task Load_CertificateIssuerWithNoDirectoryName_ThrowsCryptographicException()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //GeneralNames holding only a uniformResourceIdentifier
        var names = new AsnWriter(AsnEncodingRules.DER);
        using (names.PushSequence()) {
            names.WriteCharacterString(UniversalTagNumber.IA5String, "http://a.test/", new Asn1Tag(TagClass.ContextSpecific, 6));
        }
        var entries = new AsnWriter(AsnEncodingRules.DER);
        using (entries.PushSequence())
        using (entries.PushSequence()) {
            entries.WriteInteger(1);
            entries.WriteUtcTime(Now);
            using (entries.PushSequence())
            using (entries.PushSequence()) {
                entries.WriteObjectIdentifier(Oids.CertificateIssuer);
                entries.WriteBoolean(true);
                entries.WriteOctetString(names.Encode());
            }
        }

        var der = BuildCrl(key, entries.Encode(), []);

        await Assert.That(() => CertificateRevocationList.Load(der)).Throws<CryptographicException>();
    }


    [Test]
    public async Task Load_CertificateIssuerOnACrlThatIsNotIndirect_ThrowsCryptographicException()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //GeneralNames holding a directoryName
        var names = new AsnWriter(AsnEncodingRules.DER);
        using (names.PushSequence())
        using (names.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4))) {
            names.WriteEncodedValue(new X500DistinguishedName("CN=Other CA").RawData);
        }
        var entries = new AsnWriter(AsnEncodingRules.DER);
        using (entries.PushSequence())
        using (entries.PushSequence()) {
            entries.WriteInteger(1);
            entries.WriteUtcTime(Now);
            using (entries.PushSequence())
            using (entries.PushSequence()) {
                entries.WriteObjectIdentifier(Oids.CertificateIssuer);
                entries.WriteBoolean(true);
                entries.WriteOctetString(names.Encode());
            }
        }

        //No Issuing Distribution Point, then one without the indirect flag
        var notIndirect = new AsnWriter(AsnEncodingRules.DER);
        using (notIndirect.PushSequence()) { }

        await Assert.That(() => CertificateRevocationList.Load(BuildCrl(key, entries.Encode(), []))).Throws<CryptographicException>();
        await Assert.That(() => CertificateRevocationList.Load(BuildCrl(key, entries.Encode(), [(Oids.IssuingDistributionPoint, true, notIndirect.Encode())])))
            .Throws<CryptographicException>();
    }


    [Test]
    public async Task Load_AnExtensionValueWithBytesAfterIt_ThrowsCryptographicException()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //INTEGER 3 followed by NULL
        var der = BuildCrlWithExtensions(key, (Oids.CrlNumber, false, [0x02, 0x01, 0x03, 0x05, 0x00]));

        await Assert.That(() => CertificateRevocationList.Load(der)).Throws<CryptographicException>();
    }


    [Test]
    public async Task Load_AnExtensionThatAppearsTwice_ThrowsCryptographicException()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //A scope that partitions by reason, then an empty one that would hide it
        var partitioned = new AsnWriter(AsnEncodingRules.DER);
        using (partitioned.PushSequence()) {
            partitioned.WriteBitString([0x40], 6, new Asn1Tag(TagClass.ContextSpecific, 3));
        }
        var empty = new AsnWriter(AsnEncodingRules.DER);
        using (empty.PushSequence()) { }

        var der = BuildCrlWithExtensions(key,
            (Oids.IssuingDistributionPoint, true, partitioned.Encode()),
            (Oids.IssuingDistributionPoint, true, empty.Encode()));

        await Assert.That(() => CertificateRevocationList.Load(der)).Throws<CryptographicException>();
    }


    [Test]
    public async Task Load_BothCoverageFlags_IsNotAScopeItExpresses()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var idp = new AsnWriter(AsnEncodingRules.DER);
        using (idp.PushSequence()) {
            idp.WriteBoolean(true, new Asn1Tag(TagClass.ContextSpecific, 1));
            idp.WriteBoolean(true, new Asn1Tag(TagClass.ContextSpecific, 2));
        }

        var crl = CertificateRevocationList.Load(BuildCrlWithExtensions(key, (Oids.IssuingDistributionPoint, true, idp.Encode())));

        await Assert.That(crl.DistributionPoint).IsNull();
        await Assert.That(crl.Extensions.Count).IsEqualTo(1);
    }


    [Test]
    public async Task Load_ACrlWithNoEntriesOrNumber_ReadsAsEmpty()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var crl = CertificateRevocationList.Load(BuildCrlWithExtensions(key));

        await Assert.That(crl.CrlNumber).IsNull();
        await Assert.That(crl.BaseCrlNumber).IsNull();
        await Assert.That(crl.RevokedCertificates).IsEmpty();
        await Assert.That(crl.Extensions).IsEmpty();
    }


    [Test]
    public async Task RevokedCertificates_AreReadOnceAtLoad()
    {
        using var ca = CreateCa();
        var crl = CreateCrl(ca);

        await Assert.That(crl.RevokedCertificates.Count).IsEqualTo(1);
        await Assert.That(ReferenceEquals(crl.RevokedCertificates[0], crl.RevokedCertificates[0])).IsTrue();
    }
}
