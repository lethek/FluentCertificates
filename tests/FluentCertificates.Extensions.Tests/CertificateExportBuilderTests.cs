using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class CertificateExportBuilderTests
{
    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pkcs12_RoundTrip(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var bytes = cert.Export().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        await Assert.That(loaded.Thumbprint).IsEqualTo(cert.Thumbprint);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pkcs12_WithPrivateKey_IncludesKey(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        await Assert.That(cert.HasPrivateKey).IsTrue();

        var bytes = cert.Export().WithPrivateKey().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        await Assert.That(loaded.HasPrivateKey).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pkcs12_WithoutPrivateKeys_StripsKey(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        await Assert.That(cert.HasPrivateKey).IsTrue();

        var bytes = cert.Export().WithoutPrivateKeys().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        await Assert.That(loaded.HasPrivateKey).IsFalse();
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pem_ToPemString_ContainsCertBlock(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var result = cert.Export().WithoutPrivateKeys().AsPem().ToPemString();

        await Assert.That(result).Contains("-----BEGIN CERTIFICATE-----");
        await Assert.That(result).Contains("-----END CERTIFICATE-----");
        await Assert.That(result).DoesNotContain("PRIVATE KEY");

        using var parsed = X509Certificate2.CreateFromPem(result);
        await Assert.That(parsed.RawData).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
        await Assert.That(parsed.HasPrivateKey).IsFalse();
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pem_WithPrivateKey_ContainsKeyAndCertBlocks(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var result = cert.Export().WithPrivateKey().AsPem().ToPemString();

        await Assert.That(
                result.Contains("-----BEGIN PRIVATE KEY-----") || result.Contains("-----BEGIN EC PRIVATE KEY-----"))
            .IsTrue()
            .Because("a PRIVATE KEY block is expected in the PEM output");
        await Assert.That(result).Contains("-----BEGIN CERTIFICATE-----");

        using var parsed = X509Certificate2.CreateFromPem(result, result);
        await Assert.That(parsed.RawData).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
        await Assert.That(parsed.Thumbprint).IsEqualTo(cert.Thumbprint);
        await Assert.That(parsed.HasPrivateKey).IsTrue();
        await Assert.That(SignedByPrivateKeyVerifiesAgainst(parsed, cert, algorithm))
            .IsTrue()
            .Because("the exported private key must pair with the exported certificate's public key");
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Cert_ToByteArray_MatchesRawData(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var result = cert.Export().AsCert().ToByteArray();
        await Assert.That(result).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Pkcs7_ToByteArray_RoundTrips(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var bytes = cert.Export().AsPkcs7().ToByteArray();

        var coll = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        coll.Import(bytes);
#pragma warning restore SYSLIB0057
        await Assert.That(coll).HasSingleItem();
        await Assert.That(coll[0].Thumbprint).IsEqualTo(cert.Thumbprint);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Chain_Pkcs12_ContainsAllCerts(KeyAlgorithm algorithm)
    {
        using var rootCert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetUsage(CertificateUsage.CA)
            .Create();
        using var leafCert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetIssuer(rootCert)
            .Create();

        var certs = new[] { leafCert, rootCert };
        var bytes = certs.Export().AsPkcs12().ToByteArray();

        var loaded = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        loaded.Import(bytes);
#pragma warning restore SYSLIB0057

        var thumbprints = loaded.Cast<X509Certificate2>().Select(c => c.Thumbprint).ToHashSet();
        await Assert.That(thumbprints).Contains(leafCert.Thumbprint);
        await Assert.That(thumbprints).Contains(rootCert.Thumbprint);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_WithChain_DeduplicatesByThumbprint(KeyAlgorithm algorithm)
    {
        using var rootCert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetUsage(CertificateUsage.CA)
            .Create();
        using var leafCert = new CertificateBuilder()
            .SetKeyAlgorithm(algorithm)
            .SetIssuer(rootCert)
            .Create();

        // leafCert already in the initial list; WithChain adds leafCert again + rootCert
        var bytes = leafCert.Export()
            .WithChain([leafCert, rootCert])
            .AsPkcs12()
            .ToByteArray();

        var loaded = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        loaded.Import(bytes);
#pragma warning restore SYSLIB0057
        await Assert.That(loaded.Count).IsEqualTo(2);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_ToFile_WritesCorrectContent(KeyAlgorithm algorithm)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
        try {
            using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
            cert.Export().AsCert().ToFile(path);
            await Assert.That(File.ReadAllBytes(path)).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
        } finally {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_ToFile_ReturnsThis_EnablesChaining(KeyAlgorithm algorithm)
    {
        var path1 = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
        var path2 = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
        try {
            using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
            cert.Export().AsCert().ToFile(path1).ToFile(path2);
            await Assert.That(File.ReadAllBytes(path1)).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
            await Assert.That(File.ReadAllBytes(path2)).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
        } finally {
            if (File.Exists(path1)) File.Delete(path1);
            if (File.Exists(path2)) File.Delete(path2);
        }
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_ToStream_WritesBytes(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var ms = new MemoryStream();
        cert.Export().AsCert().ToStream(ms);
        await Assert.That(ms.ToArray()).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
    }

    [Test]
    [MethodDataSource(nameof(KeyAlgorithmsTestData))]
    public async Task ExportBuilder_Collection_EntryPoint_Works(KeyAlgorithm algorithm)
    {
        using var cert = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        using var cert2 = new CertificateBuilder().SetKeyAlgorithm(algorithm).Create();
        var coll = new X509Certificate2Collection(new[] { cert, cert2 });
        var pem = coll.Export().WithoutPrivateKeys().AsPem().ToPemString();

        var parsed = new X509Certificate2Collection();
        parsed.ImportFromPem(pem);
        try {
            //Two unrelated certificates are not a chain, so the supplied order is written through as-is
            await Assert.That(parsed.Count).IsEqualTo(2);
            await Assert.That(parsed[0].RawData).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
            await Assert.That(parsed[1].RawData).IsEquivalentTo(cert2.RawData, CollectionOrdering.Matching);
        } finally {
            foreach (var c in parsed) c.Dispose();
        }
    }


    private static bool SignedByPrivateKeyVerifiesAgainst(X509Certificate2 signer, X509Certificate2 verifier, KeyAlgorithm algorithm)
    {
        var data = "FluentCertificates"u8.ToArray();
        switch (algorithm) {
            case KeyAlgorithm.ECDsa: {
                using var priv = signer.GetECDsaPrivateKey()!;
                using var pub = verifier.GetECDsaPublicKey()!;
                return pub.VerifyData(data, priv.SignData(data, HashAlgorithmName.SHA256), HashAlgorithmName.SHA256);
            }
            case KeyAlgorithm.RSA: {
                using var priv = signer.GetRSAPrivateKey()!;
                using var pub = verifier.GetRSAPublicKey()!;
                var sig = priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return pub.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null);
        }
    }


    public static IEnumerable<KeyAlgorithm> KeyAlgorithmsTestData()
    {
        yield return KeyAlgorithm.ECDsa;
        yield return KeyAlgorithm.RSA;
    }


    [Test]
    [Arguments(ExportKeys.All)]
    [Arguments(ExportKeys.Primary)]
    [Arguments(ExportKeys.None)]
    public async Task Export_LeavesTheCallersCertificatesUsable(ExportKeys keys)
    {
        using var rootCa = new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetSubject("CN=Export Owner Root")
            .SetNotAfter(DateTimeOffset.UtcNow.AddDays(1))
            .Create();

        using var leaf = new CertificateBuilder()
            .SetSubject("CN=Export Owner Leaf")
            .SetIssuer(rootCa)
            .Create();

        //Anchored, so ExportKeys.Primary has a certificate to designate. A bare collection would not.
        CertificateExportBuilder Export() => leaf.Export().WithChain([rootCa]).WithKeys(keys);

        //Stripping keys creates certificates the exporter disposes; these two are not among them
        var pem = Export().AsPem().ToPemString();
        var pkcs12 = Export().AsPkcs12().ToByteArray();

        await Assert.That(pem).IsNotEmpty();
        await Assert.That(pkcs12).IsNotEmpty();

        await Assert.That(rootCa.HasPrivateKey).IsTrue();
        await Assert.That(leaf.HasPrivateKey).IsTrue();
        await Assert.That(leaf.IsIssuedBy(rootCa, true)).IsTrue();

        using var rootKey = rootCa.GetPrivateKey();
        await Assert.That(rootKey.ExportSubjectPublicKeyInfo()).IsEquivalentTo(rootCa.PublicKey.ExportSubjectPublicKeyInfo());

        //Repeating the export must give the same bytes, not fail on a disposed certificate
        await Assert.That(Export().AsPem().ToPemString()).IsEqualTo(pem);
    }


    [Test]
    public async Task FilterPrivateKeys_RecordsOnlyTheCertificatesItCreates()
    {
        using var withKey = new CertificateBuilder().SetSubject("CN=Has Key").Create();
        using var withoutKey = CertTools.LoadCertificate(withKey.RawData);

        var created = new List<X509Certificate2>();
        var result = new[] { withKey, withoutKey }.FilterPrivateKeys(ExportKeys.None, created).ToList();

        //The keyed certificate is replaced and recorded; the keyless one is passed straight through
        await Assert.That(created.Count).IsEqualTo(1);
        await Assert.That(ReferenceEquals(result[0], withKey)).IsFalse();
        await Assert.That(ReferenceEquals(result[0], created[0])).IsTrue();
        await Assert.That(ReferenceEquals(result[1], withoutKey)).IsTrue();
        await Assert.That(result[0].HasPrivateKey).IsFalse();
    }


    [Test]
    public async Task ExportBuilder_Pem_SecureStringPassword_EncryptsThePrivateKey()
    {
        using var cert = new CertificateBuilder().SetSubject("CN=Secure PEM").Create();
        using var password = SecurePassword("hunter2");

        var pem = cert.Export().WithPrivateKey().WithPassword(password).AsPem().ToPemString();

        await Assert.That(pem).Contains("BEGIN ENCRYPTED PRIVATE KEY");
        await Assert.That(pem).DoesNotContain("BEGIN PRIVATE KEY");

        //The encrypted block must actually open with that password
        using var reloaded = RSA.Create();
        reloaded.ImportFromEncryptedPem(pem, "hunter2");
        await Assert.That(reloaded.ExportSubjectPublicKeyInfo()).IsEquivalentTo(cert.PublicKey.ExportSubjectPublicKeyInfo());
    }


    [Test]
    public async Task ExportBuilder_Pem_SecureStringPasswordReplacesAnEarlierPlainText()
    {
        using var cert = new CertificateBuilder().SetSubject("CN=Secure Over Plain").Create();
        using var password = SecurePassword("secure-one");

        var pem = cert.Export().WithPrivateKey().WithPassword("plain-one").WithPassword(password).AsPem().ToPemString();

        using var reloaded = RSA.Create();
        reloaded.ImportFromEncryptedPem(pem, "secure-one");
        await Assert.That(reloaded.ExportSubjectPublicKeyInfo()).IsEquivalentTo(cert.PublicKey.ExportSubjectPublicKeyInfo());
    }


    [Test]
    public async Task ExportBuilder_Pem_PlainTextPasswordReplacesAnEarlierSecureString()
    {
        using var cert = new CertificateBuilder().SetSubject("CN=Plain Over Secure").Create();
        using var password = SecurePassword("secure-one");

        var pem = cert.Export().WithPrivateKey().WithPassword(password).WithPassword("plain-one").AsPem().ToPemString();

        using var reloaded = RSA.Create();
        reloaded.ImportFromEncryptedPem(pem, "plain-one");
        await Assert.That(reloaded.ExportSubjectPublicKeyInfo()).IsEquivalentTo(cert.PublicKey.ExportSubjectPublicKeyInfo());
    }


    [Test]
    public async Task ExportBuilder_Pem_SecureStringPasswordClearsTheEarlierPlainText()
    {
        using var cert = new CertificateBuilder().SetSubject("CN=Secure Clears Plain").Create();
        using var password = SecurePassword("secure-one");

        var builder = cert.Export().WithPrivateKey().WithPassword("plain-one").WithPassword(password);

        //Dropping the SecureString must not resurrect the plain-text password it replaced
        var pem = (builder with { SecurePassword = null }).AsPem().ToPemString();

        await Assert.That(pem).Contains("BEGIN PRIVATE KEY");
        await Assert.That(pem).DoesNotContain("BEGIN ENCRYPTED PRIVATE KEY");
        await Assert.That(builder.Password).IsNull();
    }


    [Test]
    public async Task ExportBuilder_Pem_WithoutPassword_ClearsASecureStringPassword()
    {
        using var cert = new CertificateBuilder().SetSubject("CN=Clear Secure Password").Create();
        using var password = SecurePassword("secure-one");

        var pem = cert.Export().WithPrivateKey().WithPassword(password).WithoutPassword().AsPem().ToPemString();

        await Assert.That(pem).Contains("BEGIN PRIVATE KEY");
        await Assert.That(pem).DoesNotContain("BEGIN ENCRYPTED PRIVATE KEY");
    }


    [Test]
    public async Task ExportBuilder_Pem_WithoutPassword_ClearsAPlainTextPassword()
    {
        using var cert = new CertificateBuilder().SetSubject("CN=Clear Plain Password").Create();

        var pem = cert.Export().WithPrivateKey().WithPassword("plain-one").WithoutPassword().AsPem().ToPemString();

        await Assert.That(pem).Contains("BEGIN PRIVATE KEY");
        await Assert.That(pem).DoesNotContain("BEGIN ENCRYPTED PRIVATE KEY");
    }


    [Test]
    public async Task ExportBuilder_Pem_WithChain_WritesCertificatesLeafFirst()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Order Root").Create();
        using var intermediate = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Order Intermediate").SetIssuer(root).Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Order Leaf").SetIssuer(intermediate).Create();

        var pem = leaf.Export().WithChain([root, intermediate]).WithoutPrivateKeys().AsPem().ToPemString();

        await Assert.That(ParseCertificateSubjects(pem))
            .IsEquivalentTo(new[] { leaf.Subject, intermediate.Subject, root.Subject }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_Pem_ChainSeededBuilder_WritesTheSameOrderAsALeafSeededOne()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Route Root").Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Route Leaf").SetIssuer(root).Create();

        var (_, chain) = leaf.BuildChain([root], true);
        using (chain) {
            var viaLeaf = leaf.Export().WithChain(chain).WithoutPrivateKeys().AsPem().ToPemString();
            var viaChain = chain.Export().WithoutPrivateKeys().AsPem().ToPemString();
            await Assert.That(viaLeaf).IsEqualTo(viaChain);
        }
    }


    [Test]
    public async Task ExportBuilder_WithChain_WithPrivateKey_KeepsTheLeafsKeyNotTheIssuers()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Key Owner Root").Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Key Owner Leaf").SetIssuer(root).Create();

        var bytes = leaf.Export().WithChain([root]).WithPrivateKey().AsPkcs12().ToByteArray();

        var loaded = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        loaded.Import(bytes);
#pragma warning restore SYSLIB0057

        var withKeys = loaded.Cast<X509Certificate2>().Where(c => c.HasPrivateKey).Select(c => c.Subject).ToList();
        await Assert.That(withKeys).IsEquivalentTo(new[] { leaf.Subject }, CollectionOrdering.Any);
    }


    [Test]
    public async Task Export_UnrelatedCertificates_KeepsTheSuppliedOrder()
    {
        using var first = new CertificateBuilder().SetSubject("CN=Unrelated One").Create();
        using var second = new CertificateBuilder().SetSubject("CN=Unrelated Two").Create();

        var pem = new[] { first, second }.Export().WithoutPrivateKeys().AsPem().ToPemString();

        //Nothing to sort, so the list is left alone and ExportPem writes it in that order.
        await Assert.That(ParseCertificateSubjects(pem))
            .IsEquivalentTo(new[] { first.Subject, second.Subject }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_Cert_WithChain_ExportsTheLeaf()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Cert Chain Root").Create();
        using var intermediate = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Cert Chain Intermediate").SetIssuer(root).Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Cert Chain Leaf").SetIssuer(intermediate).Create();

        var bytes = leaf.Export().WithChain([root, intermediate]).AsCert().ToByteArray();

        await Assert.That(bytes).IsEquivalentTo(leaf.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_Cert_UnanchoredCollection_ThrowsEvenWhenItFormsAChain()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Cert Order Root").Create();
        using var intermediate = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Cert Order Intermediate").SetIssuer(root).Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Cert Order Leaf").SetIssuer(intermediate).Create();

        //These three do form a chain, but they arrived as a collection and a collection is a bundle.
        //Nothing declared a chain, so nothing designates a leaf, and AsCert() refuses to pick one.
        await Assert.That(() => new[] { intermediate, root, leaf }.Export().AsCert().ToByteArray())
            .ThrowsExactly<InvalidOperationException>();

        //Declaring the same certificates a chain is what makes the leaf knowable.
        var bytes = leaf.Export().WithChain([intermediate, root]).AsCert().ToByteArray();
        await Assert.That(bytes).IsEquivalentTo(leaf.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_Cert_FromX509Chain_ExportsTheLeaf()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Cert X509Chain Root").Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Cert X509Chain Leaf").SetIssuer(root).Create();

        var (_, chain) = leaf.BuildChain([root], true);
        using (chain) {
            var bytes = chain.Export().AsCert().ToByteArray();
            await Assert.That(bytes).IsEquivalentTo(leaf.RawData, CollectionOrdering.Matching);
        }
    }


    [Test]
    public async Task ExportBuilder_Cert_SingleCertificate_ExportsThatCertificate()
    {
        using var cert = new CertificateBuilder().SetSubject("CN=Cert Solo").Create();

        var bytes = cert.Export().AsCert().ToByteArray();

        await Assert.That(bytes).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_ECDiffieHellmanCertificate_ExportsItsPrivateKey()
    {
        using var issuer = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=ECDH Export CA").Create();
        using var cert = new CertificateBuilder()
            .SetUsage(CertificateUsage.SMime)
            .SetSubject("CN=ecdh-export@fake.domain")
            .SetKeyAlgorithm(KeyAlgorithm.ECDiffieHellman)
            .SetIssuer(issuer)
            .Create();

        //An ECDH and an ECDsa public key are indistinguishable in the certificate, so the export path has
        //only the OID to go on when it reaches for the private key.
        var pem = cert.Export().WithPrivateKey().AsPem().ToPemString();
        await Assert.That(pem).Contains("-----BEGIN PRIVATE KEY-----");

        var bytes = cert.Export().WithPrivateKey().AsPkcs12().ToByteArray();
        using var loaded = CertTools.LoadPkcs12(bytes, null);
        await Assert.That(loaded.HasPrivateKey).IsTrue();
    }


    [Test]
    public async Task ExportBuilder_Pkcs7_WithChain_WritesCertificatesLeafFirst()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=P7 Order Root").Create();
        using var intermediate = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=P7 Order Intermediate").SetIssuer(root).Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=P7 Order Leaf").SetIssuer(intermediate).Create();

        var bytes = leaf.Export().WithChain([root, intermediate]).AsPkcs7().ToByteArray();

        await Assert.That(LoadedSubjects(bytes))
            .IsEquivalentTo(new[] { leaf.Subject, intermediate.Subject, root.Subject }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_Pkcs12_WithChain_WritesCertificatesLeafFirst()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=P12 Order Root").Create();
        using var intermediate = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=P12 Order Intermediate").SetIssuer(root).Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=P12 Order Leaf").SetIssuer(intermediate).Create();

        var bytes = leaf.Export().WithChain([root, intermediate]).WithoutPrivateKeys().AsPkcs12().ToByteArray();

        await Assert.That(LoadedSubjects(bytes))
            .IsEquivalentTo(new[] { leaf.Subject, intermediate.Subject, root.Subject }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_Cert_AmbiguousSetFromSeededLeaf_ExportsTheSeededCertificate()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Anchor Root").Create();
        using var leafA = new CertificateBuilder().SetSubject("CN=Anchor Leaf A").SetIssuer(root).Create();
        using var leafB = new CertificateBuilder().SetSubject("CN=Anchor Leaf B").SetIssuer(root).Create();

        //Root plus two sibling leaves is not one chain, so the canonicaliser bails out and leaves the
        //list as supplied. The certificate the caller seeded the builder with is still at index 0.
        var bytes = leafA.Export().WithChain([root, leafB]).AsCert().ToByteArray();

        await Assert.That(bytes).IsEquivalentTo(leafA.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_Cert_WithChain_CannotRetargetTheAnchor()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Retarget Root").Create();
        using var intermediate = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Retarget Intermediate").SetIssuer(root).Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Retarget Leaf").SetIssuer(intermediate).Create();

        //These three do sort into one chain whose leaf is `leaf`, but the caller anchored on the
        //intermediate, so that is what gets exported. Position does not get a vote.
        var bytes = intermediate.Export().WithChain([root, leaf]).AsCert().ToByteArray();

        await Assert.That(bytes).IsEquivalentTo(intermediate.RawData, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_WithPrivateKey_WithChain_KeepsTheAnchorsKey()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Anchor Key Root").Create();
        using var intermediate = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Anchor Key Intermediate").SetIssuer(root).Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Anchor Key Leaf").SetIssuer(intermediate).Create();

        var bytes = intermediate.Export().WithChain([root, leaf]).WithPrivateKey().AsPkcs12().ToByteArray();

        var loaded = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        loaded.Import(bytes);
#pragma warning restore SYSLIB0057
        try {
            var withKeys = loaded.Cast<X509Certificate2>().Where(x => x.HasPrivateKey).Select(x => x.Subject).ToList();
            await Assert.That(withKeys).IsEquivalentTo(new[] { intermediate.Subject }, CollectionOrdering.Any);
        } finally {
            foreach (var cert in loaded) {
                cert.Dispose();
            }
        }
    }


    [Test]
    public async Task ExportBuilder_Cert_UnanchoredAmbiguousSet_Throws()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Unanchored Root").Create();
        using var leafA = new CertificateBuilder().SetSubject("CN=Unanchored Leaf A").SetIssuer(root).Create();
        using var leafB = new CertificateBuilder().SetSubject("CN=Unanchored Leaf B").SetIssuer(root).Create();

        //A bare collection names no leaf and two siblings make the chain ambiguous, so there is
        //nothing to export and guessing would be worse than failing.
        await Assert.That(() => new[] { root, leafA, leafB }.Export().AsCert().ToByteArray())
            .ThrowsExactly<InvalidOperationException>();
    }


    [Test]
    public async Task ExportBuilder_WithPrivateKey_UnanchoredAmbiguousSet_Throws()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Unanchored Key Root").Create();
        using var leafA = new CertificateBuilder().SetSubject("CN=Unanchored Key Leaf A").SetIssuer(root).Create();
        using var leafB = new CertificateBuilder().SetSubject("CN=Unanchored Key Leaf B").SetIssuer(root).Create();

        await Assert.That(() => new[] { root, leafA, leafB }.Export().WithPrivateKey().AsPem().ToPemString())
            .ThrowsExactly<InvalidOperationException>();
    }


    [Test]
    public async Task ExportBuilder_UnanchoredAmbiguousSet_ExportsFineWithoutALeafToFind()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Ambiguous All Root").Create();
        using var leafA = new CertificateBuilder().SetSubject("CN=Ambiguous All Leaf A").SetIssuer(root).Create();
        using var leafB = new CertificateBuilder().SetSubject("CN=Ambiguous All Leaf B").SetIssuer(root).Create();

        //Only ExportKeys.Primary and AsCert() need a designated certificate; the rest never ask.
        var certs = new[] { root, leafA, leafB };
        await Assert.That(certs.Export().WithPrivateKeys().AsPem().ToPemString()).IsNotEmpty();
        await Assert.That(certs.Export().WithoutPrivateKeys().AsPkcs12().ToByteArray()).IsNotEmpty();
        await Assert.That(certs.Export().AsPkcs7().ToByteArray()).IsNotEmpty();
    }


    [Test]
    public async Task ExportBuilder_AnchorDroppedFromTheCertificates_Throws()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Orphan Anchor Root").Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Orphan Anchor Leaf").SetIssuer(root).Create();
        using var stranger = new CertificateBuilder().SetSubject("CN=Orphan Anchor Stranger").Create();

        //Certificates is public and settable, so the anchor can be left dangling. An export that
        //targets a certificate it does not contain is rejected rather than silently emitting it.
        var orphaned = leaf.Export() with { Certificates = [root, stranger] };

        await Assert.That(() => orphaned.AsCert().ToByteArray()).ThrowsExactly<ArgumentException>();
        await Assert.That(() => orphaned.WithPrivateKeys().AsPem().ToPemString()).ThrowsExactly<ArgumentException>();
    }


    [Test]
    public async Task ExportBuilder_Pem_WithChain_SortsTheDeclaredChainWhateverOrderItArrivesIn()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Group Root").Create();
        using var mid = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Group Mid").SetIssuer(root).Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Group Leaf").SetIssuer(mid).Create();

        //Declared a chain, so the group is sorted leaf-first even though it arrived root-first.
        var pem = leaf.Export().WithChain([root, mid]).WithoutPrivateKeys().AsPem().ToPemString();

        await Assert.That(ParseCertificateSubjects(pem))
            .IsEquivalentTo(new[] { leaf.Subject, mid.Subject, root.Subject }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_Pem_SeveralChains_KeepsEachOrderedInCallOrder()
    {
        using var root1 = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Multi Root1").Create();
        using var mid1 = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Multi Mid1").SetIssuer(root1).Create();
        using var leaf1 = new CertificateBuilder().SetSubject("CN=Multi Leaf1").SetIssuer(mid1).Create();

        using var root2 = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Multi Root2").Create();
        using var mid2 = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Multi Mid2").SetIssuer(root2).Create();
        using var leaf2 = new CertificateBuilder().SetSubject("CN=Multi Leaf2").SetIssuer(mid2).Create();

        //Two independent chains in one bundle. Each WithChain call is sorted as a unit and appended as a
        //block, so the second chain comes out leaf-first despite being handed over root-first.
        var pem = leaf1.Export()
            .WithChain([mid1, root1])
            .WithChain([root2, mid2, leaf2])
            .WithoutPrivateKeys()
            .AsPem()
            .ToPemString();

        await Assert.That(ParseCertificateSubjects(pem))
            .IsEquivalentTo(
                new[] { leaf1.Subject, mid1.Subject, root1.Subject, leaf2.Subject, mid2.Subject, root2.Subject },
                CollectionOrdering.Matching);
    }


    [Test]
    public async Task ExportBuilder_Pem_Collection_IsNeverReorderedEvenWhenItFormsAChain()
    {
        using var root = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Bundle Root").Create();
        using var mid = new CertificateBuilder().SetUsage(CertificateUsage.CA).SetSubject("CN=Bundle Mid").SetIssuer(root).Create();
        using var leaf = new CertificateBuilder().SetSubject("CN=Bundle Leaf").SetIssuer(mid).Create();

        //A collection is a bundle. It is written exactly as supplied, chain or not.
        var pem = new[] { root, mid, leaf }.Export().WithoutPrivateKeys().AsPem().ToPemString();

        await Assert.That(ParseCertificateSubjects(pem))
            .IsEquivalentTo(new[] { root.Subject, mid.Subject, leaf.Subject }, CollectionOrdering.Matching);
    }


    private static List<string> LoadedSubjects(byte[] bytes)
    {
        var loaded = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        loaded.Import(bytes);
#pragma warning restore SYSLIB0057
        try {
            return loaded.Cast<X509Certificate2>().Select(x => x.Subject).ToList();
        } finally {
            foreach (var cert in loaded) {
                cert.Dispose();
            }
        }
    }


    private static List<string> ParseCertificateSubjects(string pem)
    {
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";

        var result = new List<string>();
        var index = 0;
        while (true) {
            var start = pem.IndexOf(begin, index, StringComparison.Ordinal);
            if (start < 0) {
                break;
            }
            var stop = pem.IndexOf(end, start, StringComparison.Ordinal) + end.Length;
            using var cert = X509Certificate2.CreateFromPem(pem.AsSpan(start, stop - start));
            result.Add(cert.Subject);
            index = stop;
        }
        return result;
    }


    private static SecureString SecurePassword(string value)
    {
        var result = new SecureString();
        foreach (var c in value) {
            result.AppendChar(c);
        }
        result.MakeReadOnly();
        return result;
    }
}
