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
            //PEM output is leaf-first: the last certificate in the source collection is treated as the leaf
            await Assert.That(parsed.Count).IsEqualTo(2);
            await Assert.That(parsed[0].RawData).IsEquivalentTo(cert2.RawData, CollectionOrdering.Matching);
            await Assert.That(parsed[1].RawData).IsEquivalentTo(cert.RawData, CollectionOrdering.Matching);
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
    [Arguments(ExportKeys.Leaf)]
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

        var certs = new[] { rootCa, leaf };

        //Stripping keys creates certificates the exporter disposes; these two are not among them
        var pem = certs.Export().WithKeys(keys).AsPem().ToPemString();
        var pkcs12 = certs.Export().WithKeys(keys).AsPkcs12().ToByteArray();

        await Assert.That(pem).IsNotEmpty();
        await Assert.That(pkcs12).IsNotEmpty();

        await Assert.That(rootCa.HasPrivateKey).IsTrue();
        await Assert.That(leaf.HasPrivateKey).IsTrue();
        await Assert.That(leaf.IsIssuedBy(rootCa, true)).IsTrue();

        using var rootKey = rootCa.GetPrivateKey();
        await Assert.That(rootKey.ExportSubjectPublicKeyInfo()).IsEquivalentTo(rootCa.PublicKey.ExportSubjectPublicKeyInfo());

        //Repeating the export must give the same bytes, not fail on a disposed certificate
        await Assert.That(certs.Export().WithKeys(keys).AsPem().ToPemString()).IsEqualTo(pem);
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
    public async Task ExportBuilder_Pem_SecureStringPasswordTakesPrecedenceOverPlainText()
    {
        using var cert = new CertificateBuilder().SetSubject("CN=Secure PEM Precedence").Create();
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

        //Nothing to sort, so the list is left alone: ExportPem still writes it in reverse.
        await Assert.That(ParseCertificateSubjects(pem))
            .IsEquivalentTo(new[] { second.Subject, first.Subject }, CollectionOrdering.Matching);
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
