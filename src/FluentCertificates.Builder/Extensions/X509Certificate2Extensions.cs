﻿using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace FluentCertificates.Extensions
{
    public static class X509Certificate2Extensions
    {
        public static X509Chain BuildChain(this X509Certificate2 cert, IEnumerable<X509Certificate2>? extraCerts = null, bool customRootTrust = false)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            #if NET5_0_OR_GREATER
            chain.ChainPolicy.TrustMode = customRootTrust ? X509ChainTrustMode.CustomRootTrust : X509ChainTrustMode.System;
            #endif

            if (extraCerts != null) {
                if (!customRootTrust) {
                    chain.ChainPolicy.ExtraStore.AddRange(extraCerts.ToArray());
                } else {
                    var certLookup = extraCerts.ToLookup(
                        c => c.SubjectName.RawData.SequenceEqual(c.IssuerName.RawData)
                            && c.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority)
                    );
                    #if NET5_0_OR_GREATER
                    chain.ChainPolicy.CustomTrustStore.AddRange(certLookup[true].ToArray());
                    #endif
                    chain.ChainPolicy.ExtraStore.AddRange(certLookup[false].ToArray());
                }
            }

            chain.Build(cert);
            return chain;
        }


        public static X509Certificate2 ExportAsCert(this X509Certificate2 cert, string path)
        {
            File.WriteAllBytes(path, cert.Export(X509ContentType.Cert));
            return cert;
        }


        public static X509Certificate2 ExportAsPkcs12(this X509Certificate2 cert, string path, string? password = null, ExportKeys include = ExportKeys.All)
        {
            var data = FilterPrivateKey(cert, include).Export(X509ContentType.Pfx, password)
                ?? throw new ArgumentException("Nothing to export", nameof(cert));

            File.WriteAllBytes(path, data);
            return cert;
        }


        public static X509Certificate2 ExportAsPkcs12(this X509Certificate2 cert, string path, SecureString password, ExportKeys include = ExportKeys.All)
        {
            var data = FilterPrivateKey(cert, include).Export(X509ContentType.Pfx, password)
                ?? throw new ArgumentException("Nothing to export", nameof(cert));

            File.WriteAllBytes(path, data);
            return cert;
        }


        public static X509Certificate2 ExportAsPkcs7(this X509Certificate2 cert, string path)
        {
            var data = new X509Certificate2Collection(cert).Export(X509ContentType.Pkcs7)
                ?? throw new ArgumentException("Nothing to export", nameof(cert));

            File.WriteAllBytes(path, data);
            return cert;
        }


        public static X509Certificate2 ExportAsPem(this X509Certificate2 cert, string path, ExportKeys include = ExportKeys.All)
        {
            File.WriteAllText(path, cert.ToPemString(include));
            return cert;
        }


        public static string ToPemString(this X509Certificate2 cert, ExportKeys include = ExportKeys.All)
        {
            using var sw = new StringWriter();
            var pem = new PemWriter(sw);
            var bcCert = DotNetUtilities.FromX509Certificate(cert);
            pem.WriteObject(bcCert);
            if (include != ExportKeys.None && cert.HasPrivateKey) {
                pem.WriteObject(cert.GetBouncyCastleRsaKeyPair().Private);
            }
            return sw.ToString();
        }


        public static string ToBase64String(this X509Certificate2 cert)
            => Convert.ToBase64String(cert.Export(X509ContentType.Cert));


        public static AsymmetricAlgorithm? GetPrivateKey(this X509Certificate2 cert)
            => cert.PublicKey.Oid.Value switch {
                "1.2.840.113549.1.1.1" => cert.GetRSAPrivateKey(),
                "1.2.840.10040.4.1" => cert.GetDSAPrivateKey(),
                "1.2.840.10045.2.1" => cert.GetECDsaPrivateKey(),
                _ => throw new NotSupportedException($"Unsupported public-key OID {cert.PublicKey.Oid.Value}")
            };


        public static bool IsValidNow(this X509Certificate2 cert)
            => cert.IsValid(DateTime.UtcNow);


        public static bool IsValid(this X509Certificate2 cert, DateTime atTime)
            => cert.NotBefore.ToUniversalTime() <= atTime && atTime <= cert.NotAfter.ToUniversalTime();


        public static bool IsSelfSigned(this X509Certificate2 cert)
            => cert.IsIssuedBy(cert);


        public static bool IsIssuedBy(this X509Certificate2 cert, X509Certificate2 issuer)
            => AreByteSpansEqual(cert.IssuerName.RawData, issuer.SubjectName.RawData);
               

        public static bool VerifyIssuer(this X509Certificate2 cert, X509Certificate2 issuer)
            => cert.IsIssuedBy(issuer) && VerifyIssuerSignature(cert, issuer);


        private static bool VerifyIssuerSignature(X509Certificate2 cert, X509Certificate2 issuer)
        {
            var thisCert = DotNetUtilities.FromX509Certificate(cert);
            var issuerCert = DotNetUtilities.FromX509Certificate(issuer);

            var tbsCert = thisCert.GetTbsCertificate();
            var sig = thisCert.GetSignature();

            var signer = SignerUtilities.GetSigner(thisCert.SigAlgName);
            signer.Init(false, issuerCert.GetPublicKey());
            signer.BlockUpdate(tbsCert, 0, tbsCert.Length);
            return signer.VerifySignature(sig);
        }


        internal static AsymmetricCipherKeyPair GetBouncyCastleRsaKeyPair(this X509Certificate2 cert)
        {
            using var source = cert.GetRSAPrivateKey() ?? throw new KeyException("RSA private key expected but not found");
            using var rsa = RSA.Create();
            var pbeParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1);
            Span<byte> pwd = stackalloc byte[32];
            Tools.SecureRandom.NextBytes(pwd);
            rsa.ImportEncryptedPkcs8PrivateKey(pwd, source.ExportEncryptedPkcs8PrivateKey(pwd, pbeParams), out _);
            pwd.Clear();
            return DotNetUtilities.GetRsaKeyPair(rsa);
        }


        private static bool AreByteSpansEqual(Span<byte> first, Span<byte> second)
            => first.SequenceEqual(second);


        private static X509Certificate2 FilterPrivateKey(X509Certificate2 cert, ExportKeys include)
            => include switch {
                ExportKeys.All => cert,
                ExportKeys.Leaf => cert,
                ExportKeys.None => cert.HasPrivateKey ? new X509Certificate2(cert.RawData, "", X509KeyStorageFlags.Exportable) : cert,
                _ => throw new ArgumentOutOfRangeException(nameof(include))
            };
    }
}