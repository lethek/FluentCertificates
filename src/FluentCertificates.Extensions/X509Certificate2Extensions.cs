using System.Formats.Asn1;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates
{
    public static class X509Certificate2Extensions
    {
        /// <summary>
        /// Builds an X.509 certificate chain with <paramref name="cert"/> as the leaf certificate.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="extraCerts">An additional collection of certificates that can be searched by the chaining engine when building and validating a certificate chain.</param>
        /// <param name="customRootTrust">When this value is <code>true</code>, the <see cref="P:System.Security.Cryptography.X509Certificates.X509ChainPolicy.CustomTrustStore" /> will be used instead of the default root trust. This parameter is ignored on .NET Standard.</param>
        /// <returns>An X509Chain instance.</returns>
        public static X509Chain BuildChain(this X509Certificate2 cert, IEnumerable<X509Certificate2>? extraCerts = null, bool customRootTrust = false)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = customRootTrust ? X509ChainTrustMode.CustomRootTrust : X509ChainTrustMode.System;

            if (extraCerts != null) {
                (customRootTrust ? chain.ChainPolicy.CustomTrustStore : chain.ChainPolicy.ExtraStore).AddRange(extraCerts.ToArray());
            }

            chain.Build(cert);
            return chain;
        }


        #region Export to a Writer

        public static X509Certificate2 ExportAsCert(this X509Certificate2 cert, BinaryWriter writer)
        {
            writer.Write(cert.Export(X509ContentType.Cert));
            return cert;
        }


        public static X509Certificate2 ExportAsPkcs7(this X509Certificate2 cert, BinaryWriter writer)
        {
            var data = new X509Certificate2Collection(cert).Export(X509ContentType.Pkcs7)
                       ?? throw new ArgumentException("Nothing to export", nameof(cert));

            writer.Write(data);
            return cert;
        }


        public static X509Certificate2 ExportAsPkcs12(this X509Certificate2 cert, BinaryWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
        {
            var data = FilterPrivateKey(cert, include).Export(X509ContentType.Pfx, password)
                       ?? throw new ArgumentException("Nothing to export", nameof(cert));

            writer.Write(data);
            return cert;
        }


        public static X509Certificate2 ExportAsPkcs12(this X509Certificate2 cert, BinaryWriter writer, SecureString password, ExportKeys include = ExportKeys.All)
        {
            var data = FilterPrivateKey(cert, include).Export(X509ContentType.Pfx, password)
                       ?? throw new ArgumentException("Nothing to export", nameof(cert));

            writer.Write(data);
            return cert;
        }


        public static X509Certificate2 ExportAsPem(this X509Certificate2 cert, TextWriter writer, string? password = null, ExportKeys include = ExportKeys.All)
        {
            writer.Write(cert.ToPemString(password, include));
            return cert;
        }

        #endregion


        #region Export to a File

        public static X509Certificate2 ExportAsCert(this X509Certificate2 cert, string path)
        {
            using var stream = File.OpenWrite(path);
            using var writer = new BinaryWriter(stream);
            return cert.ExportAsCert(writer);
        }


        public static X509Certificate2 ExportAsPkcs7(this X509Certificate2 cert, string path)
        {
            using var stream = File.OpenWrite(path);
            using var writer = new BinaryWriter(stream);
            return cert.ExportAsPkcs7(writer);
        }


        public static X509Certificate2 ExportAsPkcs12(this X509Certificate2 cert, string path, string? password = null, ExportKeys include = ExportKeys.All)
        {
            using var stream = File.OpenWrite(path);
            using var writer = new BinaryWriter(stream);
            return cert.ExportAsPkcs12(writer, password, include);
        }


        public static X509Certificate2 ExportAsPkcs12(this X509Certificate2 cert, string path, SecureString password, ExportKeys include = ExportKeys.All)
        {
            using var stream = File.OpenWrite(path);
            using var writer = new BinaryWriter(stream);
            return cert.ExportAsPkcs12(writer, password, include);
        }


        public static X509Certificate2 ExportAsPem(this X509Certificate2 cert, string path, string? password = null, ExportKeys include = ExportKeys.All)
        {
            using var stream = File.OpenWrite(path);
            using var writer = new StreamWriter(stream);
            return cert.ExportAsPem(writer, password, include);
        }

        #endregion


        public static string ToPemString(this X509Certificate2 cert, string? password = null, ExportKeys include = ExportKeys.All)
        {
            using var sw = new StringWriter();
            if (include != ExportKeys.None && cert.HasPrivateKey) {
                cert.GetPrivateKey().ExportAsPrivateKeyPem(sw, password);
                sw.Write('\n');
            }
            sw.Write(PemEncoding.Write("CERTIFICATE", cert.RawData));
            return sw.ToString();
        }


        public static string ToBase64String(this X509Certificate2 cert)
            => Convert.ToBase64String(cert.Export(X509ContentType.Cert));


        public static AsymmetricAlgorithm GetPrivateKey(this X509Certificate2 cert)
            => (AsymmetricAlgorithm?)(cert.GetKeyAlgorithm() switch {
                "1.2.840.113549.1.1.1" => cert.GetRSAPrivateKey(),
                "1.2.840.10040.4.1" => cert.GetDSAPrivateKey(),
                "1.2.840.10045.2.1" => cert.GetECDsaPrivateKey(),
                _ => throw new NotSupportedException($"Unsupported key algorithm OID {cert.GetKeyAlgorithm()}")
            }) ?? throw new Exception($"Private key not found for OID {cert.GetKeyAlgorithm()}");


        public static ReadOnlyMemory<byte> GetToBeSignedData(this X509Certificate2 cert)
        {
            var reader = new AsnReader(cert.RawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
            return reader.ReadEncodedValue();
        }


        public static ReadOnlyMemory<byte> GetSignatureData(this X509Certificate2 cert)
        {
            var reader = new AsnReader(cert.RawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
            reader.ReadSequence(Asn1Tag.Sequence);
            reader.ReadSequence(Asn1Tag.Sequence);
            return reader.ReadBitString(out _, Asn1Tag.PrimitiveBitString);
        }


        public static SignatureAlgorithm GetSignatureAlgorithm(this X509Certificate2 cert)
        {
            var reader = new AsnReader(cert.RawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
            reader.ReadSequence(Asn1Tag.Sequence); //Skip TBSCertificate
            var algIdentifier = reader.ReadSequence(Asn1Tag.Sequence);
            var algorithm = algIdentifier.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
            if (algorithm == Oids.RsaPss) {
                var hashAlgorithm = algIdentifier
                    .ReadSequence(Asn1Tag.Sequence)
                    .ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0))
                    .ReadSequence(Asn1Tag.Sequence)
                    .ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
                return SignatureAlgorithm.ForRsaSsaPss(algorithm, hashAlgorithm);
            }
            return SignatureAlgorithm.FromOidValue(algorithm);
        }


        public static bool IsValidNow(this X509Certificate2 cert)
            => cert.IsValid(DateTime.UtcNow);


        public static bool IsValid(this X509Certificate2 cert, DateTime atTime)
            => cert.NotBefore.ToUniversalTime() <= atTime && atTime <= cert.NotAfter.ToUniversalTime();


        public static bool IsSelfSigned(this X509Certificate2 cert, bool verifySignature = false)
            => cert.IsIssuedBy(cert, verifySignature);


        public static bool IsIssuedBy(this X509Certificate2 cert, X509Certificate2 issuer, bool verifySignature = false)
            => AreByteSpansEqual(cert.IssuerName.RawData, issuer.SubjectName.RawData) && (!verifySignature || VerifySignature(cert, issuer));


        private static bool VerifySignature(X509Certificate2 cert, X509Certificate2 issuer)
        {
            var algorithm = cert.GetSignatureAlgorithm();
            var tbs = cert.GetToBeSignedData().Span;
            var sig = cert.GetSignatureData().Span;

            return algorithm.KeyAlgorithm switch {
                KeyAlgorithm.DSA => issuer.GetDSAPublicKey()!.VerifyData(tbs, sig, algorithm.HashAlgorithm),
                KeyAlgorithm.RSA => issuer.GetRSAPublicKey()!.VerifyData(tbs, sig, algorithm.HashAlgorithm, algorithm.RSASignaturePadding!),
                KeyAlgorithm.ECDsa => issuer.GetECDsaPublicKey()!.VerifyData(tbs, sig, algorithm.HashAlgorithm, DSASignatureFormat.Rfc3279DerSequence),
                _ => false
            };
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
