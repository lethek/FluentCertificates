using System.Formats.Asn1;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;


namespace FluentCertificates;

/// <summary>
/// Provides extension methods for <see cref="X509Certificate2"/> to facilitate certificate chain building,
/// exporting in various formats, and certificate property inspection.
/// </summary>
public static class X509Certificate2Extensions
{
    /// <summary>
    /// Verifies the certificate chain for the given certificate, optionally including extra certificates.
    /// </summary>
    /// <param name="cert">The certificate to verify.</param>
    /// <param name="extraCerts">Optional additional certificates to include in the chain and trust.</param>
    /// <returns><c>True</c> if the certificate chain is valid; otherwise, <c>False</c>.</returns>
    public static bool VerifyChain(this X509Certificate2 cert, IEnumerable<X509Certificate2>? extraCerts = null)
        => cert.BuildChain(extraCerts, true).Verified;


    /// <summary>
    /// Builds an <see cref="X509Chain"/> for the given certificate, optionally including extra certificates and custom root trust.
    /// </summary>
    /// <param name="cert">The certificate to build the chain for.</param>
    /// <param name="extraCerts">Optional additional certificates to include in the chain. If <paramref name="customRootTrust"/> is <c>true</c>, these extra certificates are automatically trusted within the returned <see cref="X509Chain"/>.</param>
    /// <param name="customRootTrust">If true, uses a custom root trust store in the returned chain; otherwise, uses the system trust store.</param>
    /// <returns>A tuple containing a boolean indicating if the chain is valid (<c>Verified</c>), and the built <see cref="X509Chain"/>.</returns>
    /// <remarks>No revocation checks are performed on the certificates.</remarks>
    public static (bool Verified, X509Chain Chain) BuildChain(this X509Certificate2 cert, IEnumerable<X509Certificate2>? extraCerts = null, bool customRootTrust = false)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = customRootTrust ? X509ChainTrustMode.CustomRootTrust : X509ChainTrustMode.System;

        if (extraCerts != null) {
            (customRootTrust ? chain.ChainPolicy.CustomTrustStore : chain.ChainPolicy.ExtraStore).AddRange(extraCerts.ToArray());
        }

        var result = chain.Build(cert);

        return (result, chain);
    }


    #region Export to a Writer

    #endregion


    #region Export to a File

    #endregion


    /// <summary>
    /// Gets the private key as an <see cref="AsymmetricAlgorithm"/> instance.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <returns>The private key.</returns>
    /// <exception cref="NotSupportedException">Thrown if the key algorithm is not supported.</exception>
    /// <exception cref="Exception">Thrown if the private key is not found.</exception>
    public static AsymmetricAlgorithm GetPrivateKey(this X509Certificate2 cert)
        => (AsymmetricAlgorithm?)(cert.GetKeyAlgorithm() switch {
            Oids.Rsa => cert.GetRSAPrivateKey(),
            Oids.Dsa => cert.GetDSAPrivateKey(),
            Oids.EcPublicKey => cert.GetECDsaPrivateKey(),
            _ => throw new NotSupportedException($"Unsupported key algorithm OID {cert.GetKeyAlgorithm()}")
        }) ?? throw new Exception($"Private key not found for OID {cert.GetKeyAlgorithm()}");


    /// <summary>
    /// Gets the "to be signed" (TBS) data from the certificate.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <returns>The TBS data as a <see cref="ReadOnlyMemory{Byte}"/>.</returns>
    public static ReadOnlyMemory<byte> GetToBeSignedData(this X509Certificate2 cert)
    {
        var reader = new AsnReader(cert.RawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
        return reader.ReadEncodedValue();
    }


    /// <summary>
    /// Gets the signature data from the certificate.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <returns>The signature data as a <see cref="ReadOnlyMemory{Byte}"/>.</returns>
    public static ReadOnlyMemory<byte> GetSignatureData(this X509Certificate2 cert)
    {
        var reader = new AsnReader(cert.RawData, AsnEncodingRules.DER).ReadSequence(Asn1Tag.Sequence);
        reader.ReadSequence(Asn1Tag.Sequence);
        reader.ReadSequence(Asn1Tag.Sequence);
        return reader.ReadBitString(out _, Asn1Tag.PrimitiveBitString);
    }


    /// <summary>
    /// Gets the signature algorithm used by the certificate.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <returns>The <see cref="SignatureAlgorithm"/> used.</returns>
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


    /// <summary>
    /// Determines if the certificate is currently valid (based on <see cref="DateTime.UtcNow"/>).
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <returns>True if valid now; otherwise, false.</returns>
    public static bool IsValidNow(this X509Certificate2 cert)
        => cert.IsValidAt(DateTimeOffset.UtcNow);


    /// <summary>
    /// Determines if the certificate is valid at a specific time. Both bounds are inclusive.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <param name="atTime">The instant to check validity for.</param>
    /// <returns>True if valid at the specified time; otherwise, false.</returns>
    public static bool IsValidAt(this X509Certificate2 cert, DateTimeOffset atTime)
        => cert.NotBefore.ToUniversalTime() <= atTime.UtcDateTime && atTime.UtcDateTime <= cert.NotAfter.ToUniversalTime();


    /// <summary>
    /// Determines if the certificate is valid at a specific time. Both bounds are inclusive.
    /// </summary>
    /// <remarks>
    /// Deprecated. A <see cref="DateTime"/> does not carry an offset, so the result depends on its
    /// <see cref="DateTimeKind"/>: <see cref="DateTimeKind.Unspecified"/> is treated as local time,
    /// following the behaviour of <see cref="DateTime.ToUniversalTime"/>. Use the
    /// <see cref="IsValidAt(X509Certificate2,DateTimeOffset)"/> overload, which is unambiguous.
    /// </remarks>
    /// <param name="cert">The certificate.</param>
    /// <param name="atTime">The time to check validity for.</param>
    /// <returns>True if valid at the specified time; otherwise, false.</returns>
    [Obsolete("Use the IsValidAt(DateTimeOffset) overload instead: a DateTime has no offset, so the result depends on its DateTimeKind.")]
    public static bool IsValidAt(this X509Certificate2 cert, DateTime atTime)
        => cert.IsValidAt(new DateTimeOffset(atTime.ToUniversalTime()));


    /// <summary>
    /// Determines if the certificate is self-signed.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <param name="verifySignature">Whether to verify the signature.</param>
    /// <returns>True if self-signed; otherwise, false.</returns>
    public static bool IsSelfSigned(this X509Certificate2 cert, bool verifySignature = false)
        => cert.IsIssuedBy(cert, verifySignature);


    /// <summary>
    /// Determines if the certificate was issued by the specified issuer.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <param name="issuer">The issuer certificate.</param>
    /// <param name="verifySignature">Whether to verify the signature.</param>
    /// <returns>True if issued by the specified issuer; otherwise, false.</returns>
    public static bool IsIssuedBy(this X509Certificate2 cert, X509Certificate2 issuer, bool verifySignature = false)
        => AreByteSpansEqual(cert.IssuerName.RawData, issuer.SubjectName.RawData) && (!verifySignature || VerifySignature(cert, issuer));


    /// <summary>
    /// Verifies the signature of a certificate using the issuer's public key.
    /// </summary>
    /// <param name="cert">The certificate to verify.</param>
    /// <param name="issuer">The issuer certificate.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    private static bool VerifySignature(X509Certificate2 cert, X509Certificate2 issuer)
    {
        var algorithm = cert.GetSignatureAlgorithm();
        var tbs = cert.GetToBeSignedData().Span;
        var sig = cert.GetSignatureData().Span;

        return algorithm.KeyAlgorithm switch {
            #pragma warning disable CS0618 // Type or member is obsolete
            KeyAlgorithm.DSA => issuer.GetDSAPublicKey()!.VerifyData(tbs, sig, algorithm.HashAlgorithm),
            #pragma warning restore CS0618 // Type or member is obsolete
            KeyAlgorithm.RSA => issuer.GetRSAPublicKey()!.VerifyData(tbs, sig, algorithm.HashAlgorithm, algorithm.RSASignaturePadding!),
            KeyAlgorithm.ECDsa => issuer.GetECDsaPublicKey()!.VerifyData(tbs, sig, algorithm.HashAlgorithm, DSASignatureFormat.Rfc3279DerSequence),
            _ => false
        };
    }


    /// <summary>
    /// Compares two byte spans for equality.
    /// </summary>
    /// <param name="first">The first span.</param>
    /// <param name="second">The second span.</param>
    /// <returns>True if equal; otherwise, false.</returns>
    private static bool AreByteSpansEqual(Span<byte> first, Span<byte> second)
        => first.SequenceEqual(second);


    
    /// <summary>
    /// Filters the private key from the certificate based on the <see cref="ExportKeys"/> option.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <param name="include">The export key option.</param>
    /// <returns>The filtered certificate.</returns>
    private static X509Certificate2 FilterPrivateKey(X509Certificate2 cert, ExportKeys include)
        => include switch {
            ExportKeys.All => cert,
            ExportKeys.Leaf => cert,
            ExportKeys.None => cert.HasPrivateKey ? CertTools.LoadCertificate(cert.RawDataMemory.Span) : cert,
            _ => throw new ArgumentOutOfRangeException(nameof(include))
        };


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with this certificate.
    /// Chain configuration and format-selection methods on the returned builder allow you to
    /// build a fully configured export operation.
    /// </summary>
    /// <param name="cert">The certificate to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing this certificate.</returns>
    public static CertificateExportBuilder Export(this X509Certificate2 cert)
        => new(new[] { cert });
}