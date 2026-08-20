using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// Provides extension methods for <see cref="X509Certificate2"/> to facilitate certificate chain building,
/// exporting in various formats, and certificate property inspection.
/// </summary>
public static class X509Certificate2Extensions
{
    /// <summary>
    /// Builds an <see cref="X509Chain"/> for the given certificate, optionally including extra certificates and custom root trust.
    /// </summary>
    /// <param name="cert">The certificate to build the chain for.</param>
    /// <param name="extraCerts">Optional additional certificates to include in the chain. If <paramref name="customRootTrust"/> is <c>true</c>, these extra certificates are automatically trusted within the returned <see cref="X509Chain"/>.</param>
    /// <param name="customRootTrust">If true, uses a custom root trust store in the returned chain; otherwise, uses the system trust store.</param>
    /// <returns>A tuple containing a boolean indicating if the chain is valid (<c>Verified</c>), and the built <see cref="X509Chain"/>.</returns>
    /// <remarks>No revocation checks are performed on the certificates.</remarks>
    public static (bool Verified, X509Chain Chain) BuildChain(this X509Certificate2 cert, IEnumerable<X509Certificate2>? extraCerts = null, bool customRootTrust = false)
        => cert.BuildChain(policy => {
            policy.TrustMode = customRootTrust ? X509ChainTrustMode.CustomRootTrust : X509ChainTrustMode.System;

            if (extraCerts != null) {
                (customRootTrust ? policy.CustomTrustStore : policy.ExtraStore).AddRange(extraCerts.ToArray());
            }
        });


    /// <summary>
    /// Builds an <see cref="X509Chain"/> for the given certificate, configuring the chain policy through
    /// <paramref name="configurePolicy"/> before the chain is built.
    /// </summary>
    /// <param name="cert">The certificate to build the chain for.</param>
    /// <param name="configurePolicy">
    /// An action which receives the <see cref="X509ChainPolicy"/> of the chain about to be built. Use it to set
    /// <see cref="X509ChainPolicy.TrustMode"/>, populate <see cref="X509ChainPolicy.CustomTrustStore"/> or
    /// <see cref="X509ChainPolicy.ExtraStore"/>, enable revocation checking, adjust
    /// <see cref="X509ChainPolicy.VerificationFlags"/>, and so on.
    /// </param>
    /// <returns>A tuple containing a boolean indicating if the chain is valid (<c>Verified</c>), and the built <see cref="X509Chain"/>.</returns>
    /// <remarks>
    /// The policy is pre-set to <see cref="X509RevocationMode.NoCheck"/> when <paramref name="configurePolicy"/> is
    /// invoked, matching the other <see cref="BuildChain(X509Certificate2,IEnumerable{X509Certificate2},bool)"/>
    /// overload rather than the framework's online default. Set
    /// <see cref="X509ChainPolicy.RevocationMode"/> within the action to perform revocation checks.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configurePolicy"/> is <see langword="null"/>.</exception>
    public static (bool Verified, X509Chain Chain) BuildChain(this X509Certificate2 cert, Action<X509ChainPolicy> configurePolicy)
    {
        ArgumentNullException.ThrowIfNull(configurePolicy);

        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        configurePolicy(chain.ChainPolicy);

        var result = chain.Build(cert);

        return (result, chain);
    }


    /// <summary>
    /// Gets the private key as an <see cref="AsymmetricAlgorithm"/> instance.
    /// </summary>
    /// <remarks>
    /// Every call returns a new instance, which the caller owns and should dispose. Disposing it does not
    /// affect <paramref name="cert"/> or any instance returned by another call, so the certificate remains
    /// usable and can be asked for its key again.
    /// </remarks>
    /// <param name="cert">The certificate.</param>
    /// <returns>The private key. Dispose it when finished with it.</returns>
    /// <exception cref="NotSupportedException">Thrown if the key algorithm is not supported.</exception>
    /// <exception cref="Exception">Thrown if the private key is not found.</exception>
    public static AsymmetricAlgorithm GetPrivateKey(this X509Certificate2 cert)
        => (AsymmetricAlgorithm?)(cert.GetKeyAlgorithm() switch {
            Oids.Rsa => cert.GetRSAPrivateKey(),
            Oids.Dsa => cert.GetDSAPrivateKey(),
            //An ECDH and an ECDsa key share this OID, so ask for both before giving up.
            Oids.EcPublicKey => (AsymmetricAlgorithm?)cert.GetECDsaPrivateKey() ?? cert.GetECDiffieHellmanPrivateKey(),
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

        //Each Get*PublicKey call returns a fresh instance that this method owns and must release
        switch (algorithm.KeyAlgorithm) {
            #pragma warning disable CS0618 // Type or member is obsolete
            case KeyAlgorithm.DSA: {
                using var key = issuer.GetDSAPublicKey()!;
                return key.VerifyData(tbs, sig, algorithm.HashAlgorithm);
            }
            #pragma warning restore CS0618 // Type or member is obsolete
            case KeyAlgorithm.RSA: {
                using var key = issuer.GetRSAPublicKey()!;
                return key.VerifyData(tbs, sig, algorithm.HashAlgorithm, algorithm.RSASignaturePadding!);
            }
            case KeyAlgorithm.ECDsa: {
                using var key = issuer.GetECDsaPublicKey()!;
                return key.VerifyData(tbs, sig, algorithm.HashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
            }
            default:
                return false;
        }
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
    /// Creates a <see cref="CertificateExportBuilder"/> initialised with this certificate.
    /// Chain configuration and format-selection methods on the returned builder allow you to
    /// build a fully configured export operation.
    /// </summary>
    /// <param name="cert">The certificate to export.</param>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing this certificate.</returns>
    public static CertificateExportBuilder Export(this X509Certificate2 cert)
        => new([cert]);
}