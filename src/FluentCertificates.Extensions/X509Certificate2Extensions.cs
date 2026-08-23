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
    /// Starts a fluent <see cref="X509ChainBuilder"/> for building and verifying a certificate chain
    /// for this certificate. Configure with <see cref="X509ChainBuilder.TrustRoot"/>,
    /// <see cref="X509ChainBuilder.AddCertificates"/>, <see cref="X509ChainBuilder.AllowInvalidTime"/>
    /// and <see cref="X509ChainBuilder.WithPolicy"/>; terminate with
    /// <see cref="X509ChainBuilder.Create"/> to inspect the result or
    /// <see cref="X509ChainBuilder.Export"/> to export the verified chain in one step.
    /// </summary>
    /// <param name="cert">The certificate to build the chain for.</param>
    /// <returns>A new <see cref="X509ChainBuilder"/> for <paramref name="cert"/>.</returns>
    /// <remarks>No revocation checks are performed unless enabled via <see cref="X509ChainBuilder.WithPolicy"/>.</remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="cert"/> is <see langword="null"/>.</exception>
    public static X509ChainBuilder BuildChain(this X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        return new X509ChainBuilder(cert);
    }


    /// <summary>
    /// Gets the private key, whether it is a classical or a post-quantum one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every call returns a new instance, which the caller owns and should dispose. Disposing it does not
    /// affect <paramref name="cert"/> or any instance returned by another call, so the certificate remains
    /// usable and can be asked for its key again.
    /// </para>
    /// <para>
    /// The return type is <see cref="CertificateKey"/> rather than <see cref="AsymmetricAlgorithm"/> because
    /// .NET's post-quantum key types do not derive from the latter. Reach a classical key through
    /// <see cref="CertificateKey.AsAsymmetricAlgorithm"/>.
    /// </para>
    /// </remarks>
    /// <param name="cert">The certificate.</param>
    /// <returns>The private key. Dispose it when finished with it.</returns>
    /// <exception cref="NotSupportedException">Thrown if the key algorithm is not supported.</exception>
    /// <exception cref="CryptographicException">Thrown if the private key is not found.</exception>
    public static CertificateKey GetPrivateKey(this X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);

        var oid = cert.GetKeyAlgorithm();

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
#pragma warning disable FLUENTCERT001
        //A post-quantum OID names its parameter set exactly, so the family follows from the OID alone
        var pqc = KeyAlgorithm.PostQuantumAlgorithms.FirstOrDefault(x => x.Oid == oid);
        if (pqc != null) {
            return pqc.Family switch {
                KeyAlgorithmFamily.MLDsa => new CertificateKey(
                    cert.GetMLDsaPrivateKey() ?? throw new CryptographicException($"Private key not found for OID {oid}")
                ),
                KeyAlgorithmFamily.SlhDsa => new CertificateKey(
                    cert.GetSlhDsaPrivateKey() ?? throw new CryptographicException($"Private key not found for OID {oid}")
                ),
                KeyAlgorithmFamily.CompositeMLDsa => new CertificateKey(
                    cert.GetCompositeMLDsaPrivateKey() ?? throw new CryptographicException($"Private key not found for OID {oid}")
                ),
                KeyAlgorithmFamily.MLKem => new CertificateKey(
                    cert.GetMLKemPrivateKey() ?? throw new CryptographicException($"Private key not found for OID {oid}")
                ),
                _ => throw new NotSupportedException($"Unsupported key algorithm OID {oid}")
            };
        }
#pragma warning restore FLUENTCERT001
#pragma warning restore SYSLIB5006
#endif

        var key = (AsymmetricAlgorithm?)(oid switch {
            Oids.Rsa => cert.GetRSAPrivateKey(),
            Oids.Dsa => cert.GetDSAPrivateKey(),
            //An ECDH and an ECDsa key share this OID, so ask for both before giving up.
            Oids.EcPublicKey => (AsymmetricAlgorithm?)cert.GetECDsaPrivateKey() ?? cert.GetECDiffieHellmanPrivateKey(),
            _ => throw new NotSupportedException($"Unsupported key algorithm OID {oid}")
        }) ?? throw new CryptographicException($"Private key not found for OID {oid}");

        return new CertificateKey(key);
    }


    /// <summary>
    /// Reports whether the certificate's private key can actually be used for signing, as opposed to merely
    /// being associated with the certificate.
    /// </summary>
    /// <param name="cert">The certificate to test.</param>
    /// <returns><see langword="true"/> if a signing key was resolved; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="cert"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <see cref="X509Certificate2.HasPrivateKey"/> reports only that the certificate carries metadata naming
    /// a key, which outlives the key itself: a deleted container, an ACL that excludes the caller, or an
    /// absent smartcard, TPM or HSM all leave it reporting <see langword="true"/>. This resolves the key
    /// instead, so each of those reports <see langword="false"/> here. It reaches the key store, so narrow a
    /// query by subject or thumbprint first and apply this last.
    /// <para>
    /// Two things it deliberately does not do. It never exports, because a non-exportable key signs perfectly
    /// well through its handle. It never reads <c>KeyUsage</c>, because that records what the issuer
    /// authorised rather than what the key can do; in particular a key-agreement certificate reports
    /// <see langword="true"/> wherever the platform hands its EC key back as an <see cref="ECDsa"/>, which
    /// Windows does, and that key really does produce valid signatures.
    /// </para>
    /// <para>
    /// The key is opened but never used, so no hardware-backed key is prompted for a PIN. A key that opens
    /// but fails at first use is therefore the one case left uncaught.
    /// </para>
    /// </remarks>
    public static bool CanSign(this X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);

        //Cheap and reliable as a negative; it is only as a positive that HasPrivateKey misleads
        if (!cert.HasPrivateKey) {
            return false;
        }

        try {
            using var key = cert.GetPrivateKey();
            return key.CanSign;

        } catch (CryptographicException) {
            //The container is gone, its ACL excludes this user, or its token is absent
            return false;

        } catch (NotSupportedException) {
            //An unrecognised key algorithm, or a provider this platform cannot reach
            return false;
        }
    }


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
        switch (algorithm.Family) {
            #pragma warning disable CS0618 // Type or member is obsolete
            case KeyAlgorithmFamily.Dsa: {
                using var key = issuer.GetDSAPublicKey()!;
                return key.VerifyData(tbs, sig, algorithm.HashAlgorithm!.Value);
            }
            #pragma warning restore CS0618 // Type or member is obsolete
            case KeyAlgorithmFamily.Rsa: {
                using var key = issuer.GetRSAPublicKey()!;
                return key.VerifyData(tbs, sig, algorithm.HashAlgorithm!.Value, algorithm.RSASignaturePadding!);
            }
            case KeyAlgorithmFamily.ECDsa: {
                using var key = issuer.GetECDsaPublicKey()!;
                return key.VerifyData(tbs, sig, algorithm.HashAlgorithm!.Value, DSASignatureFormat.Rfc3279DerSequence);
            }
#if NET10_0_OR_GREATER
            //The post-quantum algorithms absorb the message directly, so there is no hash to pass and no
            //signature format to pick
            case KeyAlgorithmFamily.MLDsa: {
                #pragma warning disable SYSLIB5006
                using var key = issuer.GetMLDsaPublicKey()!;
                return key.VerifyData(tbs, sig);
                #pragma warning restore SYSLIB5006
            }
            case KeyAlgorithmFamily.SlhDsa: {
                #pragma warning disable SYSLIB5006
                using var key = issuer.GetSlhDsaPublicKey()!;
                return key.VerifyData(tbs, sig);
                #pragma warning restore SYSLIB5006
            }
            case KeyAlgorithmFamily.CompositeMLDsa: {
                #pragma warning disable SYSLIB5006
                using var key = issuer.GetCompositeMLDsaPublicKey()!;
                return key.VerifyData(tbs, sig);
                #pragma warning restore SYSLIB5006
            }
#endif
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
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing this certificate, anchored on it.</returns>
    /// <remarks>
    /// The certificate becomes the builder's <see cref="CertificateExportBuilder.Anchor"/>, so
    /// <see cref="ExportKeys.Primary"/> and <see cref="CertificateExportBuilder.AsCert"/> keep targeting it
    /// however many issuers are added afterwards.
    /// </remarks>
    public static CertificateExportBuilder Export(this X509Certificate2 cert)
        => new([cert], cert);
}