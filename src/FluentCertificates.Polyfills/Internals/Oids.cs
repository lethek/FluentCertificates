using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace FluentCertificates.Internals;

internal static class Oids
{
    // Symmetric encryption algorithms
    internal const string Rc2Cbc = "1.2.840.113549.3.2";
    internal const string Rc4 = "1.2.840.113549.3.4";
    internal const string TripleDesCbc = "1.2.840.113549.3.7";
    internal const string DesCbc = "1.3.14.3.2.7";
    internal const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    internal const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
    internal const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";

    // Asymmetric encryption algorithms
    internal const string Dsa = "1.2.840.10040.4.1";
    internal const string Rsa = "1.2.840.113549.1.1.1";
    internal const string RsaOaep = "1.2.840.113549.1.1.7";
    internal const string RsaPss = "1.2.840.113549.1.1.10";
    internal const string RsaPkcs1Md5 = "1.2.840.113549.1.1.4";
    internal const string RsaPkcs1Sha1 = "1.2.840.113549.1.1.5";
    internal const string RsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
    internal const string RsaPkcs1Sha384 = "1.2.840.113549.1.1.12";
    internal const string RsaPkcs1Sha512 = "1.2.840.113549.1.1.13";
    internal const string Esdh = "1.2.840.113549.1.9.16.3.5";
    internal const string EcDiffieHellman = "1.3.132.1.12";
    internal const string DiffieHellman = "1.2.840.10046.2.1";
    internal const string DiffieHellmanPkcs3 = "1.2.840.113549.1.3.1";

    // Cryptographic Attribute Types
    internal const string SigningTime = "1.2.840.113549.1.9.5";
    internal const string ContentType = "1.2.840.113549.1.9.3";
    internal const string DocumentDescription = "1.3.6.1.4.1.311.88.2.2";
    internal const string MessageDigest = "1.2.840.113549.1.9.4";
    internal const string CounterSigner = "1.2.840.113549.1.9.6";
    internal const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    internal const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    internal const string DocumentName = "1.3.6.1.4.1.311.88.2.1";
    internal const string LocalKeyId = "1.2.840.113549.1.9.21";
    internal const string EnrollCertTypeExtension = "1.3.6.1.4.1.311.20.2";
    internal const string UserPrincipalName = "1.3.6.1.4.1.311.20.2.3";
    internal const string CertificateTemplate = "1.3.6.1.4.1.311.21.7";
    internal const string ApplicationCertPolicies = "1.3.6.1.4.1.311.21.10";
    internal const string AuthorityInformationAccess = "1.3.6.1.5.5.7.1.1";
    internal const string OcspEndpoint = "1.3.6.1.5.5.7.48.1";
    internal const string CertificateAuthorityIssuers = "1.3.6.1.5.5.7.48.2";
    internal const string Pkcs9ExtensionRequest = "1.2.840.113549.1.9.14";

    // Key wrap algorithms
    internal const string CmsRc2Wrap = "1.2.840.113549.1.9.16.3.7";
    internal const string Cms3DesWrap = "1.2.840.113549.1.9.16.3.6";

    // PKCS7 Content Types.
    internal const string Pkcs7Data = "1.2.840.113549.1.7.1";
    internal const string Pkcs7Signed = "1.2.840.113549.1.7.2";
    internal const string Pkcs7Enveloped = "1.2.840.113549.1.7.3";
    internal const string Pkcs7SignedEnveloped = "1.2.840.113549.1.7.4";
    internal const string Pkcs7Hashed = "1.2.840.113549.1.7.5";
    internal const string Pkcs7Encrypted = "1.2.840.113549.1.7.6";

    internal const string Md5 = "1.2.840.113549.2.5";
    internal const string Sha1 = "1.3.14.3.2.26";
    internal const string Sha256 = "2.16.840.1.101.3.4.2.1";
    internal const string Sha384 = "2.16.840.1.101.3.4.2.2";
    internal const string Sha512 = "2.16.840.1.101.3.4.2.3";

    // DSA CMS uses the combined signature+digest OID
    internal const string DsaWithSha1 = "1.2.840.10040.4.3";
    internal const string DsaWithSha256 = "2.16.840.1.101.3.4.3.2";
    internal const string DsaWithSha384 = "2.16.840.1.101.3.4.3.3";
    internal const string DsaWithSha512 = "2.16.840.1.101.3.4.3.4";

    // ECDSA CMS uses the combined signature+digest OID
    // https://tools.ietf.org/html/rfc5753#section-2.1.1
    internal const string EcPrimeField = "1.2.840.10045.1.1";
    internal const string EcChar2Field = "1.2.840.10045.1.2";
    internal const string EcChar2TrinomialBasis = "1.2.840.10045.1.2.3.2";
    internal const string EcChar2PentanomialBasis = "1.2.840.10045.1.2.3.3";
    internal const string EcPublicKey = "1.2.840.10045.2.1";
    internal const string ECDsaWithSha1 = "1.2.840.10045.4.1";
    internal const string ECDsaWithSha256 = "1.2.840.10045.4.3.2";
    internal const string ECDsaWithSha384 = "1.2.840.10045.4.3.3";
    internal const string ECDsaWithSha512 = "1.2.840.10045.4.3.4";

    internal const string Mgf1 = "1.2.840.113549.1.1.8";
    internal const string PSpecified = "1.2.840.113549.1.1.9";

    // PKCS#7
    internal const string NoSignature = "1.3.6.1.5.5.7.6.2";

    // X500 Names
    internal const string CommonName = "2.5.4.3";
    internal const string CountryOrRegionName = "2.5.4.6";
    internal const string LocalityName = "2.5.4.7";
    internal const string StateOrProvinceName = "2.5.4.8";
    internal const string Organization = "2.5.4.10";
    internal const string OrganizationalUnit = "2.5.4.11";
    internal const string EmailAddress = "1.2.840.113549.1.9.1";

    // Cert Extensions
    internal const string BasicConstraints = "2.5.29.10";
    internal const string SubjectKeyIdentifier = "2.5.29.14";
    internal const string KeyUsage = "2.5.29.15";
    internal const string SubjectAltName = "2.5.29.17";
    internal const string IssuerAltName = "2.5.29.18";
    internal const string BasicConstraints2 = "2.5.29.19";
    internal const string CrlNumber = "2.5.29.20";
    internal const string CrlReasons = "2.5.29.21";
    internal const string CrlDistributionPoints = "2.5.29.31";
    internal const string CertPolicies = "2.5.29.32";
    internal const string AnyCertPolicy = "2.5.29.32.0";
    internal const string CertPolicyMappings = "2.5.29.33";
    internal const string AuthorityKeyIdentifier = "2.5.29.35";
    internal const string CertPolicyConstraints = "2.5.29.36";
    internal const string EnhancedKeyUsage = "2.5.29.37";
    internal const string InhibitAnyPolicyExtension = "2.5.29.54";

    // RFC3161 Timestamping
    internal const string TstInfo = "1.2.840.113549.1.9.16.1.4";
    internal const string TimeStampingPurpose = "1.3.6.1.5.5.7.3.8";

    //public static readonly KeyPurposeID AnyExtendedKeyUsage = new KeyPurposeID(X509Extensions.ExtendedKeyUsage.Id + ".0");
    internal const string ServerAuthPurpose = "1.3.6.1.5.5.7.3.1";
    internal const string ClientAuthPurpose = "1.3.6.1.5.5.7.3.2";
    internal const string CodeSigningPurpose = "1.3.6.1.5.5.7.3.3";
    internal const string EmailProtectionPurpose = "1.3.6.1.5.5.7.3.4";
    internal const string IpsecEndSystemPurpose = "1.3.6.1.5.5.7.3.5";
    internal const string IpsecTunnelPurpose = "1.3.6.1.5.5.7.3.6";
    internal const string IpsecUserPurpose = "1.3.6.1.5.5.7.3.7";
    internal const string OcspSigningPurpose = "1.3.6.1.5.5.7.3.9";
    internal const string SmartCardLogonPurpose = "1.3.6.1.4.1.311.20.2.2";
    internal const string MacAddressPurpose = "1.3.6.1.1.1.1.22";
    internal const string LifetimeSigningPurpose = "1.3.6.1.4.1.311.10.3.13";


    // PKCS#12
    private const string Pkcs12Prefix = "1.2.840.113549.1.12.";
    private const string Pkcs12PbePrefix = Pkcs12Prefix + "1.";
    internal const string Pkcs12PbeWithShaAnd3Key3Des = Pkcs12PbePrefix + "3";
    internal const string Pkcs12PbeWithShaAnd2Key3Des = Pkcs12PbePrefix + "4";
    internal const string Pkcs12PbeWithShaAnd128BitRC2 = Pkcs12PbePrefix + "5";
    internal const string Pkcs12PbeWithShaAnd40BitRC2 = Pkcs12PbePrefix + "6";
    private const string Pkcs12BagTypesPrefix = Pkcs12Prefix + "10.1.";
    internal const string Pkcs12KeyBag = Pkcs12BagTypesPrefix + "1";
    internal const string Pkcs12ShroudedKeyBag = Pkcs12BagTypesPrefix + "2";
    internal const string Pkcs12CertBag = Pkcs12BagTypesPrefix + "3";
    internal const string Pkcs12CrlBag = Pkcs12BagTypesPrefix + "4";
    internal const string Pkcs12SecretBag = Pkcs12BagTypesPrefix + "5";
    internal const string Pkcs12SafeContentsBag = Pkcs12BagTypesPrefix + "6";
    internal const string Pkcs12X509CertBagType = "1.2.840.113549.1.9.22.1";
    internal const string Pkcs12SdsiCertBagType = "1.2.840.113549.1.9.22.2";

    // PKCS#5
    private const string Pkcs5Prefix = "1.2.840.113549.1.5.";
    internal const string PbeWithMD5AndDESCBC = Pkcs5Prefix + "3";
    internal const string PbeWithMD5AndRC2CBC = Pkcs5Prefix + "6";
    internal const string PbeWithSha1AndDESCBC = Pkcs5Prefix + "10";
    internal const string PbeWithSha1AndRC2CBC = Pkcs5Prefix + "11";
    internal const string Pbkdf2 = Pkcs5Prefix + "12";
    internal const string PasswordBasedEncryptionScheme2 = Pkcs5Prefix + "13";

    private const string RsaDsiDigestAlgorithmPrefix = "1.2.840.113549.2.";
    internal const string HmacWithSha1 = RsaDsiDigestAlgorithmPrefix + "7";
    internal const string HmacWithSha256 = RsaDsiDigestAlgorithmPrefix + "9";
    internal const string HmacWithSha384 = RsaDsiDigestAlgorithmPrefix + "10";
    internal const string HmacWithSha512 = RsaDsiDigestAlgorithmPrefix + "11";

    // Elliptic Curve curve identifiers
    internal const string secp256r1 = "1.2.840.10045.3.1.7";
    internal const string secp384r1 = "1.3.132.0.34";
    internal const string secp521r1 = "1.3.132.0.35";

    // LDAP
    internal const string DomainComponent = "0.9.2342.19200300.100.1.25";



    private static volatile Oid? s_rsaOid;
    private static volatile Oid? s_ecPublicKeyOid;
    private static volatile Oid? s_tripleDesCbcOid;
    private static volatile Oid? s_aes256CbcOid;
    private static volatile Oid? s_secp256R1Oid;
    private static volatile Oid? s_secp384R1Oid;
    private static volatile Oid? s_secp521R1Oid;
    private static volatile Oid? s_sha256Oid;
    private static volatile Oid? s_pkcs7DataOid;
    private static volatile Oid? s_contentTypeOid;
    private static volatile Oid? s_documentDescriptionOid;
    private static volatile Oid? s_documentNameOid;
    private static volatile Oid? s_localKeyIdOid;
    private static volatile Oid? s_messageDigestOid;
    private static volatile Oid? s_signingTimeOid;
    private static volatile Oid? s_pkcs9ExtensionRequestOid;
    private static volatile Oid? s_basicConstraints2Oid;
    private static volatile Oid? s_enhancedKeyUsageOid;
    private static volatile Oid? s_keyUsageOid;
    private static volatile Oid? s_subjectAltNameOid;
    private static volatile Oid? s_subjectKeyIdentifierOid;
    private static volatile Oid? s_authorityKeyIdentifierOid;
    private static volatile Oid? s_authorityInformationAccessOid;
    private static volatile Oid? s_crlNumberOid;
    private static volatile Oid? s_crlDistributionPointOid;
    private static volatile Oid? s_commonNameOid;
    private static volatile Oid? s_countryOrRegionOid;
    private static volatile Oid? s_localityNameOid;
    private static volatile Oid? s_stateOrProvinceNameOid;
    private static volatile Oid? s_organizationOid;
    private static volatile Oid? s_organizationalUnitOid;
    private static volatile Oid? s_emailAddressOid;

    internal static Oid RsaOid => s_rsaOid ??= InitializeOid(Rsa);
    internal static Oid EcPublicKeyOid => s_ecPublicKeyOid ??= InitializeOid(EcPublicKey);
    internal static Oid TripleDesCbcOid => s_tripleDesCbcOid ??= InitializeOid(TripleDesCbc);
    internal static Oid Aes256CbcOid => s_aes256CbcOid ??= InitializeOid(Aes256Cbc);
    internal static Oid secp256r1Oid => s_secp256R1Oid ??= new Oid(secp256r1, nameof(ECCurve.NamedCurves.nistP256));
    internal static Oid secp384r1Oid => s_secp384R1Oid ??= new Oid(secp384r1, nameof(ECCurve.NamedCurves.nistP384));
    internal static Oid secp521r1Oid => s_secp521R1Oid ??= new Oid(secp521r1, nameof(ECCurve.NamedCurves.nistP521));
    internal static Oid Sha256Oid => s_sha256Oid ??= InitializeOid(Sha256);

    internal static Oid Pkcs7DataOid => s_pkcs7DataOid ??= InitializeOid(Pkcs7Data);
    internal static Oid ContentTypeOid => s_contentTypeOid ??= InitializeOid(ContentType);
    internal static Oid DocumentDescriptionOid => s_documentDescriptionOid ??= InitializeOid(DocumentDescription);
    internal static Oid DocumentNameOid => s_documentNameOid ??= InitializeOid(DocumentName);
    internal static Oid LocalKeyIdOid => s_localKeyIdOid ??= InitializeOid(LocalKeyId);
    internal static Oid MessageDigestOid => s_messageDigestOid ??= InitializeOid(MessageDigest);
    internal static Oid SigningTimeOid => s_signingTimeOid ??= InitializeOid(SigningTime);
    internal static Oid Pkcs9ExtensionRequestOid => s_pkcs9ExtensionRequestOid ??= InitializeOid(Pkcs9ExtensionRequest);

    internal static Oid BasicConstraints2Oid => s_basicConstraints2Oid ??= InitializeOid(BasicConstraints2);
    internal static Oid EnhancedKeyUsageOid => s_enhancedKeyUsageOid ??= InitializeOid(EnhancedKeyUsage);
    internal static Oid KeyUsageOid => s_keyUsageOid ??= InitializeOid(KeyUsage);
    internal static Oid AuthorityKeyIdentifierOid => s_authorityKeyIdentifierOid ??= InitializeOid(AuthorityKeyIdentifier);
    internal static Oid SubjectKeyIdentifierOid => s_subjectKeyIdentifierOid ??= InitializeOid(SubjectKeyIdentifier);
    internal static Oid SubjectAltNameOid => s_subjectAltNameOid ??= InitializeOid(SubjectAltName);
    internal static Oid AuthorityInformationAccessOid => s_authorityInformationAccessOid ??= InitializeOid(AuthorityInformationAccess);
    internal static Oid CrlNumberOid => s_crlNumberOid ??= InitializeOid(CrlNumber);
    internal static Oid CrlDistributionPointsOid => s_crlDistributionPointOid ??= InitializeOid(CrlDistributionPoints);

    internal static Oid CommonNameOid => s_commonNameOid ??= InitializeOid(CommonName);
    internal static Oid CountryOrRegionNameOid => s_countryOrRegionOid ??= InitializeOid(CountryOrRegionName);
    internal static Oid LocalityNameOid => s_localityNameOid ??= InitializeOid(LocalityName);
    internal static Oid StateOrProvinceNameOid = s_stateOrProvinceNameOid ??= InitializeOid(StateOrProvinceName);
    internal static Oid OrganizationOid = s_organizationOid ??= InitializeOid(Organization);
    internal static Oid OrganizationalUnitOid = s_organizationalUnitOid ??= InitializeOid(OrganizationalUnit);
    internal static Oid EmailAddressOid = s_emailAddressOid ??= InitializeOid(EmailAddress);

    private static Oid InitializeOid(string oidValue)
    {
        Debug.Assert(oidValue != null);
        Oid oid = new Oid(oidValue, null);

        // Do not remove - the FriendlyName property get has side effects.
        // On read, it initializes the friendly name based on the value and
        // locks it to prevent any further changes.
        _ = oid.FriendlyName;

        return oid;
    }

    internal static Oid GetSharedOrNewOid(ref AsnValueReader asnValueReader)
    {
        Oid? ret = GetSharedOrNullOid(ref asnValueReader);

        if (ret is not null) {
            return ret;
        }

        string oidValue = asnValueReader.ReadObjectIdentifier();
        return new Oid(oidValue, null);
    }

    internal static Oid? GetSharedOrNullOid(ref AsnValueReader asnValueReader, Asn1Tag? expectedTag = null)
    {
#if NET
        Asn1Tag tag = asnValueReader.PeekTag();

        // This isn't a valid OID, so return null and let whatever's going to happen happen.
        if (tag.IsConstructed) {
            return null;
        }

        Asn1Tag expected = expectedTag.GetValueOrDefault(Asn1Tag.ObjectIdentifier);

        Debug.Assert(
            expected.TagClass != TagClass.Universal ||
            expected.TagValue == (int)UniversalTagNumber.ObjectIdentifier,
            $"{nameof(GetSharedOrNullOid)} was called with the wrong Universal class tag: {expectedTag}");

        // Not the tag we're expecting, so don't match.
        if (!tag.HasSameClassAndValue(expected)) {
            return null;
        }

        ReadOnlySpan<byte> contentBytes = asnValueReader.PeekContentBytes();

        Oid? ret = contentBytes switch {
            [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => EmailAddressOid,
            [0x55, 0x04, 0x03] => CommonNameOid,
            [0x55, 0x04, 0x06] => CountryOrRegionNameOid,
            [0x55, 0x04, 0x07] => LocalityNameOid,
            [0x55, 0x04, 0x08] => StateOrProvinceNameOid,
            [0x55, 0x04, 0x0A] => OrganizationOid,
            [0x55, 0x04, 0x0B] => OrganizationalUnitOid,
            [0x55, 0x1D, 0x14] => CrlNumberOid,
            _ => null,
        };

        if (ret is not null) {
            // Move to the next item.
            asnValueReader.ReadEncodedValue();
        }

        return ret;
#else
            // The list pattern isn't available in System.Security.Cryptography.Pkcs for the
            // netstandard2.0 or netfx builds.  Any OIDs that it's important to optimize in
            // those contexts can be matched on here, but using a longer form of matching.

            return null;
#endif
    }

    internal static bool ValueEquals(this Oid oid, Oid? other)
    {
        Debug.Assert(oid is not null);

        if (ReferenceEquals(oid, other)) {
            return true;
        }

        if (other is null) {
            return false;
        }

        return oid.Value is not null && oid.Value.Equals(other.Value);
    }
}
