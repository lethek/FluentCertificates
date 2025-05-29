using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;

using FluentCertificates.Internals;

namespace FluentCertificates;

public static class Oids
{
    // Symmetric encryption algorithms
    public const string Rc2Cbc = "1.2.840.113549.3.2";
    public const string Rc4 = "1.2.840.113549.3.4";
    public const string TripleDesCbc = "1.2.840.113549.3.7";
    public const string DesCbc = "1.3.14.3.2.7";
    public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    public const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
    public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";

    // Asymmetric encryption algorithms
    public const string Dsa = "1.2.840.10040.4.1";
    public const string Rsa = "1.2.840.113549.1.1.1";
    public const string RsaOaep = "1.2.840.113549.1.1.7";
    public const string RsaPss = "1.2.840.113549.1.1.10";
    public const string RsaPkcs1Md5 = "1.2.840.113549.1.1.4";
    public const string RsaPkcs1Sha1 = "1.2.840.113549.1.1.5";
    public const string RsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
    public const string RsaPkcs1Sha384 = "1.2.840.113549.1.1.12";
    public const string RsaPkcs1Sha512 = "1.2.840.113549.1.1.13";
    public const string Esdh = "1.2.840.113549.1.9.16.3.5";
    public const string EcDiffieHellman = "1.3.132.1.12";
    public const string DiffieHellman = "1.2.840.10046.2.1";
    public const string DiffieHellmanPkcs3 = "1.2.840.113549.1.3.1";

    // Cryptographic Attribute Types
    public const string SigningTime = "1.2.840.113549.1.9.5";
    public const string ContentType = "1.2.840.113549.1.9.3";
    public const string DocumentDescription = "1.3.6.1.4.1.311.88.2.2";
    public const string MessageDigest = "1.2.840.113549.1.9.4";
    public const string CounterSigner = "1.2.840.113549.1.9.6";
    public const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    public const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    public const string DocumentName = "1.3.6.1.4.1.311.88.2.1";
    public const string FriendlyName = "1.2.840.113549.1.9.20";
    public const string LocalKeyId = "1.2.840.113549.1.9.21";
    public const string EnrollCertTypeExtension = "1.3.6.1.4.1.311.20.2";
    public const string UserPrincipalName = "1.3.6.1.4.1.311.20.2.3";
    public const string CertificateTemplate = "1.3.6.1.4.1.311.21.7";
    public const string ApplicationCertPolicies = "1.3.6.1.4.1.311.21.10";
    public const string AuthorityInformationAccess = "1.3.6.1.5.5.7.1.1";
    public const string OcspEndpoint = "1.3.6.1.5.5.7.48.1";
    public const string CertificateAuthorityIssuers = "1.3.6.1.5.5.7.48.2";
    public const string Pkcs9ExtensionRequest = "1.2.840.113549.1.9.14";

    // Key wrap algorithms
    public const string CmsRc2Wrap = "1.2.840.113549.1.9.16.3.7";
    public const string Cms3DesWrap = "1.2.840.113549.1.9.16.3.6";

    // PKCS7 Content Types.
    public const string Pkcs7Data = "1.2.840.113549.1.7.1";
    public const string Pkcs7Signed = "1.2.840.113549.1.7.2";
    public const string Pkcs7Enveloped = "1.2.840.113549.1.7.3";
    public const string Pkcs7SignedEnveloped = "1.2.840.113549.1.7.4";
    public const string Pkcs7Hashed = "1.2.840.113549.1.7.5";
    public const string Pkcs7Encrypted = "1.2.840.113549.1.7.6";

    public const string Md5 = "1.2.840.113549.2.5";
    public const string Sha1 = "1.3.14.3.2.26";
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";

    // DSA CMS uses the combined signature+digest OID
    public const string DsaWithSha1 = "1.2.840.10040.4.3";
    public const string DsaWithSha256 = "2.16.840.1.101.3.4.3.2";
    public const string DsaWithSha384 = "2.16.840.1.101.3.4.3.3";
    public const string DsaWithSha512 = "2.16.840.1.101.3.4.3.4";

    // ECDSA CMS uses the combined signature+digest OID
    // https://tools.ietf.org/html/rfc5753#section-2.1.1
    public const string EcPrimeField = "1.2.840.10045.1.1";
    public const string EcChar2Field = "1.2.840.10045.1.2";
    public const string EcChar2TrinomialBasis = "1.2.840.10045.1.2.3.2";
    public const string EcChar2PentanomialBasis = "1.2.840.10045.1.2.3.3";
    public const string EcPublicKey = "1.2.840.10045.2.1";
    public const string ECDsaWithSha1 = "1.2.840.10045.4.1";
    public const string ECDsaWithSha256 = "1.2.840.10045.4.3.2";
    public const string ECDsaWithSha384 = "1.2.840.10045.4.3.3";
    public const string ECDsaWithSha512 = "1.2.840.10045.4.3.4";

    public const string Mgf1 = "1.2.840.113549.1.1.8";
    public const string PSpecified = "1.2.840.113549.1.1.9";

    // PKCS#7
    public const string NoSignature = "1.3.6.1.5.5.7.6.2";

    // X500 Names
    public const string CommonName = "2.5.4.3";
    public const string CountryOrRegionName = "2.5.4.6";
    public const string LocalityName = "2.5.4.7";
    public const string StateOrProvinceName = "2.5.4.8";
    public const string Organization = "2.5.4.10";
    public const string OrganizationalUnit = "2.5.4.11";
    public const string EmailAddress = "1.2.840.113549.1.9.1";
    public const string TelephoneNumber = "2.5.4.20";
    public const string StreetAddress = "2.5.4.9";
    public const string PostalCode = "2.5.4.17";
    public const string SerialNumber = "2.5.4.5";
    public const string Surname = "2.5.4.4";
    public const string GivenName = "2.5.4.42";
    public const string Title = "2.5.4.12";
    public const string DnQualifier = "2.5.4.46";

    // Cert Extensions
    public const string BasicConstraints = "2.5.29.10";
    public const string SubjectKeyIdentifier = "2.5.29.14";
    public const string KeyUsage = "2.5.29.15";
    public const string SubjectAltName = "2.5.29.17";
    public const string IssuerAltName = "2.5.29.18";
    public const string BasicConstraints2 = "2.5.29.19";
    public const string CrlNumber = "2.5.29.20";
    public const string CrlReasons = "2.5.29.21";
    public const string NameConstraints = "2.5.29.30";
    public const string CrlDistributionPoints = "2.5.29.31";
    public const string CertPolicies = "2.5.29.32";
    public const string AnyCertPolicy = "2.5.29.32.0";
    public const string CertPolicyMappings = "2.5.29.33";
    public const string AuthorityKeyIdentifier = "2.5.29.35";
    public const string CertPolicyConstraints = "2.5.29.36";
    public const string EnhancedKeyUsage = "2.5.29.37";
    public const string InhibitAnyPolicyExtension = "2.5.29.54";

    public const string AnyExtendedKeyUsage = "2.5.29.37.0";

    // RFC3161 Timestamping
    public const string TstInfo = "1.2.840.113549.1.9.16.1.4";
    public const string TimeStampingPurpose = "1.3.6.1.5.5.7.3.8";

    public const string ServerAuthPurpose = "1.3.6.1.5.5.7.3.1";
    public const string ClientAuthPurpose = "1.3.6.1.5.5.7.3.2";
    public const string CodeSigningPurpose = "1.3.6.1.5.5.7.3.3";
    public const string EmailProtectionPurpose = "1.3.6.1.5.5.7.3.4";
    public const string IpsecEndSystemPurpose = "1.3.6.1.5.5.7.3.5";
    public const string IpsecTunnelPurpose = "1.3.6.1.5.5.7.3.6";
    public const string IpsecUserPurpose = "1.3.6.1.5.5.7.3.7";
    public const string OcspSigningPurpose = "1.3.6.1.5.5.7.3.9";
    public const string SmartCardLogonPurpose = "1.3.6.1.4.1.311.20.2.2";
    public const string MacAddressPurpose = "1.3.6.1.1.1.1.22";
    public const string LifetimeSigningPurpose = "1.3.6.1.4.1.311.10.3.13";


    // PKCS#12
    private const string Pkcs12Prefix = "1.2.840.113549.1.12.";
    private const string Pkcs12PbePrefix = Pkcs12Prefix + "1.";
    public const string Pkcs12PbeWithShaAnd3Key3Des = Pkcs12PbePrefix + "3";
    public const string Pkcs12PbeWithShaAnd2Key3Des = Pkcs12PbePrefix + "4";
    public const string Pkcs12PbeWithShaAnd128BitRC2 = Pkcs12PbePrefix + "5";
    public const string Pkcs12PbeWithShaAnd40BitRC2 = Pkcs12PbePrefix + "6";
    private const string Pkcs12BagTypesPrefix = Pkcs12Prefix + "10.1.";
    public const string Pkcs12KeyBag = Pkcs12BagTypesPrefix + "1";
    public const string Pkcs12ShroudedKeyBag = Pkcs12BagTypesPrefix + "2";
    public const string Pkcs12CertBag = Pkcs12BagTypesPrefix + "3";
    public const string Pkcs12CrlBag = Pkcs12BagTypesPrefix + "4";
    public const string Pkcs12SecretBag = Pkcs12BagTypesPrefix + "5";
    public const string Pkcs12SafeContentsBag = Pkcs12BagTypesPrefix + "6";
    public const string Pkcs12X509CertBagType = "1.2.840.113549.1.9.22.1";
    public const string Pkcs12SdsiCertBagType = "1.2.840.113549.1.9.22.2";

    // PKCS#5
    private const string Pkcs5Prefix = "1.2.840.113549.1.5.";
    public const string PbeWithMD5AndDESCBC = Pkcs5Prefix + "3";
    public const string PbeWithMD5AndRC2CBC = Pkcs5Prefix + "6";
    public const string PbeWithSha1AndDESCBC = Pkcs5Prefix + "10";
    public const string PbeWithSha1AndRC2CBC = Pkcs5Prefix + "11";
    public const string Pbkdf2 = Pkcs5Prefix + "12";
    public const string PasswordBasedEncryptionScheme2 = Pkcs5Prefix + "13";

    private const string RsaDsiDigestAlgorithmPrefix = "1.2.840.113549.2.";
    public const string HmacWithSha1 = RsaDsiDigestAlgorithmPrefix + "7";
    public const string HmacWithSha256 = RsaDsiDigestAlgorithmPrefix + "9";
    public const string HmacWithSha384 = RsaDsiDigestAlgorithmPrefix + "10";
    public const string HmacWithSha512 = RsaDsiDigestAlgorithmPrefix + "11";

    // Elliptic Curve curve identifiers
    public const string secp256r1 = "1.2.840.10045.3.1.7";
    public const string secp384r1 = "1.3.132.0.34";
    public const string secp521r1 = "1.3.132.0.35";

    // LDAP
    public const string DomainComponent = "0.9.2342.19200300.100.1.25";
    public const string UserId = "0.9.2342.19200300.100.1.1";



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
    private static volatile Oid? s_telephoneNumberOid;
    private static volatile Oid? s_streetAddressOid;
    private static volatile Oid? s_postalCodeOid;
    private static volatile Oid? s_userIdOid;
    private static volatile Oid? s_serialNumberOid;
    private static volatile Oid? s_givenNameOid;
    private static volatile Oid? s_surnameOid;
    private static volatile Oid? s_titleOid;
    private static volatile Oid? s_dnQualifierOid;
    private static volatile Oid? s_domainComponentOid;



    public static Oid RsaOid => s_rsaOid ??= InitializeOid(Rsa);
    public static Oid EcPublicKeyOid => s_ecPublicKeyOid ??= InitializeOid(EcPublicKey);
    public static Oid TripleDesCbcOid => s_tripleDesCbcOid ??= InitializeOid(TripleDesCbc);
    public static Oid Aes256CbcOid => s_aes256CbcOid ??= InitializeOid(Aes256Cbc);
    public static Oid secp256r1Oid => s_secp256R1Oid ??= new Oid(secp256r1, nameof(ECCurve.NamedCurves.nistP256));
    public static Oid secp384r1Oid => s_secp384R1Oid ??= new Oid(secp384r1, nameof(ECCurve.NamedCurves.nistP384));
    public static Oid secp521r1Oid => s_secp521R1Oid ??= new Oid(secp521r1, nameof(ECCurve.NamedCurves.nistP521));
    public static Oid Sha256Oid => s_sha256Oid ??= InitializeOid(Sha256);

    public static Oid Pkcs7DataOid => s_pkcs7DataOid ??= InitializeOid(Pkcs7Data);
    public static Oid ContentTypeOid => s_contentTypeOid ??= InitializeOid(ContentType);
    public static Oid DocumentDescriptionOid => s_documentDescriptionOid ??= InitializeOid(DocumentDescription);
    public static Oid DocumentNameOid => s_documentNameOid ??= InitializeOid(DocumentName);
    public static Oid LocalKeyIdOid => s_localKeyIdOid ??= InitializeOid(LocalKeyId);
    public static Oid MessageDigestOid => s_messageDigestOid ??= InitializeOid(MessageDigest);
    public static Oid SigningTimeOid => s_signingTimeOid ??= InitializeOid(SigningTime);
    public static Oid Pkcs9ExtensionRequestOid => s_pkcs9ExtensionRequestOid ??= InitializeOid(Pkcs9ExtensionRequest);

    public static Oid BasicConstraints2Oid => s_basicConstraints2Oid ??= InitializeOid(BasicConstraints2);
    public static Oid EnhancedKeyUsageOid => s_enhancedKeyUsageOid ??= InitializeOid(EnhancedKeyUsage);
    public static Oid KeyUsageOid => s_keyUsageOid ??= InitializeOid(KeyUsage);
    public static Oid AuthorityKeyIdentifierOid => s_authorityKeyIdentifierOid ??= InitializeOid(AuthorityKeyIdentifier);
    public static Oid SubjectKeyIdentifierOid => s_subjectKeyIdentifierOid ??= InitializeOid(SubjectKeyIdentifier);
    public static Oid SubjectAltNameOid => s_subjectAltNameOid ??= InitializeOid(SubjectAltName);
    public static Oid AuthorityInformationAccessOid => s_authorityInformationAccessOid ??= InitializeOid(AuthorityInformationAccess);
    public static Oid CrlNumberOid => s_crlNumberOid ??= InitializeOid(CrlNumber);
    public static Oid CrlDistributionPointsOid => s_crlDistributionPointOid ??= InitializeOid(CrlDistributionPoints);

    public static Oid CommonNameOid => s_commonNameOid ??= InitializeOid(CommonName);
    public static Oid CountryOrRegionNameOid => s_countryOrRegionOid ??= InitializeOid(CountryOrRegionName);
    public static Oid LocalityNameOid => s_localityNameOid ??= InitializeOid(LocalityName);
    public static Oid StateOrProvinceNameOid = s_stateOrProvinceNameOid ??= InitializeOid(StateOrProvinceName);
    public static Oid OrganizationOid = s_organizationOid ??= InitializeOid(Organization);
    public static Oid OrganizationalUnitOid = s_organizationalUnitOid ??= InitializeOid(OrganizationalUnit);
    public static Oid EmailAddressOid = s_emailAddressOid ??= InitializeOid(EmailAddress);
    public static Oid TelephoneNumberOid = s_telephoneNumberOid ??= InitializeOid(TelephoneNumber);
    public static Oid StreetAddressOid = s_streetAddressOid ??= InitializeOid(StreetAddress);
    public static Oid PostalCodeOid = s_postalCodeOid ??= InitializeOid(PostalCode);
    public static Oid UserIdOid = s_userIdOid ??= InitializeOid(UserId);
    public static Oid SerialNumberOid = s_serialNumberOid ??= InitializeOid(SerialNumber);
    public static Oid GivenNameOid = s_givenNameOid ??= InitializeOid(GivenName);
    public static Oid SurnameOid = s_surnameOid ??= InitializeOid(Surname);
    public static Oid TitleOid = s_titleOid ??= InitializeOid(Title);
    public static Oid DnQualifierOid = s_dnQualifierOid ??= InitializeOid(DnQualifier);
    public static Oid DomainComponentOid = s_domainComponentOid ??= InitializeOid(DomainComponent);

    
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

    
    public static bool ValueEquals(this Oid oid, Oid? other)
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
