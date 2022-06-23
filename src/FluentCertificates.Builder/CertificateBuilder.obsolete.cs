using System.Security.Cryptography;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;


namespace FluentCertificates;

public partial record CertificateBuilder
{
    [Obsolete("Use the ToCertificateRequest method instead. Note: this method only supports RSA and DSA encryption keys.")]
    internal Pkcs10CertificationRequest ToBouncyCertificateRequest()
    {
        if (KeyParameters == null) {
            throw new ArgumentNullException($"Call {nameof(SetKeyPair)}(...) or {nameof(GenerateKeyPair)}() first to provide a public/private keypair");
        }

        using var keys = KeyParameters.CreateKeyPair();
        var keypair = keys ?? throw new ArgumentNullException(nameof(keys), "Call SetKeyPair(key) first to provide a public/private keypair");
        var bouncyKeyPair = DotNetUtilities.GetKeyPair(keypair);
        var extensions = new X509Extensions(BuildExtensions(this, null).ToDictionary(x => new DerObjectIdentifier(x.Oid?.Value), x => x.ConvertToBouncyCastle()));
        var attributes = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions)));
        var sigFactory = new Asn1SignatureFactory(GetSignatureAlgorithm(this).Id, bouncyKeyPair.Private);
        return new Pkcs10CertificationRequest(sigFactory, Subject, bouncyKeyPair.Public, attributes);
    }


    private static DerObjectIdentifier GetSignatureAlgorithm(CertificateBuilder builder)
        => builder.HashAlgorithm.Name switch {
            nameof(HashAlgorithmName.MD5) => PkcsObjectIdentifiers.MD5WithRsaEncryption,
            nameof(HashAlgorithmName.SHA1) => PkcsObjectIdentifiers.Sha1WithRsaEncryption,
            nameof(HashAlgorithmName.SHA256) => PkcsObjectIdentifiers.Sha256WithRsaEncryption,
            nameof(HashAlgorithmName.SHA384) => PkcsObjectIdentifiers.Sha384WithRsaEncryption,
            nameof(HashAlgorithmName.SHA512) => PkcsObjectIdentifiers.Sha512WithRsaEncryption,
            _ => throw new NotSupportedException($"Specified {nameof(HashAlgorithm)} {builder.HashAlgorithm} is not supported.")
        };
}
