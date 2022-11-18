using System.Security.Cryptography;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;


namespace FluentCertificates;

public static class CertificateBuilderExtensions
{
    public static CertificateBuilder SetSubject(this CertificateBuilder builder, X509Name value)
        => builder with { Subject = new X500NameBuilder(value) };


    public static CertificateBuilder AddExtension(this CertificateBuilder builder, DerObjectIdentifier oid, X509Extension extension)
        => builder.AddExtension(extension.ConvertToDotNet(oid));


    public static DerObjectIdentifier GetSignatureAlgorithm(this CertificateBuilder builder)
        => builder.HashAlgorithm.Name switch {
            nameof(HashAlgorithmName.MD5) => PkcsObjectIdentifiers.MD5WithRsaEncryption,
            nameof(HashAlgorithmName.SHA1) => PkcsObjectIdentifiers.Sha1WithRsaEncryption,
            nameof(HashAlgorithmName.SHA256) => PkcsObjectIdentifiers.Sha256WithRsaEncryption,
            nameof(HashAlgorithmName.SHA384) => PkcsObjectIdentifiers.Sha384WithRsaEncryption,
            nameof(HashAlgorithmName.SHA512) => PkcsObjectIdentifiers.Sha512WithRsaEncryption,
            _ => throw new NotSupportedException($"Specified {nameof(HashAlgorithm)} {builder.HashAlgorithm} is not supported.")
        };
}
