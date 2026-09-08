using System.Security.Cryptography.X509Certificates;

using BclAuthorityKeyIdentifier = System.Security.Cryptography.X509Certificates.X509AuthorityKeyIdentifierExtension;

namespace FluentCertificates;

/// <summary>
/// Represents the X.509 Authority Key Identifier extension, which identifies the public key corresponding to the certificate authority (CA) that signed the certificate.
/// </summary>
/// <remarks>
/// The extension names the CA by its Subject Key Identifier, which RFC 5280 s4.2.1.2 requires every CA
/// certificate to carry. Where the CA has none, it names the CA by issuer and serial number instead: those
/// fields are equally permitted by s4.2.1.1, and an extension asserting nothing at all would leave the
/// certificate without the key identifier that same section requires of a conforming CA.
/// </remarks>
/// <param name="certificateAuthority">The certificate authority to identify.</param>
/// <param name="critical">Indicates whether the extension is critical.</param>
public sealed class X509AuthorityKeyIdentifierExtension(X509Certificate2 certificateAuthority, bool critical)
    : X509Extension(Oids.AuthorityKeyIdentifierOid, EncodeExtension(certificateAuthority), critical)
{
    private static byte[] EncodeExtension(X509Certificate2 ca)
        => ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Any()
            ? BclAuthorityKeyIdentifier.CreateFromCertificate(ca, includeKeyIdentifier: true, includeIssuerAndSerial: false).RawData
            : BclAuthorityKeyIdentifier.CreateFromCertificate(ca, includeKeyIdentifier: false, includeIssuerAndSerial: true).RawData;
}
