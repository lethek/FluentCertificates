using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Represents the X.509 Authority Key Identifier extension, which identifies the public key corresponding to the certificate authority (CA) that signed the certificate.
/// </summary>
/// <param name="certificateAuthority">The certificate authority whose key identifier will be encoded in the extension.</param>
/// <param name="critical">Indicates whether the extension is critical.</param>
public sealed class X509AuthorityKeyIdentifierExtension(X509Certificate2 certificateAuthority, bool critical)
    : X509Extension(Oids.AuthorityKeyIdentifierOid, EncodeExtension(certificateAuthority), critical)
{
    /// <summary>
    /// Encodes the Authority Key Identifier extension using the subject key identifier of the provided CA certificate.
    /// </summary>
    /// <param name="ca">The certificate authority whose subject key identifier will be used.</param>
    /// <returns>A byte array containing the DER-encoded extension value.</returns>
    private static byte[] EncodeExtension(X509Certificate2 ca)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence()) {
            var subjectKeyIdentifier = ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
            if (subjectKeyIdentifier != null) {
                // Write the subject key identifier as a context-specific tagged octet string (tag 0)
                writer.WriteOctetString(subjectKeyIdentifier.RawData.AsSpan().Slice(2), KeyIdTag);
            }
        }

        return writer.Encode();
    }
    
    
    private static readonly Asn1Tag KeyIdTag = new(TagClass.ContextSpecific, 0);
}
