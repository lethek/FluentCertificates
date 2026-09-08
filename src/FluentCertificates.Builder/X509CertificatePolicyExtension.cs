using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>Represents the X.509 Certificate Policies extension, naming the policies under which the
/// certificate was issued.</summary>
/// <remarks>Policy qualifiers are not represented: each policy is encoded as a bare <c>policyIdentifier</c>.</remarks>
/// <param name="policyIdentifiers">The policy OIDs to assert. RFC 5280 s4.2.1.4 requires at least one; use
/// <see cref="Oids.AnyCertPolicy"/> for anyPolicy.</param>
/// <param name="critical">Whether to mark the extension critical, which forces a relying party that cannot
/// interpret it to reject the certificate. CA/Browser Forum s7.1.2 requires it non-critical.</param>
/// <exception cref="ArgumentException"><paramref name="policyIdentifiers"/> is empty, or contains the same OID more than once.</exception>
public class X509CertificatePolicyExtension(IEnumerable<string> policyIdentifiers, bool critical = false)
    : X509Extension(Oids.CertPolicies, EncodeExtension(policyIdentifiers), critical)
{
    /// <summary>Encodes the Certificate Policies extension from the supplied policy OIDs.</summary>
    /// <param name="policyIdentifiers">The policy OIDs to encode.</param>
    /// <returns>The DER-encoded extension value.</returns>
    private static byte[] EncodeExtension(IEnumerable<string> policyIdentifiers)
    {
        ArgumentNullException.ThrowIfNull(policyIdentifiers);

        var writer = new AsnWriter(AsnEncodingRules.DER);

        //RFC 5280 s4.2.1.4: a certificate policy OID MUST NOT appear more than once
        var seen = new HashSet<string>();

        using (writer.PushSequence()) {
            foreach (var policyIdentifier in policyIdentifiers) {
                if (!seen.Add(policyIdentifier)) {
                    throw new ArgumentException($"Policy identifier '{policyIdentifier}' was supplied more than once", nameof(policyIdentifiers));
                }
                using (writer.PushSequence()) {
                    writer.WriteObjectIdentifier(policyIdentifier);
                }
            }
        }

        return seen.Count > 0
            ? writer.Encode()
            : throw new ArgumentException("At least one policy identifier must be supplied", nameof(policyIdentifiers));
    }
}
