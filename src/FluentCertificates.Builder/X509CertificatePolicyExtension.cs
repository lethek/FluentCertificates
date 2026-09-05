using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Represents the X.509 Certificate Policies extension, which names the policies under which the
/// certificate was issued.
/// </summary>
/// <remarks>
/// Policy qualifiers are not represented: each policy is encoded as a bare <c>policyIdentifier</c>.
/// The extension is non-critical, as recommended by RFC 5280 s4.2.1.4.
/// </remarks>
/// <param name="policyIdentifiers">
/// The OIDs of the policies to assert. Must contain at least one OID, as required by RFC 5280 s4.2.1.4.
/// Use <see cref="Oids.AnyCertPolicy"/> to assert the anyPolicy OID.
/// </param>
/// <exception cref="ArgumentException">Thrown when <paramref name="policyIdentifiers"/> is empty, or contains the same OID more than once.</exception>
public class X509CertificatePolicyExtension(IEnumerable<string> policyIdentifiers)
    : X509Extension(Oids.CertPolicies, EncodeExtension(policyIdentifiers), false)
{
    /// <summary>
    /// Encodes the Certificate Policies extension from the supplied policy OIDs.
    /// </summary>
    /// <param name="policyIdentifiers">The policy OIDs to encode.</param>
    /// <returns>A byte array containing the DER-encoded extension value.</returns>
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
