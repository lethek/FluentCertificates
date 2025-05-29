using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Represents the X.509 Name Constraints extension, which specifies permitted and excluded name subtrees for certificate subjects.
/// </summary>
/// <param name="permittedSubtrees">
/// A collection of <see cref="GeneralName"/> objects representing the permitted name subtrees. May be null.
/// </param>
/// <param name="excludedSubtrees">
/// A collection of <see cref="GeneralName"/> objects representing the excluded name subtrees. May be null.
/// </param>
public class X509NameConstraintExtension(IEnumerable<GeneralName>? permittedSubtrees, IEnumerable<GeneralName>? excludedSubtrees)
    : X509Extension(Oids.NameConstraints, EncodeExtension(permittedSubtrees, excludedSubtrees), true)
{
    /// <summary>
    /// Encodes the Name Constraints extension using the provided permitted and excluded subtrees.
    /// </summary>
    /// <param name="permittedSubtrees">The permitted name subtrees to encode, or null if none.</param>
    /// <param name="excludedSubtrees">The excluded name subtrees to encode, or null if none.</param>
    /// <returns>A byte array containing the DER-encoded extension value.</returns>
    private static byte[] EncodeExtension(IEnumerable<GeneralName>? permittedSubtrees, IEnumerable<GeneralName>? excludedSubtrees)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence()) {
            if (permittedSubtrees != null) {
                using var permittedSubtreesScope = writer.PushSequence(PermittedSubtreesTag);
                foreach (var subtree in permittedSubtrees) {
                    using (writer.PushSequence()) {
                        subtree.WriteTo(writer);
                    }
                }
            }

            if (excludedSubtrees != null) {
                using var excludedSubtreesScope = writer.PushSequence(ExcludedSubtreesTag);
                foreach (var subtree in excludedSubtrees) {
                    using (writer.PushSequence()) {
                        subtree.WriteTo(writer);
                    }
                }
            }
        }

        return writer.Encode();
    }
    
    
    private static readonly Asn1Tag PermittedSubtreesTag = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag ExcludedSubtreesTag = new(TagClass.ContextSpecific, 1);
}