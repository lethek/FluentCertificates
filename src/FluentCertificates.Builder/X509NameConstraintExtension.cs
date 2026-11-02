using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// Represents the X.509 Name Constraints extension, which specifies permitted and excluded name subtrees for certificate subjects.
/// </summary>
/// <remarks>RFC 5280 s4.2.1.10 requires at least one of the two lists, and each list it carries to hold at
/// least one name, so a null list is omitted and an empty one is refused.</remarks>
/// <param name="permittedSubtrees">
/// A collection of <see cref="GeneralName"/> objects representing the permitted name subtrees. May be null, which omits the field.
/// </param>
/// <param name="excludedSubtrees">
/// A collection of <see cref="GeneralName"/> objects representing the excluded name subtrees. May be null, which omits the field.
/// </param>
/// <exception cref="ArgumentException">Both lists are null, or a list that is supplied is empty.</exception>
/// <exception cref="ArgumentNullException">A list that is supplied contains a null name.</exception>
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
        var permitted = permittedSubtrees?.ToList();
        var excluded = excludedSubtrees?.ToList();

        if (permitted is null && excluded is null) {
            throw new ArgumentException("Supply a permitted or an excluded subtree list, since RFC 5280 s4.2.1.10 forbids an empty name constraints sequence", nameof(permittedSubtrees));
        }

        if (permitted is { Count: 0 }) {
            throw new ArgumentException("A subtree list must hold at least one name, since RFC 5280 s4.2.1.10 gives GeneralSubtrees a minimum size of 1. Pass null to omit it", nameof(permittedSubtrees));
        }

        if (excluded is { Count: 0 }) {
            throw new ArgumentException("A subtree list must hold at least one name, since RFC 5280 s4.2.1.10 gives GeneralSubtrees a minimum size of 1. Pass null to omit it", nameof(excludedSubtrees));
        }

        if (permitted is not null && permitted.Contains(null!)) {
            throw new ArgumentNullException(nameof(permittedSubtrees), "A subtree list must not contain a null name");
        }

        if (excluded is not null && excluded.Contains(null!)) {
            throw new ArgumentNullException(nameof(excludedSubtrees), "A subtree list must not contain a null name");
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence()) {
            if (permitted != null) {
                using var permittedSubtreesScope = writer.PushSequence(PermittedSubtreesTag);
                foreach (var subtree in permitted) {
                    using (writer.PushSequence()) {
                        subtree.WriteTo(writer);
                    }
                }
            }

            if (excluded != null) {
                using var excludedSubtreesScope = writer.PushSequence(ExcludedSubtreesTag);
                foreach (var subtree in excluded) {
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