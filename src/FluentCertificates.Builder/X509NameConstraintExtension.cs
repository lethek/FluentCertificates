using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using FluentCertificates.Internals;

namespace FluentCertificates;

public class X509NameConstraintExtension(GeneralSubtree? permittedSubtrees, GeneralSubtree? excludedSubtrees)
    : X509Extension(Oids.NameConstraints, EncodeExtension(permittedSubtrees, excludedSubtrees), true)
{
    private static byte[] EncodeExtension(GeneralSubtree? permittedSubtrees, GeneralSubtree? excludedSubtrees)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence()) {
            if (permittedSubtrees != null) {
                using var permittedSubtreesScope = writer.PushSequence(PermittedSubtreesTag);
                foreach (var subtree in permittedSubtrees) {
                    subtree.WriteTo(writer);
                }
            }

            if (excludedSubtrees != null) {
                using var excludedSubtreesScope = writer.PushSequence(ExcludedSubtreesTag);
                foreach (var subtree in excludedSubtrees) {
                    subtree.WriteTo(writer);
                }
            }
        }

        return writer.Encode();
    }
    
    
    private static readonly Asn1Tag PermittedSubtreesTag = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag ExcludedSubtreesTag = new(TagClass.ContextSpecific, 1);
}