using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record RegisteredIdConstraint(string RegisteredId) : GeneralNameConstraint
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 8);

    protected override void EncodeCore(AsnWriter writer)
        => writer.WriteObjectIdentifier(RegisteredId, Tag);
}