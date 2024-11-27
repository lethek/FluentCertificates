using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record Rfc822NameConstraint(string EmailAddress) : GeneralNameConstraint
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 1);

    protected override void EncodeCore(AsnWriter writer)
        => writer.WriteCharacterString(UniversalTagNumber.IA5String, EmailAddress, Tag);
}