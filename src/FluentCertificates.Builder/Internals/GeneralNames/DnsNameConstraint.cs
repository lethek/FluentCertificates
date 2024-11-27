using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record DnsNameConstraint(string DnsName) : GeneralNameConstraint
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 2);

    protected override void EncodeCore(AsnWriter writer)
        => writer.WriteCharacterString(UniversalTagNumber.IA5String, DnsName, Tag);
}
