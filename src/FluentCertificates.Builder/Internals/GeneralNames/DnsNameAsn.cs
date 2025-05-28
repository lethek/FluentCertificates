using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record DnsNameAsn(string DnsName) : GeneralName
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 2);

    protected override void EncodeCore(AsnWriter writer)
        => writer.WriteCharacterString(UniversalTagNumber.IA5String, DnsName, Tag);
}
