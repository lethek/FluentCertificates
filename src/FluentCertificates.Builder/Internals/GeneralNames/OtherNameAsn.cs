using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record OtherNameAsn : GeneralName
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 0);

    protected override void EncodeCore(AsnWriter writer)
        => throw new NotImplementedException();
}
