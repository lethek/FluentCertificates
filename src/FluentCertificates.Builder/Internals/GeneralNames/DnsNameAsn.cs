using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record DnsNameAsn : GeneralName
{
    public string DnsName { get; }

    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 2);

    public DnsNameAsn(string dnsName)
        => DnsName = Ia5NameValidator.ValidateDnsName(dnsName, nameof(dnsName));

    protected override void EncodeCore(AsnWriter writer)
        => writer.WriteCharacterString(UniversalTagNumber.IA5String, DnsName, Tag);
}
