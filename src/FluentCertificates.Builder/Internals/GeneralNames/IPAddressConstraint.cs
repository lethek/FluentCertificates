using System.Formats.Asn1;
using System.Net;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record IPAddressConstraint(IPAddress IPAddress, IPAddress? SubnetMask = null) : GeneralNameConstraint
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 7);

    protected override void EncodeCore(AsnWriter writer)
    {
        if (SubnetMask != null && SubnetMask.AddressFamily != IPAddress.AddressFamily) {
            throw new ArgumentException($"{nameof(SubnetMask)} must be of the same AddressFamily as {nameof(IPAddress)}");
        }

        var value = IPAddress.GetAddressBytes().Concat(SubnetMask?.GetAddressBytes() ?? []).ToArray();

        writer.WriteOctetString(value, Tag);
    }
}