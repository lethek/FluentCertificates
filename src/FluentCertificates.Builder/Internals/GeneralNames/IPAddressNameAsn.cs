using System.Formats.Asn1;
using System.Net;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record IPAddressNameAsn : GeneralName
{
    public IPAddress IPAddress { get; }

    public IPAddress? SubnetMask { get; }

    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 7);

    public IPAddressNameAsn(IPAddress ipAddress, IPAddress? subnetMask = null)
    {
        if (subnetMask != null && subnetMask.AddressFamily != ipAddress.AddressFamily) {
            throw new ArgumentException($"{nameof(subnetMask)} must be of the same AddressFamily as {nameof(ipAddress)}", nameof(subnetMask));
        }

        IPAddress = ipAddress;
        SubnetMask = subnetMask;
    }

    protected override void EncodeCore(AsnWriter writer)
    {
        var value = IPAddress.GetAddressBytes().Concat(SubnetMask?.GetAddressBytes() ?? []).ToArray();

        writer.WriteOctetString(value, Tag);
    }
}
