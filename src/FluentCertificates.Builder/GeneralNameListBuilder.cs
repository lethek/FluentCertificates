using System.Collections.Immutable;
using System.Net;
using FluentCertificates.Internals.GeneralNames;

namespace FluentCertificates;

public record GeneralNameListBuilder {
    public GeneralNameList Create()
        => new GeneralNameList(NameConstraints);

    public GeneralNameListBuilder AddEmailAddress(string emailAddress)
        => Add(new Rfc822NameAsn(emailAddress));

    public GeneralNameListBuilder AddDnsName(string dnsName)
        => Add(new DnsNameAsn(dnsName));

    public GeneralNameListBuilder AddUri(Uri uri)
        => Add(new UriNameAsn(uri));

    public GeneralNameListBuilder AddIPAddress(IPAddress ipAddress, IPAddress? subnetMask = null)
        => Add(new IPAddressNameAsn(ipAddress, subnetMask));

    private GeneralNameListBuilder Add(GeneralName generalNameConstraint)
        => this with {
            NameConstraints = NameConstraints.Add(generalNameConstraint)
        };
    
    private ImmutableList<GeneralName> NameConstraints { get; init; }
        = ImmutableList<GeneralName>.Empty;
}
