using System.Collections.Immutable;
using System.Net;
using FluentCertificates.Internals.GeneralNames;

namespace FluentCertificates;

public record GeneralSubtreeBuilder {
    public GeneralSubtree Create()
        => new GeneralSubtree(NameConstraints);

    public GeneralSubtreeBuilder AddEmailAddress(string emailAddress)
        => Add(new Rfc822NameConstraint(emailAddress));

    public GeneralSubtreeBuilder AddDnsName(string dnsName)
        => Add(new DnsNameConstraint(dnsName));

    public GeneralSubtreeBuilder AddUri(Uri uri)
        => Add(new UriConstraint(uri));

    public GeneralSubtreeBuilder AddIPAddress(IPAddress ipAddress, IPAddress? subnetMask = null)
        => Add(new IPAddressConstraint(ipAddress, subnetMask));

    private GeneralSubtreeBuilder Add(GeneralNameConstraint generalNameConstraint)
        => this with {
            NameConstraints = NameConstraints.Add(generalNameConstraint)
        };
    
    private ImmutableList<GeneralNameConstraint> NameConstraints { get; init; }
        = ImmutableList<GeneralNameConstraint>.Empty;
}
