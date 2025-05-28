using System.Collections.Immutable;
using System.Net;
using FluentCertificates.Internals.GeneralNames;

namespace FluentCertificates;

public record GeneralNameListBuilder {
    public GeneralNameList Create()
        => new GeneralNameList(NameConstraints);

    public GeneralNameListBuilder AddEmailAddress(string emailAddress)
        => Add(new Rfc822NameAsn(emailAddress));

    public GeneralNameListBuilder AddEmailAddresses(params string[] emailAddresses)
        => AddRange(emailAddresses.Select(x => new Rfc822NameAsn(x)));
    
    public GeneralNameListBuilder AddDnsName(string dnsName)
        => Add(new DnsNameAsn(dnsName));

    public GeneralNameListBuilder AddDnsNames(params string[] dnsNames)
        => AddRange(dnsNames.Select(x => new DnsNameAsn(x)));

    public GeneralNameListBuilder AddUri(Uri uri)
        => Add(new UriNameAsn(uri));

    public GeneralNameListBuilder AddUris(params Uri[] uris)
        => AddRange(uris.Select(x => new UriNameAsn(x)));
    
    public GeneralNameListBuilder AddIPAddress(IPAddress ipAddress, IPAddress? subnetMask = null)
        => Add(new IPAddressNameAsn(ipAddress, subnetMask));

    public GeneralNameListBuilder AddIPAddresses(params IPAddress[] ipAddresses)
        => AddRange(ipAddresses.Select(x => new IPAddressNameAsn(x)));
    
    private GeneralNameListBuilder Add(GeneralName generalNameConstraint)
        => this with {
            NameConstraints = NameConstraints.Add(generalNameConstraint)
        };

    private GeneralNameListBuilder AddRange(IEnumerable<GeneralName> generalNameConstraints)
        => this with {
            NameConstraints = NameConstraints.AddRange(generalNameConstraints)
        };
    
    private ImmutableList<GeneralName> NameConstraints { get; init; }
        = ImmutableList<GeneralName>.Empty;
}
