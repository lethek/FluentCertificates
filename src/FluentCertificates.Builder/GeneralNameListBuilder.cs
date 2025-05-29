using System.Collections.Immutable;
using System.Net;
using FluentCertificates.Internals.GeneralNames;

namespace FluentCertificates;

/// <summary>
/// Provides a builder for constructing a list of <see cref="GeneralName"/> objects,
/// commonly used for X.509 Subject Alternative Name and Name Constraints extensions.
/// </summary>
public record GeneralNameListBuilder
{
    /// <summary>
    /// Creates a list of the current <see cref="GeneralName"/> constraints.
    /// </summary>
    /// <returns>A list containing all added <see cref="GeneralName"/> instances.</returns>
    public ImmutableList<GeneralName> Create()
        => NameConstraints;

    
    /// <summary>
    /// Adds an RFC822 (email) name to the list.
    /// </summary>
    /// <param name="emailAddress">The email address to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the email address added.</returns>
    public GeneralNameListBuilder AddEmailAddress(string emailAddress)
        => Add(new Rfc822NameAsn(emailAddress));

    
    /// <summary>
    /// Adds multiple RFC822 (email) names to the list.
    /// </summary>
    /// <param name="emailAddresses">The email addresses to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the email addresses added.</returns>
    public GeneralNameListBuilder AddEmailAddresses(params string[] emailAddresses)
        => AddRange(emailAddresses.Select(x => new Rfc822NameAsn(x)));
    
    
    /// <summary>
    /// Adds a DNS name to the list.
    /// </summary>
    /// <param name="dnsName">The DNS name to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the DNS name added.</returns>
    public GeneralNameListBuilder AddDnsName(string dnsName)
        => Add(new DnsNameAsn(dnsName));

    
    /// <summary>
    /// Adds multiple DNS names to the list.
    /// </summary>
    /// <param name="dnsNames">The DNS names to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the DNS names added.</returns>
    public GeneralNameListBuilder AddDnsNames(params string[] dnsNames)
        => AddRange(dnsNames.Select(x => new DnsNameAsn(x)));

    
    /// <summary>
    /// Adds a URI to the list.
    /// </summary>
    /// <param name="uri">The URI to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the URI added.</returns>
    public GeneralNameListBuilder AddUri(Uri uri)
        => Add(new UriNameAsn(uri));
    
    
    /// <summary>
    /// Adds multiple URIs to the list.
    /// </summary>
    /// <param name="uris">The URIs to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the URIs added.</returns>
    public GeneralNameListBuilder AddUris(params Uri[] uris)
        => AddRange(uris.Select(x => new UriNameAsn(x)));
    
    
    /// <summary>
    /// Adds an IP address (as a string) and an optional subnet mask (as a string) to the list.
    /// </summary>
    /// <param name="ipAddress">The IP address to add, in string format.</param>
    /// <param name="subnetMask">The optional subnet mask to add, in string format. If null, no subnet mask is used.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the IP address (and optional subnet mask) added.</returns>
    public GeneralNameListBuilder AddIPAddress(string ipAddress, string? subnetMask = null)
        => Add(new IPAddressNameAsn(IPAddress.Parse(ipAddress), subnetMask != null ? IPAddress.Parse(subnetMask) : null));

    
    /// <summary>
    /// Adds an IP address (optionally with subnet mask) to the list.
    /// </summary>
    /// <param name="ipAddress">The IP address to add.</param>
    /// <param name="subnetMask">The optional subnet mask.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the IP address added.</returns>
    public GeneralNameListBuilder AddIPAddress(IPAddress ipAddress, IPAddress? subnetMask = null)
        => Add(new IPAddressNameAsn(ipAddress, subnetMask));


    /// <summary>
    /// Adds multiple IP addresses (as strings) to the list. Subnet masks are not supported in this method.
    /// </summary>
    /// <param name="ipAddresses">The IP addresses to add, each in string format.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the IP addresses added.</returns>
    public GeneralNameListBuilder AddIPAddresses(params string[] ipAddresses)
        => AddRange(ipAddresses.Select(x => new IPAddressNameAsn(IPAddress.Parse(x))));


    /// <summary>
    /// Adds multiple IP addresses to the list. Subnet masks are not supported in this method.
    /// </summary>
    /// <param name="ipAddresses">The IP addresses to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the IP addresses added.</returns>
    public GeneralNameListBuilder AddIPAddresses(params IPAddress[] ipAddresses)
        => AddRange(ipAddresses.Select(x => new IPAddressNameAsn(x)));


    /// <summary>
    /// Implicitly converts a <see cref="GeneralNameListBuilder"/> instance to an <see cref="ImmutableList{GeneralName}"/>.
    /// This allows a <see cref="GeneralNameListBuilder"/> to be used wherever an <see cref="ImmutableList{GeneralName}"/> is expected,
    /// by returning the list of <see cref="GeneralName"/> objects built by the builder.
    /// </summary>
    /// <param name="builder">The <see cref="GeneralNameListBuilder"/> instance to convert.</param>
    /// <returns>An <see cref="ImmutableList{GeneralName}"/> containing all added <see cref="GeneralName"/> instances.</returns>
    public static implicit operator ImmutableList<GeneralName>(GeneralNameListBuilder builder)
        => builder.Create();

    
    /// <summary>
    /// Adds a <see cref="GeneralName"/> to the list.
    /// </summary>
    /// <param name="generalNameConstraint">The general name to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the general name added.</returns>
    private GeneralNameListBuilder Add(GeneralName generalNameConstraint)
        => this with {
            NameConstraints = NameConstraints.Add(generalNameConstraint)
        };

    
    /// <summary>
    /// Adds a range of <see cref="GeneralName"/> objects to the list.
    /// </summary>
    /// <param name="generalNameConstraints">The general names to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the general names added.</returns>
    private GeneralNameListBuilder AddRange(IEnumerable<GeneralName> generalNameConstraints)
        => this with {
            NameConstraints = NameConstraints.AddRange(generalNameConstraints)
        };
    
    
    /// <summary>
    /// Gets the current list of <see cref="GeneralName"/> constraints.
    /// </summary>
    private ImmutableList<GeneralName> NameConstraints { get; init; }
        = ImmutableList<GeneralName>.Empty;
}
