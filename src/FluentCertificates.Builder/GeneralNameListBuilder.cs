using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    public GeneralNameListBuilder AddEmailAddresses(params IEnumerable<string> emailAddresses)
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
    public GeneralNameListBuilder AddDnsNames(params IEnumerable<string> dnsNames)
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
    public GeneralNameListBuilder AddUris(params IEnumerable<Uri> uris)
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
    public GeneralNameListBuilder AddIPAddresses(params IEnumerable<string> ipAddresses)
        => AddRange(ipAddresses.Select(x => new IPAddressNameAsn(IPAddress.Parse(x))));


    /// <summary>
    /// Adds multiple IP addresses to the list. Subnet masks are not supported in this method.
    /// </summary>
    /// <param name="ipAddresses">The IP addresses to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the IP addresses added.</returns>
    public GeneralNameListBuilder AddIPAddresses(params IEnumerable<IPAddress> ipAddresses)
        => AddRange(ipAddresses.Select(x => new IPAddressNameAsn(x)));


    /// <summary>
    /// Adds an <c>otherName</c> to the list, whose value is supplied already encoded.
    /// </summary>
    /// <param name="typeId">The OID naming the kind of name being added.</param>
    /// <param name="derEncodedValue">The DER encoding of the value, including its own tag and length.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the name added.</returns>
    /// <remarks>An <c>otherName</c>'s value may be any ASN.1 type, chosen by <paramref name="typeId"/>, so the
    /// caller owns its encoding and its correctness. <see cref="AddUserPrincipalName"/> covers the one case
    /// where the OID fixes the value to a string.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="typeId"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="typeId"/> has no value, or
    /// <paramref name="derEncodedValue"/> is empty.</exception>
    public GeneralNameListBuilder AddOtherName(Oid typeId, ReadOnlySpan<byte> derEncodedValue)
    {
        var oidValue = GetOidValue(typeId, nameof(typeId));
        if (derEncodedValue.IsEmpty) {
            throw new ArgumentException("An otherName's value cannot be empty; it must be a complete DER encoding.", nameof(derEncodedValue));
        }
        return Add(new OtherNameAsn(oidValue, derEncodedValue));
    }


    /// <summary>
    /// Adds multiple <c>otherName</c> entries to the list, each value supplied already encoded.
    /// </summary>
    /// <param name="otherNames">The names to add, each an OID paired with the DER encoding of its value.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the names added.</returns>
    /// <exception cref="ArgumentNullException">An OID is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An OID has no value, or a value is null or empty.</exception>
    public GeneralNameListBuilder AddOtherNames(params IEnumerable<(Oid TypeId, byte[] Value)> otherNames)
        => AddRange(otherNames.Select(x => {
            var oidValue = GetOidValue(x.TypeId, nameof(otherNames));
            if (x.Value is not { Length: > 0 }) {
                throw new ArgumentException("An otherName's value cannot be empty; it must be a complete DER encoding.", nameof(otherNames));
            }
            return new OtherNameAsn(oidValue, x.Value);
        }));


    /// <summary>
    /// Adds a User Principal Name to the list, as the <c>otherName</c> form Active Directory reads.
    /// </summary>
    /// <param name="upn">The user principal name, such as <c>user@corp.example</c>.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the name added.</returns>
    /// <remarks>The name is encoded under OID <c>1.3.6.1.4.1.311.20.2.3</c> with a UTF8String value, which is
    /// the pairing Windows expects.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="upn"/> is <see langword="null"/>.</exception>
    public GeneralNameListBuilder AddUserPrincipalName(string upn)
        => Add(new OtherNameAsn(Oids.UserPrincipalName, EncodeUtf8String(upn, nameof(upn))));


    /// <summary>
    /// Adds multiple User Principal Names to the list.
    /// </summary>
    /// <param name="upns">The user principal names to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the names added.</returns>
    /// <exception cref="ArgumentNullException">A name is <see langword="null"/>.</exception>
    public GeneralNameListBuilder AddUserPrincipalNames(params IEnumerable<string> upns)
        => AddRange(upns.Select(x => new OtherNameAsn(Oids.UserPrincipalName, EncodeUtf8String(x, nameof(upns)))));


    /// <summary>
    /// Adds a <c>directoryName</c> to the list.
    /// </summary>
    /// <param name="name">The X.500 name to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the name added.</returns>
    public GeneralNameListBuilder AddDirectoryName(X500DistinguishedName name)
        => Add(new DirectoryNameAsn(name));


    /// <summary>
    /// Adds a <c>directoryName</c> to the list.
    /// </summary>
    /// <param name="name">A builder for the X.500 name to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the name added.</returns>
    public GeneralNameListBuilder AddDirectoryName(X500NameBuilder name)
        => AddDirectoryName(name.Create());


    /// <summary>
    /// Adds a <c>directoryName</c> to the list, parsed from its string form.
    /// </summary>
    /// <param name="name">The X.500 name to add, such as <c>CN=Example, O=Example Org</c>.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the name added.</returns>
    public GeneralNameListBuilder AddDirectoryName(string name)
        => AddDirectoryName(new X500DistinguishedName(name));


    /// <summary>
    /// Adds a <c>directoryName</c> to the list, built by the supplied function.
    /// </summary>
    /// <param name="configureName">A function to configure the X.500 name.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the name added.</returns>
    public GeneralNameListBuilder AddDirectoryName(Func<X500NameBuilder, X500NameBuilder> configureName)
        => AddDirectoryName(configureName(new X500NameBuilder()));


    /// <summary>
    /// Adds multiple <c>directoryName</c> entries to the list.
    /// </summary>
    /// <param name="names">The X.500 names to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the names added.</returns>
    public GeneralNameListBuilder AddDirectoryNames(params IEnumerable<X500DistinguishedName> names)
        => AddRange(names.Select(x => new DirectoryNameAsn(x)));


    /// <summary>
    /// Adds multiple <c>directoryName</c> entries to the list.
    /// </summary>
    /// <param name="names">Builders for the X.500 names to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the names added.</returns>
    public GeneralNameListBuilder AddDirectoryNames(params IEnumerable<X500NameBuilder> names)
        => AddRange(names.Select(x => new DirectoryNameAsn(x.Create())));


    /// <summary>
    /// Adds multiple <c>directoryName</c> entries to the list, each parsed from its string form.
    /// </summary>
    /// <param name="names">The X.500 names to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the names added.</returns>
    public GeneralNameListBuilder AddDirectoryNames(params IEnumerable<string> names)
        => AddRange(names.Select(x => new DirectoryNameAsn(new X500DistinguishedName(x))));


    /// <summary>
    /// Adds a <c>registeredID</c> to the list.
    /// </summary>
    /// <param name="oid">The OID to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the name added.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="oid"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="oid"/> has no value.</exception>
    public GeneralNameListBuilder AddRegisteredId(Oid oid)
        => Add(new RegisteredIdNameAsn(GetOidValue(oid, nameof(oid))));


    /// <summary>
    /// Adds multiple <c>registeredID</c> entries to the list.
    /// </summary>
    /// <param name="oids">The OIDs to add.</param>
    /// <returns>A new <see cref="GeneralNameListBuilder"/> with the names added.</returns>
    /// <exception cref="ArgumentNullException">An OID is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An OID has no value.</exception>
    public GeneralNameListBuilder AddRegisteredIds(params IEnumerable<Oid> oids)
        => AddRange(oids.Select(x => new RegisteredIdNameAsn(GetOidValue(x, nameof(oids)))));


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


    /// <summary>Returns an OID's dotted-decimal value, which is the only part of it that can be encoded.</summary>
    /// <param name="oid">The OID to read.</param>
    /// <param name="paramName">The name of the parameter the OID arrived in.</param>
    /// <returns>The OID's value.</returns>
    private static string GetOidValue(Oid oid, string paramName)
    {
        ArgumentNullException.ThrowIfNull(oid, paramName);
        //An Oid constructed from a friendly name alone, or from nothing, has no value to write
        return oid.Value
            ?? throw new ArgumentException("The OID has no dotted-decimal value to encode.", paramName);
    }


    /// <summary>Encodes a string as a DER UTF8String, tag and length included.</summary>
    /// <param name="value">The string to encode.</param>
    /// <param name="paramName">The name of the parameter the string arrived in.</param>
    /// <returns>The complete DER encoding of the string.</returns>
    private static byte[] EncodeUtf8String(string value, string paramName)
    {
        ArgumentNullException.ThrowIfNull(value, paramName);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
        return writer.Encode();
    }
    
    
    /// <summary>Determines whether another builder holds the same general names in the same order.</summary>
    /// <param name="other">The other builder to compare.</param>
    /// <returns>True if equal; otherwise, false.</returns>
    /// <remarks>This is the record's value equality, so <see cref="ImmutableList{T}"/>'s reference equality
    /// does not stand in for it.</remarks>
    public virtual bool Equals(GeneralNameListBuilder? other)
        => other is not null
           && other.GetType() == GetType()
           && (ReferenceEquals(this, other) || NameConstraints.SequenceEqual(other.NameConstraints));


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var name in NameConstraints) {
            hash.Add(name);
        }
        return hash.ToHashCode();
    }


    /// <summary>
    /// Gets the current list of <see cref="GeneralName"/> constraints.
    /// </summary>
    private ImmutableList<GeneralName> NameConstraints { get; init; }
        = ImmutableList<GeneralName>.Empty;
}
