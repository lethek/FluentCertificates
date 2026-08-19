using System.Collections.Immutable;
using System.Net;
using FluentCertificates.Internals.GeneralNames;

using TUnit.Assertions.Enums;


namespace FluentCertificates;

public class GeneralNameListBuilderTests
{
    [Test]
    public async Task Create_ReturnsEmptyList_WhenNoNamesAdded()
    {
        var builder = new GeneralNameListBuilder();
        var result = builder.Create();
        await Assert.That(result).IsEmpty();
    }


    [Test]
    public async Task AddEmailAddress_AddsSingleEmail()
    {
        var builder = new GeneralNameListBuilder()
            .AddEmailAddress("user@example.com");
        var result = builder.Create();

        await Assert.That(result).HasSingleItem();
        var name = (await Assert.That(result[0]).IsTypeOf<Rfc822NameAsn>())!;
        await Assert.That(name.EmailAddress).IsEqualTo("user@example.com");
    }


    [Test]
    public async Task AddEmailAddresses_AddsMultipleEmails()
    {
        var builder = new GeneralNameListBuilder()
            .AddEmailAddresses("a@b.com", "c@d.com");
        var result = builder.Create();

        await Assert
            .That(result.Cast<Rfc822NameAsn>().Select(x => x.EmailAddress))
            .IsEquivalentTo(new[] { "a@b.com", "c@d.com" }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddDnsName_AddsSingleDns()
    {
        var builder = new GeneralNameListBuilder()
            .AddDnsName("example.com");
        var result = builder.Create();

        await Assert.That(result).HasSingleItem();
        var name = (await Assert.That(result[0]).IsTypeOf<DnsNameAsn>())!;
        await Assert.That(name.DnsName).IsEqualTo("example.com");
    }


    [Test]
    public async Task AddDnsNames_AddsMultipleDns()
    {
        var builder = new GeneralNameListBuilder()
            .AddDnsNames("a.com", "b.com");
        var result = builder.Create();

        await Assert
            .That(result.Cast<DnsNameAsn>().Select(x => x.DnsName))
            .IsEquivalentTo(new[] { "a.com", "b.com" }, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddUri_AddsSingleUri()
    {
        var uri = new Uri("https://example.com");
        var builder = new GeneralNameListBuilder()
            .AddUri(uri);
        var result = builder.Create();

        await Assert.That(result).HasSingleItem();
        var name = (await Assert.That(result[0]).IsTypeOf<UriNameAsn>())!;
        await Assert.That(name.Uri).IsEqualTo(uri);
    }


    [Test]
    public async Task AddUris_AddsMultipleUris()
    {
        var uris = new[] { new Uri("https://a.com"), new Uri("https://b.com") };
        var builder = new GeneralNameListBuilder()
            .AddUris(uris);
        var result = builder.Create();

        await Assert
            .That(result.Cast<UriNameAsn>().Select(x => x.Uri))
            .IsEquivalentTo(uris, CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddIPAddress_AddsSingleIp()
    {
        var ip = IPAddress.Parse("127.0.0.1");
        var builder = new GeneralNameListBuilder()
            .AddIPAddress(ip);
        var result = builder.Create();

        await Assert.That(result).HasSingleItem();
        var ipName = (await Assert.That(result[0]).IsTypeOf<IPAddressNameAsn>())!;
        await Assert.That(ipName.IPAddress).IsEqualTo(ip);
        await Assert.That(ipName.SubnetMask).IsNull();
    }


    [Test]
    public async Task AddIPAddress_WithSubnetMask_AddsIpWithMask()
    {
        var ip = IPAddress.Parse("192.168.1.0");
        var mask = IPAddress.Parse("255.255.255.0");
        var builder = new GeneralNameListBuilder()
            .AddIPAddress(ip, mask);
        var result = builder.Create();

        await Assert.That(result).HasSingleItem();
        var ipName = (await Assert.That(result[0]).IsTypeOf<IPAddressNameAsn>())!;
        await Assert.That(ipName.IPAddress).IsEqualTo(ip);
        await Assert.That(ipName.SubnetMask).IsEqualTo(mask);
    }


    [Test]
    public async Task AddIPAddresses_AddsMultipleIps()
    {
        var ips = new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("2.2.2.2") };
        var builder = new GeneralNameListBuilder()
            .AddIPAddresses(ips);
        var result = builder.Create();

        await Assert
            .That(result.Cast<IPAddressNameAsn>().Select(x => x.IPAddress.ToString()))
            .IsEquivalentTo(ips.Select(x => x.ToString()), CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddIPAddress_String_AddsSingleIp()
    {
        var builder = new GeneralNameListBuilder()
            .AddIPAddress("10.0.0.1");
        var result = builder.Create();

        await Assert.That(result).HasSingleItem();
        var ipName = (await Assert.That(result[0]).IsTypeOf<IPAddressNameAsn>())!;
        await Assert.That(ipName.IPAddress).IsEqualTo(IPAddress.Parse("10.0.0.1"));
        await Assert.That(ipName.SubnetMask).IsNull();
    }


    [Test]
    public async Task AddIPAddress_StringWithSubnet_AddsIpWithMask()
    {
        var builder = new GeneralNameListBuilder()
            .AddIPAddress("192.168.0.0", "255.255.255.0");
        var result = builder.Create();

        await Assert.That(result).HasSingleItem();
        var ipName = (await Assert.That(result[0]).IsTypeOf<IPAddressNameAsn>())!;
        await Assert.That(ipName.IPAddress).IsEqualTo(IPAddress.Parse("192.168.0.0"));
        await Assert.That(ipName.SubnetMask).IsEqualTo(IPAddress.Parse("255.255.255.0"));
    }


    [Test]
    public async Task AddIPAddresses_String_AddsMultipleIps()
    {
        var builder = new GeneralNameListBuilder()
            .AddIPAddresses("8.8.8.8", "8.8.4.4");
        var result = builder.Create();

        await Assert
            .That(result.Cast<IPAddressNameAsn>().Select(x => x.IPAddress.ToString()))
            .IsEquivalentTo(new[] { "8.8.8.8", "8.8.4.4" }, CollectionOrdering.Matching);
        await Assert.That(result.Cast<IPAddressNameAsn>()).All(x => x.SubnetMask == null);
    }


    [Test]
    public async Task ImplicitConversion_ReturnsSameAsCreate()
    {
        var builder = new GeneralNameListBuilder()
            .AddDnsName("example.com");

        ImmutableList<GeneralName> list = builder;

        await Assert.That(list).IsEquivalentTo(builder.Create(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddMethods_AreImmutable()
    {
        var builder = new GeneralNameListBuilder();
        var builder2 = builder.AddDnsName("a.com");

        await Assert.That(builder2).IsNotSameReferenceAs(builder);
        await Assert.That(builder.Create()).IsEmpty();
        await Assert.That(builder2.Create()).HasSingleItem();
    }
}
