using System.Collections.Immutable;
using System.Net;
using FluentCertificates.Internals.GeneralNames;


namespace FluentCertificates;

public class GeneralNameListBuilderTests
{
    [Fact]
    public void Create_ReturnsEmptyList_WhenNoNamesAdded()
    {
        var builder = new GeneralNameListBuilder();
        var result = builder.Create();
        Assert.Empty(result);
    }


    [Fact]
    public void AddEmailAddress_AddsSingleEmail()
    {
        var builder = new GeneralNameListBuilder()
            .AddEmailAddress("user@example.com");
        var result = builder.Create();

        Assert.Single(result);
        Assert.IsType<Rfc822NameAsn>(result[0]);
    }


    [Fact]
    public void AddEmailAddresses_AddsMultipleEmails()
    {
        var builder = new GeneralNameListBuilder()
            .AddEmailAddresses("a@b.com", "c@d.com");
        var result = builder.Create();

        Assert.Equal(2, result.Count);
        Assert.All(result, x => Assert.IsType<Rfc822NameAsn>(x));
    }


    [Fact]
    public void AddDnsName_AddsSingleDns()
    {
        var builder = new GeneralNameListBuilder()
            .AddDnsName("example.com");
        var result = builder.Create();

        Assert.Single(result);
        Assert.IsType<DnsNameAsn>(result[0]);
    }


    [Fact]
    public void AddDnsNames_AddsMultipleDns()
    {
        var builder = new GeneralNameListBuilder()
            .AddDnsNames("a.com", "b.com");
        var result = builder.Create();

        Assert.Equal(2, result.Count);
        Assert.All(result, x => Assert.IsType<DnsNameAsn>(x));
    }

    
    [Fact]
    public void AddUri_AddsSingleUri()
    {
        var uri = new Uri("https://example.com");
        var builder = new GeneralNameListBuilder()
            .AddUri(uri);
        var result = builder.Create();

        Assert.Single(result);
        Assert.IsType<UriNameAsn>(result[0]);
    }

    
    [Fact]
    public void AddUris_AddsMultipleUris()
    {
        var uris = new[] { new Uri("https://a.com"), new Uri("https://b.com") };
        var builder = new GeneralNameListBuilder()
            .AddUris(uris);
        var result = builder.Create();

        Assert.Equal(2, result.Count);
        Assert.All(result, x => Assert.IsType<UriNameAsn>(x));
    }

    
    [Fact]
    public void AddIPAddress_AddsSingleIp()
    {
        var ip = IPAddress.Parse("127.0.0.1");
        var builder = new GeneralNameListBuilder()
            .AddIPAddress(ip);
        var result = builder.Create();

        Assert.Single(result);
        Assert.IsType<IPAddressNameAsn>(result[0]);
    }

    
    [Fact]
    public void AddIPAddress_WithSubnetMask_AddsIpWithMask()
    {
        var ip = IPAddress.Parse("192.168.1.0");
        var mask = IPAddress.Parse("255.255.255.0");
        var builder = new GeneralNameListBuilder()
            .AddIPAddress(ip, mask);
        var result = builder.Create();

        Assert.Single(result);
        var ipName = Assert.IsType<IPAddressNameAsn>(result[0]);
        Assert.Equal(ip, ipName.IPAddress);
        Assert.Equal(mask, ipName.SubnetMask);
    }

    
    [Fact]
    public void AddIPAddresses_AddsMultipleIps()
    {
        var ips = new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("2.2.2.2") };
        var builder = new GeneralNameListBuilder()
            .AddIPAddresses(ips);
        var result = builder.Create();

        Assert.Equal(2, result.Count);
        Assert.All(result, x => Assert.IsType<IPAddressNameAsn>(x));
    }

    
    [Fact]
    public void AddIPAddress_String_AddsSingleIp()
    {
        var builder = new GeneralNameListBuilder()
            .AddIPAddress("10.0.0.1");
        var result = builder.Create();

        Assert.Single(result);
        var ipName = Assert.IsType<IPAddressNameAsn>(result[0]);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), ipName.IPAddress);
        Assert.Null(ipName.SubnetMask);
    }

    
    [Fact]
    public void AddIPAddress_StringWithSubnet_AddsIpWithMask()
    {
        var builder = new GeneralNameListBuilder()
            .AddIPAddress("192.168.0.0", "255.255.255.0");
        var result = builder.Create();

        Assert.Single(result);
        var ipName = Assert.IsType<IPAddressNameAsn>(result[0]);
        Assert.Equal(IPAddress.Parse("192.168.0.0"), ipName.IPAddress);
        Assert.Equal(IPAddress.Parse("255.255.255.0"), ipName.SubnetMask);
    }

    
    [Fact]
    public void AddIPAddresses_String_AddsMultipleIps()
    {
        var builder = new GeneralNameListBuilder()
            .AddIPAddresses("8.8.8.8", "8.8.4.4");
        var result = builder.Create();

        Assert.Equal(2, result.Count);
        Assert.All(result, x => Assert.IsType<IPAddressNameAsn>(x));
        Assert.Equal(IPAddress.Parse("8.8.8.8"), ((IPAddressNameAsn)result[0]).IPAddress);
        Assert.Equal(IPAddress.Parse("8.8.4.4"), ((IPAddressNameAsn)result[1]).IPAddress);
        Assert.All(result, x => Assert.Null(((IPAddressNameAsn)x).SubnetMask));
    }
    
    
    [Fact]
    public void ImplicitConversion_ReturnsSameAsCreate()
    {
        var builder = new GeneralNameListBuilder()
            .AddDnsName("example.com");

        ImmutableList<GeneralName> list = builder;

        Assert.Equal(builder.Create(), list);
    }

    
    [Fact]
    public void AddMethods_AreImmutable()
    {
        var builder = new GeneralNameListBuilder();
        var builder2 = builder.AddDnsName("a.com");

        Assert.NotSame(builder, builder2);
        Assert.Empty(builder.Create());
        Assert.Single(builder2.Create());
    }
}