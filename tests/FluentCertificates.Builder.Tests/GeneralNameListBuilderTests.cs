using System.Collections.Immutable;
using System.Formats.Asn1;
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
    public async Task AddIPAddress_IPv6_EncodedWithCorrectLength()
    {
        var ip = IPAddress.Parse("2001:db8::1");
        var encoded = EncodeSingleIPAddress(new GeneralNameListBuilder().AddIPAddress(ip));

        //IPv6 addresses encode as 16 bytes, not 4
        await Assert.That(encoded.Length).IsEqualTo(16);
        await Assert.That(encoded).IsEquivalentTo(ip.GetAddressBytes(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddIPAddress_IPv4_EncodedAsFourBytes()
    {
        var ip = IPAddress.Parse("192.0.2.1");
        var encoded = EncodeSingleIPAddress(new GeneralNameListBuilder().AddIPAddress(ip));

        await Assert.That(encoded.Length).IsEqualTo(4);
        await Assert.That(encoded).IsEquivalentTo(ip.GetAddressBytes(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddIPAddress_IPv6WithSubnetMask_EncodesAddressThenMask()
    {
        var ip = IPAddress.Parse("2001:db8::");
        var mask = IPAddress.Parse("ffff:ffff:ffff:ffff::");
        var encoded = EncodeSingleIPAddress(new GeneralNameListBuilder().AddIPAddress(ip, mask));

        await Assert.That(encoded.Length).IsEqualTo(32);
        await Assert.That(encoded.Take(16)).IsEquivalentTo(ip.GetAddressBytes(), CollectionOrdering.Matching);
        await Assert.That(encoded.Skip(16)).IsEquivalentTo(mask.GetAddressBytes(), CollectionOrdering.Matching);
    }


    [Test]
    public async Task AddIPAddress_MismatchedAddressFamily_ThrowsOnEncode()
    {
        var names = new GeneralNameListBuilder()
            .AddIPAddress(IPAddress.Parse("192.0.2.1"), IPAddress.Parse("ffff:ffff::"))
            .Create();

        //Validation happens when encoding, not when adding
        await Assert.That(names).HasSingleItem();
        await Assert.That(() => names.Encode()).ThrowsExactly<ArgumentException>();
    }


    [Test]
    public async Task AddIPAddress_InvalidAddressString_Throws()
    {
        await Assert.That(() => new GeneralNameListBuilder().AddIPAddress("not-an-ip")).ThrowsExactly<FormatException>();
        await Assert.That(() => new GeneralNameListBuilder().AddIPAddress("192.0.2.1", "not-a-mask")).ThrowsExactly<FormatException>();
    }


    [Test]
    public async Task AddDnsName_Wildcard_IsPreserved()
    {
        var builder = new GeneralNameListBuilder().AddDnsName("*.example.com");
        var result = builder.Create();

        var name = (await Assert.That(result[0]).IsTypeOf<DnsNameAsn>())!;
        await Assert.That(name.DnsName).IsEqualTo("*.example.com");

        //The wildcard must survive encoding too
        await Assert.That(DecodeSingleIA5String(builder, 2)).IsEqualTo("*.example.com");
    }


    [Test]
    public async Task AddDnsName_EmptyString_IsStoredAndEncoded()
    {
        //Documents current behaviour: no validation, the empty name round-trips
        var builder = new GeneralNameListBuilder().AddDnsName("");
        var name = (await Assert.That(builder.Create()[0]).IsTypeOf<DnsNameAsn>())!;

        await Assert.That(name.DnsName).IsEqualTo(String.Empty);
        await Assert.That(DecodeSingleIA5String(builder, 2)).IsEqualTo(String.Empty);
    }


    [Test]
    public async Task AddEmailAddress_EmptyString_IsStoredAndEncoded()
    {
        //Documents current behaviour: no validation, the empty address round-trips
        var builder = new GeneralNameListBuilder().AddEmailAddress("");
        var name = (await Assert.That(builder.Create()[0]).IsTypeOf<Rfc822NameAsn>())!;

        await Assert.That(name.EmailAddress).IsEqualTo(String.Empty);
        await Assert.That(DecodeSingleIA5String(builder, 1)).IsEqualTo(String.Empty);
    }


    private static byte[] EncodeSingleIPAddress(GeneralNameListBuilder builder)
        => new AsnReader(builder.Create().Encode(), AsnEncodingRules.DER)
            .ReadSequence()
            .ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 7));


    private static string DecodeSingleIA5String(GeneralNameListBuilder builder, int contextTag)
        => new AsnReader(builder.Create().Encode(), AsnEncodingRules.DER)
            .ReadSequence()
            .ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, contextTag));


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
