using FluentCertificates.Internals.GeneralNames;

namespace FluentCertificates;

/// <summary>
/// The validator's diagnostics are its contract: a caller handed a rejected name needs to know which
/// character offended and where. Asserting only the exception type leaves the messages unverified.
/// </summary>
public class Ia5NameValidatorTests
{
    [Test]
    public async Task ValidateDnsName_NonAscii_NamesTheCharacterAndIndex()
    {
        var ex = await Assert.That(() => Ia5NameValidator.ValidateDnsName("caf\u00E9.example.com", "dnsName"))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("DNS name");
        await Assert.That(ex.Message).Contains("non-ASCII character '\u00E9'");
        await Assert.That(ex.Message).Contains("at index 3");
        await Assert.That(ex.Message).Contains("IdnMapping.GetAscii");
        await Assert.That(ex.ParamName).IsEqualTo("dnsName");
    }


    [Test]
    public async Task ValidateEmailAddress_NonAscii_NamesTheDescription()
    {
        var ex = await Assert.That(() => Ia5NameValidator.ValidateEmailAddress("us\u00E9r@example.com", "emailAddress"))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("Email address");
        await Assert.That(ex.Message).Contains("non-ASCII character '\u00E9'");
    }


    [Test]
    public async Task ValidateDnsName_ControlCharacter_ReportsCodePointAndIndex()
    {
        var ex = await Assert.That(() => Ia5NameValidator.ValidateDnsName("ab\u0001.com", "dnsName"))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("control character (U+0001)");
        await Assert.That(ex.Message).Contains("at index 2");
    }


    /// <summary>
    /// U+007F is the boundary: it is the last ASCII code point, so the non-ASCII check must not claim it.
    /// It is still a control character, so it is rejected by the following check and reported as one.
    /// </summary>
    [Test]
    public async Task ValidateDnsName_Delete_IsReportedAsControlNotNonAscii()
    {
        var ex = await Assert.That(() => Ia5NameValidator.ValidateDnsName("a\u007F.com", "dnsName"))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("control character (U+007F)");
        await Assert.That(ex.Message).DoesNotContain("non-ASCII");
    }


    [Test]
    public async Task ValidateDnsName_TooLong_ReportsActualAndMaximum()
    {
        var label = new String('a', 63);
        var tooLong = String.Join(".", label, label, label, new String('a', 62));
        await Assert.That(tooLong.Length).IsEqualTo(254);

        var ex = await Assert.That(() => Ia5NameValidator.ValidateDnsName(tooLong, "dnsName"))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("DNS name is 254 characters");
        await Assert.That(ex.Message).Contains("the maximum is 253");
    }


    [Test]
    public async Task ValidateDnsName_LabelTooLong_QuotesTheOffendingLabel()
    {
        var label = new String('a', 64);

        var ex = await Assert.That(() => Ia5NameValidator.ValidateDnsName(label + ".com", "dnsName"))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains($"DNS label '{label}' is 64 characters");
        await Assert.That(ex.Message).Contains("the maximum is 63");
    }


    [Test]
    public async Task ValidateEmailAddress_TooLong_ReportsActualAndMaximum()
    {
        var tooLong = new String('a', 64) + "@" + new String('b', 186) + ".com";
        await Assert.That(tooLong.Length).IsEqualTo(255);

        var ex = await Assert.That(() => Ia5NameValidator.ValidateEmailAddress(tooLong, "emailAddress"))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("Email address is 255 characters");
        await Assert.That(ex.Message).Contains("the maximum is 254");
    }


    [Test]
    public async Task ValidateEmailAddress_LocalPartTooLong_ReportsActualAndMaximum()
    {
        var ex = await Assert.That(() => Ia5NameValidator.ValidateEmailAddress(new String('a', 65) + "@b.com", "emailAddress"))
            .ThrowsExactly<ArgumentException>();

        await Assert.That(ex!.Message).Contains("local part is 65 characters");
        await Assert.That(ex.Message).Contains("the maximum is 64");
    }


    [Test]
    public async Task Validate_AcceptedNames_AreReturnedUnchanged()
    {
        await Assert.That(Ia5NameValidator.ValidateDnsName(".example.com", "dnsName")).IsEqualTo(".example.com");
        await Assert.That(Ia5NameValidator.ValidateEmailAddress("example.com", "emailAddress")).IsEqualTo("example.com");
    }
}
