namespace FluentCertificates.Internals.GeneralNames;

/// <summary>
/// Shared validation for GeneralName types encoded as IA5String (dNSName and rfc822Name).
/// Only checks constraints which hold regardless of whether the name is used in a
/// SubjectAlternativeName or a NameConstraints extension: an empty name, a leading-dot
/// subtree such as ".example.com" and a bare domain are all legal name-constraint forms
/// and are deliberately not rejected here.
/// </summary>
internal static class Ia5NameValidator
{
    /// <summary>Maximum length of a DNS name, per RFC 1035.</summary>
    public const int MaxDnsNameLength = 253;

    /// <summary>Maximum length of a single DNS label, per RFC 1035.</summary>
    public const int MaxDnsLabelLength = 63;

    /// <summary>Maximum length of an email address, per RFC 5321.</summary>
    public const int MaxEmailAddressLength = 254;

    /// <summary>Maximum length of the local part of an email address, per RFC 5321.</summary>
    public const int MaxEmailLocalPartLength = 64;


    public static string ValidateDnsName(string dnsName, string paramName)
    {
        ValidateIa5(dnsName, paramName, MaxDnsNameLength, "DNS name");

        foreach (var label in dnsName.Split('.')) {
            if (label.Length > MaxDnsLabelLength) {
                throw new ArgumentException(
                    $"DNS label '{label}' is {label.Length} characters; the maximum is {MaxDnsLabelLength}.",
                    paramName);
            }
        }

        return dnsName;
    }


    public static string ValidateEmailAddress(string emailAddress, string paramName)
    {
        ValidateIa5(emailAddress, paramName, MaxEmailAddressLength, "Email address");

        //A bare domain (no local part) is a valid name-constraint form, so only check the
        //local part when there is an '@' to delimit it.
        var at = emailAddress.LastIndexOf('@');
        if (at > MaxEmailLocalPartLength) {
            throw new ArgumentException(
                $"Email address local part is {at} characters; the maximum is {MaxEmailLocalPartLength}.",
                paramName);
        }

        return emailAddress;
    }


    private static void ValidateIa5(string value, string paramName, int maxLength, string description)
    {
        for (var i = 0; i < value.Length; i++) {
            var c = value[i];
            if (c > 0x7F) {
                throw new ArgumentException(
                    $"{description} contains the non-ASCII character '{c}' at index {i}. "
                    + "IA5String cannot encode it; convert the name with IdnMapping.GetAscii first.",
                    paramName);
            }
            if (Char.IsControl(c)) {
                throw new ArgumentException(
                    $"{description} contains a control character (U+{(int)c:X4}) at index {i}.",
                    paramName);
            }
        }

        if (value.Length > maxLength) {
            throw new ArgumentException(
                $"{description} is {value.Length} characters; the maximum is {maxLength}.",
                paramName);
        }
    }
}
