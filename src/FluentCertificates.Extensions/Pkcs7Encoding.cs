namespace FluentCertificates;

/// <summary>
/// Selects how a PKCS#7 export is encoded. Both are in common use under <c>.p7b</c> and <c>.p7c</c>,
/// and they carry the same bundle.
/// </summary>
public enum Pkcs7Encoding
{
    /// <summary>
    /// Binary DER, which is what the structure is natively and what a PKCS#7 reader accepts without
    /// unwrapping. The default.
    /// </summary>
    Der,

    /// <summary>
    /// The DER base64-encoded inside a <c>PKCS7</c> block, for text-only transports.
    /// </summary>
    /// <remarks>
    /// RFC 7468 s8 defines the <c>PKCS7</c> label and says implementations SHOULD NOT generate it where
    /// the <c>CMS</c> label of s9 will do. Practice went the other way: OpenSSL writes <c>PKCS7</c> and
    /// support for <c>CMS</c> is thin, so <c>PKCS7</c> is what is written here.
    /// </remarks>
    Pem
}
