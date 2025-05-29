namespace FluentCertificates;

/// <summary>
/// Specifies the intended usage of an X.509 certificate.
/// </summary>
public enum CertificateUsage
{
    /// <summary>
    /// Certificate Authority (CA) usage.
    /// </summary>    
    CA,

    /// <summary>
    /// Client authentication usage.
    /// </summary>
    Client,

    /// <summary>
    /// Server authentication usage (e.g. typical HTTPS certificates for the web).
    /// </summary>
    Server,

    /// <summary>
    /// Code signing usage.
    /// </summary>
    CodeSign,

    /// <summary>
    /// S/MIME (email protection) usage.
    /// </summary>
    SMime
}
