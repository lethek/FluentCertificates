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
    SMime,

    /// <summary>
    /// OCSP response signing usage, as described by RFC 6960 §4.2.2.2.
    /// </summary>
    OcspSigning,

    /// <summary>
    /// Time-Stamping Authority (TSA) usage, as described by RFC 3161 §2.3.
    /// </summary>
    TimeStamping
}
