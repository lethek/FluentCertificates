namespace FluentCertificates;

/// <summary>
/// Selects which private keys an export includes.
/// </summary>
public enum ExportKeys
{
    /// <summary>Export every private key present.</summary>
    All,

    /// <summary>
    /// Export only the primary certificate's private key, stripping the others.
    /// </summary>
    /// <remarks>
    /// Which certificate is primary depends on where this is used. An export reads it from
    /// <see cref="CertificateExportBuilder.Anchor"/>, or takes the only certificate of a one-certificate
    /// bundle, and its output methods throw when there is neither, since a larger bundle of certificates
    /// designates no leaf. <c>FilterPrivateKeys</c> has no anchor to consult and always
    /// takes the first certificate in the sequence.
    /// </remarks>
    Primary,

    /// <summary>Export no private keys.</summary>
    None
}
