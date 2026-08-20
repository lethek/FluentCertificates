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
    /// <see cref="CertificateExportBuilder.Anchor"/>, falling back to the leaf of the sorted chain and
    /// throwing when there is neither. <c>FilterPrivateKeys</c> has no anchor to consult and always
    /// takes the first certificate in the sequence.
    /// </remarks>
    Primary,

    /// <summary>Export no private keys.</summary>
    None
}
