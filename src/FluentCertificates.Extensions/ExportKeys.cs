namespace FluentCertificates;

/// <summary>
/// Selects which private keys an export includes.
/// </summary>
public enum ExportKeys
{
    /// <summary>Export every private key present.</summary>
    All,

    /// <summary>
    /// Export only the last certificate's private key, stripping the others. Certificates forming a
    /// single issuer chain are ordered root-first at export, so the last one is the chain's leaf.
    /// </summary>
    Leaf,

    /// <summary>Export no private keys.</summary>
    None
}
