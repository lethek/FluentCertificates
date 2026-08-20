namespace FluentCertificates;

/// <summary>
/// Selects which private keys an export includes.
/// </summary>
public enum ExportKeys
{
    /// <summary>Export every private key present.</summary>
    All,

    /// <summary>
    /// Export only the first certificate's private key, stripping the others. Certificates forming a
    /// single issuer chain are ordered leaf-first at export, so the first one is the chain's leaf.
    /// Exporting throws when they are not a single chain, since the leaf is then unknown.
    /// </summary>
    Leaf,

    /// <summary>Export no private keys.</summary>
    None
}
