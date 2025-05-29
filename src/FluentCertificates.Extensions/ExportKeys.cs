namespace FluentCertificates;

/// <summary>
/// ECDsa (Elliptic Curve Digital Signature Algorithm).
/// </summary>
public enum ExportKeys
{
    /// <summary>Export all keys.</summary>
    All,
    
    /// <summary>Export only the leaf key.</summary>
    Leaf,
    
    /// <summary>Do not export any keys.</summary>
    None
}
