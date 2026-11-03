namespace FluentCertificates;

/// <summary>Which certificates a CRL claims to list the revocations of.</summary>
/// <remarks>A CRL that states no coverage claims to be the complete list for its issuer, so a relying party
/// that is handed one shard of a sharded CRL would read its silence about a certificate as "not revoked".
/// That is why <see cref="CrlDistributionPoint.Covers"/> is never left unstated.</remarks>
public enum CrlCoverage
{
    /// <summary>Every certificate the CRL's issuer issued, whether or not they are certificate authorities.</summary>
    AllCertificates,

    /// <summary>Only end-entity certificates: those that are not certificate authorities.</summary>
    EndEntityCertificates,

    /// <summary>Only certificate authority certificates.</summary>
    CACertificates
}
