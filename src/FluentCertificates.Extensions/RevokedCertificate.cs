using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

/// <summary>One entry of a CRL: a certificate that has been revoked, and when and why.</summary>
/// <remarks>Equality compares <see cref="SerialNumber"/> and <see cref="Extensions"/> by content, and
/// <see cref="CertificateIssuer"/> by its encoded bytes. A serial number is unsigned. A loaded CRL that lists a negative one, which
/// RFC 5280 s4.1.2.2 forbids, yields its two's-complement bytes, and writing those back gives a different,
/// positive number.</remarks>
/// <param name="SerialNumber">The revoked certificate's serial number, as unsigned big-endian bytes.</param>
/// <param name="RevocationDate">When the certificate was revoked.</param>
/// <param name="Reason">Why it was revoked, or <see langword="null"/> to state no reason.</param>
/// <param name="InvalidityDate">When the key is known or suspected to have been compromised, if that is earlier
/// than <paramref name="RevocationDate"/>, or <see langword="null"/>.</param>
/// <param name="CertificateIssuer">The issuer of the revoked certificate where it is not the CRL's own issuer, as
/// happens in an indirect CRL, or <see langword="null"/> for the CRL's own issuer. Neither Windows nor .NET on
/// Linux honours an indirect CRL.</param>
public sealed record RevokedCertificate(
    ReadOnlyMemory<byte> SerialNumber,
    DateTimeOffset RevocationDate,
    X509RevocationReason? Reason = null,
    DateTimeOffset? InvalidityDate = null,
    X500DistinguishedName? CertificateIssuer = null)
{
    /// <summary>Gets the entry extensions this library has no property for, kept so that a CRL read and
    /// written again does not lose them.</summary>
    public ImmutableList<X509Extension> Extensions { get; init; } = [];


    /// <summary>Gets whether another entry describes the same revocation, comparing the serial number, the entry
    /// extensions and the certificate issuer by content.</summary>
    /// <param name="other">The entry to compare with.</param>
    public bool Equals(RevokedCertificate? other)
        => other != null
           && SerialNumber.Span.SequenceEqual(other.SerialNumber.Span)
           && RevocationDate == other.RevocationDate
           && Reason == other.Reason
           && InvalidityDate == other.InvalidityDate
           && (CertificateIssuer?.RawData is { } issuer
               ? other.CertificateIssuer?.RawData is { } otherIssuer && issuer.AsSpan().SequenceEqual(otherIssuer)
               : other.CertificateIssuer == null)
           && CrlEncoding.HaveSameExtensions(Extensions, other.Extensions);

    /// <summary>Gets a hash code consistent with <see cref="Equals(RevokedCertificate)"/>.</summary>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(SerialNumber.Span);
        hash.Add(RevocationDate);
        hash.Add(Reason);
        hash.Add(InvalidityDate);
        if (CertificateIssuer != null) {
            hash.AddBytes(CertificateIssuer.RawData);
        }
        CrlEncoding.AddExtensionsToHash(ref hash, Extensions);
        return hash.ToHashCode();
    }


    /// <summary>Describes the revocation of a certificate.</summary>
    /// <param name="certificate">The certificate being revoked.</param>
    /// <param name="revokedAt">When it was revoked.</param>
    /// <param name="reason">Why it was revoked, or <see langword="null"/> to state no reason.</param>
    /// <returns>An entry naming the certificate by its serial number and issuer.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is <see langword="null"/>.</exception>
    public static RevokedCertificate From(X509Certificate2 certificate, DateTimeOffset revokedAt, X509RevocationReason? reason = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new RevokedCertificate(certificate.SerialNumberBytes.ToArray(), revokedAt, reason, null, certificate.IssuerName);
    }
}
