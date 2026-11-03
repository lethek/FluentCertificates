using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FluentCertificates.Internals;

/// <summary>
/// The encodings a CRL and the certificates it covers share: the distribution point structures of RFC 5280
/// s4.2.1.13, s4.2.1.15 and s5.2.5, and the extension wrapper.
/// </summary>
internal static class CrlEncoding
{
    private static readonly Asn1Tag s_context0 = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag s_context1 = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag s_context2 = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag s_context4 = new(TagClass.ContextSpecific, 4);
    private static readonly Asn1Tag s_directoryName = new(TagClass.ContextSpecific, 4);
    private static readonly Asn1Tag s_uri = new(TagClass.ContextSpecific, 6);


    /// <summary>Writes one extension: its OID, its criticality when critical, and the value wrapped in an OCTET STRING.</summary>
    public static void WriteExtension(AsnWriter writer, string oid, bool critical, Action<AsnWriter> writeValue)
    {
        using (writer.PushSequence()) {
            writer.WriteObjectIdentifier(oid);
            if (critical) {
                writer.WriteBoolean(true);
            }
            using (writer.PushOctetString()) {
                writeValue(writer);
            }
        }
    }


    /// <summary>Writes one extension whose value is already encoded, as <c>X509Extension.RawData</c> holds it.</summary>
    public static void WriteExtension(AsnWriter writer, string oid, bool critical, ReadOnlySpan<byte> encodedValue)
    {
        using (writer.PushSequence()) {
            writer.WriteObjectIdentifier(oid);
            if (critical) {
                writer.WriteBoolean(true);
            }
            writer.WriteOctetString(encodedValue);
        }
    }


    /// <summary>
    /// Encodes a <c>CRLDistributionPoints</c> value: the one a certificate carries, or with
    /// <paramref name="delta"/> the Freshest CRL one, which has the same shape and names the delta addresses.
    /// </summary>
    /// <returns>The encoded value, or <see langword="null"/> when no point names an address in the chosen set.</returns>
    /// <exception cref="ArgumentException">A point names neither an address nor a CRL issuer, or an address is not ASCII.</exception>
    /// <remarks>A Freshest CRL inside a CRL leaves out <c>cRLIssuer</c> (RFC 5280 s5.2.6), so it passes
    /// <paramref name="includeCrlIssuer"/> as <see langword="false"/>.</remarks>
    public static byte[]? EncodeDistributionPoints(IEnumerable<CrlDistributionPoint> points, bool delta, bool includeCrlIssuer = true)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        var any = false;
        using (writer.PushSequence()) {
            foreach (var point in points) {
                ArgumentNullException.ThrowIfNull(point, nameof(points));
                IReadOnlyCollection<string> uris = delta ? point.DeltaUris : point.Uris;
                if (delta && uris.Count == 0) {
                    continue;
                }
                if (uris.Count == 0 && point.CrlIssuer == null) {
                    throw new ArgumentException("A distribution point must name an address or a CRL issuer", nameof(points));
                }

                any = true;
                using (writer.PushSequence()) {
                    if (uris.Count > 0) {
                        WriteDistributionPointName(writer, uris);
                    }
                    if (includeCrlIssuer && point.CrlIssuer != null) {
                        WriteDirectoryName(writer, point.CrlIssuer, s_context2);
                    }
                }
            }
        }

        return any ? writer.Encode() : null;
    }


    /// <summary>
    /// Writes an <c>IssuingDistributionPoint</c> value (RFC 5280 s5.2.5) stating the scope of the CRL it is in.
    /// </summary>
    /// <remarks>Only the fields this library supports are written. The reasons field is never written, since
    /// reason partitioning is not supported, and neither is the attribute certificates field. A
    /// <see cref="CrlDistributionPoint.CrlIssuer"/> marks the CRL indirect.</remarks>
    public static void WriteIssuingDistributionPoint(AsnWriter writer, CrlDistributionPoint point)
    {
        using (writer.PushSequence()) {
            if (point.Uris.Count > 0) {
                WriteDistributionPointName(writer, point.Uris);
            }
            if (point.Covers == CrlCoverage.EndEntityCertificates) {
                writer.WriteBoolean(true, s_context1);
            }
            if (point.Covers == CrlCoverage.CACertificates) {
                writer.WriteBoolean(true, s_context2);
            }
            if (point.CrlIssuer != null) {
                writer.WriteBoolean(true, s_context4);
            }
        }
    }


    /// <summary>Writes a <c>GeneralNames</c> holding one <c>directoryName</c>, under <paramref name="tag"/> where given.</summary>
    public static void WriteDirectoryName(AsnWriter writer, X500DistinguishedName name, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        using (writer.PushSequence(s_directoryName)) {
            writer.WriteEncodedValue(name.RawData);
        }
    }


    /// <summary>Writes <c>distributionPoint [0] { fullName [0] { uniformResourceIdentifier [6]... } }</c>.</summary>
    private static void WriteDistributionPointName(AsnWriter writer, IEnumerable<string> uris)
    {
        using (writer.PushSequence(s_context0))
        using (writer.PushSequence(s_context0)) {
            foreach (var uri in uris) {
                //A point read from a CRL skips the constructor's check and can carry an address it would refuse
                if (String.IsNullOrEmpty(uri) || !Ascii.IsValid(uri)) {
                    throw new ArgumentException($"A distribution point address must be a non-empty ASCII string, but was '{uri}'", nameof(uris));
                }
                writer.WriteCharacterString(UniversalTagNumber.IA5String, uri, s_uri);
            }
        }
    }


    /// <summary>Writes a UTCTime for 1950 to 2049 and a GeneralizedTime outside it, as RFC 5280 s5.1.2.4 requires.</summary>
    public static void WriteTime(AsnWriter writer, DateTimeOffset time)
    {
        var utc = time.ToUniversalTime();
        if (utc.Year is >= 1950 and < 2050) {
            writer.WriteUtcTime(utc);
        } else {
            writer.WriteGeneralizedTime(utc, omitFractionalSeconds: true);
        }
    }
}
