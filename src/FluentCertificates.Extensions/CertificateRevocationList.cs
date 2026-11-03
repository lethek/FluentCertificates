using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

/// <summary>
/// A certificate revocation list (RFC 5280 s5), read from its encoding or produced by <c>X509CrlBuilder</c>.
/// </summary>
/// <remarks>
/// <para>.NET's own <see cref="CertificateRevocationListBuilder"/> can load a CRL but keeps only its entries,
/// and drops the CRL-wide extensions that say whether it is a delta, which certificates it covers and where it
/// is published. This type keeps them.</para>
/// <para>Loading does not check the signature, which needs the issuer's certificate: call
/// <see cref="VerifySignature"/> for that. The BER encoding is accepted as well as DER, and
/// <see cref="RawData"/> and the signed bytes are kept exactly as they were received.</para>
/// </remarks>
public sealed class CertificateRevocationList
{
    private readonly byte[] _rawData;
    private readonly ReadOnlyMemory<byte> _toBeSigned;
    private readonly ReadOnlyMemory<byte> _signature;
    private readonly ReadOnlyMemory<byte> _entries;
    private readonly ReadOnlyMemory<byte> _signatureAlgorithm;


    private CertificateRevocationList(
        byte[] rawData,
        ReadOnlyMemory<byte> toBeSigned,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> signatureAlgorithm,
        X500DistinguishedName issuer,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        ReadOnlyMemory<byte> entries)
    {
        _rawData = rawData;
        _toBeSigned = toBeSigned;
        _signature = signature;
        _signatureAlgorithm = signatureAlgorithm;
        Issuer = issuer;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
        _entries = entries;
    }


    /// <summary>Gets the CRL's encoding, as received.</summary>
    public ReadOnlyMemory<byte> RawData => _rawData;

    /// <summary>Gets the name of the party that signed the CRL.</summary>
    public X500DistinguishedName Issuer { get; }

    /// <summary>Gets when this CRL was issued.</summary>
    public DateTimeOffset ThisUpdate { get; }

    /// <summary>Gets when the next CRL is due, or <see langword="null"/> where the CRL does not say.</summary>
    public DateTimeOffset? NextUpdate { get; }

    /// <summary>Gets the CRL number, or <see langword="null"/> where the CRL carries none.</summary>
    public BigInteger? CrlNumber { get; private set; }

    /// <summary>Gets the number of the full CRL this delta CRL builds on, or <see langword="null"/> where this is not a delta CRL.</summary>
    public BigInteger? BaseCrlNumber { get; private set; }

    /// <summary>Gets the address and coverage the CRL states for itself, or <see langword="null"/> where it states none.</summary>
    /// <remarks>Also <see langword="null"/> where the CRL states a scope this library cannot express, which is
    /// one that partitions by reason, covers only attribute certificates, or names its address in a form other
    /// than a URI. The extension is then left in <see cref="Extensions"/> as it was received.</remarks>
    public CrlDistributionPoint? DistributionPoint { get; private set; }

    /// <summary>Gets the CRL-wide extensions this type has no property for, as they were received.</summary>
    public ImmutableList<X509Extension> Extensions { get; private set; } = [];

    /// <summary>Gets the revoked certificates.</summary>
    /// <remarks>Read from <see cref="RawData"/> each time it is enumerated. Where the CRL is indirect, an entry's
    /// <see cref="RevokedCertificate.CertificateIssuer"/> has the Certificate Issuer extension's inheritance
    /// already applied: an entry without the extension takes the issuer of the entry before it.</remarks>
    public IEnumerable<RevokedCertificate> RevokedCertificates => ReadEntries(_entries);


    /// <summary>Reads a CRL from its binary encoding.</summary>
    /// <param name="data">The BER or DER encoded <c>CertificateList</c>.</param>
    /// <returns>The CRL.</returns>
    /// <exception cref="CryptographicException"><paramref name="data"/> is not a well-formed CRL.</exception>
    public static CertificateRevocationList Load(ReadOnlySpan<byte> data)
    {
        try {
            return Parse(data.ToArray());
        } catch (AsnContentException ex) {
            throw new CryptographicException("The data is not a well-formed certificate revocation list", ex);
        }
    }


    /// <summary>Reads a CRL from PEM text, taking the first <c>X509 CRL</c> block in it.</summary>
    /// <param name="pem">The PEM text.</param>
    /// <returns>The CRL.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pem"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException"><paramref name="pem"/> holds no <c>X509 CRL</c> block, or the
    /// block is not a well-formed CRL.</exception>
    public static CertificateRevocationList LoadPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);

        var remaining = pem.AsSpan();
        while (PemEncoding.TryFind(remaining, out var fields)) {
            if (remaining[fields.Label].SequenceEqual(PemLabel.AsSpan())) {
                byte[] data;
                try {
                    data = Convert.FromBase64String(remaining[fields.Base64Data].ToString());
                } catch (FormatException ex) {
                    throw new CryptographicException("The PEM block is not valid base64", ex);
                }
                return Load(data);
            }
            remaining = remaining[fields.Location.End..];
        }

        throw new CryptographicException($"The text holds no {PemLabel} PEM block");
    }


    /// <summary>Checks the CRL's signature against a certificate's public key.</summary>
    /// <param name="issuer">The certificate of the party that signed the CRL.</param>
    /// <returns><see langword="true"/> if the signature is valid for that key; otherwise <see langword="false"/>,
    /// including when the key is of a different kind than the one that signed.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="issuer"/> is <see langword="null"/>.</exception>
    /// <exception cref="NotSupportedException">The CRL's signature algorithm is not recognised.</exception>
    /// <remarks>Only the signature is checked. That the certificate is the CRL's <see cref="Issuer"/>, that it may
    /// sign CRLs, and that it is trusted are for the caller to establish.</remarks>
    public bool VerifySignature(X509Certificate2 issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        var algorithm = SignatureAlgorithm.FromAlgorithmIdentifier(_signatureAlgorithm);
        return X509Certificate2Extensions.VerifySignature(algorithm, _toBeSigned.Span, _signature.Span, issuer);
    }


    /// <summary>Gets the CRL as PEM text with the <c>X509 CRL</c> label.</summary>
    public string ToPemString()
        => new(PemEncoding.Write(PemLabel, _rawData));


    private const string PemLabel = "X509 CRL";

    private static readonly Asn1Tag s_context0 = new(TagClass.ContextSpecific, 0);


    private static CertificateRevocationList Parse(byte[] raw)
    {
        var outer = new AsnReader(raw, AsnEncodingRules.BER);
        var list = outer.ReadSequence();
        outer.ThrowIfNotEmpty();

        var toBeSigned = list.PeekEncodedValue();
        var tbs = list.ReadSequence();
        var algorithm = list.ReadEncodedValue();
        var signature = list.ReadBitString(out var unusedBits);
        if (unusedBits != 0) {
            throw new AsnContentException("The signature has unused bits.");
        }
        list.ThrowIfNotEmpty();

        if (tbs.PeekTag() == Asn1Tag.Integer) {
            var version = tbs.ReadInteger();
            if (version != 0 && version != 1) {
                throw new AsnContentException($"CRL version {version + 1} is not supported.");
            }
        }

        //RFC 5280 s5.1.1.2: the two identifiers name the same algorithm. Only the one inside the signed bytes
        //is trusted for its parameters, since the outer one is not covered by the signature.
        var signedAlgorithm = tbs.ReadEncodedValue();
        if (ReadAlgorithmOid(signedAlgorithm) != ReadAlgorithmOid(algorithm)) {
            throw new AsnContentException("The signature algorithm differs between the signed and unsigned parts of the CRL.");
        }
        algorithm = signedAlgorithm;

        var issuer = new X500DistinguishedName(tbs.ReadEncodedValue().ToArray());
        var thisUpdate = ReadTime(tbs);
        var nextUpdate = tbs.HasData && IsTime(tbs.PeekTag()) ? ReadTime(tbs) : (DateTimeOffset?)null;

        ReadOnlyMemory<byte> entries = default;
        if (tbs.HasData && tbs.PeekTag() == Asn1Tag.Sequence) {
            entries = tbs.PeekEncodedValue();
            tbs.ReadEncodedValue();
        }

        var result = new CertificateRevocationList(raw, toBeSigned, signature, algorithm, issuer, thisUpdate, nextUpdate, entries);

        if (tbs.HasData) {
            var wrapper = tbs.ReadSequence(s_context0);
            var extensions = ReadExtensions(wrapper.ReadSequence());
            wrapper.ThrowIfNotEmpty();
            result.ApplyExtensions(extensions, issuer);
        }
        tbs.ThrowIfNotEmpty();

        //Read every entry now, so that a malformed one fails the load rather than a later enumeration
        foreach (var _ in result.RevokedCertificates) { }

        return result;
    }


    private void ApplyExtensions(List<X509Extension> extensions, X500DistinguishedName crlIssuer)
    {
        CrlDistributionPoint? point = null;
        X509Extension? scope = null;
        X509Extension? freshest = null;
        var others = ImmutableList.CreateBuilder<X509Extension>();

        foreach (var extension in extensions) {
            switch (extension.Oid?.Value) {
                case Oids.CrlNumber:
                    CrlNumber = ReadWhole(extension.RawData).ReadInteger();
                    break;
                case Oids.DeltaCrlIndicator:
                    BaseCrlNumber = ReadWhole(extension.RawData).ReadInteger();
                    break;
                case Oids.IssuingDistributionPoint:
                    scope = extension;
                    point = ReadIssuingDistributionPoint(extension.RawData, crlIssuer);
                    break;
                case Oids.FreshestCrl:
                    freshest = extension;
                    break;
                default:
                    others.Add(extension);
                    break;
            }
        }

        //Freshest CRL has a home only on a scope that could itself be read; otherwise both stay as received
        if (point != null && freshest != null && TryReadDeltaUris(freshest.RawData, out var deltaUris)) {
            point = point with { DeltaUris = deltaUris };
            freshest = null;
        }
        if (point == null && scope != null) {
            others.Add(scope);
        }
        if (freshest != null) {
            others.Add(freshest);
        }

        DistributionPoint = point;
        Extensions = others.ToImmutable();
    }


    private static IEnumerable<RevokedCertificate> ReadEntries(ReadOnlyMemory<byte> entries)
    {
        if (entries.IsEmpty) {
            yield break;
        }

        var list = new AsnReader(entries, AsnEncodingRules.BER).ReadSequence();
        X500DistinguishedName? issuer = null;

        while (list.HasData) {
            RevokedCertificate entry;
            try {
                entry = ReadEntry(list.ReadSequence(), ref issuer);
            } catch (AsnContentException ex) {
                throw new CryptographicException("The certificate revocation list has a malformed entry", ex);
            }
            yield return entry;
        }
    }


    private static RevokedCertificate ReadEntry(AsnReader entry, ref X500DistinguishedName? issuer)
    {
        var serial = entry.ReadIntegerBytes().ToArray();
        var start = 0;
        while (start < serial.Length - 1 && serial[start] == 0) {
            start++;
        }

        var revokedAt = ReadTime(entry);
        X509RevocationReason? reason = null;
        DateTimeOffset? invalidity = null;
        var others = ImmutableList.CreateBuilder<X509Extension>();

        if (entry.HasData) {
            foreach (var extension in ReadExtensions(entry.ReadSequence())) {
                switch (extension.Oid?.Value) {
                    case Oids.CrlReasons:
                        reason = ReadWhole(extension.RawData).ReadEnumeratedValue<X509RevocationReason>();
                        break;
                    case Oids.InvalidityDate:
                        invalidity = ReadWhole(extension.RawData).ReadGeneralizedTime();
                        break;
                    case Oids.CertificateIssuer:
                        //Held in CertificateIssuer once read, so it is not also kept as a raw extension
                        //that the builder would refuse to write again
                        if (ReadCertificateIssuer(extension.RawData) is { } name) {
                            issuer = name;
                        } else {
                            others.Add(extension);
                        }
                        break;
                    default:
                        others.Add(extension);
                        break;
                }
            }
        }
        entry.ThrowIfNotEmpty();

        return new RevokedCertificate(serial[start..], revokedAt, reason, invalidity, issuer) {
            Extensions = others.ToImmutable()
        };
    }


    /// <summary>The first <c>directoryName</c> in a Certificate Issuer extension, or <see langword="null"/> where it holds none.</summary>
    private static X500DistinguishedName? ReadCertificateIssuer(byte[] value)
    {
        var names = ReadWhole(value).ReadSequence();
        var directoryName = new Asn1Tag(TagClass.ContextSpecific, 4);
        while (names.HasData) {
            if (names.PeekTag().HasSameClassAndValue(directoryName)) {
                var wrapper = names.ReadSequence(directoryName);
                var name = new X500DistinguishedName(wrapper.ReadEncodedValue().ToArray());
                wrapper.ThrowIfNotEmpty();
                return name;
            }
            names.ReadEncodedValue();
        }
        return null;
    }


    private static CrlDistributionPoint? ReadIssuingDistributionPoint(byte[] value, X500DistinguishedName crlIssuer)
    {
        var seq = ReadWhole(value).ReadSequence();
        List<string> uris = [];
        var representable = true;
        bool onlyUser = false, onlyCa = false, indirect = false;

        while (seq.HasData) {
            var tag = seq.PeekTag();
            if (tag.TagClass != TagClass.ContextSpecific) {
                throw new AsnContentException("Unexpected field in the issuing distribution point.");
            }

            switch (tag.TagValue) {
                case 0:
                    var name = seq.ReadSequence(tag);
                    representable &= ReadDistributionPointName(name, uris);
                    name.ThrowIfNotEmpty();
                    break;
                case 1:
                    onlyUser = seq.ReadBoolean(tag);
                    break;
                case 2:
                    onlyCa = seq.ReadBoolean(tag);
                    break;
                case 3:
                    seq.ReadEncodedValue();
                    representable = false;
                    break;
                case 4:
                    indirect = seq.ReadBoolean(tag);
                    break;
                case 5:
                    representable &= !seq.ReadBoolean(tag);
                    break;
                default:
                    throw new AsnContentException("Unexpected field in the issuing distribution point.");
            }
        }

        if (!representable || (onlyUser && onlyCa)) {
            return null;
        }

        return new CrlDistributionPoint(uris) {
            Covers = onlyUser ? CrlCoverage.EndEntityCertificates : onlyCa ? CrlCoverage.CACertificates : CrlCoverage.AllCertificates,
            CrlIssuer = indirect ? crlIssuer : null
        };
    }


    /// <summary>Collects the URIs of a <c>DistributionPointName</c>, and reports whether that was all it held.</summary>
    private static bool ReadDistributionPointName(AsnReader name, List<string> uris)
    {
        var fullName = new Asn1Tag(TagClass.ContextSpecific, 0);
        if (!name.PeekTag().HasSameClassAndValue(fullName)) {
            name.ReadEncodedValue();
            return false;
        }

        var names = name.ReadSequence(fullName);
        var uri = new Asn1Tag(TagClass.ContextSpecific, 6);
        var onlyUris = true;
        while (names.HasData) {
            if (names.PeekTag().HasSameClassAndValue(uri)) {
                uris.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, uri));
            } else {
                names.ReadEncodedValue();
                onlyUris = false;
            }
        }
        return onlyUris;
    }


    /// <summary>Reads the addresses out of a Freshest CRL value, and reports whether that was all it held.</summary>
    private static bool TryReadDeltaUris(byte[] value, out ImmutableList<string> deltaUris)
    {
        var points = ReadWhole(value).ReadSequence();
        List<string> uris = [];
        var onlyAddresses = true;

        while (points.HasData) {
            var point = points.ReadSequence();
            while (point.HasData) {
                var tag = point.PeekTag();
                if (tag.HasSameClassAndValue(s_context0)) {
                    var name = point.ReadSequence(tag);
                    onlyAddresses &= ReadDistributionPointName(name, uris);
                    name.ThrowIfNotEmpty();
                } else {
                    point.ReadEncodedValue();
                    onlyAddresses = false;
                }
            }
        }

        deltaUris = [.. uris];
        return onlyAddresses;
    }


    private static string ReadAlgorithmOid(ReadOnlyMemory<byte> algorithmIdentifier)
        => new AsnReader(algorithmIdentifier, AsnEncodingRules.BER).ReadSequence().ReadObjectIdentifier();


    private static List<X509Extension> ReadExtensions(AsnReader sequence)
    {
        List<X509Extension> extensions = [];
        while (sequence.HasData) {
            var extension = sequence.ReadSequence();
            var oid = extension.ReadObjectIdentifier();
            var critical = extension.PeekTag() == Asn1Tag.Boolean && extension.ReadBoolean();
            var value = extension.ReadOctetString();
            extension.ThrowIfNotEmpty();
            extensions.Add(new X509Extension(new Oid(oid), value, critical));
        }
        return extensions;
    }


    private static AsnReader ReadWhole(byte[] value)
        => new(value, AsnEncodingRules.BER);


    private static bool IsTime(Asn1Tag tag)
        => tag.HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.UtcTime))
           || tag.HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.GeneralizedTime));


    private static DateTimeOffset ReadTime(AsnReader reader)
        => reader.PeekTag().HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.UtcTime))
            ? reader.ReadUtcTime()
            : reader.ReadGeneralizedTime();
}
