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
/// <para>RFC 5280 s5.2 and s5.3 have a relying party reject a CRL that carries a critical extension it does not
/// recognise. Loading does not: such an extension is kept in <see cref="Extensions"/> or
/// <see cref="RevokedCertificate.Extensions"/> with its <see cref="X509Extension.Critical"/> flag, for the caller
/// to judge.</para>
/// </remarks>
public sealed class CertificateRevocationList
{
    private readonly byte[] _rawData;
    private readonly ReadOnlyMemory<byte> _toBeSigned;
    private readonly ReadOnlyMemory<byte> _signature;
    private readonly ReadOnlyMemory<byte> _signatureAlgorithm;


    private CertificateRevocationList(
        byte[] rawData,
        ReadOnlyMemory<byte> toBeSigned,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> signatureAlgorithm,
        X500DistinguishedName issuer,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate)
    {
        _rawData = rawData;
        _toBeSigned = toBeSigned;
        _signature = signature;
        _signatureAlgorithm = signatureAlgorithm;
        Issuer = issuer;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
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
    public BigInteger? CrlNumber { get; private init; }

    /// <summary>Gets the number of the full CRL this delta CRL builds on, or <see langword="null"/> where this is not a delta CRL.</summary>
    public BigInteger? BaseCrlNumber { get; private init; }

    /// <summary>Gets the address and coverage the CRL states for itself, or <see langword="null"/> where it states none.</summary>
    /// <remarks>Also <see langword="null"/> where the CRL states a scope this library cannot express, which is
    /// one that partitions by reason, covers only attribute certificates, or names its address in a form other
    /// than a URI. The extension is then left in <see cref="Extensions"/> as it was received.</remarks>
    public CrlDistributionPoint? DistributionPoint { get; private init; }

    /// <summary>Gets the Authority Key Identifier extension as it was received, or <see langword="null"/> where the CRL carries none.</summary>
    /// <remarks>Not repeated in <see cref="Extensions"/>. <c>X509CrlBuilder</c> writes its own from the issuer's key.</remarks>
    public X509Extension? AuthorityKeyIdentifier { get; private init; }

    /// <summary>Gets the CRL-wide extensions this type has no property for, as they were received.</summary>
    /// <remarks>Each can be passed to <c>X509CrlBuilder.AddExtension</c> except an Issuing Distribution Point or
    /// Freshest CRL extension that <see cref="DistributionPoint"/> could not express, which the builder writes only
    /// from its own settings.</remarks>
    public ImmutableList<X509Extension> Extensions { get; private init; } = [];

    /// <summary>Gets the revoked certificates.</summary>
    /// <remarks>Read once, when the CRL is loaded. Where the CRL is indirect, an entry's
    /// <see cref="RevokedCertificate.CertificateIssuer"/> has the Certificate Issuer extension's inheritance
    /// already applied: an entry without the extension takes the issuer of the entry before it.</remarks>
    public ImmutableList<RevokedCertificate> RevokedCertificates { get; private init; } = [];


    /// <summary>Reads a CRL from its binary encoding.</summary>
    /// <param name="data">The BER or DER encoded <c>CertificateList</c>.</param>
    /// <returns>The CRL.</returns>
    /// <exception cref="CryptographicException"><paramref name="data"/> is not a well-formed CRL.</exception>
    public static CertificateRevocationList Load(ReadOnlySpan<byte> data)
        => LoadWithoutCopy(data.ToArray());


    /// <summary>Reads a CRL from an array it then keeps and never copies.</summary>
    /// <param name="data">The BER or DER encoded <c>CertificateList</c>. The caller must not change it afterwards.</param>
    /// <exception cref="CryptographicException"><paramref name="data"/> is not a well-formed CRL.</exception>
    /// <remarks>For a caller that has just made the array and holds no other reference to it.</remarks>
    internal static CertificateRevocationList LoadWithoutCopy(byte[] data)
    {
        try {
            return Parse(data);
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
                return LoadWithoutCopy(PemTools.DecodeBlock(remaining, fields));
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
    /// <exception cref="NotSupportedException">The CRL's signature algorithm is not recognised, is post-quantum on a target before .NET 10, or is RSASSA-PSS with
    /// parameters other than MGF1 over the same hash, a salt as long as the hash, and trailer field 1.</exception>
    /// <remarks>Only the signature is checked. That the certificate is the CRL's <see cref="Issuer"/>, that it may
    /// sign CRLs, and that it is trusted are for the caller to establish.</remarks>
    public bool VerifySignature(X509Certificate2 issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        return X509Certificate2Extensions.VerifySignature(_signatureAlgorithm,_toBeSigned.Span, _signature.Span, issuer);
    }


    /// <summary>Gets the CRL as PEM text with the <c>X509 CRL</c> label.</summary>
    public string ToPemString()
        => new(PemEncoding.Write(PemLabel, _rawData));


    private const string PemLabel = "X509 CRL";

    private static readonly Asn1Tag Context0Tag = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag DirectoryNameTag = new(TagClass.ContextSpecific, 4);
    private static readonly Asn1Tag UriTag = new(TagClass.ContextSpecific, 6);
    private static readonly Asn1Tag UtcTimeTag = new(UniversalTagNumber.UtcTime);
    private static readonly Asn1Tag GeneralizedTimeTag = new(UniversalTagNumber.GeneralizedTime);


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
            entries = tbs.ReadEncodedValue();
        }

        var extensions = new CrlExtensions(null, null, null, false, null, []);
        if (tbs.HasData) {
            var wrapper = tbs.ReadSequence(Context0Tag);
            extensions = ReadCrlExtensions(ReadExtensions(wrapper.ReadSequence()), issuer);
            wrapper.ThrowIfNotEmpty();
        }
        tbs.ThrowIfNotEmpty();

        return new CertificateRevocationList(raw, toBeSigned, signature, algorithm, issuer, thisUpdate, nextUpdate) {
            CrlNumber = extensions.CrlNumber,
            BaseCrlNumber = extensions.BaseCrlNumber,
            DistributionPoint = extensions.DistributionPoint,
            AuthorityKeyIdentifier = extensions.AuthorityKeyIdentifier,
            Extensions = extensions.Others,
            //After the extensions, because whether the CRL is indirect decides whether its entries may name another issuer
            RevokedCertificates = ReadEntries(entries, extensions.IsIndirect)
        };
    }


    private readonly record struct CrlExtensions(
        BigInteger? CrlNumber,
        BigInteger? BaseCrlNumber,
        CrlDistributionPoint? DistributionPoint,
        bool IsIndirect,
        X509Extension? AuthorityKeyIdentifier,
        ImmutableList<X509Extension> Others);


    /// <summary>An extension as read, before it is known whether it needs an <see cref="X509Extension"/>.</summary>
    private readonly record struct RawExtension(string Oid, bool Critical, byte[] Value)
    {
        public X509Extension ToX509Extension() => new(new Oid(Oid), Value, Critical);
    }


    private static CrlExtensions ReadCrlExtensions(List<RawExtension> extensions, X500DistinguishedName crlIssuer)
    {
        BigInteger? number = null, baseNumber = null;
        CrlDistributionPoint? point = null;
        var indirect = false;
        X509Extension? authorityKeyIdentifier = null;
        RawExtension? scope = null;
        RawExtension? freshest = null;
        var others = ImmutableList.CreateBuilder<X509Extension>();

        foreach (var extension in extensions) {
            switch (extension.Oid) {
                case Oids.CrlNumber:
                    number = ReadWhole(extension.Value, x => x.ReadInteger());
                    break;
                case Oids.DeltaCrlIndicator:
                    baseNumber = ReadWhole(extension.Value, x => x.ReadInteger());
                    break;
                case Oids.IssuingDistributionPoint:
                    scope = extension;
                    point = ReadIssuingDistributionPoint(extension.Value, crlIssuer, out indirect);
                    break;
                case Oids.FreshestCrl:
                    freshest = extension;
                    break;
                case Oids.AuthorityKeyIdentifier:
                    authorityKeyIdentifier = extension.ToX509Extension();
                    break;
                default:
                    others.Add(extension.ToX509Extension());
                    break;
            }
        }

        //Freshest CRL has a home only on a scope that could itself be read; otherwise both stay as received
        if (point != null && freshest != null && TryReadDeltaUris(freshest.Value.Value, out var deltaUris)) {
            point = CrlDistributionPoint.CreateUnchecked(point.Uris, deltaUris, point.Covers, point.CrlIssuer);
            freshest = null;
        }
        if (point == null && scope != null) {
            others.Add(scope.Value.ToX509Extension());
        }
        if (freshest != null) {
            others.Add(freshest.Value.ToX509Extension());
        }

        return new CrlExtensions(number, baseNumber, point, indirect, authorityKeyIdentifier, others.ToImmutable());
    }


    private static ImmutableList<RevokedCertificate> ReadEntries(ReadOnlyMemory<byte> entries, bool indirect)
    {
        if (entries.IsEmpty) {
            return [];
        }

        var list = new AsnReader(entries, AsnEncodingRules.BER).ReadSequence();
        var result = ImmutableList.CreateBuilder<RevokedCertificate>();
        X500DistinguishedName? issuer = null;
        while (list.HasData) {
            result.Add(ReadEntry(list.ReadSequence(), indirect, ref issuer));
        }
        return result.ToImmutable();
    }


    private static RevokedCertificate ReadEntry(AsnReader entry, bool indirect, ref X500DistinguishedName? issuer)
    {
        var serial = entry.ReadIntegerBytes().Span.TrimStart((byte)0);
        byte[] serialNumber = serial.IsEmpty ? [0] : serial.ToArray();

        var revokedAt = ReadTime(entry);
        X509RevocationReason? reason = null;
        DateTimeOffset? invalidity = null;
        ImmutableList<X509Extension>.Builder? others = null;

        if (entry.HasData) {
            foreach (var extension in ReadExtensions(entry.ReadSequence())) {
                switch (extension.Oid) {
                    case Oids.CrlReasons:
                        reason = ReadWhole(extension.Value, x => x.ReadEnumeratedValue<X509RevocationReason>());
                        break;
                    case Oids.InvalidityDate:
                        invalidity = ReadWhole(extension.Value, x => x.ReadGeneralizedTime());
                        break;
                    case Oids.CertificateIssuer:
                        //Held in CertificateIssuer once read, so it is not also kept as a raw extension
                        //that the builder would refuse to write again
                        //Without a directoryName the entry's issuer cannot be named, and carrying on with the
                        //previous one would attribute the revocation to the wrong authority
                        if (!indirect) {
                            throw new AsnContentException("An entry names a Certificate Issuer, but the CRL is not indirect (RFC 5280 s5.3.3).");
                        }
                        issuer = ReadCertificateIssuer(extension.Value)
                            ?? throw new AsnContentException("The Certificate Issuer extension names no directoryName.");
                        break;
                    default:
                        (others ??= ImmutableList.CreateBuilder<X509Extension>()).Add(extension.ToX509Extension());
                        break;
                }
            }
        }
        entry.ThrowIfNotEmpty();

        return new RevokedCertificate(serialNumber, revokedAt, reason, invalidity, issuer) {
            Extensions = others?.ToImmutable() ?? []
        };
    }


    /// <summary>The first <c>directoryName</c> in a Certificate Issuer extension, or <see langword="null"/> where it holds none.</summary>
    private static X500DistinguishedName? ReadCertificateIssuer(byte[] value)
    {
        var names = ReadWhole(value, x => x.ReadSequence());
        while (names.HasData) {
            if (names.PeekTag().HasSameClassAndValue(DirectoryNameTag)) {
                var wrapper = names.ReadSequence(DirectoryNameTag);
                var name = new X500DistinguishedName(wrapper.ReadEncodedValue().ToArray());
                wrapper.ThrowIfNotEmpty();
                return name;
            }
            names.ReadEncodedValue();
        }
        return null;
    }


    private static CrlDistributionPoint? ReadIssuingDistributionPoint(byte[] value, X500DistinguishedName crlIssuer, out bool isIndirect)
    {
        //Reported even where the scope cannot be expressed, since it decides what the entries may name
        isIndirect = false;
        var seq = ReadWhole(value, x => x.ReadSequence());
        List<string> uris = [];
        var representable = true;
        bool onlyUser = false, onlyCa = false;
        HashSet<int> seen = [];

        while (seq.HasData) {
            var tag = seq.PeekTag();
            if (tag.TagClass != TagClass.ContextSpecific) {
                throw new AsnContentException("Unexpected field in the issuing distribution point.");
            }
            //A field appears at most once, and taking the last of two would be a guess about the scope
            if (!seen.Add(tag.TagValue)) {
                throw new AsnContentException("The issuing distribution point repeats a field.");
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
                    isIndirect = seq.ReadBoolean(tag);
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

        return CrlDistributionPoint.CreateUnchecked(
            [.. uris],
            [],
            onlyUser ? CrlCoverage.EndEntityCertificates : onlyCa ? CrlCoverage.CACertificates : CrlCoverage.AllCertificates,
            isIndirect ? crlIssuer : null);
    }


    /// <summary>Collects the URIs of a <c>DistributionPointName</c>, and reports whether that was all it held.</summary>
    private static bool ReadDistributionPointName(AsnReader name, List<string> uris)
    {
        //fullName is [0]
        if (!name.PeekTag().HasSameClassAndValue(Context0Tag)) {
            name.ReadEncodedValue();
            return false;
        }

        var names = name.ReadSequence(Context0Tag);
        var onlyUris = true;
        while (names.HasData) {
            if (names.PeekTag().HasSameClassAndValue(UriTag)) {
                uris.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, UriTag));
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
        var points = ReadWhole(value, x => x.ReadSequence());
        List<string> uris = [];
        var onlyAddresses = true;

        while (points.HasData) {
            var point = points.ReadSequence();
            while (point.HasData) {
                var tag = point.PeekTag();
                if (tag.HasSameClassAndValue(Context0Tag)) {
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


    private static List<RawExtension> ReadExtensions(AsnReader sequence)
    {
        List<RawExtension> extensions = [];
        HashSet<string> seen = [];
        while (sequence.HasData) {
            var extension = sequence.ReadSequence();
            var oid = extension.ReadObjectIdentifier();
            //RFC 5280 s5.2: an extension appears at most once, and taking either of two would be a guess
            if (!seen.Add(oid)) {
                throw new AsnContentException($"The extension {oid} appears more than once.");
            }
            var critical = extension.PeekTag() == Asn1Tag.Boolean && extension.ReadBoolean();
            var value = extension.ReadOctetString();
            extension.ThrowIfNotEmpty();
            extensions.Add(new RawExtension(oid, critical, value));
        }
        return extensions;
    }


    /// <summary>Reads the one value an extension holds, and refuses anything after it.</summary>
    private static T ReadWhole<T>(byte[] value, Func<AsnReader, T> read)
    {
        var reader = new AsnReader(value, AsnEncodingRules.BER);
        var result = read(reader);
        reader.ThrowIfNotEmpty();
        return result;
    }


    private static bool IsTime(Asn1Tag tag)
        => tag.HasSameClassAndValue(UtcTimeTag) || tag.HasSameClassAndValue(GeneralizedTimeTag);


    private static DateTimeOffset ReadTime(AsnReader reader)
        => reader.PeekTag().HasSameClassAndValue(UtcTimeTag)
            ? reader.ReadUtcTime()
            : reader.ReadGeneralizedTime();
}
