using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

/// <summary>
/// Builds and signs a certificate revocation list (RFC 5280 s5): a full CRL, a partition of one, a delta CRL,
/// or an indirect CRL.
/// </summary>
/// <remarks>
/// <para>This signs the list it is given and nothing more. Which certificates are revoked, what number each CRL
/// carries, when to publish and where are all the caller's: nothing here remembers a previous CRL, so a
/// <see cref="CrlNumber"/> that does not rise from one publication to the next is not caught.</para>
/// <para>.NET's own <see cref="CertificateRevocationListBuilder"/> cannot write the Issuing Distribution Point,
/// Delta CRL Indicator, Freshest CRL, invalidity date or Certificate Issuer extensions, and refuses an issuer
/// that is not a certificate authority, which includes one made with <see cref="CertificateUsage.CrlSigning"/>.
/// This encodes the CRL itself and signs it through an <see cref="X509SignatureGenerator"/>.</para>
/// <para>Use <see cref="SetDistributionPoint"/> for every CRL that is one of several covering the same issuer,
/// and for any delta CRL. A CRL that states no scope claims to be the complete list.</para>
/// </remarks>
public record X509CrlBuilder
{
    /// <summary>Gets the certificate that signs the CRL, or <see langword="null"/> where only a name and a
    /// <see cref="SignatureGenerator"/> were supplied.</summary>
    public X509Certificate2? Issuer { get; init; }

    /// <summary>Gets the name written as the CRL's issuer.</summary>
    public X500DistinguishedName? IssuerName { get; init; }

    /// <summary>Gets the key identifier written as the CRL's Authority Key Identifier, or empty to derive it from
    /// the signing key's public key (RFC 5280 s4.2.1.2 method 1), since s5.2.1 has every CRL carry one.</summary>
    public ReadOnlyMemory<byte> IssuerKeyIdentifier { get; init; }

    /// <summary>Gets the generator that signs the CRL, or <see langword="null"/> to sign with the
    /// <see cref="Issuer"/>'s private key.</summary>
    public X509SignatureGenerator? SignatureGenerator { get; init; }

    /// <summary>Gets the hash algorithm for signing. Ignored by algorithms that take none.</summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>Gets the RSA signature padding when signing with the <see cref="Issuer"/>'s key. Ignored for other algorithms.</summary>
    public RSASignaturePadding RSASignaturePadding { get; init; } = RSASignaturePadding.Pkcs1;

    /// <summary>Gets the CRL number, or <see langword="null"/> if not yet set.</summary>
    public BigInteger? CrlNumber { get; init; }

    /// <summary>Gets when the CRL is issued, or <see langword="null"/> to use the time <see cref="Create"/> runs.</summary>
    public DateTimeOffset? ThisUpdate { get; init; }

    /// <summary>Gets when the next CRL is due, or <see langword="null"/> if not yet set.</summary>
    public DateTimeOffset? NextUpdate { get; init; }

    /// <summary>Gets the address and coverage the CRL states for itself, or <see langword="null"/> to state none.</summary>
    public CrlDistributionPoint? DistributionPoint { get; init; }

    /// <summary>Gets the number of the full CRL this is a delta of, or <see langword="null"/> where this is a full CRL.</summary>
    public BigInteger? BaseCrlNumber { get; init; }

    /// <summary>Gets the revoked certificates, in the order they are written.</summary>
    public ImmutableList<RevokedCertificate> RevokedCertificates { get; init; } = [];

    /// <summary>Gets the CRL-wide extensions added beyond the ones this builder writes itself.</summary>
    public ImmutableList<X509Extension> Extensions { get; init; } = [];

    private CertificateRevocationList? BaseCrl { get; init; }


    /// <summary>Sets the certificate that signs the CRL, using its private key.</summary>
    /// <param name="issuer">The signing certificate. It need not be a certificate authority, but its key usage,
    /// where it states one, must allow <see cref="X509KeyUsageFlags.CrlSign"/>.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the specified issuer.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="issuer"/> is <see langword="null"/>.</exception>
    /// <remarks>The issuer name is the certificate's subject, and the Authority Key Identifier is taken from its
    /// Subject Key Identifier where it has one, and derived from its public key where it has not. The key is neither exported nor disposed. Any generator set
    /// earlier is cleared, so that the CRL is signed by this certificate's key: call
    /// <see cref="SetSignatureGenerator"/> afterwards to sign with a key held elsewhere.</remarks>
    public X509CrlBuilder SetIssuer(X509Certificate2 issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        var ski = issuer.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
        return this with {
            Issuer = issuer,
            SignatureGenerator = null,
            IssuerName = issuer.SubjectName,
            IssuerKeyIdentifier = ski?.SubjectKeyIdentifier is { } id ? Convert.FromHexString(id) : default
        };
    }

    /// <summary>Sets the name a CRL is issued under and the generator that signs it, for a key held where this
    /// library cannot reach it.</summary>
    /// <param name="name">The issuer name.</param>
    /// <param name="generator">The generator that signs the CRL.</param>
    /// <param name="keyIdentifier">The identifier of the signing key, written as the Authority Key Identifier, or
    /// empty to derive it from the generator's public key.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the specified issuer.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="name"/> or <paramref name="generator"/> is <see langword="null"/>.</exception>
    /// <remarks>Nothing checks that the generator matches the name or the key identifier.</remarks>
    public X509CrlBuilder SetIssuer(X500DistinguishedName name, X509SignatureGenerator generator, ReadOnlyMemory<byte> keyIdentifier = default)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(generator);
        return this with { Issuer = null, IssuerName = name, SignatureGenerator = generator, IssuerKeyIdentifier = keyIdentifier };
    }

    /// <summary>Sets the generator that signs the CRL, in place of the <see cref="Issuer"/>'s private key.</summary>
    /// <param name="generator">The generator, or <see langword="null"/> to sign with the issuer's private key.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the specified generator.</returns>
    public X509CrlBuilder SetSignatureGenerator(X509SignatureGenerator? generator)
        => this with { SignatureGenerator = generator };

    /// <summary>Sets the hash algorithm for signing. The default is SHA-256.</summary>
    /// <param name="value">The hash algorithm.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the specified hash algorithm.</returns>
    public X509CrlBuilder SetHashAlgorithm(HashAlgorithmName value)
        => this with { HashAlgorithm = value };

    /// <summary>Sets the RSA signature padding. The default is PKCS#1 v1.5.</summary>
    /// <param name="value">The padding.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the specified padding.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is <see langword="null"/>.</exception>
    public X509CrlBuilder SetRSASignaturePadding(RSASignaturePadding value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return this with { RSASignaturePadding = value };
    }

    /// <summary>Sets the CRL number, which must rise with every CRL the issuer publishes.</summary>
    /// <param name="value">The number. A full CRL and its delta CRLs share one sequence per scope.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the specified number.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="value"/> is negative.</exception>
    public X509CrlBuilder SetCrlNumber(BigInteger value)
        => value.Sign >= 0
            ? this with { CrlNumber = value }
            : throw new ArgumentOutOfRangeException(nameof(value), "A CRL number cannot be negative");

    /// <summary>Sets when the CRL is issued. The default is the time <see cref="Create"/> runs.</summary>
    /// <param name="value">The time.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the specified time.</returns>
    public X509CrlBuilder SetThisUpdate(DateTimeOffset value)
        => this with { ThisUpdate = value };

    /// <summary>Sets when the next CRL is due. A relying party treats the CRL as stale after this time.</summary>
    /// <param name="value">The time.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the specified time.</returns>
    public X509CrlBuilder SetNextUpdate(DateTimeOffset value)
        => this with { NextUpdate = value };

    /// <summary>States the address and coverage of the CRL.</summary>
    /// <param name="point">The distribution point, as passed to <see cref="CertificateBuilder.SetCrlDistributionPoints(IEnumerable{CrlDistributionPoint}, bool)"/>
    /// for the certificates the CRL covers.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the specified distribution point.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="point"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An address is empty or not ASCII, or the point names no address and no
    /// <see cref="CrlDistributionPoint.CrlIssuer"/> and covers <see cref="CrlCoverage.AllCertificates"/>, which would
    /// write an empty Issuing Distribution Point that RFC 5280 s5.2.5 forbids.</exception>
    /// <remarks>
    /// <para>The scope is always written, even for <see cref="CrlCoverage.AllCertificates"/>, so that a CRL that is
    /// one shard of several is never read as the complete list.</para>
    /// <para>Of <see cref="CrlDistributionPoint.DeltaUris"/>, a full CRL writes the Freshest CRL extension and a
    /// delta CRL writes nothing, since RFC 5280 s5.2.6 forbids a delta CRL to carry one.</para>
    /// <para>A <see cref="CrlDistributionPoint.CrlIssuer"/> makes the CRL indirect. It must be the name this
    /// builder issues under.</para>
    /// </remarks>
    public X509CrlBuilder SetDistributionPoint(CrlDistributionPoint point)
    {
        ArgumentNullException.ThrowIfNull(point);
        CrlEncoding.CheckAddresses(point.Uris, nameof(point));
        CrlEncoding.CheckAddresses(point.DeltaUris, nameof(point));
        if (point.Uris.Count == 0 && point.CrlIssuer == null && point.Covers == CrlCoverage.AllCertificates) {
            throw new ArgumentException("The distribution point states nothing, which would write an empty Issuing Distribution Point (RFC 5280 s5.2.5). Name an address or narrow the coverage", nameof(point));
        }
        return this with { DistributionPoint = point };
    }

    /// <summary>Makes the CRL a delta CRL of the full CRL with the given number.</summary>
    /// <param name="baseCrlNumber">The number of the last complete CRL. A delta is cumulative from that CRL, so
    /// it lists everything that changed since, and never builds on another delta.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> that builds a delta CRL.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="baseCrlNumber"/> is negative.</exception>
    /// <remarks>The scope must be the same as the base CRL's, which this cannot see: pass the base CRL itself to
    /// <see cref="SetDeltaOf(CertificateRevocationList)"/> to have it checked. A delta needs a
    /// <see cref="CrlNumber"/> above the base's.</remarks>
    public X509CrlBuilder SetDeltaOf(BigInteger baseCrlNumber)
        => baseCrlNumber.Sign >= 0
            ? this with { BaseCrlNumber = baseCrlNumber, BaseCrl = null }
            : throw new ArgumentOutOfRangeException(nameof(baseCrlNumber), "A CRL number cannot be negative");

    /// <summary>Makes the CRL a delta CRL of a full CRL.</summary>
    /// <param name="baseCrl">The last complete CRL.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> that builds a delta CRL.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="baseCrl"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="baseCrl"/> has no CRL number, is itself a delta CRL, or has a
    /// scope that <see cref="CertificateRevocationList.DistributionPoint"/> cannot express.</exception>
    /// <remarks><see cref="Create"/> refuses a <see cref="DistributionPoint"/> whose scope differs from the base's,
    /// since RFC 5280 s5.2.4 requires the two to match.</remarks>
    public X509CrlBuilder SetDeltaOf(CertificateRevocationList baseCrl)
    {
        ArgumentNullException.ThrowIfNull(baseCrl);
        if (baseCrl.CrlNumber is not { } number) {
            throw new ArgumentException("The base CRL has no CRL number", nameof(baseCrl));
        }
        if (baseCrl.BaseCrlNumber != null) {
            throw new ArgumentException("A delta CRL is cumulative from a complete CRL, so the base cannot be a delta CRL", nameof(baseCrl));
        }
        if (baseCrl.Extensions.Any(x => x.Oid?.Value == Oids.IssuingDistributionPoint)) {
            throw new ArgumentException("The base CRL has a scope this library cannot express, such as one partitioned by reason, so a delta CRL cannot be given the same scope", nameof(baseCrl));
        }
        return this with { BaseCrlNumber = number, BaseCrl = baseCrl };
    }

    /// <summary>Adds a revoked certificate.</summary>
    /// <param name="revoked">The entry.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the entry added.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="revoked"/> is <see langword="null"/>.</exception>
    public X509CrlBuilder AddRevokedCertificate(RevokedCertificate revoked)
    {
        ArgumentNullException.ThrowIfNull(revoked);
        return this with { RevokedCertificates = RevokedCertificates.Add(revoked) };
    }

    /// <summary>Adds revoked certificates.</summary>
    /// <param name="revoked">The entries.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the entries added.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="revoked"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="revoked"/> contains a <see langword="null"/>.</exception>
    public X509CrlBuilder AddRevokedCertificates(params IEnumerable<RevokedCertificate> revoked)
    {
        ArgumentNullException.ThrowIfNull(revoked);
        var list = revoked.ToList();
        return list.Contains(null!)
            ? throw new ArgumentException("An entry in the sequence is null", nameof(revoked))
            : this with { RevokedCertificates = RevokedCertificates.AddRange(list) };
    }

    /// <summary>Adds a CRL-wide extension this builder has no method for.</summary>
    /// <param name="extension">The extension, written exactly as given.</param>
    /// <returns>A new instance of <see cref="X509CrlBuilder"/> with the extension added.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="extension"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">The extension is one the builder writes itself (Authority Key
    /// Identifier, CRL Number, Delta CRL Indicator, Issuing Distribution Point or Freshest CRL), or its OID was
    /// already added.</exception>
    public X509CrlBuilder AddExtension(X509Extension extension)
    {
        ArgumentNullException.ThrowIfNull(extension);
        var oid = extension.Oid?.Value ?? throw new ArgumentException("The extension has no OID", nameof(extension));
        if (s_crlExtensionOids.Contains(oid)) {
            throw new ArgumentException($"The builder writes the {oid} extension itself, from its own settings", nameof(extension));
        }
        if (Extensions.Any(x => x.Oid?.Value == oid)) {
            throw new ArgumentException($"A {oid} extension was already added", nameof(extension));
        }
        return this with { Extensions = Extensions.Add(extension) };
    }


    /// <summary>Encodes and signs the CRL.</summary>
    /// <returns>The signed CRL, read back from its encoding.</returns>
    /// <exception cref="InvalidOperationException">The issuer, signing key, CRL number or next update is missing;
    /// or the settings contradict each other or RFC 5280. The message says which.</exception>
    /// <exception cref="CryptographicException">The <see cref="Issuer"/> certificate has no private key that can be found.</exception>
    /// <exception cref="NotSupportedException">The <see cref="Issuer"/>'s key cannot sign, such as an ECDH key, or is of an unsupported kind.</exception>
    /// <remarks>Refuses: a signing certificate whose key usage lacks <see cref="X509KeyUsageFlags.CrlSign"/>; a next
    /// update before this update; a delta CRL whose number is not above its base's, or whose issuer or scope differs from the
    /// base CRL passed to <see cref="SetDeltaOf(CertificateRevocationList)"/>; a certificate listed twice with
    /// different details; a <see cref="X509RevocationReason.RemoveFromCrl"/> entry in a full CRL; an entry naming
    /// another certificate issuer where the CRL is not indirect; and a <see cref="CrlDistributionPoint.CrlIssuer"/> other
    /// than the issuer. It does not check CRL numbering across publications, whether the issuer is trusted, or
    /// that the list is complete.</remarks>
    public CertificateRevocationList Create()
    {
        var issuerName = IssuerName ?? throw new InvalidOperationException($"Call {nameof(SetIssuer)}(...) first to say who issues the CRL");
        var crlNumber = CrlNumber ?? throw new InvalidOperationException($"Call {nameof(SetCrlNumber)}(...) first: every CRL carries a number");
        var nextUpdate = NextUpdate ?? throw new InvalidOperationException($"Call {nameof(SetNextUpdate)}(...) first: RFC 5280 s5.1.2.5 requires conforming CRL issuers to say when the next CRL is due");
        var thisUpdate = ThisUpdate ?? DateTimeOffset.UtcNow;

        if (nextUpdate < thisUpdate) {
            throw new InvalidOperationException($"The next update ({nextUpdate:O}) is before this update ({thisUpdate:O})");
        }

        CheckIssuerMaySignCrls();
        CheckDelta(crlNumber, issuerName);
        var indirect = CheckDistributionPoint(issuerName);
        var entries = CheckEntries(issuerName, indirect);

        //GetPrivateKey hands back a fresh instance which is ours to release, unlike a generator the caller supplied
        using var issuerKey = SignatureGenerator == null && Issuer != null
            ? Issuer.GetPrivateKey()
            : null;
        var generator = SignatureGenerator
            ?? (issuerKey != null
                ? SignatureGenerators.GetForKey(issuerKey, RSASignaturePadding)
                : throw new InvalidOperationException($"Call {nameof(SetIssuer)}(...) with a certificate that has a private key, or {nameof(SetSignatureGenerator)}(...), to say how to sign"));

        var algorithm = generator.GetSignatureAlgorithmIdentifier(HashAlgorithm);
        //RFC 5280 s5.2.1: every CRL carries the Authority Key Identifier, so a signer that publishes none gets
        //the key identifier derived from its public key, as CertificateBuilder does for the certificates it issues
        var keyIdentifier = IssuerKeyIdentifier.IsEmpty
            ? new X509SubjectKeyIdentifierExtension(generator.PublicKey, false).SubjectKeyIdentifierBytes.ToArray()
            : IssuerKeyIdentifier.ToArray();
        var toBeSigned = EncodeToBeSigned(algorithm, issuerName, thisUpdate, nextUpdate, crlNumber, entries, indirect, keyIdentifier);
        var signature = generator.SignData(toBeSigned, HashAlgorithm);

        var crl = new AsnWriter(AsnEncodingRules.DER);
        using (crl.PushSequence()) {
            crl.WriteEncodedValue(toBeSigned);
            crl.WriteEncodedValue(algorithm);
            crl.WriteBitString(signature);
        }

        return CertificateRevocationList.Load(crl.Encode());
    }


    //Extensions the builder writes itself, which a caller cannot also supply
    private static readonly ImmutableHashSet<string> s_crlExtensionOids = [
        Oids.AuthorityKeyIdentifier, Oids.CrlNumber, Oids.DeltaCrlIndicator, Oids.IssuingDistributionPoint, Oids.FreshestCrl
    ];

    private static readonly ImmutableHashSet<string> s_entryExtensionOids = [
        Oids.CrlReasons, Oids.InvalidityDate, Oids.CertificateIssuer
    ];

    private static readonly Asn1Tag s_context0 = new(TagClass.ContextSpecific, 0);


    private void CheckIssuerMaySignCrls()
    {
        //RFC 5280 s4.2.1.3: where the signing certificate states a key usage, cRLSign must be one
        var usage = Issuer?.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (usage != null && !usage.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign)) {
            throw new InvalidOperationException($"The issuer's key usage does not include {nameof(X509KeyUsageFlags.CrlSign)}, so it may not sign CRLs. Use a certificate made for it, such as with {nameof(CertificateUsage)}.{nameof(CertificateUsage.CrlSigning)}");
        }
    }


    private void CheckDelta(BigInteger crlNumber, X500DistinguishedName issuerName)
    {
        if (BaseCrlNumber is not { } baseNumber) {
            return;
        }
        if (BaseCrl != null && !X500NameComparer.Values.Equals(BaseCrl.Issuer, issuerName)) {
            throw new InvalidOperationException($"A delta CRL must have the same issuer as its base CRL (RFC 5280 s5.2.4), but the base is issued by '{BaseCrl.Issuer.Name}' and this by '{issuerName.Name}'");
        }
        if (crlNumber <= baseNumber) {
            throw new InvalidOperationException($"A delta CRL must be numbered above its base: the CRL number is {crlNumber} but the base is {baseNumber}");
        }
        if (BaseCrl != null && !HasSameScope(DistributionPoint, BaseCrl.DistributionPoint)) {
            throw new InvalidOperationException($"A delta CRL must have the same scope as its base CRL (RFC 5280 s5.2.4), but the {nameof(DistributionPoint)} differs from the base CRL's");
        }
    }


    private static bool HasSameScope(CrlDistributionPoint? a, CrlDistributionPoint? b)
        => a == null || b == null
            ? a == null && b == null
            : a.Covers == b.Covers
              && a.Uris.Order(StringComparer.Ordinal).SequenceEqual(b.Uris.Order(StringComparer.Ordinal))
              &&(a.CrlIssuer == null) == (b.CrlIssuer == null);


    /// <summary>Whether the CRL is indirect, once the distribution point has been checked.</summary>
    private bool CheckDistributionPoint(X500DistinguishedName issuerName)
    {
        if (DistributionPoint?.CrlIssuer is not { } crlIssuer) {
            return false;
        }
        if (!X500NameComparer.Values.Equals(crlIssuer, issuerName)) {
            throw new InvalidOperationException($"The distribution point's {nameof(CrlDistributionPoint.CrlIssuer)} names who signs the CRL, so it must be the issuer name '{issuerName.Name}' but was '{crlIssuer.Name}'");
        }
        return true;
    }


    /// <summary>The entries to write: validated, with exact repeats removed.</summary>
    private List<RevokedCertificate> CheckEntries(X500DistinguishedName signer, bool indirect)
    {
        var seen = new Dictionary<X500DistinguishedName, Dictionary<string, RevokedCertificate>>(X500NameComparer.Values);
        var result = new List<RevokedCertificate>(RevokedCertificates.Count);

        foreach (var entry in RevokedCertificates) {
            var serial = Convert.ToHexString(entry.SerialNumber.Span).TrimStart('0');
            if (entry.SerialNumber.IsEmpty) {
                throw new InvalidOperationException("A revoked certificate has no serial number");
            }

            var issuer = entry.CertificateIssuer ?? signer;
            if (!indirect && !X500NameComparer.Values.Equals(issuer, signer)) {
                throw new InvalidOperationException($"Certificate {serial} was issued by '{issuer.Name}', which is not the CRL issuer '{signer.Name}'. Only an indirect CRL can list another issuer's certificates: give the {nameof(DistributionPoint)} a {nameof(CrlDistributionPoint.CrlIssuer)}");
            }
            if (entry.Reason == X509RevocationReason.RemoveFromCrl && BaseCrlNumber == null) {
                throw new InvalidOperationException($"Certificate {serial} has reason {nameof(X509RevocationReason.RemoveFromCrl)}, which means something only in a delta CRL (RFC 5280 s5.3.1)");
            }
            if (entry.Extensions.Any(x => x.Oid?.Value is not { } oid || s_entryExtensionOids.Contains(oid))) {
                throw new InvalidOperationException($"Certificate {serial} has an extension the builder writes itself, from the entry's own properties, or one with no OID");
            }
            if (entry.Extensions.GroupBy(x => x.Oid!.Value).FirstOrDefault(x => x.Count() > 1) is { } repeated) {
                throw new InvalidOperationException($"Certificate {serial} has the {repeated.Key} extension more than once (RFC 5280 s5.3)");
            }

            if (!seen.TryGetValue(issuer, out var byIssuer)) {
                seen[issuer] = byIssuer = [];
            }
            if (byIssuer.TryGetValue(serial, out var existing)) {
                if (!IsSameRevocation(existing, entry)) {
                    throw new InvalidOperationException($"Certificate {serial} is listed twice with different details");
                }
                continue;
            }
            byIssuer[serial] = entry;
            result.Add(entry);
        }

        return result;
    }


    private static bool IsSameRevocation(RevokedCertificate a, RevokedCertificate b)
        => a.RevocationDate.ToUnixTimeSeconds() == b.RevocationDate.ToUnixTimeSeconds()
           && a.Reason == b.Reason
           && a.InvalidityDate?.ToUnixTimeSeconds() == b.InvalidityDate?.ToUnixTimeSeconds()
           && a.Extensions.Count == b.Extensions.Count
           && a.Extensions.Zip(b.Extensions).All(x =>
               x.First.Oid?.Value == x.Second.Oid?.Value
               && x.First.Critical == x.Second.Critical
               && x.First.RawData.AsSpan().SequenceEqual(x.Second.RawData));


    private byte[] EncodeToBeSigned(
        byte[] algorithm,
        X500DistinguishedName issuerName,
        DateTimeOffset thisUpdate,
        DateTimeOffset nextUpdate,
        BigInteger crlNumber,
        List<RevokedCertificate> entries,
        bool indirect,
        byte[] keyIdentifier)
    {
        var tbs = new AsnWriter(AsnEncodingRules.DER);
        using (tbs.PushSequence()) {
            tbs.WriteInteger(1);
            tbs.WriteEncodedValue(algorithm);
            tbs.WriteEncodedValue(issuerName.RawData);
            CrlEncoding.WriteTime(tbs, thisUpdate);
            CrlEncoding.WriteTime(tbs, nextUpdate);

            if (entries.Count > 0) {
                using (tbs.PushSequence()) {
                    var current = issuerName;
                    foreach (var entry in entries) {
                        WriteEntry(tbs, entry, issuerName, ref current, indirect);
                    }
                }
            }

            using (tbs.PushSequence(s_context0))
            using (tbs.PushSequence()) {
                CrlEncoding.WriteExtension(tbs, Oids.AuthorityKeyIdentifier, false, w => {
                    using (w.PushSequence()) {
                        w.WriteOctetString(keyIdentifier, s_context0);
                    }
                });

                CrlEncoding.WriteExtension(tbs, Oids.CrlNumber, false, w => w.WriteInteger(crlNumber));

                if (BaseCrlNumber is { } baseNumber) {
                    CrlEncoding.WriteExtension(tbs, Oids.DeltaCrlIndicator, true, w => w.WriteInteger(baseNumber));
                }

                if (DistributionPoint is { } point) {
                    CrlEncoding.WriteExtension(tbs, Oids.IssuingDistributionPoint, true, w => CrlEncoding.WriteIssuingDistributionPoint(w, point, indirect));

                    //A delta CRL carries no Freshest CRL (RFC 5280 s5.2.6)
                    if (BaseCrlNumber == null && CrlEncoding.EncodeDistributionPoints([point], delta: true, includeCrlIssuer: false) is { } freshest) {
                        CrlEncoding.WriteExtension(tbs, Oids.FreshestCrl, false, freshest);
                    }
                }

                foreach (var extension in Extensions) {
                    CrlEncoding.WriteExtension(tbs, extension.Oid!.Value!, extension.Critical, extension.RawData);
                }
            }
        }

        return tbs.Encode();
    }


    /// <summary>Writes one entry, adding the Certificate Issuer extension where the issuer changes from the entry before.</summary>
    private static void WriteEntry(AsnWriter writer, RevokedCertificate entry, X500DistinguishedName signer, ref X500DistinguishedName current, bool indirect)
    {
        var issuer = entry.CertificateIssuer ?? signer;
        var changesIssuer = indirect && !X500NameComparer.Values.Equals(issuer, current);
        current = indirect ? issuer : current;

        using (writer.PushSequence()) {
            //The writer takes the minimal form, with no redundant leading zero bytes
            var serial = entry.SerialNumber.Span.TrimStart((byte)0);
            writer.WriteIntegerUnsigned(serial.IsEmpty ? [0] : serial);
            CrlEncoding.WriteTime(writer, entry.RevocationDate);

            if (entry.Reason == null && entry.InvalidityDate == null && !changesIssuer && entry.Extensions.IsEmpty) {
                return;
            }

            using (writer.PushSequence()) {
                if (entry.Reason is { } reason) {
                    CrlEncoding.WriteExtension(writer, Oids.CrlReasons, false, w => w.WriteEnumeratedValue(reason));
                }
                if (entry.InvalidityDate is { } invalidity) {
                    CrlEncoding.WriteExtension(writer, Oids.InvalidityDate, false, w => w.WriteGeneralizedTime(invalidity.ToUniversalTime(), omitFractionalSeconds: true));
                }
                if (changesIssuer) {
                    //RFC 5280 s5.3.3: critical, and applies to this entry and every one after it until the next
                    CrlEncoding.WriteExtension(writer, Oids.CertificateIssuer, true, w => {
                        using (w.PushSequence())
                        using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4))) {
                            w.WriteEncodedValue(issuer.RawData);
                        }
                    });
                }
                foreach (var extension in entry.Extensions) {
                    CrlEncoding.WriteExtension(writer, extension.Oid!.Value!, extension.Critical, extension.RawData);
                }
            }
        }
    }
}
