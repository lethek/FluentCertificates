using System.Collections.Immutable;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace FluentCertificates;

/// <summary>
/// An immutable fluent builder for configuring certificate export operations. Obtain one from
/// <c>cert.Export()</c>, <c>chain.Export()</c>, or <c>collection.Export()</c>, configure it, then select a
/// format with <see cref="AsPkcs12"/>, <see cref="AsPem"/>, <see cref="AsPkcs7"/>, or <see cref="AsCert"/>.
/// </summary>
public record CertificateExportBuilder
{
    /// <summary>The certificates to be exported, in the order they were added.</summary>
    public ImmutableList<X509Certificate2> Certificates { get; init; } = ImmutableList<X509Certificate2>.Empty;

    /// <summary>The certificate the export is about, or null when the builder was seeded from a set that
    /// designates none, such as <c>collection.Export()</c>.</summary>
    /// <remarks>
    /// <see cref="ExportKeys.Primary"/> and <see cref="AsCert"/> read the primary certificate from here
    /// rather than from list position, so <see cref="AddChain(IEnumerable{X509Certificate2})"/> cannot
    /// retarget the export and both throw without an anchor. Only the entry points set this; it cannot be
    /// assigned through a <c>with</c> expression, and an anchor absent from the certificates is rejected.
    /// </remarks>
    public X509Certificate2? Anchor { get; private init; }

    /// <summary>Controls which private keys are included. Defaults to <see cref="ExportKeys.None"/>.</summary>
    public ExportKeys Keys { get; init; } = ExportKeys.None;

    /// <summary>Plain-text password used to protect private keys. Only a <c>with</c> expression can set this
    /// alongside <see cref="SecurePassword"/>, which wins when both are set.</summary>
    public string? Password { get; init; }

    /// <summary>SecureString password used to protect private keys. Disposing it after export is the
    /// caller's responsibility.</summary>
    public SecureString? SecurePassword { get; init; }


    /// <summary>Initializes a new builder with the given certificates.</summary>
    /// <param name="certs">The initial set of certificates to export.</param>
    /// <param name="anchor">The certificate known to be the leaf, or null. See <see cref="Anchor"/>.</param>
    internal CertificateExportBuilder(IEnumerable<X509Certificate2> certs, X509Certificate2? anchor = null)
    {
        Certificates = [.. certs];
        Anchor = anchor;
    }


    /// <summary>Prints every property, with <see cref="Password"/> redacted. Hand-written, so a property
    /// added to this record has to be added here too.</summary>
    /// <param name="builder">Receives the printed members.</param>
    /// <returns>Always <see langword="true"/>.</returns>
    protected virtual bool PrintMembers(StringBuilder builder)
    {
        builder.Append("Certificates = ").Append(Certificates);
        builder.Append(", Anchor = ").Append(Anchor);
        builder.Append(", Keys = ").Append(Keys);
        builder.Append(", Password = ").Append(Password is null ? "null" : "***");
        builder.Append(", SecurePassword = ").Append(SecurePassword);
        return true;
    }


    /// <summary>Returns a new builder with the key-export behaviour set to <paramref name="keys"/>.</summary>
    /// <param name="keys">Which private keys to include in the export.</param>
    public CertificateExportBuilder WithKeys(ExportKeys keys)
        => this with { Keys = keys };

    /// <summary>Returns a new builder including only the <see cref="Anchor"/>'s private key.</summary>
    public CertificateExportBuilder WithPrivateKey()
        => this with { Keys = ExportKeys.Primary };

    /// <summary>Returns a new builder including every private key the caller holds, CA keys among them.</summary>
    public CertificateExportBuilder WithAllPrivateKeys()
        => this with { Keys = ExportKeys.All };

    /// <summary>Returns a new builder that strips all private keys from the export, which is the default.</summary>
    public CertificateExportBuilder WithoutPrivateKeys()
        => this with { Keys = ExportKeys.None };

    /// <summary>Returns a new builder appending <paramref name="chain"/>, deduplicating by thumbprint.</summary>
    /// <param name="chain">An X.509 chain whose elements are appended.</param>
    public CertificateExportBuilder AddChain(X509Chain chain)
        => AddChain(chain.ToEnumerable());

    /// <summary>Returns a new builder appending <paramref name="certs"/>, deduplicating by thumbprint. This
    /// call declares them a chain, so when they form one they are sorted leaf-first and appended as a block;
    /// each call is sorted separately, producing several ordered chains in call order.</summary>
    /// <param name="certs">Additional certificates to include, forming a chain.</param>
    /// <seealso cref="AddCertificates"/>
    public CertificateExportBuilder AddChain(params IEnumerable<X509Certificate2> certs)
        => Append(certs, OrderLeafFirst);

    /// <summary>Returns a new builder appending <paramref name="certs"/> in exactly the order given,
    /// deduplicating by thumbprint. They are never reordered, unlike a chain.</summary>
    /// <param name="certs">Additional certificates to include, in the order they should be written.</param>
    /// <seealso cref="AddChain(IEnumerable{X509Certificate2})"/>
    public CertificateExportBuilder AddCertificates(params IEnumerable<X509Certificate2> certs)
        => Append(certs, x => x);

    /// <summary>Returns a new builder appending whatever <paramref name="arrange"/> makes of the
    /// not-already-present members of <paramref name="certs"/>.</summary>
    private CertificateExportBuilder Append(IEnumerable<X509Certificate2> certs, Func<IReadOnlyList<X509Certificate2>, IReadOnlyList<X509Certificate2>> arrange)
    {
        var existing = Certificates.Select(c => c.Thumbprint).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var toAdd = certs.Where(c => existing.Add(c.Thumbprint)).ToList();
        return toAdd.Count == 0
            ? this
            : this with { Certificates = Certificates.AddRange(arrange(toAdd)) };
    }

    /// <summary>Returns <paramref name="certs"/> ordered leaf-first, root last, when they form a single
    /// unambiguous issuer chain. Every other input is returned untouched.</summary>
    private static IReadOnlyList<X509Certificate2> OrderLeafFirst(IReadOnlyList<X509Certificate2> certs)
    {
        if (certs.Count < 2) {
            return certs;
        }

        //The leaf issued nothing else in the list. Self-issued doesn't count, or a self-signed root would
        //disqualify itself.
        var leafIndex = -1;
        for (var i = 0; i < certs.Count; i++) {
            var cert = certs[i];
            if (certs.Any(subject => !ReferenceEquals(subject, cert) && subject.IsIssuedBy(cert))) {
                continue;
            }
            if (leafIndex >= 0) {
                return certs;
            }
            leafIndex = i;
        }
        if (leafIndex < 0) {
            return certs;
        }

        var placed = new bool[certs.Count];
        placed[leafIndex] = true;

        var ordered = new List<X509Certificate2>(certs.Count) { certs[leafIndex] };
        while (ordered.Count < certs.Count) {
            var subject = ordered[^1];
            var next = -1;
            for (var i = 0; i < certs.Count; i++) {
                if (placed[i] || !subject.IsIssuedBy(certs[i])) {
                    continue;
                }
                if (next >= 0) {
                    return certs;
                }
                next = i;
            }
            if (next < 0) {
                return certs;
            }
            ordered.Add(certs[next]);
            placed[next] = true;
        }
        return ordered;
    }

    /// <summary>Returns a new builder with a plain-text password, clearing any <see cref="SecurePassword"/>.</summary>
    /// <param name="password">The plain-text password, or <c>null</c> to clear it.</param>
    public CertificateExportBuilder WithPassword(string? password)
        => this with { Password = password, SecurePassword = null };

    /// <summary>Returns a new builder with a <see cref="SecureString"/> password, clearing any plain-text
    /// <see cref="Password"/>. Disposing it after export is the caller's responsibility.</summary>
    /// <remarks>
    /// <see cref="AsPem"/> zeroes the decrypted password afterwards. <see cref="AsPkcs12"/> cannot: the
    /// platform accepts only a <see cref="string"/>, which lives in the managed heap and cannot be erased.
    /// </remarks>
    /// <param name="password">The secure password.</param>
    public CertificateExportBuilder WithPassword(SecureString password)
        => this with { Password = null, SecurePassword = password };

    /// <summary>Returns a new builder with no export password of either kind.</summary>
    public CertificateExportBuilder WithoutPassword()
        => this with { Password = null, SecurePassword = null };


    /// <summary>Selects PKCS#12 (PFX) as the export format, written as binary.</summary>
    public CertificateExporter AsPkcs12()
        => new(Certificates, Anchor, ExportFormat.Pkcs12, Password, SecurePassword, Keys);

    /// <summary>Selects PEM as the export format, written as the UTF-8 bytes of the PEM text.</summary>
    public PemCertificateExporter AsPem()
        => new(Certificates, Anchor, ExportFormat.Pem, Password, SecurePassword, Keys);

    /// <summary>Selects DER-encoded PKCS#7 (P7B). Private keys are never included.</summary>
    public CertificateExporter AsPkcs7()
        => new(Certificates, Anchor, ExportFormat.Pkcs7, null, null, ExportKeys.None);

    /// <summary>Selects the <see cref="AsPkcs7"/> bundle wrapped in a <c>PKCS7</c> PEM block, for text-only
    /// transports. Private keys are never included.</summary>
    /// <remarks>
    /// RFC 7468 s8 says implementations SHOULD NOT generate the <c>PKCS7</c> label where s9's <c>CMS</c>
    /// will do, but OpenSSL writes <c>PKCS7</c> and <c>CMS</c> support is thin, so <c>PKCS7</c> is used.
    /// </remarks>
    public PemCertificateExporter AsPkcs7Pem()
        => new(Certificates, Anchor, ExportFormat.Pkcs7Pem, null, null, ExportKeys.None);

    /// <summary>Selects DER-encoded certificate (CER/CRT). Only the <see cref="Anchor"/> is exported, and
    /// this throws when there is none.</summary>
    public CertificateExporter AsCert()
        => new(Certificates, Anchor, ExportFormat.Cert, null, null, ExportKeys.None);
}
