using System.Collections.Immutable;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace FluentCertificates;

/// <summary>
/// An immutable fluent builder for configuring certificate export operations.
/// Obtain an instance by calling <c>cert.Export()</c>, <c>chain.Export()</c>, or <c>collection.Export()</c>.
/// Chain configuration methods (e.g. <see cref="WithPrivateKey"/>, <see cref="AddChain(IEnumerable{X509Certificate2})"/>,
/// <see cref="WithPassword(string)"/>, <see cref="WithoutPassword"/>) then select a format with <see cref="AsPkcs12"/>, <see cref="AsPem"/>,
/// <see cref="AsPkcs7"/>, or <see cref="AsCert"/>.
/// </summary>
public record CertificateExportBuilder
{
    /// <summary>
    /// The certificates to be exported, in the order they were added.
    /// </summary>
    public ImmutableList<X509Certificate2> Certificates { get; init; } = ImmutableList<X509Certificate2>.Empty;

    /// <summary>
    /// The certificate this builder was seeded with, and therefore the one the export is about:
    /// <c>cert.Export()</c> supplies the certificate itself and <c>chain.Export()</c> supplies the
    /// chain's end certificate. Null when the builder was seeded from a set that designates none,
    /// such as <c>collection.Export()</c>.
    /// </summary>
    /// <remarks>
    /// <see cref="ExportKeys.Primary"/> and <see cref="AsCert"/> read the primary certificate from here
    /// rather than inferring it from list position, so <see cref="AddChain(IEnumerable{X509Certificate2})"/>
    /// cannot retarget the export onto a certificate the caller did not anchor on. This holds even when
    /// the set does sort into one chain: an anchored intermediate stays the target rather than being
    /// displaced by the chain's leaf. Without an anchor those two throw, because a bundle of
    /// certificates designates no leaf and position is not evidence of one.
    /// <para>
    /// Only the entry points set this. It cannot be assigned through a <c>with</c> expression, and an
    /// export whose anchor is not among its certificates is rejected.
    /// </para>
    /// </remarks>
    public X509Certificate2? Anchor { get; private init; }

    /// <summary>
    /// Controls which private keys are included in the export.
    /// Defaults to <see cref="ExportKeys.None"/>: an export writes certificates, and every private key
    /// it carries is one the caller asked for, via <see cref="WithPrivateKey"/> or
    /// <see cref="WithAllPrivateKeys"/>.
    /// </summary>
    public ExportKeys Keys { get; init; } = ExportKeys.None;

    /// <summary>
    /// Plain-text password used to protect private keys (e.g. in PKCS#12 output).
    /// Only a <c>with</c> expression can set this alongside <see cref="SecurePassword"/>; when both are
    /// set, <see cref="SecurePassword"/> wins.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// SecureString password used to protect private keys (e.g. in PKCS#12 output).
    /// Wins over <see cref="Password"/> in the only case where both can be set, a <c>with</c> expression.
    /// Disposal of the <see cref="SecureString"/> after export is the caller's responsibility.
    /// </summary>
    public SecureString? SecurePassword { get; init; }


    /// <summary>
    /// Initializes a new <see cref="CertificateExportBuilder"/> with the given certificates.
    /// </summary>
    /// <param name="certs">The initial set of certificates to export.</param>
    /// <param name="anchor">The certificate known to be the leaf, or null when the set designates none.
    /// See <see cref="Anchor"/>.</param>
    internal CertificateExportBuilder(IEnumerable<X509Certificate2> certs, X509Certificate2? anchor = null)
    {
        Certificates = [.. certs];
        Anchor = anchor;
    }


    /// <summary>
    /// Prints every property, with <see cref="Password"/> redacted. Written out by hand rather than
    /// generated, so a property added to this record has to be added here too.
    /// </summary>
    /// <param name="builder">Receives the printed members.</param>
    /// <returns>Always <see langword="true"/>: this record always prints something.</returns>
    protected virtual bool PrintMembers(StringBuilder builder)
    {
        builder.Append("Certificates = ").Append(Certificates);
        builder.Append(", Anchor = ").Append(Anchor);
        builder.Append(", Keys = ").Append(Keys);
        builder.Append(", Password = ").Append(Password is null ? "null" : "***");
        builder.Append(", SecurePassword = ").Append(SecurePassword);
        return true;
    }


    /// <summary>
    /// Returns a new builder with the key-export behaviour set to <paramref name="keys"/>.
    /// </summary>
    /// <param name="keys">Which private keys to include in the export.</param>
    public CertificateExportBuilder WithKeys(ExportKeys keys)
        => this with { Keys = keys };

    /// <summary>
    /// Returns a new builder that will include only the primary certificate's private key in the export
    /// (i.e. <see cref="ExportKeys.Primary"/>). See <see cref="Anchor"/> for which one that is.
    /// </summary>
    public CertificateExportBuilder WithPrivateKey()
        => this with { Keys = ExportKeys.Primary };

    /// <summary>
    /// Returns a new builder that will include every private key the caller holds in the export
    /// (i.e. <see cref="ExportKeys.All"/>), CA keys among them.
    /// </summary>
    public CertificateExportBuilder WithAllPrivateKeys()
        => this with { Keys = ExportKeys.All };

    /// <summary>
    /// Returns a new builder that will strip all private keys from the export
    /// (i.e. <see cref="ExportKeys.None"/>), which is also the default.
    /// </summary>
    public CertificateExportBuilder WithoutPrivateKeys()
        => this with { Keys = ExportKeys.None };

    /// <summary>
    /// Returns a new builder that appends the certificates from <paramref name="chain"/> to the
    /// builder's certificate list, deduplicating by thumbprint (certificates already present are skipped).
    /// </summary>
    /// <param name="chain">An X.509 chain whose elements are appended.</param>
    public CertificateExportBuilder AddChain(X509Chain chain)
        => AddChain(chain.ToEnumerable());

    /// <summary>
    /// Returns a new builder that appends <paramref name="certs"/> to the builder's certificate list,
    /// deduplicating by thumbprint (certificates already present are skipped). The order they are added
    /// in does not matter: this call declares them a chain, so when they form one they are sorted
    /// leaf-first and appended as a block. Each call is sorted separately, so several calls produce
    /// several ordered chains in call order.
    /// </summary>
    /// <param name="certs">Additional certificates to include, forming a chain. Pass them loose, as an
    /// array or collection, or as any <see cref="IEnumerable{T}"/>.</param>
    /// <seealso cref="AddCertificates"/>
    public CertificateExportBuilder AddChain(params IEnumerable<X509Certificate2> certs)
        => Append(certs, OrderLeafFirst);

    /// <summary>
    /// Returns a new builder that appends <paramref name="certs"/> to the builder's certificate list in
    /// exactly the order given, deduplicating by thumbprint (certificates already present are skipped).
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="AddChain(IEnumerable{X509Certificate2})"/> this claims nothing about how the
    /// certificates relate, so they are never reordered even when they do form a chain. Use it for a
    /// CA bundle, a trust store, or any set whose order is the caller's to decide.
    /// </remarks>
    /// <param name="certs">Additional certificates to include, in the order they should be written. Pass
    /// them loose, as an array or collection, or as any <see cref="IEnumerable{T}"/>.</param>
    /// <seealso cref="AddChain(IEnumerable{X509Certificate2})"/>
    public CertificateExportBuilder AddCertificates(params IEnumerable<X509Certificate2> certs)
        => Append(certs, x => x);

    /// <summary>
    /// Returns a new builder that appends whatever <paramref name="arrange"/> makes of the not-already-present
    /// members of <paramref name="certs"/>.
    /// </summary>
    private CertificateExportBuilder Append(IEnumerable<X509Certificate2> certs, Func<IReadOnlyList<X509Certificate2>, IReadOnlyList<X509Certificate2>> arrange)
    {
        var existing = Certificates.Select(c => c.Thumbprint).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var toAdd = certs.Where(c => existing.Add(c.Thumbprint)).ToList();
        return toAdd.Count == 0
            ? this
            : this with { Certificates = Certificates.AddRange(arrange(toAdd)) };
    }

    /// <summary>
    /// Returns <paramref name="certs"/> ordered leaf-first, root last, when they form a single unambiguous
    /// issuer chain. Every other input, including an unrelated bag of certificates or one holding two
    /// candidates for the same position, is returned untouched: the caller called this a chain, but nothing
    /// here can tell which order they meant.
    /// </summary>
    /// <remarks>
    /// This runs per <see cref="AddChain(IEnumerable{X509Certificate2})"/> call, so each declared chain is
    /// sorted as a unit and appended as a block. Several calls therefore produce several ordered chains in
    /// call order, and a bundle assembled through <c>collection.Export()</c> is never reordered at all.
    /// </remarks>
    private static IReadOnlyList<X509Certificate2> OrderLeafFirst(IReadOnlyList<X509Certificate2> certs)
    {
        if (certs.Count < 2) {
            return certs;
        }

        //The leaf is the one certificate that issued nothing else in the list. Self-issued doesn't count:
        //a self-signed root is its own issuer and would otherwise disqualify itself.
        var leafIndex = -1;
        for (var i = 0; i < certs.Count; i++) {
            var cert = certs[i];
            if (certs.Any(subject => !ReferenceEquals(subject, cert) && subject.IsIssuedBy(cert))) {
                continue;
            }
            if (leafIndex >= 0) {
                //More than one certificate that issued nothing here, so this isn't a single chain.
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
                    //Two candidates for the same rung: the ordering isn't ours to decide.
                    return certs;
                }
                next = i;
            }
            if (next < 0) {
                //A gap or a disjoint certificate, so this isn't a single chain.
                return certs;
            }
            ordered.Add(certs[next]);
            placed[next] = true;
        }
        return ordered;
    }

    /// <summary>
    /// Returns a new builder with a plain-text export password, clearing any <see cref="SecurePassword"/>
    /// set earlier.
    /// </summary>
    /// <param name="password">The plain-text password, or <c>null</c> to clear it.</param>
    public CertificateExportBuilder WithPassword(string? password)
        => this with { Password = password, SecurePassword = null };

    /// <summary>
    /// Returns a new builder with a <see cref="SecureString"/> export password, clearing any plain-text
    /// <see cref="Password"/> set earlier.
    /// Disposal of the <see cref="SecureString"/> after export is the caller's responsibility.
    /// </summary>
    /// <remarks>
    /// <see cref="AsPem"/> decrypts the password into a buffer it zeroes afterwards. <see cref="AsPkcs12"/>
    /// cannot: the platform's PKCS#12 export accepts only a <see cref="string"/>, so the password is copied
    /// into one that lives in the managed heap until collected and cannot be erased.
    /// </remarks>
    /// <param name="password">The secure password.</param>
    public CertificateExportBuilder WithPassword(SecureString password)
        => this with { Password = null, SecurePassword = password };

    /// <summary>
    /// Returns a new builder with no export password, clearing both <see cref="Password"/> and
    /// <see cref="SecurePassword"/>.
    /// </summary>
    public CertificateExportBuilder WithoutPassword()
        => this with { Password = null, SecurePassword = null };


    /// <summary>
    /// Selects PKCS#12 (PFX) as the export format.
    /// Returns a <see cref="CertificateExporter"/> whose output methods write the binary PKCS#12 data.
    /// </summary>
    public CertificateExporter AsPkcs12()
        => new(Certificates, Anchor, ExportFormat.Pkcs12, Password, SecurePassword, Keys);

    /// <summary>
    /// Selects PEM as the export format.
    /// Returns a <see cref="PemCertificateExporter"/> whose <see cref="PemCertificateExporter.ToPemString"/>
    /// method produces a PEM-encoded string, and whose output methods write the UTF-8 bytes of that string.
    /// </summary>
    public PemCertificateExporter AsPem()
        => new(Certificates, Anchor, Password, SecurePassword, Keys);

    /// <summary>
    /// Selects PKCS#7 (P7B) as the export format. Private keys are never included in PKCS#7 output.
    /// Returns a <see cref="CertificateExporter"/> whose output methods write the binary PKCS#7 data.
    /// </summary>
    public CertificateExporter AsPkcs7()
        => new(Certificates, Anchor, ExportFormat.Pkcs7, null, null, ExportKeys.None);

    /// <summary>
    /// Selects DER-encoded certificate (CER/CRT) as the export format.
    /// Only the primary certificate is exported, which is the <see cref="Anchor"/>.
    /// Throws when there is no anchor, since a bundle of certificates designates none.
    /// Returns a <see cref="CertificateExporter"/> whose output methods write the raw DER bytes.
    /// </summary>
    public CertificateExporter AsCert()
        => new(Certificates, Anchor, ExportFormat.Cert, null, null, ExportKeys.None);
}
