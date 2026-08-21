using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates;

/// <summary>
/// The outcome of <see cref="X509ChainBuilder.Create"/>: the built <see cref="X509Chain"/> together with
/// its verification verdict. Owns the chain; disposing this result disposes the chain and every
/// certificate in its <see cref="X509Chain.ChainElements"/>.
/// </summary>
public sealed class ChainResult : IDisposable
{
    internal ChainResult(bool verified, X509Chain chain)
    {
        Verified = verified;
        Chain = chain;
    }


    /// <summary>Whether the chain built and verified successfully.</summary>
    public bool Verified { get; }

    /// <summary>The built chain, for direct access to <see cref="X509Chain.ChainElements"/> and policy.</summary>
    public X509Chain Chain { get; }

    /// <summary>The chain-wide status entries reported by the build.</summary>
    public X509ChainStatus[] ChainStatus => Chain.ChainStatus;


    /// <summary>
    /// Returns this result when <see cref="Verified"/> is true; otherwise throws, naming each failed status.
    /// </summary>
    /// <returns>This instance, for chaining.</returns>
    /// <exception cref="CryptographicException">The chain did not verify.</exception>
    public ChainResult EnsureVerified()
        => Verified
            ? this
            : throw new CryptographicException(
                "Certificate chain verification failed: "
                + String.Join("; ", Chain.ChainStatus.Select(x => $"{x.Status}: {x.StatusInformation.Trim()}")));


    /// <summary>
    /// Creates a <see cref="CertificateExportBuilder"/> over the chain's certificates, leaf first,
    /// anchored on the chain's end certificate. The certificates belong to the chain, so keep this
    /// result undisposed until the export terminates.
    /// </summary>
    /// <returns>A new <see cref="CertificateExportBuilder"/> containing the chain's certificates.</returns>
    /// <remarks>
    /// This does <b>not</b> verify, matching every other <c>Export()</c> in the library: a result whose
    /// <see cref="Verified"/> is false exports whatever was built, which for a partial chain is an
    /// incomplete bundle. Write <c>result.EnsureVerified().Export()</c> for the guarded form, or use
    /// <see cref="X509ChainBuilder.Export"/>, which verifies before exporting.
    /// <para>
    /// Like every export, this one carries no private key until asked: call
    /// <see cref="CertificateExportBuilder.WithPrivateKey"/> for the leaf's, which is what a fullchain
    /// wants, or <see cref="CertificateExportBuilder.WithAllPrivateKeys"/> to include any CA keys this
    /// process happens to hold.
    /// </para>
    /// </remarks>
    public CertificateExportBuilder Export() => Chain.Export();


    /// <summary>Disposes the owned <see cref="X509Chain"/> and with it the chain's element certificates.</summary>
    public void Dispose() => Chain.Dispose();
}
