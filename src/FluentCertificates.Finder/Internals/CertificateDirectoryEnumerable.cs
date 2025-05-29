using System.Collections;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

/// <summary>
/// Enumerates certificates from a specified <see cref="CertificateDirectory"/>.
/// Supports loading certificates from various file formats within a directory,
/// yielding <see cref="CertificateFinderResult"/> for each successfully loaded certificate.
/// </summary>
/// <param name="dirStore">The certificate directory source.</param>
internal sealed class CertificateDirectoryEnumerable(CertificateDirectory dirStore) : IEnumerable<CertificateFinderResult>
{
    /// <summary>
    /// Initializes a new instance of <see cref="CertificateDirectoryEnumerable"/> using a directory path.
    /// </summary>
    /// <param name="directory">The directory path containing certificate files.</param>
    public CertificateDirectoryEnumerable(string directory)
        : this(new CertificateDirectory(directory)) { }

    
    /// <summary>
    /// Returns an enumerator that iterates through the certificates in the directory.
    /// </summary>
    /// <returns>An enumerator of <see cref="CertificateFinderResult"/>.</returns>
    public IEnumerator<CertificateFinderResult> GetEnumerator()
        => GetCertificatesFromDirectory(dirStore).GetEnumerator();

    
    /// <summary>
    /// Returns a non-generic enumerator that iterates through the certificates in the directory.
    /// </summary>
    /// <returns>An enumerator object.</returns>
    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();

    
    /// <summary>
    /// Retrieves certificates from the specified <see cref="CertificateDirectory"/>.
    /// Supports multiple file formats and handles errors gracefully by skipping unreadable files.
    /// </summary>
    /// <param name="certDir">The certificate directory to enumerate.</param>
    /// <returns>An enumerable of <see cref="CertificateFinderResult"/>.</returns>
    private static IEnumerable<CertificateFinderResult> GetCertificatesFromDirectory(CertificateDirectory certDir)
        => Directory.EnumerateFiles(certDir.Path)
            .Select(path => new {
                Path = path,
                Extension = Path.GetExtension(path)
            })
            .Where(x => SupportedFileExtensions.Contains(x.Extension))
            .SelectMany(x => {
                try {
                    switch (x.Extension.ToLowerInvariant()) {
                        case ".p7b":
                        case ".p7c":
                            var cms = new SignedCms();
                            cms.Decode(File.ReadAllBytes(x.Path));
                            return cms.Certificates;
                        case ".pem":
                            return [X509Certificate2.CreateFromPemFile(x.Path)];
                        default:
                            return [Tools.LoadCertificateFromFile(x.Path)];
                    }
                } catch {
                    //Ignore any certificate files which couldn't be loaded
                    return [];
                }
            })
            .Select(x => new CertificateFinderResult { Certificate = x, Directory = certDir });

    
    /// <summary>
    /// The list of supported certificate file extensions.
    /// </summary>
    private static readonly string[] SupportedFileExtensions = [
        ".cer", ".der", ".crt", ".pfx", ".p12", ".p7b", ".p7c", ".pem", ".ca-bundle"
    ];
}
