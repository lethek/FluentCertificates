using System.Collections;
using System.IO.Abstractions;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

/// <summary>
/// Enumerates certificates from a specified <see cref="CertificateDirectory"/>.
/// Supports loading certificates from various file formats within a directory,
/// yielding <see cref="CertificateFinderResult"/> for each successfully loaded certificate.
/// </summary>
/// <param name="fileSystem">The file system abstraction to use for file operations.</param>
/// <param name="directory">The certificate directory source.</param>
/// <param name="recurse">Indicates whether to search subdirectories.</param>
internal sealed class CertificateDirectoryEnumerable(IFileSystem fileSystem, CertificateDirectory directory, bool recurse = false) : IEnumerable<CertificateFinderResult>
{
    /// <summary>
    /// Initializes a new instance of <see cref="CertificateDirectoryEnumerable"/> using a directory path.
    /// </summary>
    /// <param name="fileSystem">The file system abstraction to use for file operations.</param>
    /// <param name="directory">The directory path containing certificate files.</param>
    /// <param name="recurse">Indicates whether to search subdirectories.</param>
    public CertificateDirectoryEnumerable(IFileSystem fileSystem, string directory, bool recurse = false)
        : this(fileSystem, new CertificateDirectory(directory), recurse) { }

    
    /// <summary>
    /// Returns an enumerator that iterates through the certificates in the directory.
    /// </summary>
    /// <returns>An enumerator of <see cref="CertificateFinderResult"/>.</returns>
    public IEnumerator<CertificateFinderResult> GetEnumerator()
        => GetCertificatesFromDirectory(fileSystem, directory, recurse).GetEnumerator();

    
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
    /// <param name="fileSystem">The file system abstraction to use for file operations.</param>
    /// <param name="certDir">The certificate directory to enumerate.</param>
    /// <param name="recurse">Indicates whether to search subdirectories.</param>
    /// <returns>An Enumerable of <see cref="CertificateFinderResult"/>.</returns>
    private static IEnumerable<CertificateFinderResult> GetCertificatesFromDirectory(IFileSystem fileSystem, CertificateDirectory certDir, bool recurse)
        => fileSystem.Directory
            .EnumerateFiles(certDir.Path, "*", recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
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
                            cms.Decode(fileSystem.File.ReadAllBytes(x.Path));
                            return cms.Certificates;
                        case ".pem":
                            return [X509Certificate2.CreateFromPem(fileSystem.File.ReadAllText(x.Path))];
                        default:
                            //TODO: this should be replaced with a loading method that uses IFileSystem
                            return [CertTools.LoadCertificateFromFile(x.Path)];
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
        ".crt", ".cer", ".der", ".pfx", ".p12", ".p7b", ".p7c", ".pem", ".ca-bundle"
    ];
}
