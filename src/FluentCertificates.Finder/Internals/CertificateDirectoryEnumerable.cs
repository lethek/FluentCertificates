using System.Collections;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals;

internal sealed class CertificateDirectoryEnumerable(CertificateDirectory dirStore) : IEnumerable<CertificateFinderResult>
{
    public CertificateDirectoryEnumerable(string directory)
        : this(new CertificateDirectory(directory)) { }

    public IEnumerator<CertificateFinderResult> GetEnumerator()
        => GetCertificatesFromDirectory(dirStore).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator()
        => GetEnumerator();

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
                            return [new X509Certificate2(x.Path)];
                    }
                } catch {
                    //Ignore any certificate files which couldn't be loaded
                    return [];
                }
            })
            .Select(x => new CertificateFinderResult { Certificate = x, Directory = certDir });

    private static readonly string[] SupportedFileExtensions = [
        ".cer", ".der", ".crt", ".pfx", ".p12", ".p7b", ".p7c", ".pem", ".ca-bundle"
    ];
}
