using System.IO.Abstractions;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

/// <summary>
/// A certificate source reading certificate files from a directory.
/// </summary>
/// <remarks>
/// A record, so two instances naming the same directory, recursion setting and file system compare equal
/// and <see cref="CertificateFinder"/> reads that directory once however many times it was added.
/// Searching the top level and searching the tree are different searches, so they are different sources.
/// <para>
/// A file that cannot be read as a certificate is skipped rather than throwing, so one bad file does not
/// hide the good ones beside it.
/// </para>
/// </remarks>
public sealed record CertificateDirectorySource : AbstractCertificateSource
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateDirectorySource"/> class.
    /// </summary>
    /// <param name="path">The file system path to the directory containing certificates.</param>
    /// <param name="recurse">Whether to search subdirectories.</param>
    /// <param name="fileSystem">
    /// The file system to read through. If <see langword="null"/>, the real one is used.
    /// </param>
    public CertificateDirectorySource(string path, bool recurse = false, IFileSystem? fileSystem = null)
    {
        Path = path;
        Recurse = recurse;
        FileSystem = fileSystem ?? new FileSystem();
    }


    /// <summary>The file system path to the directory containing certificates.</summary>
    public string Path { get; init; }


    /// <summary>Whether subdirectories are searched.</summary>
    public bool Recurse { get; init; }


    /// <summary>The file system this directory is read through.</summary>
    public IFileSystem FileSystem { get; init; }


    /// <inheritdoc/>
    public override string Kind => "Directory";


    /// <summary>
    /// Reads every certificate file in the directory. Nothing here is filtered natively yet: a predicate
    /// on the certificate cannot be answered without parsing the file, which is the same work as loading
    /// it.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>Every certificate loadable from the directory.</returns>
    protected override IEnumerable<CertificateFinderResult> Enumerate(CertificateFilter filter)
        => Load(CertificateFiles());


    /// <summary>
    /// Reverses the file listing before loading anything, so a caller after the last match parses from the
    /// end of the directory rather than through all of it. Only the paths are buffered, but the listing
    /// itself has to run to completion before the first certificate is yielded.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>Every certificate loadable from the directory, last file first.</returns>
    protected override IEnumerable<CertificateFinderResult> EnumerateDescending(CertificateFilter filter)
        => Load(CertificateFiles().Reverse());


    private IEnumerable<(string Path, string Extension)> CertificateFiles()
        => FileSystem.Directory
            .EnumerateFiles(Path, "*", Recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Select(path => (Path: path, Extension: FileSystem.Path.GetExtension(path)))
            .Where(x => SupportedFileExtensions.Contains(x.Extension));


    private IEnumerable<CertificateFinderResult> Load(IEnumerable<(string Path, string Extension)> files)
        => files.SelectMany(x => {
            //Canonicalised once per file: a container format yields many certificates from the one path,
            //and the same file reached from two overlapping roots reports one location
            var location = FileSystem.Path.GetFullPath(x.Path);
            return SelectResults(Load(x.Path, x.Extension), _ => location);
        });


    private IEnumerable<X509Certificate2> Load(string path, string extension)
    {
        try {
            switch (extension.ToLowerInvariant()) {
                case ".p7b":
                case ".p7c":
                    var cms = new SignedCms();
                    cms.Decode(FileSystem.File.ReadAllBytes(path));
                    return cms.Certificates;
                case ".pfx":
                case ".p12":
                    //X509CertificateLoader.LoadCertificate rejects PKCS#12, so these must go
                    //through the PKCS#12 loader rather than the default branch
                    return CertTools.LoadPkcs12Collection(FileSystem.File.ReadAllBytes(path), null);
                case ".pem":
                case ".ca-bundle":
                    //Both extensions name PEM text, which holds any number of certificates
                    var pem = new X509Certificate2Collection();
                    pem.ImportFromPem(FileSystem.File.ReadAllText(path));
                    return pem;
                default:
                    return [CertTools.LoadCertificate(FileSystem.File.ReadAllBytes(path))];
            }
        } catch {
            //Ignore any certificate files which couldn't be loaded
            return [];
        }
    }


    /// <summary>
    /// The set of supported certificate file extensions. Compared case-insensitively:
    /// file systems commonly preserve whatever case the file was created with, so a
    /// certificate named "SERVER.PFX" must be found just as "server.pfx" is.
    /// </summary>
    private static readonly HashSet<string> SupportedFileExtensions = new(StringComparer.OrdinalIgnoreCase) {
        ".crt", ".cer", ".der", ".pfx", ".p12", ".p7b", ".p7c", ".pem", ".ca-bundle"
    };
}
