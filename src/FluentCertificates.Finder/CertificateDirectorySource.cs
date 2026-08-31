using System.IO.Abstractions;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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
/// hide the good ones beside it. So is a subdirectory that cannot be opened, and a directory that is not
/// there yields no results, matching what <see cref="CertificateStoreSource"/> does with a store that
/// does not exist. Set <see cref="OnLoadFailure"/> to learn what was skipped.
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


    /// <summary>
    /// Which file names to read, matched the way <see cref="System.IO.Directory.EnumerateFiles(string,string)"/>
    /// matches them. Defaults to <c>"*"</c>, every file.
    /// </summary>
    /// <remarks>
    /// The one filter worth pushing down to a directory: it decides what is read and parsed, where a
    /// predicate on the certificate can only be answered by parsing the file first. It narrows the set of
    /// supported extensions rather than widening it, so <c>"*.txt"</c> still finds nothing.
    /// </remarks>
    public string SearchPattern { get; init; } = "*";


    /// <summary>The file system this directory is read through.</summary>
    public IFileSystem FileSystem { get; init; }


    /// <summary>
    /// The password protecting the <c>.pfx</c>, <c>.p12</c> and <c>.pkcs12</c> files in this directory.
    /// One password covers the whole directory. A file this password does not open is skipped like any
    /// other file that cannot be read, and reported through <see cref="OnLoadFailure"/>.
    /// </summary>
    /// <remarks>
    /// Redacted from <see cref="ToString"/>, since a <see cref="CertificateFinderResult"/> carries the
    /// source it came from and would otherwise print the password with it.
    /// </remarks>
    public string? Password { get; init; }


    /// <summary>
    /// Called with the path and the exception each time this source skips something it could not read:
    /// a file that would not parse, or the directory itself when it is not there. Nothing is reported
    /// by default, which makes a search that skipped forty files look like one that found nothing.
    /// </summary>
    /// <remarks>
    /// Diagnostics only. The search carries on regardless of what this does, but an exception thrown
    /// here is not caught and will end the search.
    /// <para>
    /// Part of the record's value equality, like every other property, so two sources reading the same
    /// directory with different handlers are two sources and that directory is read twice.
    /// </para>
    /// </remarks>
    public Action<string, Exception>? OnLoadFailure { get; init; }


    /// <inheritdoc/>
    public override string Kind => "Directory";


    /// <summary>
    /// Prints every property, with <see cref="Password"/> redacted. Written out by hand rather than
    /// generated, so a property added to this record has to be added here too.
    /// </summary>
    /// <param name="builder">Receives the printed members.</param>
    /// <returns>Always <see langword="true"/>: this record always prints something.</returns>
    protected override bool PrintMembers(StringBuilder builder)
    {
        base.PrintMembers(builder);
        builder.Append(", Path = ").Append(Path);
        builder.Append(", Recurse = ").Append(Recurse);
        builder.Append(", SearchPattern = ").Append(SearchPattern);
        builder.Append(", FileSystem = ").Append(FileSystem);
        builder.Append(", Password = ").Append(Password is null ? "null" : "***");
        builder.Append(", OnLoadFailure = ").Append(OnLoadFailure);
        return true;
    }


    /// <summary>
    /// Reads every certificate file in the directory. Nothing here is filtered natively yet: a predicate
    /// on the certificate cannot be answered without parsing the file, which is the same work as loading
    /// it.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>One batch per file, each holding every certificate that file yielded.</returns>
    protected override IEnumerable<CertificateBatch> Enumerate(CertificateFilter filter)
        => Load(CertificateFiles());


    /// <summary>
    /// Reverses the file listing before loading anything, so a caller after the last match parses from the
    /// end of the directory rather than through all of it. Only the paths are buffered, but the listing
    /// itself has to run to completion before the first certificate is yielded.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <returns>One batch per file, last file first.</returns>
    protected override IEnumerable<CertificateBatch> EnumerateDescending(CertificateFilter filter)
        => Load(CertificateFiles().Reverse());


    /// <summary>
    /// Reads each file asynchronously, which is where a directory search spends its time. The listing
    /// itself stays synchronous: <see cref="IFileSystem"/> offers no asynchronous form of it, and it is
    /// one enumeration against the file system rather than a read per certificate.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <param name="cancellationToken">Cancels the enumeration; the file reads honour it.</param>
    /// <returns>One batch per file, each holding every certificate that file yielded.</returns>
    protected override IAsyncEnumerable<CertificateBatch> EnumerateAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken)
        => LoadAsync(CertificateFiles(), cancellationToken);


    /// <summary>
    /// The asynchronous counterpart of <see cref="EnumerateDescending"/>.
    /// </summary>
    /// <param name="filter">The predicates the caller asked for; unused.</param>
    /// <param name="cancellationToken">Cancels the enumeration; the file reads honour it.</param>
    /// <returns>One batch per file, last file first.</returns>
    protected override IAsyncEnumerable<CertificateBatch> EnumerateDescendingAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken)
        => LoadAsync(CertificateFiles().Reverse(), cancellationToken);


    private IEnumerable<(string Path, string Extension)> CertificateFiles()
        => ListFiles()
            .Select(path => (Path: path, Extension: FileSystem.Path.GetExtension(path)))
            .Where(x => SupportedFileExtensions.Contains(x.Extension));


    /// <summary>
    /// Lists the directory, yielding nothing rather than throwing if it is not there. A directory that
    /// cannot be opened needs no guard: <see cref="EnumerationOptions.IgnoreInaccessible"/> covers the
    /// root of the scan as well as the subdirectories below it.
    /// </summary>
    private IEnumerable<string> ListFiles()
    {
        try {
            return FileSystem.Directory.EnumerateFiles(Path, SearchPattern, ListingOptions);
        } catch (DirectoryNotFoundException ex) {
            OnLoadFailure?.Invoke(Path, ex);
            return [];
        }
    }


    //One batch per file: a container format yields several certificates from the one path, and they are
    //all parsed together. The path is canonicalised once for the batch, so the same file reached from two
    //overlapping roots reports one location
    private IEnumerable<CertificateBatch> Load(IEnumerable<(string Path, string Extension)> files)
        => files.Select(x => new CertificateBatch(
            Load(x.Path, x.Extension),
            FileSystem.Path.GetFullPath(x.Path)
        ));


    private async IAsyncEnumerable<CertificateBatch> LoadAsync(
        IEnumerable<(string Path, string Extension)> files,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var file in files) {
            yield return new CertificateBatch(
                await LoadAsync(file.Path, file.Extension, cancellationToken).ConfigureAwait(false),
                FileSystem.Path.GetFullPath(file.Path)
            );
        }
    }


    private IEnumerable<X509Certificate2> Load(string path, string extension)
    {
        try {
            return Parse(extension, FileSystem.File.ReadAllBytes(path));
        } catch (Exception ex) {
            //One bad file must not hide the good ones beside it, so it is skipped and reported
            OnLoadFailure?.Invoke(path, ex);
            return [];
        }
    }


    private async ValueTask<IEnumerable<X509Certificate2>> LoadAsync(
        string path,
        string extension,
        CancellationToken cancellationToken)
    {
        try {
            return Parse(extension, await FileSystem.File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false));
        } catch (Exception ex) when (ex is not OperationCanceledException) {
            //Cancellation is not a file that could not be read, so it propagates rather than being reported
            OnLoadFailure?.Invoke(path, ex);
            return [];
        }
    }


    /// <summary>
    /// Turns a file's bytes into certificates. Split from reading them so the synchronous and asynchronous
    /// paths differ only in how they get the bytes, rather than carrying a copy of this each.
    /// </summary>
    /// <param name="extension">The file's extension, which decides the format.</param>
    /// <param name="data">The file's contents.</param>
    /// <returns>Every certificate the file holds.</returns>
    private IEnumerable<X509Certificate2> Parse(string extension, byte[] data)
    {
        switch (extension.ToLowerInvariant()) {
            case ".p7b":
            case ".p7c":
                var cms = new SignedCms();
                cms.Decode(UnwrapPem(data));
                return cms.Certificates;
            case ".pfx":
            case ".p12":
            case ".pkcs12":
                //X509CertificateLoader.LoadCertificate rejects PKCS#12, so these must go
                //through the PKCS#12 loader rather than the default branch
                return CertTools.LoadPkcs12Collection(data, Password);
            case ".pem":
            case ".ca-bundle":
                //Both extensions name PEM text, which holds any number of certificates
                var pem = new X509Certificate2Collection();
                pem.ImportFromPem(DecodeText(data));
                return pem;
            default:
                return [CertTools.LoadCertificate(data)];
        }
    }


    /// <summary>
    /// Unwraps a PEM-encoded PKCS#7 file to the DER it holds, which is what
    /// <see cref="SignedCms.Decode(byte[])"/> reads. Both encodings are written under both extensions:
    /// <c>openssl crl2pkcs7</c> writes PEM, and <c>certutil -encode</c> converts a DER file to it.
    /// </summary>
    /// <remarks>
    /// The PEM label is not checked. <c>certutil -encode</c> labels whatever it converts
    /// <c>CERTIFICATE</c>, so demanding <c>PKCS7</c> would reject the files Windows produces, and the
    /// payload is the same DER whichever label a producer wrote.
    /// </remarks>
    /// <param name="data">The file's contents.</param>
    /// <returns>
    /// The PEM block's contents, or <paramref name="data"/> unchanged when the file is not PEM.
    /// </returns>
    private static byte[] UnwrapPem(byte[] data)
    {
        //A DER file opens with a SEQUENCE tag. Its bytes decode to text that can spell out anything at
        //all, a PEM block that is no part of the encoding included, so it must not be read as text
        const byte derSequenceTag = 0x30;
        if (data.Length == 0 || data[0] == derSequenceTag) {
            return data;
        }

        var text = DecodeText(data);
        if (!PemEncoding.TryFind(text, out var pem)) {
            return data;
        }

        //TryFind has already established that this is base64 of exactly this length, so it cannot fail
        var der = new byte[pem.DecodedDataLength];
        Convert.TryFromBase64Chars(text.AsSpan()[pem.Base64Data], der, out _);
        return der;
    }


    /// <summary>
    /// Decodes PEM text the way <c>File.ReadAllText</c> would: UTF-8 unless a byte order mark says
    /// otherwise. Reading the bytes and decoding them here is what lets one parser serve both paths.
    /// </summary>
    /// <param name="data">The file's contents.</param>
    /// <returns>The decoded text.</returns>
    private static string DecodeText(byte[] data)
    {
        using var reader = new StreamReader(new MemoryStream(data), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }


    /// <summary>
    /// Matches what the <see cref="SearchOption"/> overload of <c>EnumerateFiles</c> does, save for
    /// <see cref="EnumerationOptions.IgnoreInaccessible"/>: that overload aborts a recursive scan at the
    /// first subdirectory it cannot open, losing every certificate below and beside it.
    /// </summary>
    private EnumerationOptions ListingOptions => new() {
        RecurseSubdirectories = Recurse,
        IgnoreInaccessible = true,
        //Hidden and system files are certificates like any other, and the default here would skip them
        AttributesToSkip = 0,
        MatchType = MatchType.Win32
    };


    /// <summary>
    /// The set of supported certificate file extensions. Compared case-insensitively:
    /// file systems commonly preserve whatever case the file was created with, so a
    /// certificate named "SERVER.PFX" must be found just as "server.pfx" is.
    /// <para>
    /// An extension added here needs a branch in <see cref="Parse"/> too, or the file falls through to
    /// the one that reads a lone certificate and is skipped as unreadable. Internal so a test can hold
    /// the two together.
    /// </para>
    /// </summary>
    internal static readonly HashSet<string> SupportedFileExtensions = new(StringComparer.OrdinalIgnoreCase) {
        ".crt", ".cer", ".der", ".pfx", ".p12", ".pkcs12", ".p7b", ".p7c", ".pem", ".ca-bundle"
    };
}
