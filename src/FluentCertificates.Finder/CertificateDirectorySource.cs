using System.Collections.Frozen;
using System.Formats.Asn1;
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


    /// <summary>
    /// The files worth reading, each paired with the format its extension names. A file whose extension
    /// names no format is not one of ours and never reaches <see cref="Parse"/>.
    /// </summary>
    private IEnumerable<(string Path, FileFormat Format)> CertificateFiles()
    {
        foreach (var path in ListFiles()) {
            if (FileFormats.TryGetValue(FileSystem.Path.GetExtension(path), out var format)) {
                yield return (path, format);
            }
        }
    }


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
    private IEnumerable<CertificateBatch> Load(IEnumerable<(string Path, FileFormat Format)> files)
        => files.Select(x => new CertificateBatch(
            Load(x.Path, x.Format),
            FileSystem.Path.GetFullPath(x.Path)
        ));


    private async IAsyncEnumerable<CertificateBatch> LoadAsync(
        IEnumerable<(string Path, FileFormat Format)> files,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var file in files) {
            yield return new CertificateBatch(
                await LoadAsync(file.Path, file.Format, cancellationToken).ConfigureAwait(false),
                FileSystem.Path.GetFullPath(file.Path)
            );
        }
    }


    private IEnumerable<X509Certificate2> Load(string path, FileFormat format)
    {
        try {
            return Parse(format, FileSystem.File.ReadAllBytes(path));
        } catch (Exception ex) {
            //One bad file must not hide the good ones beside it, so it is skipped and reported
            OnLoadFailure?.Invoke(path, ex);
            return [];
        }
    }


    private async ValueTask<IEnumerable<X509Certificate2>> LoadAsync(
        string path,
        FileFormat format,
        CancellationToken cancellationToken)
    {
        try {
            return Parse(format, await FileSystem.File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false));
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
    /// <param name="format">The format the file's extension named.</param>
    /// <param name="data">The file's contents.</param>
    /// <returns>Every certificate the file holds.</returns>
    private IEnumerable<X509Certificate2> Parse(FileFormat format, ReadOnlySpan<byte> data)
    {
        switch (format) {
            case FileFormat.Pkcs12:
                //PKCS#12 is binary alone. There is no PEM form of it to look for, and its own loader is
                //the only one that reads it, so it is settled before anything sniffs the bytes.
                return CertTools.LoadPkcs12Collection(data, Password);

            case FileFormat.Certificates:
            case FileFormat.Pem:
                //Everything else is read by what the file holds rather than by what its name promised,
                //since those extensions are all used for both encodings and for each other's payloads.
                return IsDer(data)
                    ? ReadDer(data)
                    : ReadPem(data, mayBeEmpty: format == FileFormat.Pem);

            default:
                throw new InvalidOperationException($"Unsupported file format: {format}.");
        }
    }


    /// <summary>
    /// Reads every certificate a file's PEM text holds.
    /// </summary>
    /// <param name="data">The file's bytes, already established not to be DER.</param>
    /// <param name="mayBeEmpty">
    /// Whether holding no certificates is a legitimate answer, which only <c>.pem</c> and
    /// <c>.ca-bundle</c> promise. Under an extension naming certificates outright an empty result means
    /// the file is not what it claims, and reporting it is the only way a caller learns that.
    /// </param>
    private static X509Certificate2Collection ReadPem(ReadOnlySpan<byte> data, bool mayBeEmpty)
    {
        var certs = ParsePem(DecodeText(data));
        if (certs.Count == 0 && !mayBeEmpty) {
            throw new CryptographicException(
                "The file holds no certificate in any encoding this source reads.");
        }
        return certs;
    }


    /// <summary>
    /// Reads every certificate PEM text holds, whether written as <c>CERTIFICATE</c> blocks or as a
    /// PKCS#7 bundle. Blocks holding neither are passed over, so a private key or a CRL beside the
    /// certificates costs nothing.
    /// </summary>
    /// <remarks>
    /// A block is read by what it decodes to rather than by the label over it, since the two are
    /// routinely at odds: <c>openssl crl2pkcs7</c> writes a <c>PKCS7</c> block that people save as
    /// <c>.pem</c>, and <c>certutil -encode</c> labels whatever it converts <c>CERTIFICATE</c>, PKCS#7
    /// included. The label decides only the one case the content cannot: whether data that is not
    /// PKCS#7 was meant to be a certificate, and so should be reported when it will not load.
    /// </remarks>
    private static X509Certificate2Collection ParsePem(string text)
    {
        var certs = new X509Certificate2Collection();
        var remaining = text.AsSpan();
        try {
            while (PemEncoding.TryFind(remaining, out var pem)) {
                ReadBlock(remaining[pem.Label], PemTools.DecodeBlock(remaining, pem), certs);
                remaining = remaining[pem.Location.End..];
            }
            return certs;

        } catch {
            //A batch that never reaches its caller has no other owner, so what was read before the bad
            //block must be released here. No test can observe this: an undisposed certificate is only
            //unreachable, so a mutation run reports the loop below as a survivor.
            foreach (var cert in certs) {
                cert.Dispose();
            }
            throw;
        }
    }


    private static void ReadBlock(ReadOnlySpan<char> label, ReadOnlySpan<byte> der, X509Certificate2Collection certs)
    {
        if (IsPkcs7(der)) {
            certs.AddRange(DecodePkcs7(der));
        } else if (label.SequenceEqual("CERTIFICATE")) {
            certs.Add(CertTools.LoadCertificate(der));
        }
        //Anything else is not certificate material: a private key, a CRL, a CMS content type carrying
        //no certificates. It sits beside the certificates rather than naming them, so it is passed over
        //instead of costing the whole file.
    }


    /// <summary>
    /// Reads DER as whatever its content says it is: a PKCS#7 bundle, or a lone certificate. Data that
    /// is neither reaches the certificate loader and throws, so it is reported rather than read as empty.
    /// </summary>
    private static X509Certificate2Collection ReadDer(ReadOnlySpan<byte> der)
        => IsPkcs7(der) ? DecodePkcs7(der) : [CertTools.LoadCertificate(der)];


    /// <summary>
    /// Whether a file's bytes are binary rather than text: one complete DER value and nothing after it.
    /// DER must never be read as text, since its bytes decode to characters that can spell out anything
    /// at all, a PEM block that is no part of the encoding included.
    /// </summary>
    /// <remarks>
    /// The opening tag alone will not do. A SEQUENCE opens with <c>0x30</c>, which is also the digit
    /// <c>0</c>, so a bundle whose text happens to start with one would be taken for binary and only
    /// its first certificate read. Requiring the value to span the whole file separates the two.
    /// </remarks>
    private static bool IsDer(ReadOnlySpan<byte> data)
    {
        try {
            return new AsnValueReader(data, AsnEncodingRules.BER).PeekEncodedValue().Length == data.Length;
        } catch (AsnContentException) {
            return false;
        }
    }


    /// <summary>
    /// Whether DER holds the signed-data PKCS#7 that <see cref="SignedCms"/> reads, rather than a lone
    /// certificate. Both are a SEQUENCE, and what separates them is the first thing inside it: the OID
    /// naming a ContentInfo's content type, where a certificate opens with its TBSCertificate SEQUENCE.
    /// </summary>
    private static bool IsPkcs7(ReadOnlySpan<byte> der)
    {
        try {
            //A certificate opens its SEQUENCE with the TBSCertificate SEQUENCE, so reading the OID
            //outright would answer the commonest case by throwing. Peeking keeps it off that path.
            var content = new AsnValueReader(der, AsnEncodingRules.BER).ReadSequence();
            return content.PeekTag() == Asn1Tag.ObjectIdentifier
                && content.ReadObjectIdentifier() == Oids.Pkcs7Signed;
        } catch (AsnContentException) {
            //Not readable as ASN.1 at all, so it is no more PKCS#7 than it is a certificate. Loading it
            //as the latter is what reports the file as unreadable.
            return false;
        }
    }


    /// <summary>Reads the certificates out of a DER-encoded PKCS#7 bundle.</summary>
    private static X509Certificate2Collection DecodePkcs7(ReadOnlySpan<byte> der)
    {
        var cms = new SignedCms();
        cms.Decode(der);
        return cms.Certificates;
    }


    /// <summary>
    /// Decodes PEM text the way <c>File.ReadAllText</c> would: a byte order mark names the encoding, and
    /// UTF-8 is assumed when there is none. Reading the bytes and decoding them here is what lets one
    /// parser serve both paths.
    /// </summary>
    private static string DecodeText(ReadOnlySpan<byte> data)
    {
        foreach (var encoding in MarkedEncodings) {
            if (data.StartsWith(encoding.Preamble)) {
                return encoding.GetString(data[encoding.Preamble.Length..]);
            }
        }
        return Encoding.UTF8.GetString(data);
    }


    /// <summary>
    /// The encodings a byte order mark can name, longest mark first: UTF-32 little endian opens with
    /// the same two bytes as UTF-16 little endian, so testing it second would never match.
    /// </summary>
    private static readonly Encoding[] MarkedEncodings = [
        Encoding.UTF32,
        new UTF32Encoding(bigEndian: true, byteOrderMark: true),
        Encoding.Unicode,
        Encoding.BigEndianUnicode,
        Encoding.UTF8
    ];


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
    /// Every file extension this source reads, each naming how that extension is read. One table rather
    /// than a set beside a switch, so an extension cannot be recognised without saying how to read it.
    /// Compared case-insensitively: file systems commonly preserve whatever case the file was created
    /// with, so a certificate named "SERVER.PFX" must be found just as "server.pfx" is.
    /// </summary>
    /// <remarks>
    /// Internal so a test can check these extensions against the formats the tests write, which is what
    /// has every one of them read end to end in the format it really holds.
    /// </remarks>
    internal static readonly FrozenDictionary<string, FileFormat> FileFormats =
        new Dictionary<string, FileFormat> {
            [".crt"] = FileFormat.Certificates,
            [".cer"] = FileFormat.Certificates,
            [".der"] = FileFormat.Certificates,
            [".p7b"] = FileFormat.Certificates,
            [".p7c"] = FileFormat.Certificates,
            [".pfx"] = FileFormat.Pkcs12,
            [".p12"] = FileFormat.Pkcs12,
            [".pkcs12"] = FileFormat.Pkcs12,
            [".pem"] = FileFormat.Pem,
            [".ca-bundle"] = FileFormat.Pem
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);


    /// <summary>
    /// How an extension is read, which is all an extension still decides. Which encoding and which
    /// payload a file holds are read from the file, so <c>.crt</c> and <c>.p7b</c> land on one value.
    /// </summary>
    internal enum FileFormat
    {
        /// <summary>
        /// An extension naming certificates outright, so a file holding none is reported rather than
        /// read as empty.
        /// </summary>
        Certificates,

        /// <summary>
        /// A PKCS#12 container, which needs <see cref="Password"/> when one protects it. The one format
        /// with no text form, and the one its own loader alone can read.
        /// </summary>
        Pkcs12,

        /// <summary>
        /// PEM text, which may carry other material beside the certificates or hold none at all, so an
        /// empty result is a real answer.
        /// </summary>
        Pem
    }
}
