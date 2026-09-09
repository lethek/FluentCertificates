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

/// <summary>A certificate source reading certificate files from a directory.</summary>
/// <remarks>
/// A file that will not parse, a subdirectory that cannot be opened, and a directory that is not there
/// are all skipped rather than throwing. Set <see cref="OnLoadFailure"/> to learn what was skipped.
/// </remarks>
public sealed record CertificateDirectorySource : AbstractCertificateSource
{
    /// <summary>Initializes a new instance of the <see cref="CertificateDirectorySource"/> class.</summary>
    /// <param name="path">The directory containing certificates.</param>
    /// <param name="recurse">Whether to search subdirectories.</param>
    /// <param name="fileSystem">The file system to read through; <see langword="null"/> uses the real one.</param>
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
    /// <remarks>Narrows the supported extensions, never widens them, so <c>"*.txt"</c> finds nothing.</remarks>
    public string SearchPattern { get; init; } = "*";


    /// <summary>The file system this directory is read through.</summary>
    public IFileSystem FileSystem { get; init; }


    /// <summary>The one password covering every PKCS#12 file in this directory.</summary>
    /// <remarks>Redacted from <see cref="ToString"/>.</remarks>
    public string? Password { get; init; }


    /// <summary>Called with the path and the exception each time this source skips what it cannot read.</summary>
    /// <remarks>An exception thrown here is not caught and will end the search.</remarks>
    public Action<string, Exception>? OnLoadFailure { get; init; }


    /// <inheritdoc/>
    public override string Kind => "Directory";


    /// <summary>
    /// Prints every property, with <see cref="Password"/> redacted. Hand-written, so a property added to
    /// this record has to be added here too.
    /// </summary>
    /// <param name="builder">Receives the printed members.</param>
    /// <returns>Always <see langword="true"/>.</returns>
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


    /// <inheritdoc/>
    /// <remarks>Nothing is filtered natively: answering a predicate means parsing the file anyway.</remarks>
    protected override IEnumerable<CertificateBatch> Enumerate(CertificateFilter filter)
        => Load(CertificateFiles());


    /// <inheritdoc/>
    /// <remarks>The listing runs to completion before the first certificate is yielded.</remarks>
    protected override IEnumerable<CertificateBatch> EnumerateDescending(CertificateFilter filter)
        => Load(CertificateFiles().Reverse());


    /// <inheritdoc/>
    /// <remarks>The file reads are asynchronous; the directory listing stays synchronous.</remarks>
    protected override IAsyncEnumerable<CertificateBatch> EnumerateAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken)
        => LoadAsync(CertificateFiles(), cancellationToken);


    /// <inheritdoc/>
    protected override IAsyncEnumerable<CertificateBatch> EnumerateDescendingAsync(
        CertificateFilter filter,
        CancellationToken cancellationToken)
        => LoadAsync(CertificateFiles().Reverse(), cancellationToken);


    /// <summary>The files whose extension names a format, paired with that format.</summary>
    private IEnumerable<(string Path, FileFormat Format)> CertificateFiles()
    {
        foreach (var path in ListFiles()) {
            if (FileFormats.TryGetValue(FileSystem.Path.GetExtension(path), out var format)) {
                yield return (path, format);
            }
        }
    }


    /// <summary>Lists the files to read, or nothing at all when the directory cannot be listed.</summary>
    /// <remarks>An unopenable root needs no guard here: IgnoreInaccessible covers the root of the scan
    /// too.</remarks>
    private IEnumerable<string> ListFiles()
    {
        try {
            return FileSystem.Directory.EnumerateFiles(Path, SearchPattern, ListingOptions);
        } catch (DirectoryNotFoundException ex) {
            OnLoadFailure?.Invoke(Path, ex);
            return [];
        }
    }


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
            //Cancellation is not an unreadable file: it must propagate rather than be reported and skipped
            OnLoadFailure?.Invoke(path, ex);
            return [];
        }
    }


    /// <summary>Turns a file's bytes into certificates.</summary>
    private IEnumerable<X509Certificate2> Parse(FileFormat format, ReadOnlySpan<byte> data)
    {
        switch (format) {
            case FileFormat.Pkcs12:
                return CertTools.LoadPkcs12Collection(data, Password);

            case FileFormat.Certificates:
            case FileFormat.Pem:
                //Read by what the file holds, not by what its name promised: those extensions are all
                //used for both encodings and for each other's payloads
                return IsDer(data)
                    ? ReadDer(data)
                    : ReadPem(data, mayBeEmpty: format == FileFormat.Pem);

            default:
                throw new InvalidOperationException($"Unsupported file format: {format}.");
        }
    }


    /// <summary>
    /// Reads every certificate a file's PEM text holds. Only <c>.pem</c> and <c>.ca-bundle</c> may
    /// legitimately hold none, so under any other extension an empty result is reported as a failure.
    /// </summary>
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
    /// Reads every certificate PEM text holds, as <c>CERTIFICATE</c> blocks or as a PKCS#7 bundle, and
    /// passes over blocks holding neither.
    /// </summary>
    /// <remarks>
    /// A block is read by what it decodes to rather than by the label over it, since the two are
    /// routinely at odds: <c>openssl crl2pkcs7</c> writes a <c>PKCS7</c> block that people save as
    /// <c>.pem</c>, and <c>certutil -encode</c> labels whatever it converts <c>CERTIFICATE</c>.
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
            //This batch never reaches its caller, so nothing else can release what was read before the bad
            //block. Unobservable from a test, so a mutation run reports the loop below as a survivor.
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
    }


    /// <summary>Reads DER as whatever its content says it is: a PKCS#7 bundle, or a lone certificate.</summary>
    private static X509Certificate2Collection ReadDer(ReadOnlySpan<byte> der)
        => IsPkcs7(der) ? DecodePkcs7(der) : [CertTools.LoadCertificate(der)];


    /// <summary>
    /// Whether a file's bytes are binary rather than text: one complete DER value and nothing after it.
    /// </summary>
    /// <remarks>
    /// The opening tag alone will not do. A SEQUENCE opens with <c>0x30</c>, which is also the digit
    /// <c>0</c>, so a PEM bundle starting with one would be truncated to its first certificate.
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
    /// certificate.
    /// </summary>
    private static bool IsPkcs7(ReadOnlySpan<byte> der)
    {
        try {
            //Peek, don't read: a certificate opens with the TBSCertificate SEQUENCE, so reading the OID
            //outright would answer the commonest case by throwing
            var content = new AsnValueReader(der, AsnEncodingRules.BER).ReadSequence();
            return content.PeekTag() == Asn1Tag.ObjectIdentifier
                && content.ReadObjectIdentifier() == Oids.Pkcs7Signed;
        } catch (AsnContentException) {
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
    /// Decodes PEM text as <c>File.ReadAllText</c> would: a byte order mark names the encoding, UTF-8 is
    /// assumed without one.
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
    /// The encodings a byte order mark can name. Longest mark first: UTF-32 LE opens with the same two
    /// bytes as UTF-16 LE, so testing it second would never match.
    /// </summary>
    private static readonly Encoding[] MarkedEncodings = [
        Encoding.UTF32,
        new UTF32Encoding(bigEndian: true, byteOrderMark: true),
        Encoding.Unicode,
        Encoding.BigEndianUnicode,
        Encoding.UTF8
    ];


    /// <summary>
    /// Matches the <see cref="SearchOption"/> overload of <c>EnumerateFiles</c>, save for
    /// <see cref="EnumerationOptions.IgnoreInaccessible"/>: that overload aborts a recursive scan at the
    /// first subdirectory it cannot open.
    /// </summary>
    private EnumerationOptions ListingOptions => new() {
        RecurseSubdirectories = Recurse,
        IgnoreInaccessible = true,
        //Hidden and system files are certificates like any other, and the default here would skip them
        AttributesToSkip = 0,
        MatchType = MatchType.Win32
    };


    /// <summary>Every file extension this source reads, each naming how that extension is read.</summary>
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


    /// <summary>How an extension is read; its encoding and payload are read from the file itself.</summary>
    internal enum FileFormat
    {
        /// <summary>An extension naming certificates outright, so a file holding none is reported.</summary>
        Certificates,

        /// <summary>A PKCS#12 container, which needs <see cref="Password"/> when one protects it.</summary>
        Pkcs12,

        /// <summary>PEM text, which may hold no certificates at all.</summary>
        Pem
    }
}
