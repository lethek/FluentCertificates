namespace FluentCertificates;

/// <summary>
/// Represents a certificate source that loads certificates from a specified directory path.
/// </summary>
/// <param name="Path">The file system path to the directory containing certificates.</param>
public record CertificateDirectory(string Path) : AbstractCertificateSource;
