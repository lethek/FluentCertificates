namespace FluentCertificates;

/// <summary>
/// Base type for the sources a <see cref="CertificateFinder"/> can search. A result carries the
/// source it came from, so a caller can tell where a certificate was found.
/// </summary>
public abstract record AbstractCertificateSource;
