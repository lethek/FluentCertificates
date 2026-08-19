using Org.BouncyCastle.Asn1.X509;


namespace FluentCertificates;

public static class CertificateBuilderExtensions
{
    public static CertificateBuilder SetSubject(this CertificateBuilder builder, X509Name value)
        => builder with { Subject = new X500NameBuilder(value.ConvertToDotNet()) };
}
