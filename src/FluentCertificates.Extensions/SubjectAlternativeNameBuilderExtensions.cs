using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

public static class SubjectAlternativeNameBuilderExtensions
{
    public static SubjectAlternativeNameBuilder AddDnsNames(this SubjectAlternativeNameBuilder builder, params string[] dnsNames)
    {
        foreach (var dnsName in dnsNames.Where(x => !String.IsNullOrEmpty(x))) {
            builder.AddDnsName(dnsName);
        }
        return builder;
    }
}
