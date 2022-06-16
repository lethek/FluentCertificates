using System;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Extensions;


namespace FluentCertificates.Fixtures;

public class CertificateTestingFixture : IDisposable
{
    public X509Certificate2 RootCA => _rootCA.Value;
    public X509Certificate2 IntermediateCA => _intermediateCA.Value;
    public X509Chain CAs => _caChain.Value;

    
    private Lazy<X509Certificate2> _rootCA { get; }
    private Lazy<X509Certificate2> _intermediateCA { get; }
    private Lazy<X509Chain> _caChain { get; }


    public CertificateTestingFixture()
    {
        _rootCA = new(() => CreateCertificateAuthority("Root CA", 100));
        _intermediateCA = new(() => CreateCertificateAuthority("Intermediate CA", 99, RootCA));
        _caChain = new(() => IntermediateCA.BuildChain(new[] { RootCA }, true));
    }


    public void Dispose()
    {
        if (_rootCA.IsValueCreated) {
            _rootCA.Value.Dispose();
        }
        if (_intermediateCA.IsValueCreated) {
            _intermediateCA.Value.Dispose();
        }
        if (_caChain.IsValueCreated) {
            _caChain.Value.Dispose();
        }
    }


    private static X509Certificate2 CreateCertificateAuthority(string name, int years, X509Certificate2? issuer = null)
        => new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetFriendlyName($"{CertNamePrefix} {name}")
            .SetSubject(new X500NameBuilder().SetCommonName($"{CertNamePrefix} {name}"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddYears(years))
            .SetIssuer(issuer)
            .Build();


    private const string CertNamePrefix = "FluentCertificates Test";
}
