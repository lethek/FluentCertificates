using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates.Fixtures;

public sealed class CertificateTestingFixture : IDisposable
{
    public X509Certificate2 RootCA => _rootCa.Value;
    public X509Certificate2 IntermediateCA => _intermediateCa.Value;
    public X509Chain CAs => _caChain.Value;


    public CertificateTestingFixture()
    {
        _rootCa = new(() => CreateCertificateAuthority("Root CA", 100));
        _intermediateCa = new(() => CreateCertificateAuthority("Intermediate CA", 99, RootCA));
        _caChain = new(() => IntermediateCA.BuildChain(new[] { RootCA }, true));
    }


    public void Dispose()
    {
        if (_rootCa.IsValueCreated) {
            _rootCa.Value.Dispose();
        }
        if (_intermediateCa.IsValueCreated) {
            _intermediateCa.Value.Dispose();
        }
        if (_caChain.IsValueCreated) {
            _caChain.Value.Dispose();
        }
    }


    public static X509Certificate2 CreateCertificateAuthority(string name, int years, X509Certificate2? issuer = null)
        => new CertificateBuilder()
            .SetUsage(CertificateUsage.CA)
            .SetFriendlyName($"{CertNamePrefix} {name}")
            .SetSubject(new X500NameBuilder().SetCommonName($"{CertNamePrefix} {name}"))
            .SetNotAfter(DateTimeOffset.UtcNow.AddYears(years))
            .SetIssuer(issuer)
            .Create();


    private readonly Lazy<X509Certificate2> _rootCa;
    private readonly Lazy<X509Certificate2> _intermediateCa;
    private readonly Lazy<X509Chain> _caChain;

    
    private const string CertNamePrefix = "FluentCertificates Test";
}
