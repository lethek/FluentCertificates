using System;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Extensions;

namespace FluentCertificates.Tests.Fixtures;

public class CertificateTestingFixture : IDisposable
{
    public X509Certificate2 RootCA { get; }
    public X509Certificate2 IntermediateCA { get; }
    public X509Chain CAs { get; }


    public CertificateTestingFixture()
    {
        var namePrefix = "FluentCertificates Test";
        var nameBuilder = new X509NameBuilder();
        var now = DateTimeOffset.UtcNow;

        RootCA = CertificateBuilder.Create()
            .SetUsage(CertificateUsage.CA)
            .SetFriendlyName($"{namePrefix} Root CA")
            .SetSubject(nameBuilder.SetCommonName($"{namePrefix} Root CA"))
            .SetNotAfter(now.AddYears(100))
            .Build();

        IntermediateCA = CertificateBuilder.Create()
            .SetUsage(CertificateUsage.CA)
            .SetFriendlyName($"{namePrefix} Intermediate CA")
            .SetSubject(nameBuilder.SetCommonName($"{namePrefix} Intermediate CA"))
            .SetNotAfter(now.AddYears(99))
            .SetIssuer(RootCA)
           .Build();

        CAs = IntermediateCA.BuildChain(new[] { RootCA }, true);
    }


    public void Dispose()
    {
        RootCA.Dispose();
        IntermediateCA.Dispose();
        CAs.Dispose();
    }
}
