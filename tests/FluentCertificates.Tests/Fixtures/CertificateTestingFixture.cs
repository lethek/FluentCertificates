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

        RootCA = CertificateBuilder.Create()
            .SetUsage(CertificateUsage.CA)
            .SetFriendlyName($"{namePrefix} Root CA")
            .SetSubject(nameBuilder.SetCommonName($"{namePrefix} Root CA"))
            .Build();

        IntermediateCA = CertificateBuilder.Create()
            .SetUsage(CertificateUsage.CA)
            .SetFriendlyName($"{namePrefix} Intermediate CA")
            .SetSubject(nameBuilder.SetCommonName($"{namePrefix} Intermediate CA"))
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
