using System.Runtime.InteropServices;

namespace FluentCertificates;

public sealed class SupportedOSAttribute : SkipAttribute
{
    public SupportedOSAttribute(params SupportedOS[] supportedOSes)
        : base($"This test is only supported on: {String.Join(", ", supportedOSes)}")
    {
        foreach (var supportedOS in supportedOSes) {
            if (!OsMappings.ContainsKey(supportedOS)) {
                throw new ArgumentException($"Supported OS value '{supportedOS}' is not a known OS",
                    nameof(supportedOSes));
            }
        }

        _supportedOSes = supportedOSes;
    }


    public override Task<bool> ShouldSkip(TestRegisteredContext context)
        => Task.FromResult(!_supportedOSes.Any(x => RuntimeInformation.IsOSPlatform(OsMappings[x])));


    private readonly SupportedOS[] _supportedOSes;


    private static readonly Dictionary<SupportedOS, OSPlatform> OsMappings = new()
    {
        { SupportedOS.FreeBSD, OSPlatform.FreeBSD },
        { SupportedOS.Linux, OSPlatform.Linux },
        { SupportedOS.OSX, OSPlatform.OSX },
        { SupportedOS.Windows, OSPlatform.Windows },
    };
}
