using System.Reflection;
using System.Runtime.InteropServices;
using Xunit.v3;

namespace FluentCertificates;

public sealed class SupportedOSAttribute(params SupportedOS[] supportedOSes) : BeforeAfterTestAttribute
{
    public override void Before(MethodInfo methodUnderTest, IXunitTest test)
    {
        var match = false;

        foreach (var supportedOS in supportedOSes) {
            if (!OsMappings.TryGetValue(supportedOS, out var osPlatform)) {
                throw new ArgumentException($"Supported OS value '{supportedOS}' is not a known OS",
                    nameof(supportedOSes));
            }

            if (RuntimeInformation.IsOSPlatform(osPlatform)) {
                match = true;
                break;
            }
        }

        // We use the dynamic skip exception message pattern to turn this into a skipped test
        // when it's not running on one of the targeted OSes
        if (!match) {
            throw new Exception($"$XunitDynamicSkip$This test is not supported on {RuntimeInformation.OSDescription}");
        }
    }

    
    private static readonly Dictionary<SupportedOS, OSPlatform> OsMappings = new()
    {
        { SupportedOS.FreeBSD, OSPlatform.FreeBSD },
        { SupportedOS.Linux, OSPlatform.Linux },
        { SupportedOS.OSX, OSPlatform.OSX },
        { SupportedOS.Windows, OSPlatform.Windows },
    };
}