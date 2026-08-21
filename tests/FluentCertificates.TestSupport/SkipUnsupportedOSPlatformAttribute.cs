using System.Reflection;
using System.Runtime.Versioning;


namespace FluentCertificates;

/// <summary>
/// Skips any test whose <see cref="SupportedOSPlatformAttribute"/> or
/// <see cref="UnsupportedOSPlatformAttribute"/> annotations, on the method or its class, exclude the OS
/// the suite is running on. A test with neither always runs.
/// </summary>
/// <remarks>
/// <para>
/// Both attributes are compile-time only: they tell CA1416 which platforms a member may be used on, but
/// they skip nothing. This supplies the missing runtime half, so the two can never drift apart the way a
/// separate skip attribute naming the same platform would.
/// </para>
/// <para>
/// Apply it at assembly level to cover every test in the assembly, either as
/// <c>[assembly: SkipUnsupportedOSPlatform]</c> in a source file or as an <c>AssemblyAttribute</c> item
/// in the project file, which keeps it out of the source entirely. Apply it to a class or a method
/// instead to confine it to that scope. The check is the same either way, since it always reads the
/// platform attributes of the test being registered rather than of wherever this attribute sits.
/// </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Method)]
public sealed class SkipUnsupportedOSPlatformAttribute()
    : SkipAttribute("The current OS is excluded by the test's platform attributes")
{
    /// <inheritdoc />
    public override Task<bool> ShouldSkip(TestRegisteredContext context)
    {
        var details = context.TestDetails;

        //TestDetails.AttributesByType carries only the attributes TUnit itself recognises, so these have
        //to come from reflection. Test methods are not normally overloaded, but taking every match costs
        //nothing and avoids AmbiguousMatchException if one ever is.
        var members = details.ClassType
            .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
            .Where(x => x.Name == details.MethodName)
            .Cast<MemberInfo>()
            .Append(details.ClassType)
            .ToList();

        //Unsupported wins. Where the two name the same platform they mark a version range, and it is
        //reaching the unsupported version that takes the current OS back out of it.
        var unsupported = members.SelectMany(x => x.GetCustomAttributes<UnsupportedOSPlatformAttribute>());
        if (unsupported.Any(x => IsCurrentOS(x.PlatformName))) {
            return Task.FromResult(true);
        }

        //One SupportedOSPlatform turns the set into an allow list; none at all means no restriction
        var supported = members
            .SelectMany(x => x.GetCustomAttributes<SupportedOSPlatformAttribute>())
            .Select(x => x.PlatformName)
            .ToList();

        return Task.FromResult(supported.Count > 0 && !supported.Any(IsCurrentOS));
    }


    private static bool IsCurrentOS(string platformName)
    {
        //A platform name may carry a version, as in "windows10.0.17763" or "android21". Both checks are
        //case-insensitive, so "Windows" and "windows" are the same platform.
        var digit = platformName.AsSpan().IndexOfAnyInRange('0', '9');
        if (digit < 0) {
            return OperatingSystem.IsOSPlatform(platformName);
        }

        var version = platformName[digit..].Split('.');
        return OperatingSystem.IsOSPlatformVersionAtLeast(
            platformName[..digit], Part(0), Part(1), Part(2), Part(3));

        int Part(int index)
            => index < version.Length && Int32.TryParse(version[index], out var number) ? number : 0;
    }
}
