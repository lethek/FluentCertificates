using System.Runtime.Versioning;


namespace FluentCertificates;

/// <summary>
/// Guards the assembly-level <see cref="SkipUnsupportedOSPlatformAttribute"/>. Both ways it can break
/// leave the suite green: skipping too little lets a test run where it cannot work, and skipping too much
/// empties the suite while still reporting success. These two catch it in either direction, whichever OS
/// they run on.
/// </summary>
public class SkipUnsupportedOSPlatformAttributeTests
{
    [Test]
    [UnsupportedOSPlatform("windows")]
    [UnsupportedOSPlatform("linux")]
    [UnsupportedOSPlatform("macos")]
    [UnsupportedOSPlatform("freebsd")]
    public Task ATestUnsupportedOnEveryPlatform_NeverRuns()
        => throw new InvalidOperationException(
            "Reaching this body means UnsupportedOSPlatform is no longer being honoured");


    [Test]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("freebsd")]
    public async Task ATestSupportedOnEveryPlatform_IsNeverSkipped()
        //Reported as skipped means the allow list has stopped matching, taking every OS-specific test in
        //the suite silently with it. The assertion restates the attributes above, so it fails rather than
        //passes vacuously if this ever runs somewhere unlisted.
        => await Assert.That(OperatingSystem.IsWindows() || OperatingSystem.IsLinux()
            || OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD()).IsTrue();
}
