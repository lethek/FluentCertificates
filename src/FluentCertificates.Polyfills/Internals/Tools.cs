#if !NET5_0_OR_GREATER
using System.Runtime.InteropServices;
#endif

#pragma warning disable IDE0022 // Use expression body for methods

namespace FluentCertificates.Internals;

internal static class Tools
{
    public static bool IsAsciiLetter(char c)
        => (uint)((c | 0x20) - 97) <= 25u;

    
    internal static bool IsWindows
#if NET5_0_OR_GREATER
        => OperatingSystem.IsWindows();
#else
        => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
#endif


    internal static byte[] ConvertFromHexString(ReadOnlySpan<char> chars)
    {
#if NET5_0_OR_GREATER
        return Convert.FromHexString(chars);
#else
        int hexStringLength = chars.Length;
        var b = new byte[hexStringLength / 2];
        for (int i = 0; i < hexStringLength; i += 2) {
            int topChar = chars[i];// & ~0x20;
            topChar = (topChar > 0x40 ? (topChar & ~0x20) - 0x37 : topChar - 0x30) << 4;
            int bottomChar = chars[i + 1];// & ~0x20;
            bottomChar = bottomChar > 0x40 ? (bottomChar & ~0x20) - 0x37 : bottomChar - 0x30;
            b[i / 2] = (byte)(topChar + bottomChar);
        }
        return b;
#endif
    }
}

#pragma warning restore IDE0022 // Use expression body for methods
