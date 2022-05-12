using Org.BouncyCastle.Security;

namespace FluentCertificates;

internal static class InternalTools
{
    internal static SecureRandom SecureRandom = new();


    internal static char[] CreateRandomCharArray(int length, string charSet = DefaultRandomCharSet)
    {
        var result = new char[length];
        for (var i = 0; i < length; i++) {
            var idx = SecureRandom.Next(charSet.Length);
            result[i] = charSet[idx];
        }
        return result;
    }


    private const string DefaultRandomCharSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()[]{}<>;:,./\?""'`~_-+=";
}