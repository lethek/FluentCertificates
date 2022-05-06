using Org.BouncyCastle.Security;

namespace FluentCertificates;

internal static class InternalTools
{
    internal static SecureRandom SecureRandom = new();
}