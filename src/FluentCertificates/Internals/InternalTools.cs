using System.Runtime.CompilerServices;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

[assembly: InternalsVisibleTo("LINQPadQuery")]

namespace FluentCertificates.Internals;

internal static class InternalTools
{
    internal static readonly SecureRandom SecureRandom = new();


    internal static AsymmetricCipherKeyPair GenerateRsaKeyPairBouncy(int length)
    {
        var parameters = new KeyGenerationParameters(SecureRandom, length);
        var generator = new RsaKeyPairGenerator();
        generator.Init(parameters);
        return generator.GenerateKeyPair();
    }


    internal static AsymmetricCipherKeyPair GenerateEcKeyPairBouncy(string curveName)
    {
        var ecParam = SecNamedCurves.GetByName(curveName);
        var ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N);
        var parameters = new ECKeyGenerationParameters(ecDomain, SecureRandom);
        var generator = new ECKeyPairGenerator();
        generator.Init(parameters);
        return generator.GenerateKeyPair();
    }


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