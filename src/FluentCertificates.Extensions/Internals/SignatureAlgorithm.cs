using System.Collections.Immutable;
using System.Security.Cryptography;

namespace FluentCertificates.Internals;

internal sealed record SignatureAlgorithm
{
    public static SignatureAlgorithm FromOidValue(string oidValue)
        => oidValue != null && InstanceLookup.TryGetValue(oidValue, out var algorithm)
            ? algorithm
            : throw new NotSupportedException($"Unsupported signature algorithm: {oidValue}");


    public static SignatureAlgorithm FromOid(Oid oid)
        => oid.Value != null && InstanceLookup.TryGetValue(oid.Value, out var algorithm)
            ? algorithm
            : throw new NotSupportedException($"Unsupported signature algorithm: {oid.Value} ({oid.FriendlyName})");


    // ReSharper disable InconsistentNaming
    public static readonly SignatureAlgorithm SHA1DSA = new(KeyAlgorithm.DSA, HashAlgorithmName.SHA1, "1.2.840.10040.4.3");
    public static readonly SignatureAlgorithm SHA256DSA = new(KeyAlgorithm.DSA, HashAlgorithmName.SHA256, "2.16.840.1.101.3.4.3.2");
    public static readonly SignatureAlgorithm SHA1ECDSA = new(KeyAlgorithm.ECDsa, HashAlgorithmName.SHA1, "1.2.840.10045.4.1");
    public static readonly SignatureAlgorithm SHA256ECDSA = new(KeyAlgorithm.ECDsa, HashAlgorithmName.SHA256, "1.2.840.10045.4.3.2");
    public static readonly SignatureAlgorithm SHA384ECDSA = new(KeyAlgorithm.ECDsa, HashAlgorithmName.SHA384, "1.2.840.10045.4.3.3");
    public static readonly SignatureAlgorithm SHA512ECDSA = new(KeyAlgorithm.ECDsa, HashAlgorithmName.SHA512, "1.2.840.10045.4.3.4");
    public static readonly SignatureAlgorithm MD5RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.MD5, "1.2.840.113549.1.1.4");
    public static readonly SignatureAlgorithm SHA1RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.SHA1, "1.2.840.113549.1.1.5");
    public static readonly SignatureAlgorithm SHA256RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.SHA256, "1.2.840.113549.1.1.11");
    public static readonly SignatureAlgorithm SHA384RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.SHA384, "1.2.840.113549.1.1.12");
    public static readonly SignatureAlgorithm SHA512RSA = new(KeyAlgorithm.RSA, HashAlgorithmName.SHA512, "1.2.840.113549.1.1.13");
    // ReSharper restore InconsistentNaming


    public KeyAlgorithm KeyAlgorithm { get; }


    public HashAlgorithmName HashAlgorithm { get; }


    public string Oid { get; }


    private SignatureAlgorithm(KeyAlgorithm keyAlgorithm, HashAlgorithmName hashAlgorithm, string oid)
    {
        KeyAlgorithm = keyAlgorithm;
        HashAlgorithm = hashAlgorithm;
        Oid = oid;
    }


    private static readonly ImmutableDictionary<string, SignatureAlgorithm> InstanceLookup = new Dictionary<string, SignatureAlgorithm> {
        [SHA1DSA.Oid] = SHA1DSA,
        [SHA256DSA.Oid] = SHA256DSA,
        [SHA1ECDSA.Oid] = SHA1ECDSA,
        [SHA256ECDSA.Oid] = SHA256ECDSA,
        [SHA384ECDSA.Oid] = SHA384ECDSA,
        [SHA512ECDSA.Oid] = SHA512ECDSA,
        [MD5RSA.Oid] = MD5RSA,
        [SHA1RSA.Oid] = SHA1RSA,
        [SHA256RSA.Oid] = SHA256RSA,
        [SHA384RSA.Oid] = SHA384RSA,
        [SHA512RSA.Oid] = SHA512RSA
    }.ToImmutableDictionary();
}
