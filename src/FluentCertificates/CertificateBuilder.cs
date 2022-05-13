﻿using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Extensions;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509;

namespace FluentCertificates;

public record CertificateBuilder
{
    public CertificateUsage? Usage { get; init; }
    public int KeyLength { get; init; } = 2048;
    public int? PathLength { get; init; }
    public DateTimeOffset NotBefore { get; init; } = DateTimeOffset.UtcNow.AddHours(-1);
    public DateTimeOffset NotAfter { get; init; } = DateTimeOffset.UtcNow.AddHours(1);
    public X509Name Subject { get; init; } = EmptyName;
    public X509Certificate2? Issuer { get; init; }
    public string[] DnsNames { get; init; } = Array.Empty<string>();
    public string? FriendlyName { get; init; }
    public string? Email { get; init; }

    private AsymmetricCipherKeyPair? Key { get; init; }


    public static CertificateBuilder Create()
        => new();


    public CertificateBuilder SetUsage(CertificateUsage value)
        => this with { Usage = value };

    public CertificateBuilder SetKeyLength(int value)
        => this with { KeyLength = value };

    public CertificateBuilder SetNotBefore(DateTimeOffset value)
        => this with { NotBefore = value };

    public CertificateBuilder SetNotAfter(DateTimeOffset value)
        => this with { NotAfter = value };

    public CertificateBuilder SetSubject(X509Name value)
        => this with { Subject = value };

    public CertificateBuilder SetIssuer(X509Certificate2 value)
        => this with { Issuer = value };

    public CertificateBuilder SetDnsNames(IEnumerable<string> values)
        => this with { DnsNames = values.ToArray() };

    public CertificateBuilder SetDnsNames(params string[] values)
        => this with { DnsNames = values.ToArray() };

    public CertificateBuilder SetFriendlyName(string value)
        => this with { FriendlyName = value };

    public CertificateBuilder SetEmail(string value)
        => this with { Email = value };

    public CertificateBuilder SetPathLength(int? value)
        => this with { PathLength = value };

    public CertificateBuilder SetKey(AsymmetricCipherKeyPair? value)
        => this with { Key = value };


    public X509Certificate2 Build()
        => CreateCertificate(
            this, 
            Usage switch {
                null => null,
                CertificateUsage.CA => GetCaExtensions(this),
                CertificateUsage.Server => GetServerExtensions(this),
                CertificateUsage.Client => GetClientExtensions(this),
                CertificateUsage.CodeSign => GetCodeSigningExtensions(this),
                _ => throw new NotSupportedException($"{Usage} {nameof(Usage)} not yet supported")
            }
        );


    //public CertificateBuilder ExportCsrAsPem()
    //{
    //    Validate();
    //    var builder = Key != null ? this : SetKey(GenerateRsaKeyPair(KeyLength));

    //    return this;
    //}


    public void Validate()
        => Validate(this);


    private static void Validate(CertificateBuilder options)
    {
        if (options.KeyLength <= 0) throw new ArgumentException($"{nameof(KeyLength)} must be greater than zero", nameof(KeyLength));
        if (options.NotBefore >= options.NotAfter) throw new ArgumentException($"{nameof(NotBefore)} cannot be later than or equal to {nameof(NotAfter)}", nameof(NotAfter));
    }


    private static List<X509ExtensionItem> GetCaExtensions(CertificateBuilder options)
        => new() {
            new (X509Extensions.BasicConstraints, true, options.PathLength.HasValue ? new BasicConstraints(options.PathLength.Value) : new BasicConstraints(true)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign))
        };


    private static List<X509ExtensionItem> GetServerExtensions(CertificateBuilder options)
        => new() {
            new (X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)),
            new (X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth)),
        };


    private static List<X509ExtensionItem> GetClientExtensions(CertificateBuilder options)
        => new() {
            new (X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature)),
            new (X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth)),
        };


    private static List<X509ExtensionItem> GetCodeSigningExtensions(CertificateBuilder options)
        => new() {
            new (X509Extensions.BasicConstraints, true, new BasicConstraints(false)),
            new (X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)),
            new (X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(new DerSequence(
                KeyPurposeID.IdKPCodeSigning,
                KeyPurposeID.IdKPTimeStamping,
                new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.13")
            ))),
        };


    private static X509Certificate2 CreateCertificate(CertificateBuilder options, IEnumerable<X509ExtensionItem>? extensions = null)
    {
        Validate(options);

        var issuerCert = (options.Issuer != null)
            ? DotNetUtilities.FromX509Certificate(options.Issuer)
            : null;

        var key = options.Key ?? GenerateRsaKeyPair(options.KeyLength);

        var generator = CreateCertificateGenerator(
            issuer: issuerCert?.SubjectDN ?? options.Subject,
            issuerPublic: issuerCert?.GetPublicKey(),
            subject: options.Subject,
            subjectPublic: key.Public,
            notBefore: options.NotBefore.DateTime,
            notAfter: options.NotAfter.DateTime
        );

        if (extensions != null) {
            foreach (var extension in extensions) {
                generator.AddExtension(extension.Oid, extension.Extension.IsCritical, extension.Extension.GetParsedValue());
            }
        }

        //Add Subject Alternative Name if necessary
        var sanGeneralNames = new List<GeneralName>();
        if (options.DnsNames.Any()) {
            sanGeneralNames.AddRange(options.DnsNames.Select(dnsName => new GeneralName(GeneralName.DnsName, dnsName)));
        }
        if (!String.IsNullOrEmpty(options.Email)) {
            sanGeneralNames.Add(new GeneralName(GeneralName.Rfc822Name, options.Email));
        }
        if (sanGeneralNames.Any()) {
            generator.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(sanGeneralNames.ToArray()));
        }

        //Create certificate
        var algorithm = PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString();
        var cert = options.Issuer != null
            ? generator.Generate(new Asn1SignatureFactory(algorithm, options.Issuer.GetBouncyCastleRsaKeyPair().Private, InternalTools.SecureRandom))
            : generator.Generate(new Asn1SignatureFactory(algorithm, key.Private, InternalTools.SecureRandom));

        //Place the certificate and private-key into a PKCS12 store
        var store = new Pkcs12Store();
        var certEntry = new X509CertificateEntry(cert);
        store.SetCertificateEntry(cert.SerialNumber.ToString(), certEntry);
        store.SetKeyEntry(cert.SerialNumber.ToString(), new AsymmetricKeyEntry(key.Private), new[] { certEntry });

        //Finally copy the PKCS12 store to a .NET X509Certificate2 structure to return
        using var pfxStream = new MemoryStream();
        var pwd = InternalTools.CreateRandomCharArray(20);
        store.Save(pfxStream, pwd, InternalTools.SecureRandom);
        pfxStream.Seek(0, SeekOrigin.Begin);
        var newCert = new X509Certificate2(pfxStream.ToArray(), new String(pwd), X509KeyStorageFlags.Exportable);
        if (options.FriendlyName != null && IsWindows()) {
            newCert.FriendlyName = options.FriendlyName;
        }

        return newCert;
    }


    private static bool IsWindows()
#if NET5_0_OR_GREATER
        => OperatingSystem.IsWindows();
#else
        => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
#endif


    private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
    {
        var parameters = new KeyGenerationParameters(InternalTools.SecureRandom, length);
        var generator = new RsaKeyPairGenerator();
        generator.Init(parameters);
        return generator.GenerateKeyPair();
    }


    private static AsymmetricCipherKeyPair GenerateEcKeyPair(string curveName)
    {
        var ecParam = SecNamedCurves.GetByName(curveName);
        var ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N);
        var parameters = new ECKeyGenerationParameters(ecDomain, InternalTools.SecureRandom);
        var generator = new ECKeyPairGenerator();
        generator.Init(parameters);
        return generator.GenerateKeyPair();
    }


    private static X509V3CertificateGenerator CreateCertificateGenerator(X509Name issuer, AsymmetricKeyParameter? issuerPublic, X509Name subject, AsymmetricKeyParameter subjectPublic, DateTime notBefore, DateTime notAfter)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetIssuerDN(issuer);
        generator.SetSubjectDN(subject);
        generator.SetPublicKey(subjectPublic);
        generator.SetSerialNumber(GenerateSerialNumber());
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);

        generator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(subjectPublic));

        if (issuerPublic != null) {
            generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuerPublic));
        }

        return generator;
    }


    private static BigInteger GenerateSerialNumber()
    {
        Span<byte> span = stackalloc byte[18];
        BinaryPrimitives.WriteInt16BigEndian(span.Slice(0, 2), 0x4D58);
        BinaryPrimitives.WriteInt64BigEndian(span.Slice(2, 8), DateTime.UtcNow.Ticks);
        BinaryPrimitives.WriteInt64BigEndian(span.Slice(10, 8), InternalTools.SecureRandom.NextLong());
        return new BigInteger(span.ToArray());
    }


    private static readonly X509Name EmptyName = new X509NameBuilder();
}