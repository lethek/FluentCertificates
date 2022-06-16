using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Extensions;
using FluentCertificates.Internals;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;


namespace FluentCertificates;

public partial record CertificateBuilder
{
    [Obsolete("Use the ToCertificateRequest method instead. Note: this method only supports RSA and DSA encryption keys.")]
    internal Pkcs10CertificationRequest ToBouncyCertificateRequest()
    {
        var keypair = KeyPair ?? throw new ArgumentNullException(nameof(KeyPair), "Call SetKeyPair(key) first to provide a public/private keypair");
        var bouncyKeyPair = DotNetUtilities.GetKeyPair(keypair);
        var extensions = new X509Extensions(BuildExtensions(this, null).ToDictionary(x => new DerObjectIdentifier(x.Oid.Value), x => x.ConvertToBouncyCastle()));
        var attributes = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions)));
        var sigFactory = new Asn1SignatureFactory(GetSignatureAlgorithm(this).Id, bouncyKeyPair.Private);
        return new Pkcs10CertificationRequest(sigFactory, Subject, bouncyKeyPair.Public, attributes);
    }


    /// <summary>
    /// Builds an X509Certificate2 instance based on the parameters that have been set previously in the builder. Uses a combination of BouncyCastle and system .NET methods.
    /// </summary>
    /// <returns>An X509Certificate2 instance.</returns>
    [Obsolete("Use the Build method instead. Note: this method only supports RSA and DSA encryption keys.")]
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Call site is only reachable on supported platforms")]
    internal X509Certificate2 BouncyBuild()
    {
        Validate();

        var builder = KeyPair == null
            ? GenerateKeyPair(KeyAlgorithm.RSA)
            : this;

        var issuerCert = (builder.Issuer != null)
            ? DotNetUtilities.FromX509Certificate(builder.Issuer)
            : null;

        var bouncyKeyPair = DotNetUtilities.GetKeyPair(builder.KeyPair);

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(new BigInteger(GenerateSerialNumber()));
        generator.SetIssuerDN(issuerCert?.SubjectDN ?? builder.Subject);
        generator.SetSubjectDN(builder.Subject);
        generator.SetPublicKey(bouncyKeyPair?.Public);
        generator.SetNotBefore(builder.NotBefore.DateTime);
        generator.SetNotAfter(builder.NotAfter.DateTime);

        if (issuerCert != null) {
            generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuerCert.GetPublicKey()));
        }

        foreach (var extension in BuildExtensions(builder, null)) {
            generator.AddExtension(extension.Oid?.Value, extension.Critical, extension.ConvertToBouncyCastle().GetParsedValue());
        }

        //Create certificate
        var algorithm = GetSignatureAlgorithm(builder).Id;
        var cert = builder.Issuer != null
            ? generator.Generate(new Asn1SignatureFactory(algorithm, builder.Issuer.GetBouncyCastleRsaKeyPair().Private, Tools.SecureRandom))
            : generator.Generate(new Asn1SignatureFactory(algorithm, bouncyKeyPair?.Private, Tools.SecureRandom));

        //Place the certificate and private-key into a PKCS12 store
        var store = new Pkcs12Store();
        var certEntry = new X509CertificateEntry(cert);
        store.SetCertificateEntry(cert.SerialNumber.ToString(), certEntry);
        store.SetKeyEntry(cert.SerialNumber.ToString(), new AsymmetricKeyEntry(bouncyKeyPair?.Private), new[] { certEntry });

        //Finally copy the PKCS12 store to a .NET X509Certificate2 structure to return
        using var pfxStream = new MemoryStream();
        var pwd = Tools.CreateRandomCharArray(20);
        store.Save(pfxStream, pwd, Tools.SecureRandom);
        pfxStream.Seek(0, SeekOrigin.Begin);
        var newCert = new X509Certificate2(pfxStream.ToArray(), new string(pwd), X509KeyStorageFlags.Exportable);
        if (!String.IsNullOrEmpty(builder.FriendlyName) && Tools.IsWindows) {
            newCert.FriendlyName = builder.FriendlyName;
        }

        return newCert;
    }
}