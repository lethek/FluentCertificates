using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace FluentCertificates;

/// <summary>
/// A <see cref="KeyAlgorithm"/> derived from a supplied public key must describe that key, not its family's
/// default, and must agree with the one derived from the same key's full pair.
/// </summary>
public class KeyAlgorithmDerivationTests
{
    [Test]
    [Arguments(2048)]
    [Arguments(3072)]
    public async Task SetPublicKey_ReadsTheRsaKeyLengthFromTheKey(int keyLength)
    {
        using var rsa = RSA.Create(keyLength);

        var builder = new CertificateBuilder().SetPublicKey(new PublicKey(rsa));

        await Assert.That(builder.KeyAlgorithm.KeyLength).IsEqualTo(keyLength);
        await Assert.That(builder.KeyAlgorithm).IsEqualTo(KeyAlgorithm.RSA(keyLength));
    }


    [Test]
    public async Task SetPublicKey_ReadsTheCurveFromTheKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        var builder = new CertificateBuilder().SetPublicKey(new PublicKey(ecdsa));

        //The curve's OID, not the default nistP256
        await Assert.That(builder.KeyAlgorithm.Curve?.Oid.Value).IsEqualTo(ECCurve.NamedCurves.nistP384.Oid.Value);
    }


    [Test]
    public async Task SetPublicKey_AndSetKeyPair_DeriveTheSameAlgorithmFromOneKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var rsa = RSA.Create(2048);

        await Assert.That(new CertificateBuilder().SetPublicKey(new PublicKey(ecdsa)).KeyAlgorithm)
            .IsEqualTo(new CertificateBuilder().SetKeyPair(ecdsa).KeyAlgorithm);
        await Assert.That(new CertificateBuilder().SetPublicKey(new PublicKey(rsa)).KeyAlgorithm)
            .IsEqualTo(new CertificateBuilder().SetKeyPair(rsa).KeyAlgorithm);
    }


    [Test]
    public async Task UseCertificateSigningRequest_ReportsTheRequestedKeysOwnAlgorithm()
    {
        //Every received request reaches SetPublicKey, so a CSR for a non-default key was the case that
        //misreported the key the CA is about to certify
        using var requesterKeys = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var csr = new CertificateBuilder()
            .SetSubject("CN=Requester")
            .SetKeyPair(requesterKeys)
            .CreateCertificateSigningRequest();

        var builder = new CertificateBuilder().UseCertificateSigningRequest(csr);

        await Assert.That(builder.KeyAlgorithm.Curve?.Oid.Value).IsEqualTo(ECCurve.NamedCurves.nistP384.Oid.Value);
    }


    [Test]
    public async Task Equals_TheSameCurveDescribedByOidOrFriendlyName_IsEqual()
    {
        //KeyAlgorithm.Name carries whichever friendly name the curve was built with: the same curve is
        //"ECDsa-nistP256" one way and "ECDsa-ECDSA_P256" the other, on one machine. Equality goes on the OID.
        var fromFriendlyName = KeyAlgorithm.ECDsa(ECCurve.CreateFromFriendlyName("nistP256"));
        var fromOid = KeyAlgorithm.ECDsa(ECCurve.CreateFromValue(ECCurve.NamedCurves.nistP256.Oid.Value!));

        await Assert.That(fromFriendlyName).IsEqualTo(fromOid);
        await Assert.That(fromFriendlyName.GetHashCode()).IsEqualTo(fromOid.GetHashCode());
    }


    [Test]
    public async Task Equals_DifferentCurvesOrKeyLengths_AreNotEqual()
    {
        await Assert.That(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP256))
            .IsNotEqualTo(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP384));
        await Assert.That(KeyAlgorithm.RSA(2048)).IsNotEqualTo(KeyAlgorithm.RSA(4096));
        //ECDsa and ECDiffieHellman share an OID and a curve, so only the family separates them
        await Assert.That(KeyAlgorithm.ECDsa(ECCurve.NamedCurves.nistP256))
            .IsNotEqualTo(KeyAlgorithm.ECDiffieHellman(ECCurve.NamedCurves.nistP256));
    }
}
