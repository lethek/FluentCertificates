using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Security;

namespace FluentCertificates
{
    public static class X509Certificate2Extensions
    {
        public static bool VerifyIssuer(this X509Certificate2 cert, X509Certificate2 issuer)
            => cert.IsIssuedBy(issuer) && VerifyIssuerSignature(cert, issuer);


        private static bool VerifyIssuerSignature(X509Certificate2 cert, X509Certificate2 issuer)
        {
            //TODO: verify signatures using standard .NET methods rather than BouncyCastle

            var thisCert = DotNetUtilities.FromX509Certificate(cert);
            var issuerCert = DotNetUtilities.FromX509Certificate(issuer);

            var tbsCert = thisCert.GetTbsCertificate();
            var sig = thisCert.GetSignature();

            var signer = SignerUtilities.GetSigner(thisCert.SigAlgName);
            signer.Init(false, issuerCert.GetPublicKey());
            signer.BlockUpdate(tbsCert, 0, tbsCert.Length);
            return signer.VerifySignature(sig);
        }
    }
}
