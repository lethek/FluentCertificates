using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;

namespace FluentCertificates;

/// <summary>
/// Provides a collection of constants and helper methods for common Object Identifier (OID) values
/// used in cryptographic operations, X.509 certificates, and related protocols.
/// </summary>
/// <remarks>
/// The <c>Oids</c> class defines string constants for well-known OIDs, as well as static properties
/// for commonly used <see cref="Oid"/> instances.
/// </remarks>
public static class Oids
{
    // Symmetric encryption algorithms
    /// <summary>Symmetric encryption algorithm OID <c>1.2.840.113549.3.2</c>.</summary>
    public const string Rc2Cbc = "1.2.840.113549.3.2";
    /// <summary>Symmetric encryption algorithm OID <c>1.2.840.113549.3.4</c>.</summary>
    public const string Rc4 = "1.2.840.113549.3.4";
    /// <summary>Symmetric encryption algorithm OID <c>1.2.840.113549.3.7</c>.</summary>
    public const string TripleDesCbc = "1.2.840.113549.3.7";
    /// <summary>Symmetric encryption algorithm OID <c>1.3.14.3.2.7</c>.</summary>
    public const string DesCbc = "1.3.14.3.2.7";
    /// <summary>Symmetric encryption algorithm OID <c>2.16.840.1.101.3.4.1.2</c>.</summary>
    public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    /// <summary>Symmetric encryption algorithm OID <c>2.16.840.1.101.3.4.1.22</c>.</summary>
    public const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
    /// <summary>Symmetric encryption algorithm OID <c>2.16.840.1.101.3.4.1.42</c>.</summary>
    public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";

    // Asymmetric encryption algorithms
    /// <summary>Public key algorithm OID <c>1.2.840.10040.4.1</c>.</summary>
    public const string Dsa = "1.2.840.10040.4.1";
    /// <summary>Public key algorithm OID <c>1.2.840.113549.1.1.1</c>.</summary>
    public const string Rsa = "1.2.840.113549.1.1.1";
    /// <summary>Public key algorithm OID <c>1.2.840.113549.1.1.7</c>.</summary>
    public const string RsaOaep = "1.2.840.113549.1.1.7";
    /// <summary>Public key algorithm OID <c>1.2.840.113549.1.1.10</c>.</summary>
    public const string RsaPss = "1.2.840.113549.1.1.10";
    /// <summary>Signature algorithm OID <c>1.2.840.113549.1.1.4</c>.</summary>
    public const string RsaPkcs1Md5 = "1.2.840.113549.1.1.4";
    /// <summary>Signature algorithm OID <c>1.2.840.113549.1.1.5</c>.</summary>
    public const string RsaPkcs1Sha1 = "1.2.840.113549.1.1.5";
    /// <summary>Signature algorithm OID <c>1.2.840.113549.1.1.14</c>.</summary>
    public const string RsaPkcs1Sha224 = "1.2.840.113549.1.1.14";
    /// <summary>Signature algorithm OID <c>1.2.840.113549.1.1.11</c>.</summary>
    public const string RsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
    /// <summary>Signature algorithm OID <c>1.2.840.113549.1.1.12</c>.</summary>
    public const string RsaPkcs1Sha384 = "1.2.840.113549.1.1.12";
    /// <summary>Signature algorithm OID <c>1.2.840.113549.1.1.13</c>.</summary>
    public const string RsaPkcs1Sha512 = "1.2.840.113549.1.1.13";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.14</c> (RSASSA-PKCS1-v1_5 with SHA3-256).</summary>
    public const string RsaPkcs1Sha3_256 = "2.16.840.1.101.3.4.3.14";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.15</c> (RSASSA-PKCS1-v1_5 with SHA3-384).</summary>
    public const string RsaPkcs1Sha3_384 = "2.16.840.1.101.3.4.3.15";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.16</c> (RSASSA-PKCS1-v1_5 with SHA3-512).</summary>
    public const string RsaPkcs1Sha3_512 = "2.16.840.1.101.3.4.3.16";
    /// <summary>Public key algorithm OID <c>1.2.840.113549.1.9.16.3.5</c>.</summary>
    public const string Esdh = "1.2.840.113549.1.9.16.3.5";
    /// <summary>Public key algorithm OID <c>1.3.132.1.12</c>.</summary>
    public const string EcDiffieHellman = "1.3.132.1.12";
    /// <summary>Public key algorithm OID <c>1.2.840.10046.2.1</c>.</summary>
    public const string DiffieHellman = "1.2.840.10046.2.1";
    /// <summary>Public key algorithm OID <c>1.2.840.113549.1.3.1</c>.</summary>
    public const string DiffieHellmanPkcs3 = "1.2.840.113549.1.3.1";

    // Post-quantum algorithms. Each OID identifies one parameter set exactly, and serves as both the
    // SubjectPublicKeyInfo algorithm OID and the certificate's signature algorithm OID, since these
    // algorithms take no separate hash.
    /// <summary>ML-DSA-44 (FIPS 204) public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.17</c>.</summary>
    public const string MLDsa44 = "2.16.840.1.101.3.4.3.17";
    /// <summary>ML-DSA-65 (FIPS 204) public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.18</c>.</summary>
    public const string MLDsa65 = "2.16.840.1.101.3.4.3.18";
    /// <summary>ML-DSA-87 (FIPS 204) public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.19</c>.</summary>
    public const string MLDsa87 = "2.16.840.1.101.3.4.3.19";

    // SLH-DSA (FIPS 205). Note the arc is not in declaration order: SHA2 takes .20-.25 and
    // SHAKE takes .26-.31.
    /// <summary>SLH-DSA-SHA2-128s public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.20</c>.</summary>
    public const string SlhDsaSha2_128s = "2.16.840.1.101.3.4.3.20";
    /// <summary>SLH-DSA-SHA2-128f public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.21</c>.</summary>
    public const string SlhDsaSha2_128f = "2.16.840.1.101.3.4.3.21";
    /// <summary>SLH-DSA-SHA2-192s public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.22</c>.</summary>
    public const string SlhDsaSha2_192s = "2.16.840.1.101.3.4.3.22";
    /// <summary>SLH-DSA-SHA2-192f public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.23</c>.</summary>
    public const string SlhDsaSha2_192f = "2.16.840.1.101.3.4.3.23";
    /// <summary>SLH-DSA-SHA2-256s public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.24</c>.</summary>
    public const string SlhDsaSha2_256s = "2.16.840.1.101.3.4.3.24";
    /// <summary>SLH-DSA-SHA2-256f public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.25</c>.</summary>
    public const string SlhDsaSha2_256f = "2.16.840.1.101.3.4.3.25";
    /// <summary>SLH-DSA-SHAKE-128s public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.26</c>.</summary>
    public const string SlhDsaShake128s = "2.16.840.1.101.3.4.3.26";
    /// <summary>SLH-DSA-SHAKE-128f public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.27</c>.</summary>
    public const string SlhDsaShake128f = "2.16.840.1.101.3.4.3.27";
    /// <summary>SLH-DSA-SHAKE-192s public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.28</c>.</summary>
    public const string SlhDsaShake192s = "2.16.840.1.101.3.4.3.28";
    /// <summary>SLH-DSA-SHAKE-192f public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.29</c>.</summary>
    public const string SlhDsaShake192f = "2.16.840.1.101.3.4.3.29";
    /// <summary>SLH-DSA-SHAKE-256s public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.30</c>.</summary>
    public const string SlhDsaShake256s = "2.16.840.1.101.3.4.3.30";
    /// <summary>SLH-DSA-SHAKE-256f public key and signature algorithm OID <c>2.16.840.1.101.3.4.3.31</c>.</summary>
    public const string SlhDsaShake256f = "2.16.840.1.101.3.4.3.31";

    // Prehash variants (HashML-DSA and HashSLH-DSA), which sign a digest rather than the message
    // itself. .NET 10 exposes no API for these, so they are declared for consumers reading a
    // certificate that carries one and are absent from KeyAlgorithm.PostQuantumAlgorithms.
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.32</c> (HashML-DSA-44 with SHA-512).</summary>
    public const string MLDsa44PreHashSha512 = "2.16.840.1.101.3.4.3.32";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.33</c> (HashML-DSA-65 with SHA-512).</summary>
    public const string MLDsa65PreHashSha512 = "2.16.840.1.101.3.4.3.33";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.34</c> (HashML-DSA-87 with SHA-512).</summary>
    public const string MLDsa87PreHashSha512 = "2.16.840.1.101.3.4.3.34";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.35</c> (HashSLH-DSA-SHA2-128s with SHA-256).</summary>
    public const string SlhDsaSha2_128sPreHashSha256 = "2.16.840.1.101.3.4.3.35";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.36</c> (HashSLH-DSA-SHA2-128f with SHA-256).</summary>
    public const string SlhDsaSha2_128fPreHashSha256 = "2.16.840.1.101.3.4.3.36";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.37</c> (HashSLH-DSA-SHA2-192s with SHA-512).</summary>
    public const string SlhDsaSha2_192sPreHashSha512 = "2.16.840.1.101.3.4.3.37";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.38</c> (HashSLH-DSA-SHA2-192f with SHA-512).</summary>
    public const string SlhDsaSha2_192fPreHashSha512 = "2.16.840.1.101.3.4.3.38";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.39</c> (HashSLH-DSA-SHA2-256s with SHA-512).</summary>
    public const string SlhDsaSha2_256sPreHashSha512 = "2.16.840.1.101.3.4.3.39";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.40</c> (HashSLH-DSA-SHA2-256f with SHA-512).</summary>
    public const string SlhDsaSha2_256fPreHashSha512 = "2.16.840.1.101.3.4.3.40";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.41</c> (HashSLH-DSA-SHAKE-128s with SHAKE128).</summary>
    public const string SlhDsaShake128sPreHashShake128 = "2.16.840.1.101.3.4.3.41";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.42</c> (HashSLH-DSA-SHAKE-128f with SHAKE128).</summary>
    public const string SlhDsaShake128fPreHashShake128 = "2.16.840.1.101.3.4.3.42";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.43</c> (HashSLH-DSA-SHAKE-192s with SHAKE256).</summary>
    public const string SlhDsaShake192sPreHashShake256 = "2.16.840.1.101.3.4.3.43";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.44</c> (HashSLH-DSA-SHAKE-192f with SHAKE256).</summary>
    public const string SlhDsaShake192fPreHashShake256 = "2.16.840.1.101.3.4.3.44";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.45</c> (HashSLH-DSA-SHAKE-256s with SHAKE256).</summary>
    public const string SlhDsaShake256sPreHashShake256 = "2.16.840.1.101.3.4.3.45";
    /// <summary>Post-quantum signature algorithm OID <c>2.16.840.1.101.3.4.3.46</c> (HashSLH-DSA-SHAKE-256f with SHAKE256).</summary>
    public const string SlhDsaShake256fPreHashShake256 = "2.16.840.1.101.3.4.3.46";

    // Composite ML-DSA, arc 1.3.6.1.5.5.7.6.x. Every set here matches the registration table in
    // draft-ietf-lamps-pq-composite-sigs-19 s7, both in OID and in algorithm name. Five of them are
    // not implemented by .NET on any platform tested, so those could not also be read back off a
    // generated key the way the rest were, and are marked below.
    // Note there is no separate arc for a pure variant: every registered composite OID is prehashed,
    // which is why these names carry no PreHash suffix and cannot be ambiguous without one.
    // CompositeMLDsaOidMatchesGeneratedKey in the test suite asserts the declared OID against the
    // real one for every set the running platform supports, so an inference that is wrong fails the
    // moment a platform implements it.
    /// <summary>MLDSA44-RSA2048-PSS-SHA256 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.37</c>.</summary>
    public const string MLDsa44WithRSA2048Pss = "1.3.6.1.5.5.7.6.37";
    /// <summary>MLDSA44-RSA2048-PKCS15-SHA256 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.38</c>.</summary>
    public const string MLDsa44WithRSA2048Pkcs15 = "1.3.6.1.5.5.7.6.38";
    /// <summary>MLDSA44-Ed25519-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.39</c>. Confirmed against draft-19; unimplemented everywhere, so not cross-checked against a generated key.</summary>
    public const string MLDsa44WithEd25519 = "1.3.6.1.5.5.7.6.39";
    /// <summary>MLDSA44-ECDSA-P256-SHA256 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.40</c>.</summary>
    public const string MLDsa44WithECDsaP256 = "1.3.6.1.5.5.7.6.40";
    /// <summary>MLDSA65-RSA3072-PSS-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.41</c>.</summary>
    public const string MLDsa65WithRSA3072Pss = "1.3.6.1.5.5.7.6.41";
    /// <summary>MLDSA65-RSA3072-PKCS15-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.42</c>.</summary>
    public const string MLDsa65WithRSA3072Pkcs15 = "1.3.6.1.5.5.7.6.42";
    /// <summary>MLDSA65-RSA4096-PSS-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.43</c>.</summary>
    public const string MLDsa65WithRSA4096Pss = "1.3.6.1.5.5.7.6.43";
    /// <summary>MLDSA65-RSA4096-PKCS15-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.44</c>.</summary>
    public const string MLDsa65WithRSA4096Pkcs15 = "1.3.6.1.5.5.7.6.44";
    /// <summary>MLDSA65-ECDSA-P256-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.45</c>.</summary>
    public const string MLDsa65WithECDsaP256 = "1.3.6.1.5.5.7.6.45";
    /// <summary>MLDSA65-ECDSA-P384-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.46</c>.</summary>
    public const string MLDsa65WithECDsaP384 = "1.3.6.1.5.5.7.6.46";
    /// <summary>MLDSA65-ECDSA-brainpoolP256r1-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.47</c>. Confirmed against draft-19; unimplemented everywhere, so not cross-checked against a generated key.</summary>
    public const string MLDsa65WithECDsaBrainpoolP256r1 = "1.3.6.1.5.5.7.6.47";
    /// <summary>MLDSA65-Ed25519-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.48</c>. Confirmed against draft-19; unimplemented everywhere, so not cross-checked against a generated key.</summary>
    public const string MLDsa65WithEd25519 = "1.3.6.1.5.5.7.6.48";
    /// <summary>MLDSA87-ECDSA-P384-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.49</c>.</summary>
    public const string MLDsa87WithECDsaP384 = "1.3.6.1.5.5.7.6.49";
    /// <summary>MLDSA87-ECDSA-brainpoolP384r1-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.50</c>. Confirmed against draft-19; unimplemented everywhere, so not cross-checked against a generated key.</summary>
    public const string MLDsa87WithECDsaBrainpoolP384r1 = "1.3.6.1.5.5.7.6.50";
    /// <summary>MLDSA87-Ed448-SHAKE256 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.51</c>. Confirmed against draft-19; unimplemented everywhere, so not cross-checked against a generated key.</summary>
    public const string MLDsa87WithEd448 = "1.3.6.1.5.5.7.6.51";
    /// <summary>MLDSA87-RSA3072-PSS-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.52</c>.</summary>
    public const string MLDsa87WithRSA3072Pss = "1.3.6.1.5.5.7.6.52";
    /// <summary>MLDSA87-RSA4096-PSS-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.53</c>.</summary>
    public const string MLDsa87WithRSA4096Pss = "1.3.6.1.5.5.7.6.53";
    /// <summary>MLDSA87-ECDSA-P521-SHA512 public key and signature algorithm OID <c>1.3.6.1.5.5.7.6.54</c>.</summary>
    public const string MLDsa87WithECDsaP521 = "1.3.6.1.5.5.7.6.54";

    // ML-KEM (FIPS 203). Key encapsulation, not signature.
    /// <summary>ML-KEM-512 (FIPS 203) public key algorithm OID <c>2.16.840.1.101.3.4.4.1</c>.</summary>
    public const string MLKem512 = "2.16.840.1.101.3.4.4.1";
    /// <summary>ML-KEM-768 (FIPS 203) public key algorithm OID <c>2.16.840.1.101.3.4.4.2</c>.</summary>
    public const string MLKem768 = "2.16.840.1.101.3.4.4.2";
    /// <summary>ML-KEM-1024 (FIPS 203) public key algorithm OID <c>2.16.840.1.101.3.4.4.3</c>.</summary>
    public const string MLKem1024 = "2.16.840.1.101.3.4.4.3";

    // Composite ML-KEM, arc 1.3.6.1.5.5.7.6.x, pairing ML-KEM with a classical key-establishment
    // algorithm. .NET 10 exposes no API for these, so they are declared for consumers reading a
    // certificate that carries one.
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.55</c> (ML-KEM-768 with RSA-OAEP-2048).</summary>
    public const string MLKem768WithRsaOaep2048Sha3_256 = "1.3.6.1.5.5.7.6.55";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.56</c> (ML-KEM-768 with RSA-OAEP-3072).</summary>
    public const string MLKem768WithRsaOaep3072Sha3_256 = "1.3.6.1.5.5.7.6.56";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.57</c> (ML-KEM-768 with RSA-OAEP-4096).</summary>
    public const string MLKem768WithRsaOaep4096Sha3_256 = "1.3.6.1.5.5.7.6.57";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.58</c> (ML-KEM-768 with X25519).</summary>
    public const string MLKem768WithX25519Sha3_256 = "1.3.6.1.5.5.7.6.58";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.59</c> (ML-KEM-768 with ECDH P-256).</summary>
    public const string MLKem768WithECDiffieHellmanP256Sha3_256 = "1.3.6.1.5.5.7.6.59";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.60</c> (ML-KEM-768 with ECDH P-384).</summary>
    public const string MLKem768WithECDiffieHellmanP384Sha3_256 = "1.3.6.1.5.5.7.6.60";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.61</c> (ML-KEM-768 with ECDH brainpoolP256r1).</summary>
    public const string MLKem768WithECDiffieHellmanBrainpoolP256r1Sha3_256 = "1.3.6.1.5.5.7.6.61";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.62</c> (ML-KEM-1024 with RSA-OAEP-3072).</summary>
    public const string MLKem1024WithRsaOaep3072Sha3_256 = "1.3.6.1.5.5.7.6.62";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.63</c> (ML-KEM-1024 with ECDH P-384).</summary>
    public const string MLKem1024WithECDiffieHellmanP384Sha3_256 = "1.3.6.1.5.5.7.6.63";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.64</c> (ML-KEM-1024 with ECDH brainpoolP384r1).</summary>
    public const string MLKem1024WithECDiffieHellmanBrainpoolP384r1Sha3_256 = "1.3.6.1.5.5.7.6.64";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.65</c> (ML-KEM-1024 with X448).</summary>
    public const string MLKem1024WithX448Sha3_256 = "1.3.6.1.5.5.7.6.65";
    /// <summary>Composite key encapsulation OID <c>1.3.6.1.5.5.7.6.66</c> (ML-KEM-1024 with ECDH P-521).</summary>
    public const string MLKem1024WithECDiffieHellmanP521Sha3_256 = "1.3.6.1.5.5.7.6.66";

    // Cryptographic Attribute Types
    /// <summary>Cryptographic attribute type OID <c>1.2.840.113549.1.9.5</c>.</summary>
    public const string SigningTime = "1.2.840.113549.1.9.5";
    /// <summary>Cryptographic attribute type OID <c>1.2.840.113549.1.9.3</c>.</summary>
    public const string ContentType = "1.2.840.113549.1.9.3";
    /// <summary>Cryptographic attribute type OID <c>1.3.6.1.4.1.311.88.2.2</c>.</summary>
    public const string DocumentDescription = "1.3.6.1.4.1.311.88.2.2";
    /// <summary>Cryptographic attribute type OID <c>1.2.840.113549.1.9.4</c>.</summary>
    public const string MessageDigest = "1.2.840.113549.1.9.4";
    /// <summary>Cryptographic attribute type OID <c>1.2.840.113549.1.9.6</c>.</summary>
    public const string CounterSigner = "1.2.840.113549.1.9.6";
    /// <summary>Cryptographic attribute type OID <c>1.2.840.113549.1.9.16.2.12</c>.</summary>
    public const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    /// <summary>Cryptographic attribute type OID <c>1.2.840.113549.1.9.16.2.47</c>.</summary>
    public const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    /// <summary>Cryptographic attribute type OID <c>1.3.6.1.4.1.311.88.2.1</c>.</summary>
    public const string DocumentName = "1.3.6.1.4.1.311.88.2.1";
    /// <summary>Cryptographic attribute type OID <c>1.2.840.113549.1.9.20</c>.</summary>
    public const string FriendlyName = "1.2.840.113549.1.9.20";
    /// <summary>Cryptographic attribute type OID <c>1.2.840.113549.1.9.21</c>.</summary>
    public const string LocalKeyId = "1.2.840.113549.1.9.21";
    /// <summary>Cryptographic attribute type OID <c>1.3.6.1.4.1.311.20.2</c>.</summary>
    public const string EnrollCertTypeExtension = "1.3.6.1.4.1.311.20.2";
    /// <summary>Cryptographic attribute type OID <c>1.3.6.1.4.1.311.20.2.3</c>.</summary>
    public const string UserPrincipalName = "1.3.6.1.4.1.311.20.2.3";
    /// <summary>Cryptographic attribute type OID <c>1.3.6.1.4.1.311.21.7</c>.</summary>
    public const string CertificateTemplate = "1.3.6.1.4.1.311.21.7";
    /// <summary>Cryptographic attribute type OID <c>1.3.6.1.4.1.311.21.10</c>.</summary>
    public const string ApplicationCertPolicies = "1.3.6.1.4.1.311.21.10";
    /// <summary>Cryptographic attribute type OID <c>1.3.6.1.5.5.7.1.1</c>.</summary>
    public const string AuthorityInformationAccess = "1.3.6.1.5.5.7.1.1";
    /// <summary>Cryptographic attribute type OID <c>1.3.6.1.5.5.7.48.1</c>.</summary>
    public const string OcspEndpoint = "1.3.6.1.5.5.7.48.1";
    /// <summary>Cryptographic attribute type OID <c>1.3.6.1.5.5.7.48.2</c>.</summary>
    public const string CertificateAuthorityIssuers = "1.3.6.1.5.5.7.48.2";
    /// <summary>Cryptographic attribute type OID <c>1.2.840.113549.1.9.14</c>.</summary>
    public const string Pkcs9ExtensionRequest = "1.2.840.113549.1.9.14";

    // Key wrap algorithms
    /// <summary>Key wrap algorithm OID <c>1.2.840.113549.1.9.16.3.7</c>.</summary>
    public const string CmsRc2Wrap = "1.2.840.113549.1.9.16.3.7";
    /// <summary>Key wrap algorithm OID <c>1.2.840.113549.1.9.16.3.6</c>.</summary>
    public const string Cms3DesWrap = "1.2.840.113549.1.9.16.3.6";

    // PKCS7 Content Types.
    /// <summary>PKCS#7 content type OID <c>1.2.840.113549.1.7.1</c>.</summary>
    public const string Pkcs7Data = "1.2.840.113549.1.7.1";
    /// <summary>PKCS#7 content type OID <c>1.2.840.113549.1.7.2</c>.</summary>
    public const string Pkcs7Signed = "1.2.840.113549.1.7.2";
    /// <summary>PKCS#7 content type OID <c>1.2.840.113549.1.7.3</c>.</summary>
    public const string Pkcs7Enveloped = "1.2.840.113549.1.7.3";
    /// <summary>PKCS#7 content type OID <c>1.2.840.113549.1.7.4</c>.</summary>
    public const string Pkcs7SignedEnveloped = "1.2.840.113549.1.7.4";
    /// <summary>PKCS#7 content type OID <c>1.2.840.113549.1.7.5</c>.</summary>
    public const string Pkcs7Hashed = "1.2.840.113549.1.7.5";
    /// <summary>PKCS#7 content type OID <c>1.2.840.113549.1.7.6</c>.</summary>
    public const string Pkcs7Encrypted = "1.2.840.113549.1.7.6";

    /// <summary>Hash algorithm OID <c>1.2.840.113549.2.5</c>.</summary>
    public const string Md5 = "1.2.840.113549.2.5";
    /// <summary>Hash algorithm OID <c>1.3.14.3.2.26</c>.</summary>
    public const string Sha1 = "1.3.14.3.2.26";
    /// <summary>Hash algorithm OID <c>2.16.840.1.101.3.4.2.4</c>.</summary>
    public const string Sha224 = "2.16.840.1.101.3.4.2.4";
    /// <summary>Hash algorithm OID <c>2.16.840.1.101.3.4.2.1</c>.</summary>
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    /// <summary>Hash algorithm OID <c>2.16.840.1.101.3.4.2.2</c>.</summary>
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    /// <summary>Hash algorithm OID <c>2.16.840.1.101.3.4.2.3</c>.</summary>
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";
    /// <summary>Hash algorithm OID <c>2.16.840.1.101.3.4.2.8</c> (SHA3-256).</summary>
    public const string Sha3_256 = "2.16.840.1.101.3.4.2.8";
    /// <summary>Hash algorithm OID <c>2.16.840.1.101.3.4.2.9</c> (SHA3-384).</summary>
    public const string Sha3_384 = "2.16.840.1.101.3.4.2.9";
    /// <summary>Hash algorithm OID <c>2.16.840.1.101.3.4.2.10</c> (SHA3-512).</summary>
    public const string Sha3_512 = "2.16.840.1.101.3.4.2.10";
    /// <summary>Extendable-output function OID <c>2.16.840.1.101.3.4.2.11</c> (SHAKE128).</summary>
    public const string Shake128 = "2.16.840.1.101.3.4.2.11";
    /// <summary>Extendable-output function OID <c>2.16.840.1.101.3.4.2.12</c> (SHAKE256).</summary>
    public const string Shake256 = "2.16.840.1.101.3.4.2.12";

    // DSA CMS uses the combined signature+digest OID
    /// <summary>Signature algorithm OID <c>1.2.840.10040.4.3</c>.</summary>
    public const string DsaWithSha1 = "1.2.840.10040.4.3";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.1</c>.</summary>
    public const string DsaWithSha224 = "2.16.840.1.101.3.4.3.1";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.2</c>.</summary>
    public const string DsaWithSha256 = "2.16.840.1.101.3.4.3.2";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.3</c>.</summary>
    public const string DsaWithSha384 = "2.16.840.1.101.3.4.3.3";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.4</c>.</summary>
    public const string DsaWithSha512 = "2.16.840.1.101.3.4.3.4";

    // ECDSA CMS uses the combined signature+digest OID
    // https://tools.ietf.org/html/rfc5753#section-2.1.1
    /// <summary>Elliptic curve field OID <c>1.2.840.10045.1.1</c>.</summary>
    public const string EcPrimeField = "1.2.840.10045.1.1";
    /// <summary>Elliptic curve field OID <c>1.2.840.10045.1.2</c>.</summary>
    public const string EcChar2Field = "1.2.840.10045.1.2";
    /// <summary>Elliptic curve field OID <c>1.2.840.10045.1.2.3.2</c>.</summary>
    public const string EcChar2TrinomialBasis = "1.2.840.10045.1.2.3.2";
    /// <summary>Elliptic curve field OID <c>1.2.840.10045.1.2.3.3</c>.</summary>
    public const string EcChar2PentanomialBasis = "1.2.840.10045.1.2.3.3";
    /// <summary>Public key algorithm OID <c>1.2.840.10045.2.1</c>.</summary>
    public const string EcPublicKey = "1.2.840.10045.2.1";
    /// <summary>Signature algorithm OID <c>1.2.840.10045.4.1</c>.</summary>
    public const string ECDsaWithSha1 = "1.2.840.10045.4.1";
    /// <summary>Signature algorithm OID <c>1.2.840.10045.4.3.1</c>.</summary>
    public const string ECDsaWithSha224 = "1.2.840.10045.4.3.1";
    /// <summary>Signature algorithm OID <c>1.2.840.10045.4.3.2</c>.</summary>
    public const string ECDsaWithSha256 = "1.2.840.10045.4.3.2";
    /// <summary>Signature algorithm OID <c>1.2.840.10045.4.3.3</c>.</summary>
    public const string ECDsaWithSha384 = "1.2.840.10045.4.3.3";
    /// <summary>Signature algorithm OID <c>1.2.840.10045.4.3.4</c>.</summary>
    public const string ECDsaWithSha512 = "1.2.840.10045.4.3.4";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.10</c> (ECDSA with SHA3-256).</summary>
    public const string ECDsaWithSha3_256 = "2.16.840.1.101.3.4.3.10";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.11</c> (ECDSA with SHA3-384).</summary>
    public const string ECDsaWithSha3_384 = "2.16.840.1.101.3.4.3.11";
    /// <summary>Signature algorithm OID <c>2.16.840.1.101.3.4.3.12</c> (ECDSA with SHA3-512).</summary>
    public const string ECDsaWithSha3_512 = "2.16.840.1.101.3.4.3.12";

    /// <summary>RSA mask generation function OID <c>1.2.840.113549.1.1.8</c> (MGF1), used by RSA-OAEP and RSA-PSS.</summary>
    public const string Mgf1 = "1.2.840.113549.1.1.8";
    /// <summary>RSA-OAEP label parameter OID <c>1.2.840.113549.1.1.9</c> (pSpecified).</summary>
    public const string PSpecified = "1.2.840.113549.1.1.9";

    // PKCS#7
    /// <summary>Key wrap algorithm OID <c>1.3.6.1.5.5.7.6.2</c>.</summary>
    public const string NoSignature = "1.3.6.1.5.5.7.6.2";

    // X500 Names
    /// <summary>X.500 name attribute OID <c>2.5.4.3</c>.</summary>
    public const string CommonName = "2.5.4.3";
    /// <summary>X.500 name attribute OID <c>2.5.4.6</c>.</summary>
    public const string CountryOrRegionName = "2.5.4.6";
    /// <summary>X.500 name attribute OID <c>2.5.4.7</c>.</summary>
    public const string LocalityName = "2.5.4.7";
    /// <summary>X.500 name attribute OID <c>2.5.4.8</c>.</summary>
    public const string StateOrProvinceName = "2.5.4.8";
    /// <summary>X.500 name attribute OID <c>2.5.4.10</c>.</summary>
    public const string Organization = "2.5.4.10";
    /// <summary>X.500 name attribute OID <c>2.5.4.11</c>.</summary>
    public const string OrganizationalUnit = "2.5.4.11";
    /// <summary>X.500 name attribute OID <c>1.2.840.113549.1.9.1</c>.</summary>
    public const string EmailAddress = "1.2.840.113549.1.9.1";
    /// <summary>X.500 name attribute OID <c>2.5.4.20</c>.</summary>
    public const string TelephoneNumber = "2.5.4.20";
    /// <summary>X.500 name attribute OID <c>2.5.4.9</c>.</summary>
    public const string StreetAddress = "2.5.4.9";
    /// <summary>X.500 name attribute OID <c>2.5.4.17</c>.</summary>
    public const string PostalCode = "2.5.4.17";
    /// <summary>X.500 name attribute OID <c>2.5.4.5</c>.</summary>
    public const string SerialNumber = "2.5.4.5";
    /// <summary>X.500 name attribute OID <c>2.5.4.4</c>.</summary>
    public const string Surname = "2.5.4.4";
    /// <summary>X.500 name attribute OID <c>2.5.4.42</c>.</summary>
    public const string GivenName = "2.5.4.42";
    /// <summary>X.500 name attribute OID <c>2.5.4.12</c>.</summary>
    public const string Title = "2.5.4.12";
    /// <summary>X.500 name attribute OID <c>2.5.4.46</c>.</summary>
    public const string DnQualifier = "2.5.4.46";
    /// <summary>X.500 name attribute OID <c>2.5.4.2</c> (knowledgeInformation).</summary>
    public const string KnowledgeInformation = "2.5.4.2";
    /// <summary>X.500 name attribute OID <c>2.5.4.13</c> (description).</summary>
    public const string Description = "2.5.4.13";
    /// <summary>X.500 name attribute OID <c>2.5.4.15</c> (businessCategory).</summary>
    public const string BusinessCategory = "2.5.4.15";
    /// <summary>X.500 name attribute OID <c>2.5.4.18</c> (postOfficeBox).</summary>
    public const string PostOfficeBox = "2.5.4.18";
    /// <summary>X.500 name attribute OID <c>2.5.4.19</c> (physicalDeliveryOfficeName).</summary>
    public const string PhysicalDeliveryOfficeName = "2.5.4.19";
    /// <summary>X.500 name attribute OID <c>2.5.4.24</c> (x121Address).</summary>
    public const string X121Address = "2.5.4.24";
    /// <summary>X.500 name attribute OID <c>2.5.4.25</c> (internationalISDNNumber).</summary>
    public const string InternationalISDNNumber = "2.5.4.25";
    /// <summary>X.500 name attribute OID <c>2.5.4.27</c> (destinationIndicator).</summary>
    public const string DestinationIndicator = "2.5.4.27";
    /// <summary>X.500 name attribute OID <c>2.5.4.41</c> (name).</summary>
    public const string Name = "2.5.4.41";
    /// <summary>X.500 name attribute OID <c>2.5.4.43</c> (initials).</summary>
    public const string Initials = "2.5.4.43";
    /// <summary>X.500 name attribute OID <c>2.5.4.44</c> (generationQualifier).</summary>
    public const string GenerationQualifier = "2.5.4.44";
    /// <summary>X.500 name attribute OID <c>2.5.4.51</c> (houseIdentifier).</summary>
    public const string HouseIdentifier = "2.5.4.51";
    /// <summary>X.500 name attribute OID <c>2.5.4.54</c> (dmdName).</summary>
    public const string DmdName = "2.5.4.54";
    /// <summary>X.500 name attribute OID <c>2.5.4.65</c> (pseudonym).</summary>
    public const string Pseudonym = "2.5.4.65";
    /// <summary>X.500 name attribute OID <c>2.5.4.80</c> (uiiInUrn).</summary>
    public const string UiiInUrn = "2.5.4.80";
    /// <summary>X.500 name attribute OID <c>2.5.4.81</c> (contentUrl).</summary>
    public const string ContentUrl = "2.5.4.81";
    /// <summary>X.500 name attribute OID <c>2.5.4.83</c> (uri).</summary>
    public const string Uri = "2.5.4.83";
    /// <summary>X.500 name attribute OID <c>2.5.4.86</c> (urn).</summary>
    public const string Urn = "2.5.4.86";
    /// <summary>X.500 name attribute OID <c>2.5.4.87</c> (url).</summary>
    public const string Url = "2.5.4.87";
    /// <summary>X.500 name attribute OID <c>2.5.4.89</c> (urnC).</summary>
    public const string UrnC = "2.5.4.89";
    /// <summary>X.500 name attribute OID <c>2.5.4.94</c> (epcInUrn).</summary>
    public const string EpcInUrn = "2.5.4.94";
    /// <summary>X.500 name attribute OID <c>2.5.4.95</c> (ldapUrl).</summary>
    public const string LdapUrl = "2.5.4.95";
    /// <summary>X.500 name attribute OID <c>2.5.4.97</c> (organizationIdentifier).</summary>
    public const string OrganizationIdentifier = "2.5.4.97";
    /// <summary>X.500 name attribute OID <c>2.5.4.98</c> (countryCode3c).</summary>
    public const string CountryOrRegionName3C = "2.5.4.98";
    /// <summary>X.500 name attribute OID <c>2.5.4.99</c> (countryCode3n).</summary>
    public const string CountryOrRegionName3N = "2.5.4.99";
    /// <summary>X.500 name attribute OID <c>2.5.4.100</c> (dnsName).</summary>
    public const string DnsName = "2.5.4.100";
    /// <summary>X.500 name attribute OID <c>2.5.4.104</c> (intEmail).</summary>
    public const string IntEmail = "2.5.4.104";
    /// <summary>X.500 name attribute OID <c>2.5.4.105</c> (jabberId).</summary>
    public const string JabberId = "2.5.4.105";

    // Cert Extensions
    /// <summary>Certificate extension OID <c>2.5.29.10</c>.</summary>
    public const string BasicConstraints = "2.5.29.10";
    /// <summary>Certificate extension OID <c>2.5.29.14</c>.</summary>
    public const string SubjectKeyIdentifier = "2.5.29.14";
    /// <summary>Certificate extension OID <c>2.5.29.15</c>.</summary>
    public const string KeyUsage = "2.5.29.15";
    /// <summary>Certificate extension OID <c>2.5.29.17</c>.</summary>
    public const string SubjectAltName = "2.5.29.17";
    /// <summary>Certificate extension OID <c>2.5.29.18</c>.</summary>
    public const string IssuerAltName = "2.5.29.18";
    /// <summary>Certificate extension OID <c>2.5.29.19</c>.</summary>
    public const string BasicConstraints2 = "2.5.29.19";
    /// <summary>Certificate extension OID <c>2.5.29.20</c>.</summary>
    public const string CrlNumber = "2.5.29.20";
    /// <summary>Certificate extension OID <c>2.5.29.21</c>.</summary>
    public const string CrlReasons = "2.5.29.21";
    /// <summary>Certificate extension OID <c>2.5.29.30</c>.</summary>
    public const string NameConstraints = "2.5.29.30";
    /// <summary>Certificate extension OID <c>2.5.29.31</c>.</summary>
    public const string CrlDistributionPoints = "2.5.29.31";
    /// <summary>Certificate extension OID <c>2.5.29.32</c>.</summary>
    public const string CertPolicies = "2.5.29.32";
    /// <summary>Certificate extension OID <c>2.5.29.32.0</c>.</summary>
    public const string AnyCertPolicy = "2.5.29.32.0";
    /// <summary>Certificate extension OID <c>2.5.29.33</c>.</summary>
    public const string CertPolicyMappings = "2.5.29.33";
    /// <summary>Certificate extension OID <c>2.5.29.35</c>.</summary>
    public const string AuthorityKeyIdentifier = "2.5.29.35";
    /// <summary>Certificate extension OID <c>2.5.29.36</c>.</summary>
    public const string CertPolicyConstraints = "2.5.29.36";
    /// <summary>Certificate extension OID <c>2.5.29.37</c>.</summary>
    public const string EnhancedKeyUsage = "2.5.29.37";
    /// <summary>Certificate extension OID <c>2.5.29.54</c>.</summary>
    public const string InhibitAnyPolicyExtension = "2.5.29.54";

    //RFC3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)
    /// <summary>Certificate extension OID <c>1.2.840.113549.1.9.16.1.4</c>, defined by RFC3161.</summary>
    public const string TstInfo = "1.2.840.113549.1.9.16.1.4";

    // CA/Browser Forum certificate policy identifiers, for use as a policyIdentifier value inside the
    // CertPolicies extension (not to be confused with that extension's own OID, above).
    /// <summary>Certificate policy OID <c>2.23.140.1.1</c>, defined by the CA/Browser Forum EV Guidelines.</summary>
    public const string ExtendedValidationCertPolicy = "2.23.140.1.1";
    /// <summary>Certificate policy OID <c>2.23.140.1.2.1</c>, defined by the CA/Browser Forum Baseline Requirements.</summary>
    public const string DomainValidatedCertPolicy = "2.23.140.1.2.1";
    /// <summary>Certificate policy OID <c>2.23.140.1.2.2</c>, defined by the CA/Browser Forum Baseline Requirements.</summary>
    public const string OrganizationValidatedCertPolicy = "2.23.140.1.2.2";
    /// <summary>Certificate policy OID <c>2.23.140.1.2.3</c>, defined by the CA/Browser Forum Baseline Requirements.</summary>
    public const string IndividualValidatedCertPolicy = "2.23.140.1.2.3";
    /// <summary>Certificate policy OID <c>2.23.140.1.3</c>, defined by the CA/Browser Forum EV Code Signing Guidelines.</summary>
    public const string ExtendedValidationCodeSigningCertPolicy = "2.23.140.1.3";
    /// <summary>Certificate policy OID <c>2.23.140.1.4.1</c>, defined by the CA/Browser Forum Code Signing Baseline Requirements.</summary>
    public const string CodeSigningRequirementsCertPolicy = "2.23.140.1.4.1";

    /// <summary>Extended key usage OID <c>2.5.29.37.0</c>.</summary>
    public const string AnyExtendedKeyUsage = "2.5.29.37.0";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.1</c>.</summary>
    public const string ServerAuthPurpose = "1.3.6.1.5.5.7.3.1";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.2</c>.</summary>
    public const string ClientAuthPurpose = "1.3.6.1.5.5.7.3.2";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.3</c>.</summary>
    public const string CodeSigningPurpose = "1.3.6.1.5.5.7.3.3";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.4</c>.</summary>
    public const string EmailProtectionPurpose = "1.3.6.1.5.5.7.3.4";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.5</c>.</summary>
    public const string IpsecEndSystemPurpose = "1.3.6.1.5.5.7.3.5";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.6</c>.</summary>
    public const string IpsecTunnelPurpose = "1.3.6.1.5.5.7.3.6";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.7</c>.</summary>
    public const string IpsecUserPurpose = "1.3.6.1.5.5.7.3.7";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.8</c>.</summary>
    public const string TimeStampingPurpose = "1.3.6.1.5.5.7.3.8";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.9</c>.</summary>
    public const string OcspSigningPurpose = "1.3.6.1.5.5.7.3.9";
    //RFC3029: Internet X.509 Public Key Infrastructure Data Validation and Certification Server Protocols
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.10</c>, defined by RFC3029.</summary>
    public const string DvcsPurpose = "1.3.6.1.5.5.7.3.10";
    //"Reserved and Obsolete"
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.11</c>.</summary>
    public const string SbgpCertAaServerAuthPurpose = "1.3.6.1.5.5.7.3.11";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.12</c>.</summary>
    public const string ScvpResponderPurpose = "1.3.6.1.5.5.7.3.12";
    //RFC4334: Certificate Extensions and Attributes Supporting Authentication in Point-to-Point Protocol (PPP) and Wireless Local Area Networks (WLAN)
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.13</c>, defined by RFC4334.</summary>
    public const string EapOverPppPurpose = "1.3.6.1.5.5.7.3.13";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.14</c>.</summary>
    public const string EapOverLanPurpose = "1.3.6.1.5.5.7.3.14";
    //RFC5055: Server-Based Certificate Validation Protocol (SCVP)
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.15</c>, defined by RFC5055.</summary>
    public const string ScvpServerPurpose = "1.3.6.1.5.5.7.3.15";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.16</c>.</summary>
    public const string ScvpClientPurpose = "1.3.6.1.5.5.7.3.16";
    //RFC4945: PKI Profile for IKE, ISAKMP and PKIX
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.17</c>, defined by RFC4945.</summary>
    public const string IpsecIkePurpose = "1.3.6.1.5.5.7.3.17";
    //RFC5415: Control And Provisioning of Wireless Access Points (CAPWAP) Protocol Specification
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.18</c>, defined by RFC5415.</summary>
    public const string CapwapAcPurpose = "1.3.6.1.5.5.7.3.18";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.19</c>.</summary>
    public const string CapwapWtpPurpose = "1.3.6.1.5.5.7.3.19";
    //RFC5924: Extended Key Usage (EKU) for Session Initiation Protocol (SIP) X.509 Certificates
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.20</c>, defined by RFC5924.</summary>
    public const string SipDomainPurpose = "1.3.6.1.5.5.7.3.20";
    //RFC6187: X.509v3 Certificates for Secure Shell Authentication
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.21</c>, defined by RFC6187.</summary>
    public const string SecureShellClientPurpose = "1.3.6.1.5.5.7.3.21";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.22</c>.</summary>
    public const string SecureShellServerPurpose = "1.3.6.1.5.5.7.3.22";
    //RFC6494: Certificate Profile and Certificate Management for SEcure Neighbor Discovery (SEND)
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.23</c>, defined by RFC6494.</summary>
    public const string SendRouterPurpose = "1.3.6.1.5.5.7.3.23";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.24</c>.</summary>
    public const string SendProxiedRouterPurpose = "1.3.6.1.5.5.7.3.24";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.25</c>.</summary>
    public const string SendOwnerPurpose = "1.3.6.1.5.5.7.3.25";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.26</c>.</summary>
    public const string SendProxiedOwnerPurpose = "1.3.6.1.5.5.7.3.26";
    //RFC6402: Certificate Management over CMS (CMC) Updates
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.27</c>, defined by RFC6402.</summary>
    public const string CmcCaPurpose = "1.3.6.1.5.5.7.3.27";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.28</c>.</summary>
    public const string CmcRaPurpose = "1.3.6.1.5.5.7.3.28";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.29</c>.</summary>
    public const string CmcArchivePurpose = "1.3.6.1.5.5.7.3.29";
    //RFC8209: A Profile for BGPsec Router Certificates, Certificate Revocation Lists, and Certification Requests
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.5.5.7.3.30</c>, defined by RFC8209.</summary>
    public const string BgpSecRouterPurpose = "1.3.6.1.5.5.7.3.30";

    /// <summary>Extended key usage purpose OID <c>1.3.6.1.4.1.311.20.2.2</c>.</summary>
    public const string SmartCardLogonPurpose = "1.3.6.1.4.1.311.20.2.2";
    /// <summary>Extended key usage purpose OID <c>1.3.6.1.4.1.311.10.3.13</c>.</summary>
    public const string LifetimeSigningPurpose = "1.3.6.1.4.1.311.10.3.13";


    // PKCS#12
    private const string Pkcs12Prefix = "1.2.840.113549.1.12.";
    private const string Pkcs12PbePrefix = Pkcs12Prefix + "1.";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12PbeWithShaAnd3Key3Des = Pkcs12PbePrefix + "3";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12PbeWithShaAnd2Key3Des = Pkcs12PbePrefix + "4";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12PbeWithShaAnd128BitRC2 = Pkcs12PbePrefix + "5";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12PbeWithShaAnd40BitRC2 = Pkcs12PbePrefix + "6";
    private const string Pkcs12BagTypesPrefix = Pkcs12Prefix + "10.1.";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12KeyBag = Pkcs12BagTypesPrefix + "1";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12ShroudedKeyBag = Pkcs12BagTypesPrefix + "2";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12CertBag = Pkcs12BagTypesPrefix + "3";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12CrlBag = Pkcs12BagTypesPrefix + "4";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12SecretBag = Pkcs12BagTypesPrefix + "5";
    /// <summary>PKCS#12 OID.</summary>
    public const string Pkcs12SafeContentsBag = Pkcs12BagTypesPrefix + "6";
    /// <summary>PKCS#12 OID <c>1.2.840.113549.1.9.22.1</c>.</summary>
    public const string Pkcs12X509CertBagType = "1.2.840.113549.1.9.22.1";
    /// <summary>Microsoft PKCS#12 attribute OID <c>1.3.6.1.4.1.311.17.1</c> (key provider name).</summary>
    public const string MsPkcs12KeyProviderName = "1.3.6.1.4.1.311.17.1";
    /// <summary>Microsoft PKCS#12 attribute OID <c>1.3.6.1.4.1.311.17.2</c> (machine key set).</summary>
    public const string MsPkcs12MachineKeySet = "1.3.6.1.4.1.311.17.2";
    /// <summary>PKCS#12 OID <c>1.2.840.113549.1.9.22.2</c>.</summary>
    public const string Pkcs12SdsiCertBagType = "1.2.840.113549.1.9.22.2";

    // PKCS#5
    private const string Pkcs5Prefix = "1.2.840.113549.1.5.";
    /// <summary>Password-based encryption OID.</summary>
    public const string PbeWithMD5AndDESCBC = Pkcs5Prefix + "3";
    /// <summary>Password-based encryption OID.</summary>
    public const string PbeWithMD5AndRC2CBC = Pkcs5Prefix + "6";
    /// <summary>Password-based encryption OID.</summary>
    public const string PbeWithSha1AndDESCBC = Pkcs5Prefix + "10";
    /// <summary>Password-based encryption OID.</summary>
    public const string PbeWithSha1AndRC2CBC = Pkcs5Prefix + "11";
    /// <summary>Password-based encryption OID.</summary>
    public const string Pbkdf2 = Pkcs5Prefix + "12";
    /// <summary>Password-based encryption OID.</summary>
    public const string PasswordBasedEncryptionScheme2 = Pkcs5Prefix + "13";

    private const string RsaDsiDigestAlgorithmPrefix = "1.2.840.113549.2.";
    /// <summary>HMAC algorithm OID.</summary>
    public const string HmacWithSha1 = RsaDsiDigestAlgorithmPrefix + "7";
    /// <summary>HMAC algorithm OID.</summary>
    public const string HmacWithSha256 = RsaDsiDigestAlgorithmPrefix + "9";
    /// <summary>HMAC algorithm OID.</summary>
    public const string HmacWithSha384 = RsaDsiDigestAlgorithmPrefix + "10";
    /// <summary>HMAC algorithm OID.</summary>
    public const string HmacWithSha512 = RsaDsiDigestAlgorithmPrefix + "11";

    // Elliptic Curve curve identifiers
    /// <summary>Named elliptic curve OID <c>1.2.840.10045.3.1.7</c>.</summary>
    public const string secp256r1 = "1.2.840.10045.3.1.7";
    /// <summary>Named elliptic curve OID <c>1.3.132.0.34</c>.</summary>
    public const string secp384r1 = "1.3.132.0.34";
    /// <summary>Named elliptic curve OID <c>1.3.132.0.35</c>.</summary>
    public const string secp521r1 = "1.3.132.0.35";
    /// <summary>Named elliptic curve OID <c>1.3.36.3.3.2.8.1.1.7</c> (brainpoolP256r1).</summary>
    public const string brainpoolP256r1 = "1.3.36.3.3.2.8.1.1.7";
    /// <summary>Named elliptic curve OID <c>1.3.36.3.3.2.8.1.1.11</c> (brainpoolP384r1).</summary>
    public const string brainpoolP384r1 = "1.3.36.3.3.2.8.1.1.11";
    /// <summary>Key agreement algorithm OID <c>1.3.101.110</c> (X25519, RFC 8410).</summary>
    public const string X25519 = "1.3.101.110";
    /// <summary>Key agreement algorithm OID <c>1.3.101.111</c> (X448, RFC 8410).</summary>
    public const string X448 = "1.3.101.111";
    /// <summary>Signature algorithm OID <c>1.3.101.112</c> (Ed25519, RFC 8410).</summary>
    public const string Ed25519 = "1.3.101.112";
    /// <summary>Signature algorithm OID <c>1.3.101.113</c> (Ed448, RFC 8410).</summary>
    public const string Ed448 = "1.3.101.113";

    // LDAP
    /// <summary>LDAP attribute OID <c>0.9.2342.19200300.100.1.25</c>.</summary>
    public const string DomainComponent = "0.9.2342.19200300.100.1.25";
    /// <summary>LDAP attribute OID <c>0.9.2342.19200300.100.1.1</c>.</summary>
    public const string UserId = "0.9.2342.19200300.100.1.1";
    /// <summary>
    /// LDAP attribute OID <c>1.3.6.1.1.1.1.22</c> (<c>macAddress</c>), from the NIS schema in
    /// RFC 2307 s2.3. An attribute type, not an extended key usage purpose.
    /// </summary>
    public const string MacAddress = "1.3.6.1.1.1.1.22";



    private static Oid? s_rc2CbcOid;
    private static Oid? s_rc4Oid;
    private static Oid? s_tripleDesCbcOid;
    private static Oid? s_desCbcOid;
    private static Oid? s_aes128CbcOid;
    private static Oid? s_aes192CbcOid;
    private static Oid? s_aes256CbcOid;

    private static Oid? s_dsaOid;
    private static Oid? s_rsaOid;
    private static Oid? s_rsaOaepOid;
    private static Oid? s_rsaPssOid;
    private static Oid? s_rsaPkcs1Md5Oid;
    private static Oid? s_rsaPkcs1Sha1Oid;
    private static Oid? s_rsaPkcs1Sha224Oid;
    private static Oid? s_rsaPkcs1Sha256Oid;
    private static Oid? s_rsaPkcs1Sha384Oid;
    private static Oid? s_rsaPkcs1Sha512Oid;
    private static Oid? s_rsaPkcs1Sha3_256Oid;
    private static Oid? s_rsaPkcs1Sha3_384Oid;
    private static Oid? s_rsaPkcs1Sha3_512Oid;
    private static Oid? s_esdhOid;
    private static Oid? s_ecDiffieHellmanOid;
    private static Oid? s_diffieHellmanOid;
    private static Oid? s_diffieHellmanPkcs3Oid;

    private static Oid? s_mLDsa44Oid;
    private static Oid? s_mLDsa65Oid;
    private static Oid? s_mLDsa87Oid;

    private static Oid? s_slhDsaSha2_128sOid;
    private static Oid? s_slhDsaSha2_128fOid;
    private static Oid? s_slhDsaSha2_192sOid;
    private static Oid? s_slhDsaSha2_192fOid;
    private static Oid? s_slhDsaSha2_256sOid;
    private static Oid? s_slhDsaSha2_256fOid;
    private static Oid? s_slhDsaShake128sOid;
    private static Oid? s_slhDsaShake128fOid;
    private static Oid? s_slhDsaShake192sOid;
    private static Oid? s_slhDsaShake192fOid;
    private static Oid? s_slhDsaShake256sOid;
    private static Oid? s_slhDsaShake256fOid;

    private static Oid? s_mLDsa44PreHashSha512Oid;
    private static Oid? s_mLDsa65PreHashSha512Oid;
    private static Oid? s_mLDsa87PreHashSha512Oid;
    private static Oid? s_slhDsaSha2_128sPreHashSha256Oid;
    private static Oid? s_slhDsaSha2_128fPreHashSha256Oid;
    private static Oid? s_slhDsaSha2_192sPreHashSha512Oid;
    private static Oid? s_slhDsaSha2_192fPreHashSha512Oid;
    private static Oid? s_slhDsaSha2_256sPreHashSha512Oid;
    private static Oid? s_slhDsaSha2_256fPreHashSha512Oid;
    private static Oid? s_slhDsaShake128sPreHashShake128Oid;
    private static Oid? s_slhDsaShake128fPreHashShake128Oid;
    private static Oid? s_slhDsaShake192sPreHashShake256Oid;
    private static Oid? s_slhDsaShake192fPreHashShake256Oid;
    private static Oid? s_slhDsaShake256sPreHashShake256Oid;
    private static Oid? s_slhDsaShake256fPreHashShake256Oid;

    private static Oid? s_mLDsa44WithRSA2048PssOid;
    private static Oid? s_mLDsa44WithRSA2048Pkcs15Oid;
    private static Oid? s_mLDsa44WithEd25519Oid;
    private static Oid? s_mLDsa44WithECDsaP256Oid;
    private static Oid? s_mLDsa65WithRSA3072PssOid;
    private static Oid? s_mLDsa65WithRSA3072Pkcs15Oid;
    private static Oid? s_mLDsa65WithRSA4096PssOid;
    private static Oid? s_mLDsa65WithRSA4096Pkcs15Oid;
    private static Oid? s_mLDsa65WithECDsaP256Oid;
    private static Oid? s_mLDsa65WithECDsaP384Oid;
    private static Oid? s_mLDsa65WithECDsaBrainpoolP256r1Oid;
    private static Oid? s_mLDsa65WithEd25519Oid;
    private static Oid? s_mLDsa87WithECDsaP384Oid;
    private static Oid? s_mLDsa87WithECDsaBrainpoolP384r1Oid;
    private static Oid? s_mLDsa87WithEd448Oid;
    private static Oid? s_mLDsa87WithRSA3072PssOid;
    private static Oid? s_mLDsa87WithRSA4096PssOid;
    private static Oid? s_mLDsa87WithECDsaP521Oid;

    private static Oid? s_mLKem512Oid;
    private static Oid? s_mLKem768Oid;
    private static Oid? s_mLKem1024Oid;

    private static Oid? s_mLKem768WithRsaOaep2048Sha3_256Oid;
    private static Oid? s_mLKem768WithRsaOaep3072Sha3_256Oid;
    private static Oid? s_mLKem768WithRsaOaep4096Sha3_256Oid;
    private static Oid? s_mLKem768WithX25519Sha3_256Oid;
    private static Oid? s_mLKem768WithECDiffieHellmanP256Sha3_256Oid;
    private static Oid? s_mLKem768WithECDiffieHellmanP384Sha3_256Oid;
    private static Oid? s_mLKem768WithECDiffieHellmanBrainpoolP256r1Sha3_256Oid;
    private static Oid? s_mLKem1024WithRsaOaep3072Sha3_256Oid;
    private static Oid? s_mLKem1024WithECDiffieHellmanP384Sha3_256Oid;
    private static Oid? s_mLKem1024WithECDiffieHellmanBrainpoolP384r1Sha3_256Oid;
    private static Oid? s_mLKem1024WithX448Sha3_256Oid;
    private static Oid? s_mLKem1024WithECDiffieHellmanP521Sha3_256Oid;

    private static Oid? s_signingTimeOid;
    private static Oid? s_contentTypeOid;
    private static Oid? s_documentDescriptionOid;
    private static Oid? s_messageDigestOid;
    private static Oid? s_counterSignerOid;
    private static Oid? s_signingCertificateOid;
    private static Oid? s_signingCertificateV2Oid;
    private static Oid? s_documentNameOid;
    private static Oid? s_friendlyNameOid;
    private static Oid? s_localKeyIdOid;
    private static Oid? s_enrollCertTypeExtensionOid;
    private static Oid? s_userPrincipalNameOid;
    private static Oid? s_certificateTemplateOid;
    private static Oid? s_applicationCertPoliciesOid;
    private static Oid? s_authorityInformationAccessOid;
    private static Oid? s_ocspEndpointOid;
    private static Oid? s_certificateAuthorityIssuersOid;
    private static Oid? s_pkcs9ExtensionRequestOid;

    private static Oid? s_cmsRc2WrapOid;
    private static Oid? s_cms3DesWrapOid;

    private static Oid? s_pkcs7DataOid;
    private static Oid? s_pkcs7SignedOid;
    private static Oid? s_pkcs7EnvelopedOid;
    private static Oid? s_pkcs7SignedEnvelopedOid;
    private static Oid? s_pkcs7HashedOid;
    private static Oid? s_pkcs7EncryptedOid;

    private static Oid? s_md5Oid;
    private static Oid? s_sha1Oid;
    private static Oid? s_sha224Oid;
    private static Oid? s_sha256Oid;
    private static Oid? s_sha384Oid;
    private static Oid? s_sha512Oid;
    private static Oid? s_sha3_256Oid;
    private static Oid? s_sha3_384Oid;
    private static Oid? s_sha3_512Oid;
    private static Oid? s_shake128Oid;
    private static Oid? s_shake256Oid;

    private static Oid? s_dsaWithSha1Oid;
    private static Oid? s_dsaWithSha224Oid;
    private static Oid? s_dsaWithSha256Oid;
    private static Oid? s_dsaWithSha384Oid;
    private static Oid? s_dsaWithSha512Oid;

    private static Oid? s_ecPrimeFieldOid;
    private static Oid? s_ecChar2FieldOid;
    private static Oid? s_ecChar2TrinomialBasisOid;
    private static Oid? s_ecChar2PentanomialBasisOid;
    private static Oid? s_ecPublicKeyOid;
    private static Oid? s_eCDsaWithSha1Oid;
    private static Oid? s_eCDsaWithSha224Oid;
    private static Oid? s_eCDsaWithSha256Oid;
    private static Oid? s_eCDsaWithSha384Oid;
    private static Oid? s_eCDsaWithSha512Oid;
    private static Oid? s_eCDsaWithSha3_256Oid;
    private static Oid? s_eCDsaWithSha3_384Oid;
    private static Oid? s_eCDsaWithSha3_512Oid;

    private static Oid? s_mgf1Oid;
    private static Oid? s_pSpecifiedOid;

    private static Oid? s_noSignatureOid;

    private static Oid? s_commonNameOid;
    private static Oid? s_countryOrRegionNameOid;
    private static Oid? s_localityNameOid;
    private static Oid? s_stateOrProvinceNameOid;
    private static Oid? s_organizationOid;
    private static Oid? s_organizationalUnitOid;
    private static Oid? s_emailAddressOid;
    private static Oid? s_telephoneNumberOid;
    private static Oid? s_streetAddressOid;
    private static Oid? s_postalCodeOid;
    private static Oid? s_serialNumberOid;
    private static Oid? s_surnameOid;
    private static Oid? s_givenNameOid;
    private static Oid? s_titleOid;
    private static Oid? s_dnQualifierOid;
    private static Oid? s_knowledgeInformationOid;
    private static Oid? s_descriptionOid;
    private static Oid? s_businessCategoryOid;
    private static Oid? s_postOfficeBoxOid;
    private static Oid? s_physicalDeliveryOfficeNameOid;
    private static Oid? s_x121AddressOid;
    private static Oid? s_internationalISDNNumberOid;
    private static Oid? s_destinationIndicatorOid;
    private static Oid? s_nameOid;
    private static Oid? s_initialsOid;
    private static Oid? s_generationQualifierOid;
    private static Oid? s_houseIdentifierOid;
    private static Oid? s_dmdNameOid;
    private static Oid? s_pseudonymOid;
    private static Oid? s_uiiInUrnOid;
    private static Oid? s_contentUrlOid;
    private static Oid? s_uriOid;
    private static Oid? s_urnOid;
    private static Oid? s_urlOid;
    private static Oid? s_urnCOid;
    private static Oid? s_epcInUrnOid;
    private static Oid? s_ldapUrlOid;
    private static Oid? s_organizationIdentifierOid;
    private static Oid? s_countryOrRegionName3COid;
    private static Oid? s_countryOrRegionName3NOid;
    private static Oid? s_dnsNameOid;
    private static Oid? s_intEmailOid;
    private static Oid? s_jabberIdOid;

    private static Oid? s_basicConstraintsOid;
    private static Oid? s_subjectKeyIdentifierOid;
    private static Oid? s_keyUsageOid;
    private static Oid? s_subjectAltNameOid;
    private static Oid? s_issuerAltNameOid;
    private static Oid? s_basicConstraints2Oid;
    private static Oid? s_crlNumberOid;
    private static Oid? s_crlReasonsOid;
    private static Oid? s_nameConstraintsOid;
    private static Oid? s_crlDistributionPointsOid;
    private static Oid? s_certPoliciesOid;
    private static Oid? s_anyCertPolicyOid;
    private static Oid? s_certPolicyMappingsOid;
    private static Oid? s_authorityKeyIdentifierOid;
    private static Oid? s_certPolicyConstraintsOid;
    private static Oid? s_enhancedKeyUsageOid;
    private static Oid? s_inhibitAnyPolicyExtensionOid;

    private static Oid? s_tstInfoOid;

    private static Oid? s_extendedValidationCertPolicyOid;
    private static Oid? s_domainValidatedCertPolicyOid;
    private static Oid? s_organizationValidatedCertPolicyOid;
    private static Oid? s_individualValidatedCertPolicyOid;
    private static Oid? s_extendedValidationCodeSigningCertPolicyOid;
    private static Oid? s_codeSigningRequirementsCertPolicyOid;

    private static Oid? s_anyExtendedKeyUsageOid;
    private static Oid? s_serverAuthPurposeOid;
    private static Oid? s_clientAuthPurposeOid;
    private static Oid? s_codeSigningPurposeOid;
    private static Oid? s_emailProtectionPurposeOid;
    private static Oid? s_ipsecEndSystemPurposeOid;
    private static Oid? s_ipsecTunnelPurposeOid;
    private static Oid? s_ipsecUserPurposeOid;
    private static Oid? s_timeStampingPurposeOid;
    private static Oid? s_ocspSigningPurposeOid;
    private static Oid? s_dvcsPurposeOid;
    private static Oid? s_sbgpCertAaServerAuthPurposeOid;
    private static Oid? s_scvpResponderPurposeOid;
    private static Oid? s_eapOverPppPurposeOid;
    private static Oid? s_eapOverLanPurposeOid;
    private static Oid? s_scvpServerPurposeOid;
    private static Oid? s_scvpClientPurposeOid;
    private static Oid? s_ipsecIkePurposeOid;
    private static Oid? s_capwapAcPurposeOid;
    private static Oid? s_capwapWtpPurposeOid;
    private static Oid? s_sipDomainPurposeOid;
    private static Oid? s_secureShellClientPurposeOid;
    private static Oid? s_secureShellServerPurposeOid;
    private static Oid? s_sendRouterPurposeOid;
    private static Oid? s_sendProxiedRouterPurposeOid;
    private static Oid? s_sendOwnerPurposeOid;
    private static Oid? s_sendProxiedOwnerPurposeOid;
    private static Oid? s_cmcCaPurposeOid;
    private static Oid? s_cmcRaPurposeOid;
    private static Oid? s_cmcArchivePurposeOid;
    private static Oid? s_bgpSecRouterPurposeOid;

    private static Oid? s_smartCardLogonPurposeOid;
    private static Oid? s_lifetimeSigningPurposeOid;

    private static Oid? s_pkcs12PbeWithShaAnd3Key3DesOid;
    private static Oid? s_pkcs12PbeWithShaAnd2Key3DesOid;
    private static Oid? s_pkcs12PbeWithShaAnd128BitRC2Oid;
    private static Oid? s_pkcs12PbeWithShaAnd40BitRC2Oid;
    private static Oid? s_pkcs12KeyBagOid;
    private static Oid? s_pkcs12ShroudedKeyBagOid;
    private static Oid? s_pkcs12CertBagOid;
    private static Oid? s_pkcs12CrlBagOid;
    private static Oid? s_pkcs12SecretBagOid;
    private static Oid? s_pkcs12SafeContentsBagOid;
    private static Oid? s_pkcs12X509CertBagTypeOid;
    private static Oid? s_msPkcs12KeyProviderNameOid;
    private static Oid? s_msPkcs12MachineKeySetOid;
    private static Oid? s_pkcs12SdsiCertBagTypeOid;

    private static Oid? s_pbeWithMD5AndDESCBCOid;
    private static Oid? s_pbeWithMD5AndRC2CBCOid;
    private static Oid? s_pbeWithSha1AndDESCBCOid;
    private static Oid? s_pbeWithSha1AndRC2CBCOid;
    private static Oid? s_pbkdf2Oid;
    private static Oid? s_passwordBasedEncryptionScheme2Oid;

    private static Oid? s_hmacWithSha1Oid;
    private static Oid? s_hmacWithSha256Oid;
    private static Oid? s_hmacWithSha384Oid;
    private static Oid? s_hmacWithSha512Oid;

    private static Oid? s_secp256r1Oid;
    private static Oid? s_secp384r1Oid;
    private static Oid? s_secp521r1Oid;
    private static Oid? s_brainpoolP256r1Oid;
    private static Oid? s_brainpoolP384r1Oid;
    private static Oid? s_x25519Oid;
    private static Oid? s_x448Oid;
    private static Oid? s_ed25519Oid;
    private static Oid? s_ed448Oid;

    private static Oid? s_domainComponentOid;
    private static Oid? s_userIdOid;
    private static Oid? s_macAddressOid;


    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Rc2Cbc"/>.</summary>
    public static Oid Rc2CbcOid => LazyInitializer.EnsureInitialized(ref s_rc2CbcOid, () => InitializeOid(Rc2Cbc));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Rc4"/>.</summary>
    public static Oid Rc4Oid => LazyInitializer.EnsureInitialized(ref s_rc4Oid, () => InitializeOid(Rc4));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="TripleDesCbc"/>.</summary>
    public static Oid TripleDesCbcOid => LazyInitializer.EnsureInitialized(ref s_tripleDesCbcOid, () => InitializeOid(TripleDesCbc));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DesCbc"/>.</summary>
    public static Oid DesCbcOid => LazyInitializer.EnsureInitialized(ref s_desCbcOid, () => InitializeOid(DesCbc));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Aes128Cbc"/>.</summary>
    public static Oid Aes128CbcOid => LazyInitializer.EnsureInitialized(ref s_aes128CbcOid, () => InitializeOid(Aes128Cbc));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Aes192Cbc"/>.</summary>
    public static Oid Aes192CbcOid => LazyInitializer.EnsureInitialized(ref s_aes192CbcOid, () => InitializeOid(Aes192Cbc));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Aes256Cbc"/>.</summary>
    public static Oid Aes256CbcOid => LazyInitializer.EnsureInitialized(ref s_aes256CbcOid, () => InitializeOid(Aes256Cbc));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Dsa"/>.</summary>
    public static Oid DsaOid => LazyInitializer.EnsureInitialized(ref s_dsaOid, () => InitializeOid(Dsa));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Rsa"/>.</summary>
    public static Oid RsaOid => LazyInitializer.EnsureInitialized(ref s_rsaOid, () => InitializeOid(Rsa));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaOaep"/>.</summary>
    public static Oid RsaOaepOid => LazyInitializer.EnsureInitialized(ref s_rsaOaepOid, () => InitializeOid(RsaOaep));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPss"/>.</summary>
    public static Oid RsaPssOid => LazyInitializer.EnsureInitialized(ref s_rsaPssOid, () => InitializeOid(RsaPss));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPkcs1Md5"/>.</summary>
    public static Oid RsaPkcs1Md5Oid => LazyInitializer.EnsureInitialized(ref s_rsaPkcs1Md5Oid, () => InitializeOid(RsaPkcs1Md5));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPkcs1Sha1"/>.</summary>
    public static Oid RsaPkcs1Sha1Oid => LazyInitializer.EnsureInitialized(ref s_rsaPkcs1Sha1Oid, () => InitializeOid(RsaPkcs1Sha1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPkcs1Sha224"/>.</summary>
    public static Oid RsaPkcs1Sha224Oid => LazyInitializer.EnsureInitialized(ref s_rsaPkcs1Sha224Oid, () => InitializeOid(RsaPkcs1Sha224));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPkcs1Sha256"/>.</summary>
    public static Oid RsaPkcs1Sha256Oid => LazyInitializer.EnsureInitialized(ref s_rsaPkcs1Sha256Oid, () => InitializeOid(RsaPkcs1Sha256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPkcs1Sha384"/>.</summary>
    public static Oid RsaPkcs1Sha384Oid => LazyInitializer.EnsureInitialized(ref s_rsaPkcs1Sha384Oid, () => InitializeOid(RsaPkcs1Sha384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPkcs1Sha512"/>.</summary>
    public static Oid RsaPkcs1Sha512Oid => LazyInitializer.EnsureInitialized(ref s_rsaPkcs1Sha512Oid, () => InitializeOid(RsaPkcs1Sha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPkcs1Sha3_256"/>.</summary>
    public static Oid RsaPkcs1Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_rsaPkcs1Sha3_256Oid, () => InitializeOid(RsaPkcs1Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPkcs1Sha3_384"/>.</summary>
    public static Oid RsaPkcs1Sha3_384Oid => LazyInitializer.EnsureInitialized(ref s_rsaPkcs1Sha3_384Oid, () => InitializeOid(RsaPkcs1Sha3_384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="RsaPkcs1Sha3_512"/>.</summary>
    public static Oid RsaPkcs1Sha3_512Oid => LazyInitializer.EnsureInitialized(ref s_rsaPkcs1Sha3_512Oid, () => InitializeOid(RsaPkcs1Sha3_512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Esdh"/>.</summary>
    public static Oid EsdhOid => LazyInitializer.EnsureInitialized(ref s_esdhOid, () => InitializeOid(Esdh));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EcDiffieHellman"/>.</summary>
    public static Oid EcDiffieHellmanOid => LazyInitializer.EnsureInitialized(ref s_ecDiffieHellmanOid, () => InitializeOid(EcDiffieHellman));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DiffieHellman"/>.</summary>
    public static Oid DiffieHellmanOid => LazyInitializer.EnsureInitialized(ref s_diffieHellmanOid, () => InitializeOid(DiffieHellman));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DiffieHellmanPkcs3"/>.</summary>
    public static Oid DiffieHellmanPkcs3Oid => LazyInitializer.EnsureInitialized(ref s_diffieHellmanPkcs3Oid, () => InitializeOid(DiffieHellmanPkcs3));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa44"/>.</summary>
    public static Oid MLDsa44Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa44Oid, () => InitializeOid(MLDsa44));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65"/>.</summary>
    public static Oid MLDsa65Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa65Oid, () => InitializeOid(MLDsa65));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa87"/>.</summary>
    public static Oid MLDsa87Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa87Oid, () => InitializeOid(MLDsa87));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_128s"/>.</summary>
    public static Oid SlhDsaSha2_128sOid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_128sOid, () => InitializeOid(SlhDsaSha2_128s));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_128f"/>.</summary>
    public static Oid SlhDsaSha2_128fOid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_128fOid, () => InitializeOid(SlhDsaSha2_128f));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_192s"/>.</summary>
    public static Oid SlhDsaSha2_192sOid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_192sOid, () => InitializeOid(SlhDsaSha2_192s));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_192f"/>.</summary>
    public static Oid SlhDsaSha2_192fOid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_192fOid, () => InitializeOid(SlhDsaSha2_192f));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_256s"/>.</summary>
    public static Oid SlhDsaSha2_256sOid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_256sOid, () => InitializeOid(SlhDsaSha2_256s));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_256f"/>.</summary>
    public static Oid SlhDsaSha2_256fOid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_256fOid, () => InitializeOid(SlhDsaSha2_256f));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake128s"/>.</summary>
    public static Oid SlhDsaShake128sOid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake128sOid, () => InitializeOid(SlhDsaShake128s));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake128f"/>.</summary>
    public static Oid SlhDsaShake128fOid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake128fOid, () => InitializeOid(SlhDsaShake128f));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake192s"/>.</summary>
    public static Oid SlhDsaShake192sOid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake192sOid, () => InitializeOid(SlhDsaShake192s));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake192f"/>.</summary>
    public static Oid SlhDsaShake192fOid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake192fOid, () => InitializeOid(SlhDsaShake192f));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake256s"/>.</summary>
    public static Oid SlhDsaShake256sOid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake256sOid, () => InitializeOid(SlhDsaShake256s));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake256f"/>.</summary>
    public static Oid SlhDsaShake256fOid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake256fOid, () => InitializeOid(SlhDsaShake256f));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa44PreHashSha512"/>.</summary>
    public static Oid MLDsa44PreHashSha512Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa44PreHashSha512Oid, () => InitializeOid(MLDsa44PreHashSha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65PreHashSha512"/>.</summary>
    public static Oid MLDsa65PreHashSha512Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa65PreHashSha512Oid, () => InitializeOid(MLDsa65PreHashSha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa87PreHashSha512"/>.</summary>
    public static Oid MLDsa87PreHashSha512Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa87PreHashSha512Oid, () => InitializeOid(MLDsa87PreHashSha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_128sPreHashSha256"/>.</summary>
    public static Oid SlhDsaSha2_128sPreHashSha256Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_128sPreHashSha256Oid, () => InitializeOid(SlhDsaSha2_128sPreHashSha256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_128fPreHashSha256"/>.</summary>
    public static Oid SlhDsaSha2_128fPreHashSha256Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_128fPreHashSha256Oid, () => InitializeOid(SlhDsaSha2_128fPreHashSha256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_192sPreHashSha512"/>.</summary>
    public static Oid SlhDsaSha2_192sPreHashSha512Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_192sPreHashSha512Oid, () => InitializeOid(SlhDsaSha2_192sPreHashSha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_192fPreHashSha512"/>.</summary>
    public static Oid SlhDsaSha2_192fPreHashSha512Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_192fPreHashSha512Oid, () => InitializeOid(SlhDsaSha2_192fPreHashSha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_256sPreHashSha512"/>.</summary>
    public static Oid SlhDsaSha2_256sPreHashSha512Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_256sPreHashSha512Oid, () => InitializeOid(SlhDsaSha2_256sPreHashSha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaSha2_256fPreHashSha512"/>.</summary>
    public static Oid SlhDsaSha2_256fPreHashSha512Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaSha2_256fPreHashSha512Oid, () => InitializeOid(SlhDsaSha2_256fPreHashSha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake128sPreHashShake128"/>.</summary>
    public static Oid SlhDsaShake128sPreHashShake128Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake128sPreHashShake128Oid, () => InitializeOid(SlhDsaShake128sPreHashShake128));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake128fPreHashShake128"/>.</summary>
    public static Oid SlhDsaShake128fPreHashShake128Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake128fPreHashShake128Oid, () => InitializeOid(SlhDsaShake128fPreHashShake128));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake192sPreHashShake256"/>.</summary>
    public static Oid SlhDsaShake192sPreHashShake256Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake192sPreHashShake256Oid, () => InitializeOid(SlhDsaShake192sPreHashShake256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake192fPreHashShake256"/>.</summary>
    public static Oid SlhDsaShake192fPreHashShake256Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake192fPreHashShake256Oid, () => InitializeOid(SlhDsaShake192fPreHashShake256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake256sPreHashShake256"/>.</summary>
    public static Oid SlhDsaShake256sPreHashShake256Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake256sPreHashShake256Oid, () => InitializeOid(SlhDsaShake256sPreHashShake256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SlhDsaShake256fPreHashShake256"/>.</summary>
    public static Oid SlhDsaShake256fPreHashShake256Oid => LazyInitializer.EnsureInitialized(ref s_slhDsaShake256fPreHashShake256Oid, () => InitializeOid(SlhDsaShake256fPreHashShake256));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa44WithRSA2048Pss"/>.</summary>
    public static Oid MLDsa44WithRSA2048PssOid => LazyInitializer.EnsureInitialized(ref s_mLDsa44WithRSA2048PssOid, () => InitializeOid(MLDsa44WithRSA2048Pss));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa44WithRSA2048Pkcs15"/>.</summary>
    public static Oid MLDsa44WithRSA2048Pkcs15Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa44WithRSA2048Pkcs15Oid, () => InitializeOid(MLDsa44WithRSA2048Pkcs15));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa44WithEd25519"/>.</summary>
    public static Oid MLDsa44WithEd25519Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa44WithEd25519Oid, () => InitializeOid(MLDsa44WithEd25519));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa44WithECDsaP256"/>.</summary>
    public static Oid MLDsa44WithECDsaP256Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa44WithECDsaP256Oid, () => InitializeOid(MLDsa44WithECDsaP256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65WithRSA3072Pss"/>.</summary>
    public static Oid MLDsa65WithRSA3072PssOid => LazyInitializer.EnsureInitialized(ref s_mLDsa65WithRSA3072PssOid, () => InitializeOid(MLDsa65WithRSA3072Pss));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65WithRSA3072Pkcs15"/>.</summary>
    public static Oid MLDsa65WithRSA3072Pkcs15Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa65WithRSA3072Pkcs15Oid, () => InitializeOid(MLDsa65WithRSA3072Pkcs15));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65WithRSA4096Pss"/>.</summary>
    public static Oid MLDsa65WithRSA4096PssOid => LazyInitializer.EnsureInitialized(ref s_mLDsa65WithRSA4096PssOid, () => InitializeOid(MLDsa65WithRSA4096Pss));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65WithRSA4096Pkcs15"/>.</summary>
    public static Oid MLDsa65WithRSA4096Pkcs15Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa65WithRSA4096Pkcs15Oid, () => InitializeOid(MLDsa65WithRSA4096Pkcs15));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65WithECDsaP256"/>.</summary>
    public static Oid MLDsa65WithECDsaP256Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa65WithECDsaP256Oid, () => InitializeOid(MLDsa65WithECDsaP256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65WithECDsaP384"/>.</summary>
    public static Oid MLDsa65WithECDsaP384Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa65WithECDsaP384Oid, () => InitializeOid(MLDsa65WithECDsaP384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65WithECDsaBrainpoolP256r1"/>.</summary>
    public static Oid MLDsa65WithECDsaBrainpoolP256r1Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa65WithECDsaBrainpoolP256r1Oid, () => InitializeOid(MLDsa65WithECDsaBrainpoolP256r1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa65WithEd25519"/>.</summary>
    public static Oid MLDsa65WithEd25519Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa65WithEd25519Oid, () => InitializeOid(MLDsa65WithEd25519));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa87WithECDsaP384"/>.</summary>
    public static Oid MLDsa87WithECDsaP384Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa87WithECDsaP384Oid, () => InitializeOid(MLDsa87WithECDsaP384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa87WithECDsaBrainpoolP384r1"/>.</summary>
    public static Oid MLDsa87WithECDsaBrainpoolP384r1Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa87WithECDsaBrainpoolP384r1Oid, () => InitializeOid(MLDsa87WithECDsaBrainpoolP384r1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa87WithEd448"/>.</summary>
    public static Oid MLDsa87WithEd448Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa87WithEd448Oid, () => InitializeOid(MLDsa87WithEd448));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa87WithRSA3072Pss"/>.</summary>
    public static Oid MLDsa87WithRSA3072PssOid => LazyInitializer.EnsureInitialized(ref s_mLDsa87WithRSA3072PssOid, () => InitializeOid(MLDsa87WithRSA3072Pss));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa87WithRSA4096Pss"/>.</summary>
    public static Oid MLDsa87WithRSA4096PssOid => LazyInitializer.EnsureInitialized(ref s_mLDsa87WithRSA4096PssOid, () => InitializeOid(MLDsa87WithRSA4096Pss));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLDsa87WithECDsaP521"/>.</summary>
    public static Oid MLDsa87WithECDsaP521Oid => LazyInitializer.EnsureInitialized(ref s_mLDsa87WithECDsaP521Oid, () => InitializeOid(MLDsa87WithECDsaP521));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem512"/>.</summary>
    public static Oid MLKem512Oid => LazyInitializer.EnsureInitialized(ref s_mLKem512Oid, () => InitializeOid(MLKem512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem768"/>.</summary>
    public static Oid MLKem768Oid => LazyInitializer.EnsureInitialized(ref s_mLKem768Oid, () => InitializeOid(MLKem768));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem1024"/>.</summary>
    public static Oid MLKem1024Oid => LazyInitializer.EnsureInitialized(ref s_mLKem1024Oid, () => InitializeOid(MLKem1024));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem768WithRsaOaep2048Sha3_256"/>.</summary>
    public static Oid MLKem768WithRsaOaep2048Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem768WithRsaOaep2048Sha3_256Oid, () => InitializeOid(MLKem768WithRsaOaep2048Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem768WithRsaOaep3072Sha3_256"/>.</summary>
    public static Oid MLKem768WithRsaOaep3072Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem768WithRsaOaep3072Sha3_256Oid, () => InitializeOid(MLKem768WithRsaOaep3072Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem768WithRsaOaep4096Sha3_256"/>.</summary>
    public static Oid MLKem768WithRsaOaep4096Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem768WithRsaOaep4096Sha3_256Oid, () => InitializeOid(MLKem768WithRsaOaep4096Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem768WithX25519Sha3_256"/>.</summary>
    public static Oid MLKem768WithX25519Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem768WithX25519Sha3_256Oid, () => InitializeOid(MLKem768WithX25519Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem768WithECDiffieHellmanP256Sha3_256"/>.</summary>
    public static Oid MLKem768WithECDiffieHellmanP256Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem768WithECDiffieHellmanP256Sha3_256Oid, () => InitializeOid(MLKem768WithECDiffieHellmanP256Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem768WithECDiffieHellmanP384Sha3_256"/>.</summary>
    public static Oid MLKem768WithECDiffieHellmanP384Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem768WithECDiffieHellmanP384Sha3_256Oid, () => InitializeOid(MLKem768WithECDiffieHellmanP384Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem768WithECDiffieHellmanBrainpoolP256r1Sha3_256"/>.</summary>
    public static Oid MLKem768WithECDiffieHellmanBrainpoolP256r1Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem768WithECDiffieHellmanBrainpoolP256r1Sha3_256Oid, () => InitializeOid(MLKem768WithECDiffieHellmanBrainpoolP256r1Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem1024WithRsaOaep3072Sha3_256"/>.</summary>
    public static Oid MLKem1024WithRsaOaep3072Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem1024WithRsaOaep3072Sha3_256Oid, () => InitializeOid(MLKem1024WithRsaOaep3072Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem1024WithECDiffieHellmanP384Sha3_256"/>.</summary>
    public static Oid MLKem1024WithECDiffieHellmanP384Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem1024WithECDiffieHellmanP384Sha3_256Oid, () => InitializeOid(MLKem1024WithECDiffieHellmanP384Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem1024WithECDiffieHellmanBrainpoolP384r1Sha3_256"/>.</summary>
    public static Oid MLKem1024WithECDiffieHellmanBrainpoolP384r1Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem1024WithECDiffieHellmanBrainpoolP384r1Sha3_256Oid, () => InitializeOid(MLKem1024WithECDiffieHellmanBrainpoolP384r1Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem1024WithX448Sha3_256"/>.</summary>
    public static Oid MLKem1024WithX448Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem1024WithX448Sha3_256Oid, () => InitializeOid(MLKem1024WithX448Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MLKem1024WithECDiffieHellmanP521Sha3_256"/>.</summary>
    public static Oid MLKem1024WithECDiffieHellmanP521Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_mLKem1024WithECDiffieHellmanP521Sha3_256Oid, () => InitializeOid(MLKem1024WithECDiffieHellmanP521Sha3_256));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SigningTime"/>.</summary>
    public static Oid SigningTimeOid => LazyInitializer.EnsureInitialized(ref s_signingTimeOid, () => InitializeOid(SigningTime));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ContentType"/>.</summary>
    public static Oid ContentTypeOid => LazyInitializer.EnsureInitialized(ref s_contentTypeOid, () => InitializeOid(ContentType));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DocumentDescription"/>.</summary>
    public static Oid DocumentDescriptionOid => LazyInitializer.EnsureInitialized(ref s_documentDescriptionOid, () => InitializeOid(DocumentDescription));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MessageDigest"/>.</summary>
    public static Oid MessageDigestOid => LazyInitializer.EnsureInitialized(ref s_messageDigestOid, () => InitializeOid(MessageDigest));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CounterSigner"/>.</summary>
    public static Oid CounterSignerOid => LazyInitializer.EnsureInitialized(ref s_counterSignerOid, () => InitializeOid(CounterSigner));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SigningCertificate"/>.</summary>
    public static Oid SigningCertificateOid => LazyInitializer.EnsureInitialized(ref s_signingCertificateOid, () => InitializeOid(SigningCertificate));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SigningCertificateV2"/>.</summary>
    public static Oid SigningCertificateV2Oid => LazyInitializer.EnsureInitialized(ref s_signingCertificateV2Oid, () => InitializeOid(SigningCertificateV2));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DocumentName"/>.</summary>
    public static Oid DocumentNameOid => LazyInitializer.EnsureInitialized(ref s_documentNameOid, () => InitializeOid(DocumentName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="FriendlyName"/>.</summary>
    public static Oid FriendlyNameOid => LazyInitializer.EnsureInitialized(ref s_friendlyNameOid, () => InitializeOid(FriendlyName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="LocalKeyId"/>.</summary>
    public static Oid LocalKeyIdOid => LazyInitializer.EnsureInitialized(ref s_localKeyIdOid, () => InitializeOid(LocalKeyId));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EnrollCertTypeExtension"/>.</summary>
    public static Oid EnrollCertTypeExtensionOid => LazyInitializer.EnsureInitialized(ref s_enrollCertTypeExtensionOid, () => InitializeOid(EnrollCertTypeExtension));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="UserPrincipalName"/>.</summary>
    public static Oid UserPrincipalNameOid => LazyInitializer.EnsureInitialized(ref s_userPrincipalNameOid, () => InitializeOid(UserPrincipalName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CertificateTemplate"/>.</summary>
    public static Oid CertificateTemplateOid => LazyInitializer.EnsureInitialized(ref s_certificateTemplateOid, () => InitializeOid(CertificateTemplate));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ApplicationCertPolicies"/>.</summary>
    public static Oid ApplicationCertPoliciesOid => LazyInitializer.EnsureInitialized(ref s_applicationCertPoliciesOid, () => InitializeOid(ApplicationCertPolicies));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="AuthorityInformationAccess"/>.</summary>
    public static Oid AuthorityInformationAccessOid => LazyInitializer.EnsureInitialized(ref s_authorityInformationAccessOid, () => InitializeOid(AuthorityInformationAccess));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="OcspEndpoint"/>.</summary>
    public static Oid OcspEndpointOid => LazyInitializer.EnsureInitialized(ref s_ocspEndpointOid, () => InitializeOid(OcspEndpoint));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CertificateAuthorityIssuers"/>.</summary>
    public static Oid CertificateAuthorityIssuersOid => LazyInitializer.EnsureInitialized(ref s_certificateAuthorityIssuersOid, () => InitializeOid(CertificateAuthorityIssuers));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs9ExtensionRequest"/>.</summary>
    public static Oid Pkcs9ExtensionRequestOid => LazyInitializer.EnsureInitialized(ref s_pkcs9ExtensionRequestOid, () => InitializeOid(Pkcs9ExtensionRequest));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CmsRc2Wrap"/>.</summary>
    public static Oid CmsRc2WrapOid => LazyInitializer.EnsureInitialized(ref s_cmsRc2WrapOid, () => InitializeOid(CmsRc2Wrap));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Cms3DesWrap"/>.</summary>
    public static Oid Cms3DesWrapOid => LazyInitializer.EnsureInitialized(ref s_cms3DesWrapOid, () => InitializeOid(Cms3DesWrap));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs7Data"/>.</summary>
    public static Oid Pkcs7DataOid => LazyInitializer.EnsureInitialized(ref s_pkcs7DataOid, () => InitializeOid(Pkcs7Data));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs7Signed"/>.</summary>
    public static Oid Pkcs7SignedOid => LazyInitializer.EnsureInitialized(ref s_pkcs7SignedOid, () => InitializeOid(Pkcs7Signed));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs7Enveloped"/>.</summary>
    public static Oid Pkcs7EnvelopedOid => LazyInitializer.EnsureInitialized(ref s_pkcs7EnvelopedOid, () => InitializeOid(Pkcs7Enveloped));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs7SignedEnveloped"/>.</summary>
    public static Oid Pkcs7SignedEnvelopedOid => LazyInitializer.EnsureInitialized(ref s_pkcs7SignedEnvelopedOid, () => InitializeOid(Pkcs7SignedEnveloped));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs7Hashed"/>.</summary>
    public static Oid Pkcs7HashedOid => LazyInitializer.EnsureInitialized(ref s_pkcs7HashedOid, () => InitializeOid(Pkcs7Hashed));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs7Encrypted"/>.</summary>
    public static Oid Pkcs7EncryptedOid => LazyInitializer.EnsureInitialized(ref s_pkcs7EncryptedOid, () => InitializeOid(Pkcs7Encrypted));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Md5"/>.</summary>
    public static Oid Md5Oid => LazyInitializer.EnsureInitialized(ref s_md5Oid, () => InitializeOid(Md5));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Sha1"/>.</summary>
    public static Oid Sha1Oid => LazyInitializer.EnsureInitialized(ref s_sha1Oid, () => InitializeOid(Sha1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Sha224"/>.</summary>
    public static Oid Sha224Oid => LazyInitializer.EnsureInitialized(ref s_sha224Oid, () => InitializeOid(Sha224));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Sha256"/>.</summary>
    public static Oid Sha256Oid => LazyInitializer.EnsureInitialized(ref s_sha256Oid, () => InitializeOid(Sha256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Sha384"/>.</summary>
    public static Oid Sha384Oid => LazyInitializer.EnsureInitialized(ref s_sha384Oid, () => InitializeOid(Sha384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Sha512"/>.</summary>
    public static Oid Sha512Oid => LazyInitializer.EnsureInitialized(ref s_sha512Oid, () => InitializeOid(Sha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Sha3_256"/>.</summary>
    public static Oid Sha3_256Oid => LazyInitializer.EnsureInitialized(ref s_sha3_256Oid, () => InitializeOid(Sha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Sha3_384"/>.</summary>
    public static Oid Sha3_384Oid => LazyInitializer.EnsureInitialized(ref s_sha3_384Oid, () => InitializeOid(Sha3_384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Sha3_512"/>.</summary>
    public static Oid Sha3_512Oid => LazyInitializer.EnsureInitialized(ref s_sha3_512Oid, () => InitializeOid(Sha3_512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Shake128"/>.</summary>
    public static Oid Shake128Oid => LazyInitializer.EnsureInitialized(ref s_shake128Oid, () => InitializeOid(Shake128));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Shake256"/>.</summary>
    public static Oid Shake256Oid => LazyInitializer.EnsureInitialized(ref s_shake256Oid, () => InitializeOid(Shake256));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DsaWithSha1"/>.</summary>
    public static Oid DsaWithSha1Oid => LazyInitializer.EnsureInitialized(ref s_dsaWithSha1Oid, () => InitializeOid(DsaWithSha1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DsaWithSha224"/>.</summary>
    public static Oid DsaWithSha224Oid => LazyInitializer.EnsureInitialized(ref s_dsaWithSha224Oid, () => InitializeOid(DsaWithSha224));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DsaWithSha256"/>.</summary>
    public static Oid DsaWithSha256Oid => LazyInitializer.EnsureInitialized(ref s_dsaWithSha256Oid, () => InitializeOid(DsaWithSha256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DsaWithSha384"/>.</summary>
    public static Oid DsaWithSha384Oid => LazyInitializer.EnsureInitialized(ref s_dsaWithSha384Oid, () => InitializeOid(DsaWithSha384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DsaWithSha512"/>.</summary>
    public static Oid DsaWithSha512Oid => LazyInitializer.EnsureInitialized(ref s_dsaWithSha512Oid, () => InitializeOid(DsaWithSha512));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EcPrimeField"/>.</summary>
    public static Oid EcPrimeFieldOid => LazyInitializer.EnsureInitialized(ref s_ecPrimeFieldOid, () => InitializeOid(EcPrimeField));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EcChar2Field"/>.</summary>
    public static Oid EcChar2FieldOid => LazyInitializer.EnsureInitialized(ref s_ecChar2FieldOid, () => InitializeOid(EcChar2Field));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EcChar2TrinomialBasis"/>.</summary>
    public static Oid EcChar2TrinomialBasisOid => LazyInitializer.EnsureInitialized(ref s_ecChar2TrinomialBasisOid, () => InitializeOid(EcChar2TrinomialBasis));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EcChar2PentanomialBasis"/>.</summary>
    public static Oid EcChar2PentanomialBasisOid => LazyInitializer.EnsureInitialized(ref s_ecChar2PentanomialBasisOid, () => InitializeOid(EcChar2PentanomialBasis));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EcPublicKey"/>.</summary>
    public static Oid EcPublicKeyOid => LazyInitializer.EnsureInitialized(ref s_ecPublicKeyOid, () => InitializeOid(EcPublicKey));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ECDsaWithSha1"/>.</summary>
    public static Oid ECDsaWithSha1Oid => LazyInitializer.EnsureInitialized(ref s_eCDsaWithSha1Oid, () => InitializeOid(ECDsaWithSha1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ECDsaWithSha224"/>.</summary>
    public static Oid ECDsaWithSha224Oid => LazyInitializer.EnsureInitialized(ref s_eCDsaWithSha224Oid, () => InitializeOid(ECDsaWithSha224));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ECDsaWithSha256"/>.</summary>
    public static Oid ECDsaWithSha256Oid => LazyInitializer.EnsureInitialized(ref s_eCDsaWithSha256Oid, () => InitializeOid(ECDsaWithSha256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ECDsaWithSha384"/>.</summary>
    public static Oid ECDsaWithSha384Oid => LazyInitializer.EnsureInitialized(ref s_eCDsaWithSha384Oid, () => InitializeOid(ECDsaWithSha384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ECDsaWithSha512"/>.</summary>
    public static Oid ECDsaWithSha512Oid => LazyInitializer.EnsureInitialized(ref s_eCDsaWithSha512Oid, () => InitializeOid(ECDsaWithSha512));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ECDsaWithSha3_256"/>.</summary>
    public static Oid ECDsaWithSha3_256Oid => LazyInitializer.EnsureInitialized(ref s_eCDsaWithSha3_256Oid, () => InitializeOid(ECDsaWithSha3_256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ECDsaWithSha3_384"/>.</summary>
    public static Oid ECDsaWithSha3_384Oid => LazyInitializer.EnsureInitialized(ref s_eCDsaWithSha3_384Oid, () => InitializeOid(ECDsaWithSha3_384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ECDsaWithSha3_512"/>.</summary>
    public static Oid ECDsaWithSha3_512Oid => LazyInitializer.EnsureInitialized(ref s_eCDsaWithSha3_512Oid, () => InitializeOid(ECDsaWithSha3_512));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Mgf1"/>.</summary>
    public static Oid Mgf1Oid => LazyInitializer.EnsureInitialized(ref s_mgf1Oid, () => InitializeOid(Mgf1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PSpecified"/>.</summary>
    public static Oid PSpecifiedOid => LazyInitializer.EnsureInitialized(ref s_pSpecifiedOid, () => InitializeOid(PSpecified));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="NoSignature"/>.</summary>
    public static Oid NoSignatureOid => LazyInitializer.EnsureInitialized(ref s_noSignatureOid, () => InitializeOid(NoSignature));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CommonName"/>.</summary>
    public static Oid CommonNameOid => LazyInitializer.EnsureInitialized(ref s_commonNameOid, () => InitializeOid(CommonName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CountryOrRegionName"/>.</summary>
    public static Oid CountryOrRegionNameOid => LazyInitializer.EnsureInitialized(ref s_countryOrRegionNameOid, () => InitializeOid(CountryOrRegionName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="LocalityName"/>.</summary>
    public static Oid LocalityNameOid => LazyInitializer.EnsureInitialized(ref s_localityNameOid, () => InitializeOid(LocalityName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="StateOrProvinceName"/>.</summary>
    public static Oid StateOrProvinceNameOid => LazyInitializer.EnsureInitialized(ref s_stateOrProvinceNameOid, () => InitializeOid(StateOrProvinceName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Organization"/>.</summary>
    public static Oid OrganizationOid => LazyInitializer.EnsureInitialized(ref s_organizationOid, () => InitializeOid(Organization));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="OrganizationalUnit"/>.</summary>
    public static Oid OrganizationalUnitOid => LazyInitializer.EnsureInitialized(ref s_organizationalUnitOid, () => InitializeOid(OrganizationalUnit));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EmailAddress"/>.</summary>
    public static Oid EmailAddressOid => LazyInitializer.EnsureInitialized(ref s_emailAddressOid, () => InitializeOid(EmailAddress));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="TelephoneNumber"/>.</summary>
    public static Oid TelephoneNumberOid => LazyInitializer.EnsureInitialized(ref s_telephoneNumberOid, () => InitializeOid(TelephoneNumber));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="StreetAddress"/>.</summary>
    public static Oid StreetAddressOid => LazyInitializer.EnsureInitialized(ref s_streetAddressOid, () => InitializeOid(StreetAddress));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PostalCode"/>.</summary>
    public static Oid PostalCodeOid => LazyInitializer.EnsureInitialized(ref s_postalCodeOid, () => InitializeOid(PostalCode));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SerialNumber"/>.</summary>
    public static Oid SerialNumberOid => LazyInitializer.EnsureInitialized(ref s_serialNumberOid, () => InitializeOid(SerialNumber));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Surname"/>.</summary>
    public static Oid SurnameOid => LazyInitializer.EnsureInitialized(ref s_surnameOid, () => InitializeOid(Surname));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="GivenName"/>.</summary>
    public static Oid GivenNameOid => LazyInitializer.EnsureInitialized(ref s_givenNameOid, () => InitializeOid(GivenName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Title"/>.</summary>
    public static Oid TitleOid => LazyInitializer.EnsureInitialized(ref s_titleOid, () => InitializeOid(Title));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DnQualifier"/>.</summary>
    public static Oid DnQualifierOid => LazyInitializer.EnsureInitialized(ref s_dnQualifierOid, () => InitializeOid(DnQualifier));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="KnowledgeInformation"/>.</summary>
    public static Oid KnowledgeInformationOid => LazyInitializer.EnsureInitialized(ref s_knowledgeInformationOid, () => InitializeOid(KnowledgeInformation));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Description"/>.</summary>
    public static Oid DescriptionOid => LazyInitializer.EnsureInitialized(ref s_descriptionOid, () => InitializeOid(Description));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="BusinessCategory"/>.</summary>
    public static Oid BusinessCategoryOid => LazyInitializer.EnsureInitialized(ref s_businessCategoryOid, () => InitializeOid(BusinessCategory));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PostOfficeBox"/>.</summary>
    public static Oid PostOfficeBoxOid => LazyInitializer.EnsureInitialized(ref s_postOfficeBoxOid, () => InitializeOid(PostOfficeBox));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PhysicalDeliveryOfficeName"/>.</summary>
    public static Oid PhysicalDeliveryOfficeNameOid => LazyInitializer.EnsureInitialized(ref s_physicalDeliveryOfficeNameOid, () => InitializeOid(PhysicalDeliveryOfficeName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="X121Address"/>.</summary>
    public static Oid X121AddressOid => LazyInitializer.EnsureInitialized(ref s_x121AddressOid, () => InitializeOid(X121Address));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="InternationalISDNNumber"/>.</summary>
    public static Oid InternationalISDNNumberOid => LazyInitializer.EnsureInitialized(ref s_internationalISDNNumberOid, () => InitializeOid(InternationalISDNNumber));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DestinationIndicator"/>.</summary>
    public static Oid DestinationIndicatorOid => LazyInitializer.EnsureInitialized(ref s_destinationIndicatorOid, () => InitializeOid(DestinationIndicator));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Name"/>.</summary>
    public static Oid NameOid => LazyInitializer.EnsureInitialized(ref s_nameOid, () => InitializeOid(Name));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Initials"/>.</summary>
    public static Oid InitialsOid => LazyInitializer.EnsureInitialized(ref s_initialsOid, () => InitializeOid(Initials));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="GenerationQualifier"/>.</summary>
    public static Oid GenerationQualifierOid => LazyInitializer.EnsureInitialized(ref s_generationQualifierOid, () => InitializeOid(GenerationQualifier));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="HouseIdentifier"/>.</summary>
    public static Oid HouseIdentifierOid => LazyInitializer.EnsureInitialized(ref s_houseIdentifierOid, () => InitializeOid(HouseIdentifier));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DmdName"/>.</summary>
    public static Oid DmdNameOid => LazyInitializer.EnsureInitialized(ref s_dmdNameOid, () => InitializeOid(DmdName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pseudonym"/>.</summary>
    public static Oid PseudonymOid => LazyInitializer.EnsureInitialized(ref s_pseudonymOid, () => InitializeOid(Pseudonym));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="UiiInUrn"/>.</summary>
    public static Oid UiiInUrnOid => LazyInitializer.EnsureInitialized(ref s_uiiInUrnOid, () => InitializeOid(UiiInUrn));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ContentUrl"/>.</summary>
    public static Oid ContentUrlOid => LazyInitializer.EnsureInitialized(ref s_contentUrlOid, () => InitializeOid(ContentUrl));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Uri"/>.</summary>
    public static Oid UriOid => LazyInitializer.EnsureInitialized(ref s_uriOid, () => InitializeOid(Uri));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Urn"/>.</summary>
    public static Oid UrnOid => LazyInitializer.EnsureInitialized(ref s_urnOid, () => InitializeOid(Urn));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Url"/>.</summary>
    public static Oid UrlOid => LazyInitializer.EnsureInitialized(ref s_urlOid, () => InitializeOid(Url));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="UrnC"/>.</summary>
    public static Oid UrnCOid => LazyInitializer.EnsureInitialized(ref s_urnCOid, () => InitializeOid(UrnC));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EpcInUrn"/>.</summary>
    public static Oid EpcInUrnOid => LazyInitializer.EnsureInitialized(ref s_epcInUrnOid, () => InitializeOid(EpcInUrn));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="LdapUrl"/>.</summary>
    public static Oid LdapUrlOid => LazyInitializer.EnsureInitialized(ref s_ldapUrlOid, () => InitializeOid(LdapUrl));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="OrganizationIdentifier"/>.</summary>
    public static Oid OrganizationIdentifierOid => LazyInitializer.EnsureInitialized(ref s_organizationIdentifierOid, () => InitializeOid(OrganizationIdentifier));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CountryOrRegionName3C"/>.</summary>
    public static Oid CountryOrRegionName3COid => LazyInitializer.EnsureInitialized(ref s_countryOrRegionName3COid, () => InitializeOid(CountryOrRegionName3C));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CountryOrRegionName3N"/>.</summary>
    public static Oid CountryOrRegionName3NOid => LazyInitializer.EnsureInitialized(ref s_countryOrRegionName3NOid, () => InitializeOid(CountryOrRegionName3N));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DnsName"/>.</summary>
    public static Oid DnsNameOid => LazyInitializer.EnsureInitialized(ref s_dnsNameOid, () => InitializeOid(DnsName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="IntEmail"/>.</summary>
    public static Oid IntEmailOid => LazyInitializer.EnsureInitialized(ref s_intEmailOid, () => InitializeOid(IntEmail));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="JabberId"/>.</summary>
    public static Oid JabberIdOid => LazyInitializer.EnsureInitialized(ref s_jabberIdOid, () => InitializeOid(JabberId));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="BasicConstraints"/>.</summary>
    public static Oid BasicConstraintsOid => LazyInitializer.EnsureInitialized(ref s_basicConstraintsOid, () => InitializeOid(BasicConstraints));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SubjectKeyIdentifier"/>.</summary>
    public static Oid SubjectKeyIdentifierOid => LazyInitializer.EnsureInitialized(ref s_subjectKeyIdentifierOid, () => InitializeOid(SubjectKeyIdentifier));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="KeyUsage"/>.</summary>
    public static Oid KeyUsageOid => LazyInitializer.EnsureInitialized(ref s_keyUsageOid, () => InitializeOid(KeyUsage));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SubjectAltName"/>.</summary>
    public static Oid SubjectAltNameOid => LazyInitializer.EnsureInitialized(ref s_subjectAltNameOid, () => InitializeOid(SubjectAltName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="IssuerAltName"/>.</summary>
    public static Oid IssuerAltNameOid => LazyInitializer.EnsureInitialized(ref s_issuerAltNameOid, () => InitializeOid(IssuerAltName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="BasicConstraints2"/>.</summary>
    public static Oid BasicConstraints2Oid => LazyInitializer.EnsureInitialized(ref s_basicConstraints2Oid, () => InitializeOid(BasicConstraints2));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CrlNumber"/>.</summary>
    public static Oid CrlNumberOid => LazyInitializer.EnsureInitialized(ref s_crlNumberOid, () => InitializeOid(CrlNumber));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CrlReasons"/>.</summary>
    public static Oid CrlReasonsOid => LazyInitializer.EnsureInitialized(ref s_crlReasonsOid, () => InitializeOid(CrlReasons));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="NameConstraints"/>.</summary>
    public static Oid NameConstraintsOid => LazyInitializer.EnsureInitialized(ref s_nameConstraintsOid, () => InitializeOid(NameConstraints));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CrlDistributionPoints"/>.</summary>
    public static Oid CrlDistributionPointsOid => LazyInitializer.EnsureInitialized(ref s_crlDistributionPointsOid, () => InitializeOid(CrlDistributionPoints));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CertPolicies"/>.</summary>
    public static Oid CertPoliciesOid => LazyInitializer.EnsureInitialized(ref s_certPoliciesOid, () => InitializeOid(CertPolicies));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="AnyCertPolicy"/>.</summary>
    public static Oid AnyCertPolicyOid => LazyInitializer.EnsureInitialized(ref s_anyCertPolicyOid, () => InitializeOid(AnyCertPolicy));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CertPolicyMappings"/>.</summary>
    public static Oid CertPolicyMappingsOid => LazyInitializer.EnsureInitialized(ref s_certPolicyMappingsOid, () => InitializeOid(CertPolicyMappings));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="AuthorityKeyIdentifier"/>.</summary>
    public static Oid AuthorityKeyIdentifierOid => LazyInitializer.EnsureInitialized(ref s_authorityKeyIdentifierOid, () => InitializeOid(AuthorityKeyIdentifier));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CertPolicyConstraints"/>.</summary>
    public static Oid CertPolicyConstraintsOid => LazyInitializer.EnsureInitialized(ref s_certPolicyConstraintsOid, () => InitializeOid(CertPolicyConstraints));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EnhancedKeyUsage"/>.</summary>
    public static Oid EnhancedKeyUsageOid => LazyInitializer.EnsureInitialized(ref s_enhancedKeyUsageOid, () => InitializeOid(EnhancedKeyUsage));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="InhibitAnyPolicyExtension"/>.</summary>
    public static Oid InhibitAnyPolicyExtensionOid => LazyInitializer.EnsureInitialized(ref s_inhibitAnyPolicyExtensionOid, () => InitializeOid(InhibitAnyPolicyExtension));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="TstInfo"/>.</summary>
    public static Oid TstInfoOid => LazyInitializer.EnsureInitialized(ref s_tstInfoOid, () => InitializeOid(TstInfo));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ExtendedValidationCertPolicy"/>.</summary>
    public static Oid ExtendedValidationCertPolicyOid => LazyInitializer.EnsureInitialized(ref s_extendedValidationCertPolicyOid, () => InitializeOid(ExtendedValidationCertPolicy));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DomainValidatedCertPolicy"/>.</summary>
    public static Oid DomainValidatedCertPolicyOid => LazyInitializer.EnsureInitialized(ref s_domainValidatedCertPolicyOid, () => InitializeOid(DomainValidatedCertPolicy));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="OrganizationValidatedCertPolicy"/>.</summary>
    public static Oid OrganizationValidatedCertPolicyOid => LazyInitializer.EnsureInitialized(ref s_organizationValidatedCertPolicyOid, () => InitializeOid(OrganizationValidatedCertPolicy));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="IndividualValidatedCertPolicy"/>.</summary>
    public static Oid IndividualValidatedCertPolicyOid => LazyInitializer.EnsureInitialized(ref s_individualValidatedCertPolicyOid, () => InitializeOid(IndividualValidatedCertPolicy));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ExtendedValidationCodeSigningCertPolicy"/>.</summary>
    public static Oid ExtendedValidationCodeSigningCertPolicyOid => LazyInitializer.EnsureInitialized(ref s_extendedValidationCodeSigningCertPolicyOid, () => InitializeOid(ExtendedValidationCodeSigningCertPolicy));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CodeSigningRequirementsCertPolicy"/>.</summary>
    public static Oid CodeSigningRequirementsCertPolicyOid => LazyInitializer.EnsureInitialized(ref s_codeSigningRequirementsCertPolicyOid, () => InitializeOid(CodeSigningRequirementsCertPolicy));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="AnyExtendedKeyUsage"/>.</summary>
    public static Oid AnyExtendedKeyUsageOid => LazyInitializer.EnsureInitialized(ref s_anyExtendedKeyUsageOid, () => InitializeOid(AnyExtendedKeyUsage));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ServerAuthPurpose"/>.</summary>
    public static Oid ServerAuthPurposeOid => LazyInitializer.EnsureInitialized(ref s_serverAuthPurposeOid, () => InitializeOid(ServerAuthPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ClientAuthPurpose"/>.</summary>
    public static Oid ClientAuthPurposeOid => LazyInitializer.EnsureInitialized(ref s_clientAuthPurposeOid, () => InitializeOid(ClientAuthPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CodeSigningPurpose"/>.</summary>
    public static Oid CodeSigningPurposeOid => LazyInitializer.EnsureInitialized(ref s_codeSigningPurposeOid, () => InitializeOid(CodeSigningPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EmailProtectionPurpose"/>.</summary>
    public static Oid EmailProtectionPurposeOid => LazyInitializer.EnsureInitialized(ref s_emailProtectionPurposeOid, () => InitializeOid(EmailProtectionPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="IpsecEndSystemPurpose"/>.</summary>
    public static Oid IpsecEndSystemPurposeOid => LazyInitializer.EnsureInitialized(ref s_ipsecEndSystemPurposeOid, () => InitializeOid(IpsecEndSystemPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="IpsecTunnelPurpose"/>.</summary>
    public static Oid IpsecTunnelPurposeOid => LazyInitializer.EnsureInitialized(ref s_ipsecTunnelPurposeOid, () => InitializeOid(IpsecTunnelPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="IpsecUserPurpose"/>.</summary>
    public static Oid IpsecUserPurposeOid => LazyInitializer.EnsureInitialized(ref s_ipsecUserPurposeOid, () => InitializeOid(IpsecUserPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="TimeStampingPurpose"/>.</summary>
    public static Oid TimeStampingPurposeOid => LazyInitializer.EnsureInitialized(ref s_timeStampingPurposeOid, () => InitializeOid(TimeStampingPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="OcspSigningPurpose"/>.</summary>
    public static Oid OcspSigningPurposeOid => LazyInitializer.EnsureInitialized(ref s_ocspSigningPurposeOid, () => InitializeOid(OcspSigningPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DvcsPurpose"/>.</summary>
    public static Oid DvcsPurposeOid => LazyInitializer.EnsureInitialized(ref s_dvcsPurposeOid, () => InitializeOid(DvcsPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SbgpCertAaServerAuthPurpose"/>.</summary>
    public static Oid SbgpCertAaServerAuthPurposeOid => LazyInitializer.EnsureInitialized(ref s_sbgpCertAaServerAuthPurposeOid, () => InitializeOid(SbgpCertAaServerAuthPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ScvpResponderPurpose"/>.</summary>
    public static Oid ScvpResponderPurposeOid => LazyInitializer.EnsureInitialized(ref s_scvpResponderPurposeOid, () => InitializeOid(ScvpResponderPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EapOverPppPurpose"/>.</summary>
    public static Oid EapOverPppPurposeOid => LazyInitializer.EnsureInitialized(ref s_eapOverPppPurposeOid, () => InitializeOid(EapOverPppPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EapOverLanPurpose"/>.</summary>
    public static Oid EapOverLanPurposeOid => LazyInitializer.EnsureInitialized(ref s_eapOverLanPurposeOid, () => InitializeOid(EapOverLanPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ScvpServerPurpose"/>.</summary>
    public static Oid ScvpServerPurposeOid => LazyInitializer.EnsureInitialized(ref s_scvpServerPurposeOid, () => InitializeOid(ScvpServerPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ScvpClientPurpose"/>.</summary>
    public static Oid ScvpClientPurposeOid => LazyInitializer.EnsureInitialized(ref s_scvpClientPurposeOid, () => InitializeOid(ScvpClientPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="IpsecIkePurpose"/>.</summary>
    public static Oid IpsecIkePurposeOid => LazyInitializer.EnsureInitialized(ref s_ipsecIkePurposeOid, () => InitializeOid(IpsecIkePurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CapwapAcPurpose"/>.</summary>
    public static Oid CapwapAcPurposeOid => LazyInitializer.EnsureInitialized(ref s_capwapAcPurposeOid, () => InitializeOid(CapwapAcPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CapwapWtpPurpose"/>.</summary>
    public static Oid CapwapWtpPurposeOid => LazyInitializer.EnsureInitialized(ref s_capwapWtpPurposeOid, () => InitializeOid(CapwapWtpPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SipDomainPurpose"/>.</summary>
    public static Oid SipDomainPurposeOid => LazyInitializer.EnsureInitialized(ref s_sipDomainPurposeOid, () => InitializeOid(SipDomainPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SecureShellClientPurpose"/>.</summary>
    public static Oid SecureShellClientPurposeOid => LazyInitializer.EnsureInitialized(ref s_secureShellClientPurposeOid, () => InitializeOid(SecureShellClientPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SecureShellServerPurpose"/>.</summary>
    public static Oid SecureShellServerPurposeOid => LazyInitializer.EnsureInitialized(ref s_secureShellServerPurposeOid, () => InitializeOid(SecureShellServerPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SendRouterPurpose"/>.</summary>
    public static Oid SendRouterPurposeOid => LazyInitializer.EnsureInitialized(ref s_sendRouterPurposeOid, () => InitializeOid(SendRouterPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SendProxiedRouterPurpose"/>.</summary>
    public static Oid SendProxiedRouterPurposeOid => LazyInitializer.EnsureInitialized(ref s_sendProxiedRouterPurposeOid, () => InitializeOid(SendProxiedRouterPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SendOwnerPurpose"/>.</summary>
    public static Oid SendOwnerPurposeOid => LazyInitializer.EnsureInitialized(ref s_sendOwnerPurposeOid, () => InitializeOid(SendOwnerPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SendProxiedOwnerPurpose"/>.</summary>
    public static Oid SendProxiedOwnerPurposeOid => LazyInitializer.EnsureInitialized(ref s_sendProxiedOwnerPurposeOid, () => InitializeOid(SendProxiedOwnerPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CmcCaPurpose"/>.</summary>
    public static Oid CmcCaPurposeOid => LazyInitializer.EnsureInitialized(ref s_cmcCaPurposeOid, () => InitializeOid(CmcCaPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CmcRaPurpose"/>.</summary>
    public static Oid CmcRaPurposeOid => LazyInitializer.EnsureInitialized(ref s_cmcRaPurposeOid, () => InitializeOid(CmcRaPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CmcArchivePurpose"/>.</summary>
    public static Oid CmcArchivePurposeOid => LazyInitializer.EnsureInitialized(ref s_cmcArchivePurposeOid, () => InitializeOid(CmcArchivePurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="BgpSecRouterPurpose"/>.</summary>
    public static Oid BgpSecRouterPurposeOid => LazyInitializer.EnsureInitialized(ref s_bgpSecRouterPurposeOid, () => InitializeOid(BgpSecRouterPurpose));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SmartCardLogonPurpose"/>.</summary>
    public static Oid SmartCardLogonPurposeOid => LazyInitializer.EnsureInitialized(ref s_smartCardLogonPurposeOid, () => InitializeOid(SmartCardLogonPurpose));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="LifetimeSigningPurpose"/>.</summary>
    public static Oid LifetimeSigningPurposeOid => LazyInitializer.EnsureInitialized(ref s_lifetimeSigningPurposeOid, () => InitializeOid(LifetimeSigningPurpose));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12PbeWithShaAnd3Key3Des"/>.</summary>
    public static Oid Pkcs12PbeWithShaAnd3Key3DesOid => LazyInitializer.EnsureInitialized(ref s_pkcs12PbeWithShaAnd3Key3DesOid, () => InitializeOid(Pkcs12PbeWithShaAnd3Key3Des));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12PbeWithShaAnd2Key3Des"/>.</summary>
    public static Oid Pkcs12PbeWithShaAnd2Key3DesOid => LazyInitializer.EnsureInitialized(ref s_pkcs12PbeWithShaAnd2Key3DesOid, () => InitializeOid(Pkcs12PbeWithShaAnd2Key3Des));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12PbeWithShaAnd128BitRC2"/>.</summary>
    public static Oid Pkcs12PbeWithShaAnd128BitRC2Oid => LazyInitializer.EnsureInitialized(ref s_pkcs12PbeWithShaAnd128BitRC2Oid, () => InitializeOid(Pkcs12PbeWithShaAnd128BitRC2));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12PbeWithShaAnd40BitRC2"/>.</summary>
    public static Oid Pkcs12PbeWithShaAnd40BitRC2Oid => LazyInitializer.EnsureInitialized(ref s_pkcs12PbeWithShaAnd40BitRC2Oid, () => InitializeOid(Pkcs12PbeWithShaAnd40BitRC2));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12KeyBag"/>.</summary>
    public static Oid Pkcs12KeyBagOid => LazyInitializer.EnsureInitialized(ref s_pkcs12KeyBagOid, () => InitializeOid(Pkcs12KeyBag));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12ShroudedKeyBag"/>.</summary>
    public static Oid Pkcs12ShroudedKeyBagOid => LazyInitializer.EnsureInitialized(ref s_pkcs12ShroudedKeyBagOid, () => InitializeOid(Pkcs12ShroudedKeyBag));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12CertBag"/>.</summary>
    public static Oid Pkcs12CertBagOid => LazyInitializer.EnsureInitialized(ref s_pkcs12CertBagOid, () => InitializeOid(Pkcs12CertBag));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12CrlBag"/>.</summary>
    public static Oid Pkcs12CrlBagOid => LazyInitializer.EnsureInitialized(ref s_pkcs12CrlBagOid, () => InitializeOid(Pkcs12CrlBag));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12SecretBag"/>.</summary>
    public static Oid Pkcs12SecretBagOid => LazyInitializer.EnsureInitialized(ref s_pkcs12SecretBagOid, () => InitializeOid(Pkcs12SecretBag));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12SafeContentsBag"/>.</summary>
    public static Oid Pkcs12SafeContentsBagOid => LazyInitializer.EnsureInitialized(ref s_pkcs12SafeContentsBagOid, () => InitializeOid(Pkcs12SafeContentsBag));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12X509CertBagType"/>.</summary>
    public static Oid Pkcs12X509CertBagTypeOid => LazyInitializer.EnsureInitialized(ref s_pkcs12X509CertBagTypeOid, () => InitializeOid(Pkcs12X509CertBagType));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MsPkcs12KeyProviderName"/>.</summary>
    public static Oid MsPkcs12KeyProviderNameOid => LazyInitializer.EnsureInitialized(ref s_msPkcs12KeyProviderNameOid, () => InitializeOid(MsPkcs12KeyProviderName));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MsPkcs12MachineKeySet"/>.</summary>
    public static Oid MsPkcs12MachineKeySetOid => LazyInitializer.EnsureInitialized(ref s_msPkcs12MachineKeySetOid, () => InitializeOid(MsPkcs12MachineKeySet));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs12SdsiCertBagType"/>.</summary>
    public static Oid Pkcs12SdsiCertBagTypeOid => LazyInitializer.EnsureInitialized(ref s_pkcs12SdsiCertBagTypeOid, () => InitializeOid(Pkcs12SdsiCertBagType));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PbeWithMD5AndDESCBC"/>.</summary>
    public static Oid PbeWithMD5AndDESCBCOid => LazyInitializer.EnsureInitialized(ref s_pbeWithMD5AndDESCBCOid, () => InitializeOid(PbeWithMD5AndDESCBC));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PbeWithMD5AndRC2CBC"/>.</summary>
    public static Oid PbeWithMD5AndRC2CBCOid => LazyInitializer.EnsureInitialized(ref s_pbeWithMD5AndRC2CBCOid, () => InitializeOid(PbeWithMD5AndRC2CBC));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PbeWithSha1AndDESCBC"/>.</summary>
    public static Oid PbeWithSha1AndDESCBCOid => LazyInitializer.EnsureInitialized(ref s_pbeWithSha1AndDESCBCOid, () => InitializeOid(PbeWithSha1AndDESCBC));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PbeWithSha1AndRC2CBC"/>.</summary>
    public static Oid PbeWithSha1AndRC2CBCOid => LazyInitializer.EnsureInitialized(ref s_pbeWithSha1AndRC2CBCOid, () => InitializeOid(PbeWithSha1AndRC2CBC));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pbkdf2"/>.</summary>
    public static Oid Pbkdf2Oid => LazyInitializer.EnsureInitialized(ref s_pbkdf2Oid, () => InitializeOid(Pbkdf2));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PasswordBasedEncryptionScheme2"/>.</summary>
    public static Oid PasswordBasedEncryptionScheme2Oid => LazyInitializer.EnsureInitialized(ref s_passwordBasedEncryptionScheme2Oid, () => InitializeOid(PasswordBasedEncryptionScheme2));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="HmacWithSha1"/>.</summary>
    public static Oid HmacWithSha1Oid => LazyInitializer.EnsureInitialized(ref s_hmacWithSha1Oid, () => InitializeOid(HmacWithSha1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="HmacWithSha256"/>.</summary>
    public static Oid HmacWithSha256Oid => LazyInitializer.EnsureInitialized(ref s_hmacWithSha256Oid, () => InitializeOid(HmacWithSha256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="HmacWithSha384"/>.</summary>
    public static Oid HmacWithSha384Oid => LazyInitializer.EnsureInitialized(ref s_hmacWithSha384Oid, () => InitializeOid(HmacWithSha384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="HmacWithSha512"/>.</summary>
    public static Oid HmacWithSha512Oid => LazyInitializer.EnsureInitialized(ref s_hmacWithSha512Oid, () => InitializeOid(HmacWithSha512));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="secp256r1"/>.</summary>
    public static Oid secp256r1Oid => LazyInitializer.EnsureInitialized(ref s_secp256r1Oid, () => new Oid(secp256r1, nameof(ECCurve.NamedCurves.nistP256)));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="secp384r1"/>.</summary>
    public static Oid secp384r1Oid => LazyInitializer.EnsureInitialized(ref s_secp384r1Oid, () => new Oid(secp384r1, nameof(ECCurve.NamedCurves.nistP384)));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="secp521r1"/>.</summary>
    public static Oid secp521r1Oid => LazyInitializer.EnsureInitialized(ref s_secp521r1Oid, () => new Oid(secp521r1, nameof(ECCurve.NamedCurves.nistP521)));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="brainpoolP256r1"/>.</summary>
    public static Oid brainpoolP256r1Oid => LazyInitializer.EnsureInitialized(ref s_brainpoolP256r1Oid, () => InitializeOid(brainpoolP256r1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="brainpoolP384r1"/>.</summary>
    public static Oid brainpoolP384r1Oid => LazyInitializer.EnsureInitialized(ref s_brainpoolP384r1Oid, () => InitializeOid(brainpoolP384r1));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="X25519"/>.</summary>
    public static Oid X25519Oid => LazyInitializer.EnsureInitialized(ref s_x25519Oid, () => InitializeOid(X25519));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="X448"/>.</summary>
    public static Oid X448Oid => LazyInitializer.EnsureInitialized(ref s_x448Oid, () => InitializeOid(X448));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Ed25519"/>.</summary>
    public static Oid Ed25519Oid => LazyInitializer.EnsureInitialized(ref s_ed25519Oid, () => InitializeOid(Ed25519));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Ed448"/>.</summary>
    public static Oid Ed448Oid => LazyInitializer.EnsureInitialized(ref s_ed448Oid, () => InitializeOid(Ed448));

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DomainComponent"/>.</summary>
    public static Oid DomainComponentOid => LazyInitializer.EnsureInitialized(ref s_domainComponentOid, () => InitializeOid(DomainComponent));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="UserId"/>.</summary>
    public static Oid UserIdOid => LazyInitializer.EnsureInitialized(ref s_userIdOid, () => InitializeOid(UserId));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MacAddress"/>.</summary>
    public static Oid MacAddressOid => LazyInitializer.EnsureInitialized(ref s_macAddressOid, () => InitializeOid(MacAddress));

    
    private static Oid InitializeOid(string oidValue)
    {
        Debug.Assert(oidValue != null);
        Oid oid = new Oid(oidValue, null);

        // Do not remove - the FriendlyName property get has side effects.
        // On read, it initializes the friendly name based on the value and
        // locks it to prevent any further changes.
        _ = oid.FriendlyName;

        return oid;
    }

    
    /// <summary>
    /// Compares two <see cref="Oid"/> instances by their <see cref="Oid.Value"/>, ignoring the
    /// friendly name. <see cref="Oid"/> does not override equality, so reference comparison would
    /// otherwise be used.
    /// </summary>
    /// <param name="oid">The OID to compare.</param>
    /// <param name="other">The OID to compare against. May be null.</param>
    /// <returns><see langword="true"/> if both have the same non-null value, or are the same instance.</returns>
    public static bool ValueEquals(this Oid oid, Oid? other)
    {
        Debug.Assert(oid is not null);

        if (ReferenceEquals(oid, other)) {
            return true;
        }

        if (other is null) {
            return false;
        }

        return oid.Value is not null && oid.Value.Equals(other.Value);
    }
}
