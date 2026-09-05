using System.Diagnostics;
using System.Security.Cryptography;

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



    private static volatile Oid? s_rsaOid;
    private static volatile Oid? s_ecPublicKeyOid;
    private static volatile Oid? s_tripleDesCbcOid;
    private static volatile Oid? s_aes256CbcOid;
    private static volatile Oid? s_secp256R1Oid;
    private static volatile Oid? s_secp384R1Oid;
    private static volatile Oid? s_secp521R1Oid;
    private static volatile Oid? s_sha256Oid;
    private static volatile Oid? s_pkcs7DataOid;
    private static volatile Oid? s_contentTypeOid;
    private static volatile Oid? s_documentDescriptionOid;
    private static volatile Oid? s_documentNameOid;
    private static volatile Oid? s_localKeyIdOid;
    private static volatile Oid? s_messageDigestOid;
    private static volatile Oid? s_signingTimeOid;
    private static volatile Oid? s_pkcs9ExtensionRequestOid;
    private static volatile Oid? s_basicConstraints2Oid;
    private static volatile Oid? s_enhancedKeyUsageOid;
    private static volatile Oid? s_keyUsageOid;
    private static volatile Oid? s_subjectAltNameOid;
    private static volatile Oid? s_subjectKeyIdentifierOid;
    private static volatile Oid? s_authorityKeyIdentifierOid;
    private static volatile Oid? s_authorityInformationAccessOid;
    private static volatile Oid? s_crlNumberOid;
    private static volatile Oid? s_crlDistributionPointOid;
    private static volatile Oid? s_commonNameOid;
    private static volatile Oid? s_countryOrRegionOid;
    private static volatile Oid? s_localityNameOid;
    private static volatile Oid? s_stateOrProvinceNameOid;
    private static volatile Oid? s_organizationOid;
    private static volatile Oid? s_organizationalUnitOid;
    private static volatile Oid? s_emailAddressOid;
    private static volatile Oid? s_telephoneNumberOid;
    private static volatile Oid? s_streetAddressOid;
    private static volatile Oid? s_postalCodeOid;
    private static volatile Oid? s_userIdOid;
    private static volatile Oid? s_serialNumberOid;
    private static volatile Oid? s_givenNameOid;
    private static volatile Oid? s_surnameOid;
    private static volatile Oid? s_titleOid;
    private static volatile Oid? s_dnQualifierOid;
    private static volatile Oid? s_domainComponentOid;



    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Rsa"/>.</summary>
    public static Oid RsaOid => s_rsaOid ??= InitializeOid(Rsa);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EcPublicKey"/>.</summary>
    public static Oid EcPublicKeyOid => s_ecPublicKeyOid ??= InitializeOid(EcPublicKey);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="TripleDesCbc"/>.</summary>
    public static Oid TripleDesCbcOid => s_tripleDesCbcOid ??= InitializeOid(TripleDesCbc);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Aes256Cbc"/>.</summary>
    public static Oid Aes256CbcOid => s_aes256CbcOid ??= InitializeOid(Aes256Cbc);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="secp256r1"/>.</summary>
    public static Oid secp256r1Oid => s_secp256R1Oid ??= new Oid(secp256r1, nameof(ECCurve.NamedCurves.nistP256));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="secp384r1"/>.</summary>
    public static Oid secp384r1Oid => s_secp384R1Oid ??= new Oid(secp384r1, nameof(ECCurve.NamedCurves.nistP384));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="secp521r1"/>.</summary>
    public static Oid secp521r1Oid => s_secp521R1Oid ??= new Oid(secp521r1, nameof(ECCurve.NamedCurves.nistP521));
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Sha256"/>.</summary>
    public static Oid Sha256Oid => s_sha256Oid ??= InitializeOid(Sha256);

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs7Data"/>.</summary>
    public static Oid Pkcs7DataOid => s_pkcs7DataOid ??= InitializeOid(Pkcs7Data);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="ContentType"/>.</summary>
    public static Oid ContentTypeOid => s_contentTypeOid ??= InitializeOid(ContentType);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DocumentDescription"/>.</summary>
    public static Oid DocumentDescriptionOid => s_documentDescriptionOid ??= InitializeOid(DocumentDescription);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DocumentName"/>.</summary>
    public static Oid DocumentNameOid => s_documentNameOid ??= InitializeOid(DocumentName);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="LocalKeyId"/>.</summary>
    public static Oid LocalKeyIdOid => s_localKeyIdOid ??= InitializeOid(LocalKeyId);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="MessageDigest"/>.</summary>
    public static Oid MessageDigestOid => s_messageDigestOid ??= InitializeOid(MessageDigest);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SigningTime"/>.</summary>
    public static Oid SigningTimeOid => s_signingTimeOid ??= InitializeOid(SigningTime);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Pkcs9ExtensionRequest"/>.</summary>
    public static Oid Pkcs9ExtensionRequestOid => s_pkcs9ExtensionRequestOid ??= InitializeOid(Pkcs9ExtensionRequest);

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="BasicConstraints2"/>.</summary>
    public static Oid BasicConstraints2Oid => s_basicConstraints2Oid ??= InitializeOid(BasicConstraints2);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EnhancedKeyUsage"/>.</summary>
    public static Oid EnhancedKeyUsageOid => s_enhancedKeyUsageOid ??= InitializeOid(EnhancedKeyUsage);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="KeyUsage"/>.</summary>
    public static Oid KeyUsageOid => s_keyUsageOid ??= InitializeOid(KeyUsage);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="AuthorityKeyIdentifier"/>.</summary>
    public static Oid AuthorityKeyIdentifierOid => s_authorityKeyIdentifierOid ??= InitializeOid(AuthorityKeyIdentifier);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SubjectKeyIdentifier"/>.</summary>
    public static Oid SubjectKeyIdentifierOid => s_subjectKeyIdentifierOid ??= InitializeOid(SubjectKeyIdentifier);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SubjectAltName"/>.</summary>
    public static Oid SubjectAltNameOid => s_subjectAltNameOid ??= InitializeOid(SubjectAltName);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="AuthorityInformationAccess"/>.</summary>
    public static Oid AuthorityInformationAccessOid => s_authorityInformationAccessOid ??= InitializeOid(AuthorityInformationAccess);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CrlNumber"/>.</summary>
    public static Oid CrlNumberOid => s_crlNumberOid ??= InitializeOid(CrlNumber);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CrlDistributionPoints"/>.</summary>
    public static Oid CrlDistributionPointsOid => s_crlDistributionPointOid ??= InitializeOid(CrlDistributionPoints);

    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CommonName"/>.</summary>
    public static Oid CommonNameOid => s_commonNameOid ??= InitializeOid(CommonName);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="CountryOrRegionName"/>.</summary>
    public static Oid CountryOrRegionNameOid => s_countryOrRegionOid ??= InitializeOid(CountryOrRegionName);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="LocalityName"/>.</summary>
    public static Oid LocalityNameOid => s_localityNameOid ??= InitializeOid(LocalityName);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="StateOrProvinceName"/>.</summary>
    public static Oid StateOrProvinceNameOid => s_stateOrProvinceNameOid ??= InitializeOid(StateOrProvinceName);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Organization"/>.</summary>
    public static Oid OrganizationOid => s_organizationOid ??= InitializeOid(Organization);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="OrganizationalUnit"/>.</summary>
    public static Oid OrganizationalUnitOid => s_organizationalUnitOid ??= InitializeOid(OrganizationalUnit);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="EmailAddress"/>.</summary>
    public static Oid EmailAddressOid => s_emailAddressOid ??= InitializeOid(EmailAddress);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="TelephoneNumber"/>.</summary>
    public static Oid TelephoneNumberOid => s_telephoneNumberOid ??= InitializeOid(TelephoneNumber);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="StreetAddress"/>.</summary>
    public static Oid StreetAddressOid => s_streetAddressOid ??= InitializeOid(StreetAddress);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="PostalCode"/>.</summary>
    public static Oid PostalCodeOid => s_postalCodeOid ??= InitializeOid(PostalCode);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="UserId"/>.</summary>
    public static Oid UserIdOid => s_userIdOid ??= InitializeOid(UserId);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="SerialNumber"/>.</summary>
    public static Oid SerialNumberOid => s_serialNumberOid ??= InitializeOid(SerialNumber);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="GivenName"/>.</summary>
    public static Oid GivenNameOid => s_givenNameOid ??= InitializeOid(GivenName);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Surname"/>.</summary>
    public static Oid SurnameOid => s_surnameOid ??= InitializeOid(Surname);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="Title"/>.</summary>
    public static Oid TitleOid => s_titleOid ??= InitializeOid(Title);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DnQualifier"/>.</summary>
    public static Oid DnQualifierOid => s_dnQualifierOid ??= InitializeOid(DnQualifier);
    /// <summary>A shared, cached <see cref="Oid"/> instance for <see cref="DomainComponent"/>.</summary>
    public static Oid DomainComponentOid => s_domainComponentOid ??= InitializeOid(DomainComponent);

    
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
