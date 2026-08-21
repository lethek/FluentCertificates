using System.Security.Cryptography;


namespace FluentCertificates;

/// <summary>
/// Runtime capability checks and BCL algorithm lookups for the post-quantum algorithms.
/// </summary>
/// <remarks>
/// Availability is a property of the runtime and its cryptographic provider, not of the operating system, so
/// none of this can be expressed with <c>[SupportedOSPlatform]</c>. On .NET 9 and earlier the types do not
/// exist at all; on .NET 10 they exist but the provider may still not implement them, which is why SLH-DSA is
/// unavailable on Windows while ML-DSA and ML-KEM are not, and why several Composite ML-DSA parameter sets
/// are unavailable everywhere tested.
/// </remarks>
internal static class PostQuantumSupport
{
    /// <summary>
    /// Reports whether the given algorithm can be used to build a certificate here.
    /// </summary>
    /// <remarks>
    /// Certificate use, not merely key generation. The two come apart for Composite ML-DSA: .NET 10 generates
    /// composite keys perfectly well, but <c>X509SignatureGenerator.CreateForCompositeMLDsa</c> throws
    /// <see cref="PlatformNotSupportedException"/> on every platform tested, Linux included. Reporting a
    /// composite algorithm as supported on the strength of its key generation would hand back a
    /// <see langword="true"/> that fails at <c>Create()</c>.
    /// </remarks>
    internal static bool IsSupported(KeyAlgorithm algorithm)
    {
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006 // The BCL's post-quantum types are themselves experimental
        return algorithm.Family switch {
            KeyAlgorithmFamily.MLDsa => MLDsa.IsSupported,
            KeyAlgorithmFamily.SlhDsa => SlhDsa.IsSupported,
            //Availability is per parameter set as well as per family: the family reports supported while
            //several individual sets are not implemented. Both must hold, plus certificate signing.
            KeyAlgorithmFamily.CompositeMLDsa =>
                CompositeMLDsa.IsSupported
                && CompositeMLDsa.IsAlgorithmSupported(CompositeAlgorithmFor(algorithm))
                && CompositeCertificateSigning.Value,
            KeyAlgorithmFamily.MLKem => MLKem.IsSupported,
            _ => true
        };
#pragma warning restore SYSLIB5006
#else
        return !algorithm.IsPostQuantum;
#endif
    }


#if NET10_0_OR_GREATER
    /// <summary>
    /// Whether this runtime can build an <c>X509SignatureGenerator</c> from a composite key.
    /// </summary>
    /// <remarks>
    /// Determined by trying it once rather than by naming the platforms that lack it, so that a runtime
    /// which gains support starts working without a change here. The probe uses the cheapest composite
    /// parameter set to generate, and never throws.
    /// </remarks>
    private static readonly Lazy<bool> CompositeCertificateSigning = new(() => {
#pragma warning disable SYSLIB5006
        try {
            if (!CompositeMLDsa.IsSupported || !CompositeMLDsa.IsAlgorithmSupported(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256)) {
                return false;
            }

            using var probe = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
            System.Security.Cryptography.X509Certificates.X509SignatureGenerator.CreateForCompositeMLDsa(probe);
            return true;

        } catch (PlatformNotSupportedException) {
            return false;

        } catch (CryptographicException) {
            return false;
        }
#pragma warning restore SYSLIB5006
    });
#endif


    /// <summary>
    /// Throws unless keys for the given algorithm can be generated here, naming why not.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">Thrown when the algorithm is unavailable.</exception>
    internal static void ThrowIfUnsupported(KeyAlgorithm algorithm)
    {
        if (IsSupported(algorithm)) {
            return;
        }

#if NET10_0_OR_GREATER
        throw new PlatformNotSupportedException(
            $"{algorithm.Name} is not available on this platform. Post-quantum support depends on the platform's cryptographic provider, and this one does not implement it."
        );
#else
        throw new PlatformNotSupportedException(
            $"{algorithm.Name} requires .NET 10 or later. This assembly is running on an earlier target framework, where the post-quantum algorithms do not exist."
        );
#endif
    }


#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
    /// <summary>
    /// Maps an ML-DSA algorithm onto its BCL counterpart.
    /// </summary>
    /// <remarks>
    /// Keyed on <see cref="KeyAlgorithm.Oid"/>, which identifies a post-quantum parameter set exactly.
    /// Written out rather than reflected over so the mapping survives trimming and AOT.
    /// </remarks>
    internal static MLDsaAlgorithm MLDsaAlgorithmFor(KeyAlgorithm algorithm)
        => algorithm.Oid switch {
            Oids.MLDsa44 => MLDsaAlgorithm.MLDsa44,
            Oids.MLDsa65 => MLDsaAlgorithm.MLDsa65,
            Oids.MLDsa87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Not an ML-DSA parameter set")
        };


    /// <summary>Maps an SLH-DSA algorithm onto its BCL counterpart.</summary>
    internal static SlhDsaAlgorithm SlhDsaAlgorithmFor(KeyAlgorithm algorithm)
        => algorithm.Oid switch {
            Oids.SlhDsaSha2_128s => SlhDsaAlgorithm.SlhDsaSha2_128s,
            Oids.SlhDsaSha2_128f => SlhDsaAlgorithm.SlhDsaSha2_128f,
            Oids.SlhDsaSha2_192s => SlhDsaAlgorithm.SlhDsaSha2_192s,
            Oids.SlhDsaSha2_192f => SlhDsaAlgorithm.SlhDsaSha2_192f,
            Oids.SlhDsaSha2_256s => SlhDsaAlgorithm.SlhDsaSha2_256s,
            Oids.SlhDsaSha2_256f => SlhDsaAlgorithm.SlhDsaSha2_256f,
            Oids.SlhDsaShake128s => SlhDsaAlgorithm.SlhDsaShake128s,
            Oids.SlhDsaShake128f => SlhDsaAlgorithm.SlhDsaShake128f,
            Oids.SlhDsaShake192s => SlhDsaAlgorithm.SlhDsaShake192s,
            Oids.SlhDsaShake192f => SlhDsaAlgorithm.SlhDsaShake192f,
            Oids.SlhDsaShake256s => SlhDsaAlgorithm.SlhDsaShake256s,
            Oids.SlhDsaShake256f => SlhDsaAlgorithm.SlhDsaShake256f,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Not an SLH-DSA parameter set")
        };


    /// <summary>Maps a Composite ML-DSA algorithm onto its BCL counterpart.</summary>
    internal static CompositeMLDsaAlgorithm CompositeAlgorithmFor(KeyAlgorithm algorithm)
        => algorithm.Oid switch {
            Oids.MLDsa44WithRSA2048Pss => CompositeMLDsaAlgorithm.MLDsa44WithRSA2048Pss,
            Oids.MLDsa44WithRSA2048Pkcs15 => CompositeMLDsaAlgorithm.MLDsa44WithRSA2048Pkcs15,
            Oids.MLDsa44WithEd25519 => CompositeMLDsaAlgorithm.MLDsa44WithEd25519,
            Oids.MLDsa44WithECDsaP256 => CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256,
            Oids.MLDsa65WithRSA3072Pss => CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pss,
            Oids.MLDsa65WithRSA3072Pkcs15 => CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pkcs15,
            Oids.MLDsa65WithRSA4096Pss => CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss,
            Oids.MLDsa65WithRSA4096Pkcs15 => CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pkcs15,
            Oids.MLDsa65WithECDsaP256 => CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256,
            Oids.MLDsa65WithECDsaP384 => CompositeMLDsaAlgorithm.MLDsa65WithECDsaP384,
            Oids.MLDsa65WithECDsaBrainpoolP256r1 => CompositeMLDsaAlgorithm.MLDsa65WithECDsaBrainpoolP256r1,
            Oids.MLDsa65WithEd25519 => CompositeMLDsaAlgorithm.MLDsa65WithEd25519,
            Oids.MLDsa87WithECDsaP384 => CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384,
            Oids.MLDsa87WithECDsaBrainpoolP384r1 => CompositeMLDsaAlgorithm.MLDsa87WithECDsaBrainpoolP384r1,
            Oids.MLDsa87WithEd448 => CompositeMLDsaAlgorithm.MLDsa87WithEd448,
            Oids.MLDsa87WithRSA3072Pss => CompositeMLDsaAlgorithm.MLDsa87WithRSA3072Pss,
            Oids.MLDsa87WithRSA4096Pss => CompositeMLDsaAlgorithm.MLDsa87WithRSA4096Pss,
            Oids.MLDsa87WithECDsaP521 => CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Not a Composite ML-DSA parameter set")
        };


    /// <summary>Maps an ML-KEM algorithm onto its BCL counterpart.</summary>
    internal static MLKemAlgorithm MLKemAlgorithmFor(KeyAlgorithm algorithm)
        => algorithm.Oid switch {
            Oids.MLKem512 => MLKemAlgorithm.MLKem512,
            Oids.MLKem768 => MLKemAlgorithm.MLKem768,
            Oids.MLKem1024 => MLKemAlgorithm.MLKem1024,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Not an ML-KEM parameter set")
        };
#pragma warning restore SYSLIB5006
#endif
}
