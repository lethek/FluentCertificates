using System.Security.Cryptography;


namespace FluentCertificates;

/// <summary>
/// Runtime capability checks for the post-quantum algorithms.
/// </summary>
/// <remarks>
/// Availability is a property of the runtime and its cryptographic provider, not of the operating system, so
/// none of this can be expressed with <c>[SupportedOSPlatform]</c>. On .NET 9 and earlier the types do not
/// exist at all; on .NET 10 they exist but the provider may still not implement them, which is why SLH-DSA is
/// unavailable on Windows while ML-DSA and ML-KEM are not.
/// </remarks>
internal static class PostQuantumSupport
{
    /// <summary>
    /// Reports whether keys for the given algorithm can be generated here.
    /// </summary>
    internal static bool IsSupported(KeyAlgorithm algorithm)
    {
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006 // The BCL's post-quantum types are themselves experimental
        return algorithm.Family switch {
            KeyAlgorithmFamily.MLDsa => MLDsa.IsSupported,
            KeyAlgorithmFamily.SlhDsa => SlhDsa.IsSupported,
            KeyAlgorithmFamily.CompositeMLDsa => CompositeMLDsa.IsSupported,
            KeyAlgorithmFamily.MLKem => MLKem.IsSupported,
            _ => true
        };
#pragma warning restore SYSLIB5006
#else
        return !algorithm.IsPostQuantum;
#endif
    }


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
            $"{algorithm.Name} is not available on this platform. Post-quantum support depends on the platform's cryptographic provider, and this one does not implement {algorithm.Family}."
        );
#else
        throw new PlatformNotSupportedException(
            $"{algorithm.Name} requires .NET 10 or later. This assembly is running on an earlier target framework, where the post-quantum algorithms do not exist."
        );
#endif
    }
}
