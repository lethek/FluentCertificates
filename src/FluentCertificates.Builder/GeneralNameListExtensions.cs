using System.Formats.Asn1;

namespace FluentCertificates;

/// <summary>
/// Provides extension methods for encoding sequences of <see cref="GeneralName"/> into their DER
/// representation, as used by the SubjectAlternativeName and NameConstraints extensions.
/// </summary>
public static class GeneralNameListExtensions
{
    /// <summary>
    /// Encodes the names as the DER encoding of a <c>GeneralNames</c> SEQUENCE.
    /// </summary>
    /// <typeparam name="T">The type of <see cref="GeneralName"/> in the collection.</typeparam>
    /// <param name="generalNames">The collection of <see cref="GeneralName"/> objects to encode.</param>
    /// <returns>A precisely-sized array containing the DER encoding.</returns>
    public static byte[] Encode<T>(this IEnumerable<T> generalNames)
        where T : GeneralName
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            foreach (var gn in generalNames) {
                gn.WriteTo(writer);
            }
        }
        return writer.Encode();
    }


    /// <summary>
    /// Writes the DER encoding of a <c>GeneralNames</c> SEQUENCE of the names to <paramref name="destination"/>.
    /// </summary>
    /// <typeparam name="T">The type of <see cref="GeneralName"/> in the collection.</typeparam>
    /// <param name="generalNames">The collection of <see cref="GeneralName"/> objects to encode.</param>
    /// <param name="destination">The buffer in which to write.</param>
    /// <returns>The number of bytes written to destination.</returns>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is too small to hold the encoding.</exception>
    public static int Encode<T>(this IEnumerable<T> generalNames, Span<byte> destination)
        where T : GeneralName
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            foreach (var gn in generalNames) {
                gn.WriteTo(writer);
            }
        }
        return writer.Encode(destination);
    }
}