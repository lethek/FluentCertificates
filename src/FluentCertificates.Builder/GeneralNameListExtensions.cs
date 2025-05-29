using System.Formats.Asn1;

namespace FluentCertificates;

public static class GeneralNameListExtensions
{
    /// <summary>
    /// Return a byte array containing the encoded representation of the data.
    /// </summary>
    /// <param name="generalNames">The collection of <see cref="GeneralName"/> objects to encode.</param>
    /// <returns>A precisely-sized array containing the encoded values.</returns>
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
    /// Writes the encoded representation of the data to destination.
    /// </summary>
    /// <param name="generalNames">The collection of <see cref="GeneralName"/> objects to encode.</param>
    /// <param name="destination">The buffer in which to write.</param>
    /// <returns>The number of bytes written to destination.</returns>
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