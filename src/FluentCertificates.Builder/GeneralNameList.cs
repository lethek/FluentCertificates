using System.Formats.Asn1;

namespace FluentCertificates;

public class GeneralNameList(IEnumerable<GeneralName> constraints) : List<GeneralName>(constraints)
{
    /// <summary>
    /// Return a byte array containing the encoded representation of the data.
    /// </summary>
    /// <returns>A precisely-sized array containing the encoded values.</returns>
    public byte[] Encode()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            foreach (var gn in this) {
                gn.WriteTo(writer);
            }
        }
        return writer.Encode();
    }
    

    /// <summary>
    /// Writes the encoded representation of the data to destination.
    /// </summary>
    /// <param name="destination">The buffer in which to write.</param>
    /// <returns>The number of bytes written to destination.</returns>
    public int Encode(Span<byte> destination)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            foreach (var gn in this) {
                gn.WriteTo(writer);
            }
        }
        return writer.Encode(destination);
    }
}
