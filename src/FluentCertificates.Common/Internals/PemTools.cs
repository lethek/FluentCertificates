using System.Security.Cryptography;


namespace FluentCertificates.Internals;

/// <summary>Shared helpers for reading PEM text.</summary>
internal static class PemTools
{
    /// <summary>
    /// Decodes the base64 body of a PEM block to the DER it holds.
    /// </summary>
    /// <param name="text">The text <paramref name="fields"/> was found in.</param>
    /// <param name="fields">The block to decode, as returned by <see cref="PemEncoding.TryFind"/>.</param>
    /// <remarks>
    /// <see cref="PemEncoding.TryFind"/> has already established that the body is base64 decoding to
    /// exactly <see cref="PemFields.DecodedDataLength"/> bytes, so into a buffer of that length this
    /// cannot fail.
    /// </remarks>
    internal static byte[] DecodeBlock(ReadOnlySpan<char> text, PemFields fields)
    {
        var der = new byte[fields.DecodedDataLength];
        Convert.TryFromBase64Chars(text[fields.Base64Data], der, out _);
        return der;
    }
}
