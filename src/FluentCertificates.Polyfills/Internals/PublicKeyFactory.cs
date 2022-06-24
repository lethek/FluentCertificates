using System.Buffers;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals
{
    internal static class PublicKeyFactory
    {
#if NET6_0_OR_GREATER

        public static PublicKey? Create(AsymmetricAlgorithm? keys)
            => keys != null ? new PublicKey(keys) : null;

#else

        public static PublicKey? Create(AsymmetricAlgorithm? keys)
        {
            if (keys == null) {
                return null;
            }
            DecodeSubjectPublicKeyInfo((ReadOnlySpan<byte>)keys.ExportSubjectPublicKeyInfo(), out var oid, out var parameters, out var keyValue);
            return new PublicKey(oid, parameters, keyValue);
        }


        // ReSharper disable once ArrangeModifiersOrder
        private static unsafe int DecodeSubjectPublicKeyInfo(ReadOnlySpan<byte> source, out Oid oid, out AsnEncodedData parameters, out AsnEncodedData keyValue)
        {
            fixed (byte* ptr = &MemoryMarshal.GetReference(source)) {
                using MemoryManager<byte> manager = new PointerMemoryManager<byte>(ptr, source.Length);
                var reader = new AsnValueReader(source, AsnEncodingRules.DER);

                int read;
                SubjectPublicKeyInfoAsn spki;

                try {
                    read = reader.PeekEncodedValue().Length;
                    SubjectPublicKeyInfoAsn.Decode(ref reader, manager.Memory, out spki);
                } catch (AsnContentException e) {
                    throw new CryptographicException("ASN1 corrupted data.", e);
                }

                oid = new Oid(spki.Algorithm.Algorithm, null);
                parameters = new AsnEncodedData(spki.Algorithm.Parameters?.ToArray() ?? Array.Empty<byte>());
                keyValue = new AsnEncodedData(spki.SubjectPublicKey.ToArray());
                return read;
            }
        }

#endif
    }
}
