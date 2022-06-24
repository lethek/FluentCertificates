// ReSharper disable All

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography.Asn1
{
    /// <remarks>Original copy sourced under the MIT license from: https://github.com/dotnet/runtime/blob/425fedc0fb005af24765faa3ed423222a7dbd963/src/libraries/Common/src/System/Security/Cryptography/Asn1/AlgorithmIdentifierAsn.xml.cs</remarks>
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct AlgorithmIdentifierAsn
    {
        internal string Algorithm;
        internal ReadOnlyMemory<byte>? Parameters;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            try {
                writer.WriteObjectIdentifier(Algorithm);
            } catch (ArgumentException e) {
                throw new CryptographicException("ASN1 corrupted data.", e);
            }

            if (Parameters.HasValue) {
                try {
                    writer.WriteEncodedValue(Parameters.Value.Span);
                } catch (ArgumentException e) {
                    throw new CryptographicException("ASN1 corrupted data.", e);
                }
            }

            writer.PopSequence(tag);
        }

        internal static AlgorithmIdentifierAsn Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static AlgorithmIdentifierAsn Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            try {
                AsnValueReader reader = new AsnValueReader(encoded.Span, ruleSet);

                DecodeCore(ref reader, expectedTag, encoded, out AlgorithmIdentifierAsn decoded);
                reader.ThrowIfNotEmpty();
                return decoded;
            } catch (AsnContentException e) {
                throw new CryptographicException("ASN1 corrupted data.", e);
            }
        }

        internal static void Decode(ref AsnValueReader reader, ReadOnlyMemory<byte> rebind, out AlgorithmIdentifierAsn decoded)
        {
            Decode(ref reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(ref AsnValueReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out AlgorithmIdentifierAsn decoded)
        {
            try {
                DecodeCore(ref reader, expectedTag, rebind, out decoded);
            } catch (AsnContentException e) {
                throw new CryptographicException("ASN1 corrupted data.", e);
            }
        }

        private static void DecodeCore(ref AsnValueReader reader, Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind, out AlgorithmIdentifierAsn decoded)
        {
            decoded = default;
            AsnValueReader sequenceReader = reader.ReadSequence(expectedTag);
            ReadOnlySpan<byte> rebindSpan = rebind.Span;
            int offset;
            ReadOnlySpan<byte> tmpSpan;

            decoded.Algorithm = sequenceReader.ReadObjectIdentifier();

            if (sequenceReader.HasData) {
                tmpSpan = sequenceReader.ReadEncodedValue();
                decoded.Parameters = rebindSpan.Overlaps(tmpSpan, out offset) ? rebind.Slice(offset, tmpSpan.Length) : tmpSpan.ToArray();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
