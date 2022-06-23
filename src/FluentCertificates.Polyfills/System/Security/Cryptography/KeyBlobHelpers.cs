#if NETSTANDARD
// ReSharper disable All

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;

namespace System.Security.Cryptography
{
    /// <remarks>Original copy sourced under the MIT license from: <see href="https://github.com/dotnet/runtime/blob/425fedc0fb005af24765faa3ed423222a7dbd963/src/libraries/Common/src/System/Security/Cryptography/KeyBlobHelpers.cs"/></remarks>
    internal static class KeyBlobHelpers
    {
        internal static byte[] ToUnsignedIntegerBytes(this ReadOnlyMemory<byte> memory, int length)
        {
            if (memory.Length == length) {
                return memory.ToArray();
            }

            ReadOnlySpan<byte> span = memory.Span;

            if (memory.Length == length + 1) {
                if (span[0] == 0) {
                    return span.Slice(1).ToArray();
                }
            }

            if (span.Length > length) {
                throw new CryptographicException("ASN1 corrupted data.");
            }

            byte[] target = new byte[length];
            span.CopyTo(target.AsSpan(length - span.Length));
            return target;
        }

        internal static byte[] ToUnsignedIntegerBytes(this ReadOnlyMemory<byte> memory)
        {
            ReadOnlySpan<byte> span = memory.Span;

            if (span.Length > 1 && span[0] == 0) {
                return span.Slice(1).ToArray();
            }

            return span.ToArray();
        }

        internal static byte[] ExportKeyParameter(this BigInteger value, int length)
        {
            byte[] target = new byte[length];

            if (value.TryWriteBytes(target, out int bytesWritten, isUnsigned: true, isBigEndian: true)) {
                if (bytesWritten < length) {
                    Buffer.BlockCopy(target, 0, target, length - bytesWritten, bytesWritten);
                    target.AsSpan(0, length - bytesWritten).Clear();
                }

                return target;
            }

            throw new CryptographicException("Key is not a valid public or private key.");
        }

        internal static void WriteKeyParameterInteger(this AsnWriter writer, ReadOnlySpan<byte> integer)
        {
            Debug.Assert(!integer.IsEmpty);

            if (integer[0] == 0) {
                int newStart = 1;

                while (newStart < integer.Length) {
                    if (integer[newStart] >= 0x80) {
                        newStart--;
                        break;
                    }

                    if (integer[newStart] != 0) {
                        break;
                    }

                    newStart++;
                }

                if (newStart == integer.Length) {
                    newStart--;
                }

                integer = integer.Slice(newStart);
            }

            writer.WriteIntegerUnsigned(integer);
        }
    }
}

#endif