// ReSharper disable All

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography;

namespace System.Formats.Asn1;

/// <remarks>Original copy sourced under the MIT license from: https://github.com/dotnet/runtime/blob/425fedc0fb005af24765faa3ed423222a7dbd963/src/libraries/Common/src/System/Security/Cryptography/Asn1Reader/AsnValueReader.cs</remarks>
internal static class AsnWriterExtensions
{
    internal static void WriteEncodedValueForCrypto(
        this AsnWriter writer,
        ReadOnlySpan<byte> value)
    {
        try {
            writer.WriteEncodedValue(value);
        } catch (ArgumentException e) {
            throw new CryptographicException("ASN1 corrupted data.", e);
        }
    }

    internal static void WriteObjectIdentifierForCrypto(
        this AsnWriter writer,
        string value)
    {
        try {
            writer.WriteObjectIdentifier(value);
        } catch (ArgumentException e) {
            throw new CryptographicException("ASN1 corrupted data.", e);
        }
    }

    internal static ArraySegment<byte> RentAndEncode(this AsnWriter writer)
    {
        byte[] rented = CryptoPool.Rent(writer.GetEncodedLength());
        int written = writer.Encode(rented);
        return new ArraySegment<byte>(rented, 0, written);
    }
}
