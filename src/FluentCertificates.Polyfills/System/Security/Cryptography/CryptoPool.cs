#if NETSTANDARD
// ReSharper disable All

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;

namespace System.Security.Cryptography;

/// <remarks>Original copy sourced under the MIT license from: https://github.com/dotnet/runtime/blob/425fedc0fb005af24765faa3ed423222a7dbd963/src/libraries/Common/src/System/Security/Cryptography/CryptoPool.cs</remarks>
internal static class CryptoPool
{
    internal const int ClearAll = -1;


    internal static byte[] Rent(int minimumLength)
        => ArrayPool<byte>.Shared.Rent(minimumLength);


    internal static void Return(ArraySegment<byte> arraySegment)
    {
        Debug.Assert(arraySegment.Array != null);
        Debug.Assert(arraySegment.Offset == 0);

        Return(arraySegment.Array, arraySegment.Count);
    }


    internal static void Return(byte[] array, int clearSize = ClearAll)
    {
        Debug.Assert(clearSize <= array.Length);
        var clearWholeArray = clearSize < 0;

        if (!clearWholeArray && clearSize != 0) {
#if (NETCOREAPP || NETSTANDARD2_1) && !CP_NO_ZEROMEMORY
            CryptographicOperations.ZeroMemory(array.AsSpan(0, clearSize));
#else
            Array.Clear(array, 0, clearSize);
#endif
        }

        ArrayPool<byte>.Shared.Return(array, clearWholeArray);
    }
}

#endif