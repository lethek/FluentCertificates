// ReSharper disable All

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Buffers
{
    /// <remarks>Original copy sourced under the MIT license from: https://github.com/dotnet/runtime/blob/425fedc0fb005af24765faa3ed423222a7dbd963/src/libraries/Common/src/System/Memory/PointerMemoryManager.cs</remarks>
    internal sealed unsafe class PointerMemoryManager<T> : MemoryManager<T> where T : struct
    {
        private readonly void* _pointer;
        private readonly int _length;

        internal PointerMemoryManager(void* pointer, int length)
        {
            _pointer = pointer;
            _length = length;
        }

        protected override void Dispose(bool disposing)
        {
        }

        public override Span<T> GetSpan()
        {
            return new Span<T>(_pointer, _length);
        }

        public override MemoryHandle Pin(int elementIndex = 0)
        {
            throw new NotSupportedException();
        }

        public override void Unpin()
        {
        }
    }
}
