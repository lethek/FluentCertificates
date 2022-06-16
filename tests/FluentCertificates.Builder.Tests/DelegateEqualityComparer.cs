using System;
using System.Collections.Generic;

namespace FluentCertificates;

internal class DelegateEqualityComparer<T> : IEqualityComparer<T>
{
    public DelegateEqualityComparer(Func<T?, T?, bool> predicate)
        => _predicate = predicate;


    public bool Equals(T? x, T? y)
        => _predicate(x, y);


    public int GetHashCode(T obj)
        => HashCode.Combine(obj);


    private readonly Func<T?, T?, bool> _predicate;
}
