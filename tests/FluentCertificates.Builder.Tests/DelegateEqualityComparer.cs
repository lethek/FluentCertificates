namespace FluentCertificates;

internal class DelegateEqualityComparer<T>(Func<T?, T?, bool> predicate) : IEqualityComparer<T>
{
    public bool Equals(T? x, T? y)
        => predicate(x, y);


    public int GetHashCode(T obj)
        => HashCode.Combine(obj);
}
