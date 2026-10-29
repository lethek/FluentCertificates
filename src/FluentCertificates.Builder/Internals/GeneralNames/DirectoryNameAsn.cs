using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record DirectoryNameAsn : GeneralName
{
    public ReadOnlyMemory<byte> Value { get; }

    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 4);

    public DirectoryNameAsn(X500DistinguishedName name)
        //RawData hands out the name's own array, so a copy stops the caller's later changes reaching this one
        => Value = name.RawData.AsSpan().ToArray();

    protected override void EncodeCore(AsnWriter writer)
    {
        //directoryName's tag is explicit, because Name is a CHOICE and a tag on a CHOICE cannot be implicit.
        //The RDNSequence therefore keeps its own SEQUENCE tag inside the wrapper.
        using (writer.PushSequence(Tag)) {
            writer.WriteEncodedValue(Value.Span);
        }
    }

    public bool Equals(DirectoryNameAsn? other)
        => other is not null
           && Value.Span.SequenceEqual(other.Value.Span);

    public override int GetHashCode()
    {
        //The name is held as bytes, whose own GetHashCode is their identity rather than their contents
        var hash = new HashCode();
        hash.AddBytes(Value.Span);
        return hash.ToHashCode();
    }
}
