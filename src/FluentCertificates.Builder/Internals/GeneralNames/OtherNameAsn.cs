using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record OtherNameAsn : GeneralName
{
    public string TypeId { get; }

    public ReadOnlyMemory<byte> Value { get; }

    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 0);

    public OtherNameAsn(string typeId, ReadOnlySpan<byte> value)
    {
        TypeId = typeId;
        Value = value.ToArray();
    }

    protected override void EncodeCore(AsnWriter writer)
    {
        //AnotherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id }
        //The outer tag is implicit and so replaces the SEQUENCE's own tag, while the inner one is explicit
        //and so wraps the caller's value with its type intact.
        using (writer.PushSequence(Tag)) {
            writer.WriteObjectIdentifier(TypeId);
            using (writer.PushSequence(ExplicitValueTag)) {
                writer.WriteEncodedValue(Value.Span);
            }
        }
    }

    public bool Equals(OtherNameAsn? other)
        => other is not null
           && TypeId == other.TypeId
           && Value.Span.SequenceEqual(other.Value.Span);

    public override int GetHashCode()
    {
        //The value is an array, whose own GetHashCode is its identity rather than its contents
        var hash = new HashCode();
        hash.Add(TypeId);
        hash.AddBytes(Value.Span);
        return hash.ToHashCode();
    }

    private static readonly Asn1Tag ExplicitValueTag = new(TagClass.ContextSpecific, 0);
}
