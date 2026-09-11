using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record DirectoryNameAsn : GeneralName
{
    public X500DistinguishedName Name { get; }

    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 4);

    public DirectoryNameAsn(X500DistinguishedName name)
        => Name = name;

    protected override void EncodeCore(AsnWriter writer)
    {
        //directoryName's tag is explicit, because Name is a CHOICE and a tag on a CHOICE cannot be implicit.
        //The RDNSequence therefore keeps its own SEQUENCE tag inside the wrapper.
        using (writer.PushSequence(Tag)) {
            writer.WriteEncodedValue(Name.RawData);
        }
    }

    public bool Equals(DirectoryNameAsn? other)
        => other is not null
           && Name.RawData.AsSpan().SequenceEqual(other.Name.RawData);

    public override int GetHashCode()
    {
        //X500DistinguishedName has no value equality of its own, so the encoded name stands for it
        var hash = new HashCode();
        hash.AddBytes(Name.RawData);
        return hash.ToHashCode();
    }
}
