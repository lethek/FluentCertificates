using System.Formats.Asn1;

namespace FluentCertificates;

public abstract record GeneralNameConstraint
{
    public abstract Asn1Tag Tag { get; }

    public void WriteTo(AsnWriter writer)
    {
        EncodeCore(writer);
    }

    protected abstract void EncodeCore(AsnWriter writer);
}