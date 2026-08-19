using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record Rfc822NameAsn : GeneralName
{
    public string EmailAddress { get; }

    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 1);

    public Rfc822NameAsn(string emailAddress)
        => EmailAddress = Ia5NameValidator.ValidateEmailAddress(emailAddress, nameof(emailAddress));

    protected override void EncodeCore(AsnWriter writer)
        => writer.WriteCharacterString(UniversalTagNumber.IA5String, EmailAddress, Tag);
}
