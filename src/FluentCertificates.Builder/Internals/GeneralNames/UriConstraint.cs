﻿using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record UriConstraint(Uri Uri) : GeneralNameConstraint
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 6);

    protected override void EncodeCore(AsnWriter writer)
        => writer.WriteCharacterString(UniversalTagNumber.IA5String, Uri.AbsoluteUri, Tag);
}