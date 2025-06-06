﻿using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record EdiPartyNameAsn : GeneralName
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 5);

    protected override void EncodeCore(AsnWriter writer)
        => throw new NotImplementedException();
}
