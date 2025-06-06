﻿using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record RegisteredIdNameAsn(string RegisteredId) : GeneralName
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 8);

    protected override void EncodeCore(AsnWriter writer)
        => writer.WriteObjectIdentifier(RegisteredId, Tag);
}