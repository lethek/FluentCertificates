﻿using System.Formats.Asn1;

namespace FluentCertificates.Internals.GeneralNames;

internal sealed record DirectoryNameAsn : GeneralName
{
    public override Asn1Tag Tag { get; } = new(TagClass.ContextSpecific, 4);

    protected override void EncodeCore(AsnWriter writer)
        => throw new NotImplementedException();
}
