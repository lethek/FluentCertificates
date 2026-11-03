using System.Formats.Asn1;
using System.Security.Cryptography;

namespace FluentCertificates;

public class SignatureAlgorithmPssParameterTests
{
    private static Asn1Tag Context(int value) => new(TagClass.ContextSpecific, value);


    private static void WriteHash(AsnWriter writer, string hashOid)
    {
        using (writer.PushSequence(Context(0)))
        using (writer.PushSequence()) {
            writer.WriteObjectIdentifier(hashOid);
        }
    }


    private static void WriteMaskGenerator(AsnWriter writer, string functionOid, string maskHashOid)
    {
        using (writer.PushSequence(Context(1)))
        using (writer.PushSequence()) {
            writer.WriteObjectIdentifier(functionOid);
            using (writer.PushSequence()) {
                writer.WriteObjectIdentifier(maskHashOid);
            }
        }
    }


    private static void WriteInteger(AsnWriter writer, int tag, int value)
    {
        using (writer.PushSequence(Context(tag))) {
            writer.WriteInteger(value);
        }
    }


    /// <summary>An RSASSA-PSS AlgorithmIdentifier whose parameter SEQUENCE is written by the callback.</summary>
    private static byte[] Encode(Action<AsnWriter> writeParameters)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            writer.WriteObjectIdentifier(Oids.RsaPss);
            using (writer.PushSequence()) {
                writeParameters(writer);
            }
        }
        return writer.Encode();
    }


    private static byte[] EncodeWithoutParameters(bool explicitNull)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) {
            writer.WriteObjectIdentifier(Oids.RsaPss);
            if (explicitNull) {
                writer.WriteNull();
            }
        }
        return writer.Encode();
    }


    [Test]
    public async Task FromAlgorithmIdentifier_NonMgf1MaskFunction_ReadsTheHash()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha256);
            WriteMaskGenerator(w, "1.2.3.4", Oids.Sha1);
        });

        var algorithm = SignatureAlgorithm.FromAlgorithmIdentifier(der);

        await Assert.That(algorithm.HashAlgorithm).IsEqualTo((HashAlgorithmName?)HashAlgorithmName.SHA256);
        await Assert.That(algorithm.RSASignaturePadding).IsEqualTo(RSASignaturePadding.Pss);
    }


    [Test]
    public async Task FromAlgorithmIdentifier_UnknownExtraContextTag_ReadsTheHash()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha384);
            WriteInteger(w, 5, 1);
        });

        var algorithm = SignatureAlgorithm.FromAlgorithmIdentifier(der);

        await Assert.That(algorithm.HashAlgorithm).IsEqualTo((HashAlgorithmName?)HashAlgorithmName.SHA384);
    }


    [Test]
    public async Task FromAlgorithmIdentifier_OddSaltAndTrailer_ReadsTheHash()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha384);
            WriteMaskGenerator(w, Oids.Mgf1, Oids.Sha256);
            WriteInteger(w, 2, 7);
            WriteInteger(w, 3, 2);
        });

        var algorithm = SignatureAlgorithm.FromAlgorithmIdentifier(der);

        await Assert.That(algorithm.HashAlgorithm).IsEqualTo((HashAlgorithmName?)HashAlgorithmName.SHA384);
    }


    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task FromAlgorithmIdentifier_AbsentOrNullParameters_ThrowsNotSupported(bool explicitNull)
    {
        var der = EncodeWithoutParameters(explicitNull);

        await Assert.That(() => SignatureAlgorithm.FromAlgorithmIdentifier(der)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_FullySpecifiedSha256Parameters_DoesNotThrow()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha256);
            WriteMaskGenerator(w, Oids.Mgf1, Oids.Sha256);
            WriteInteger(w, 2, 32);
            WriteInteger(w, 3, 1);
        });

        SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der);

        await Task.CompletedTask;
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_NonMgf1MaskFunction_ThrowsNotSupported()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha256);
            WriteMaskGenerator(w, "1.2.3.4", Oids.Sha256);
        });

        await Assert.That(() => SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_UnexpectedTag_ThrowsNotSupported()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha1);
            WriteInteger(w, 5, 1);
        });

        await Assert.That(() => SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_MaskHashDiffersFromHash_ThrowsNotSupported()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha256);
            WriteMaskGenerator(w, Oids.Mgf1, Oids.Sha1);
            WriteInteger(w, 2, 32);
        });

        await Assert.That(() => SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_NullParametersOnTheHashes_DoesNotThrow()
    {
        var der = Encode(w => {
            using (w.PushSequence(Context(0)))
            using (w.PushSequence()) {
                w.WriteObjectIdentifier(Oids.Sha256);
                w.WriteNull();
            }
            using (w.PushSequence(Context(1)))
            using (w.PushSequence()) {
                w.WriteObjectIdentifier(Oids.Mgf1);
                using (w.PushSequence()) {
                    w.WriteObjectIdentifier(Oids.Sha256);
                    w.WriteNull();
                }
            }
            WriteInteger(w, 2, 32);
        });

        SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der);

        await Task.CompletedTask;
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_RepeatedSaltLength_ThrowsNotSupported()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha256);
            WriteMaskGenerator(w, Oids.Mgf1, Oids.Sha256);
            WriteInteger(w, 2, 99);
            WriteInteger(w, 2, 32);
        });

        await Assert.That(() => SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_FieldsOutOfOrder_ThrowsNotSupported()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha256);
            WriteInteger(w, 2, 32);
            WriteMaskGenerator(w, Oids.Mgf1, Oids.Sha256);
        });

        await Assert.That(() => SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_ContentAfterAFieldsValue_ThrowsNotSupported()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha256);
            WriteMaskGenerator(w, Oids.Mgf1, Oids.Sha256);
            using (w.PushSequence(Context(2))) {
                w.WriteInteger(32);
                w.WriteInteger(99);
            }
        });

        await Assert.That(() => SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_ContentAfterTheHashIdentifier_ThrowsNotSupported()
    {
        var der = Encode(w => {
            using (w.PushSequence(Context(0)))
            using (w.PushSequence()) {
                w.WriteObjectIdentifier(Oids.Sha256);
                w.WriteNull();
                w.WriteInteger(1);
            }
        });

        await Assert.That(() => SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der)).Throws<NotSupportedException>();
    }


    [Test]
    public async Task ThrowIfPssParametersNotVerifiable_TrailerOtherThanOne_ThrowsNotSupported()
    {
        var der = Encode(w => {
            WriteHash(w, Oids.Sha256);
            WriteMaskGenerator(w, Oids.Mgf1, Oids.Sha256);
            WriteInteger(w, 2, 32);
            WriteInteger(w, 3, 2);
        });

        await Assert.That(() => SignatureAlgorithm.ThrowIfPssParametersNotVerifiable(der)).Throws<NotSupportedException>();
    }
}
