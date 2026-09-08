using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using FluentCertificates.Internals;

namespace FluentCertificates;

public class X509ExtensionOidEqualityComparerTests
{
    [Test]
    public async Task Equals_SameReference_IsTrue()
    {
        var ext = BasicConstraints();

        await Assert.That(Comparer.Equals(ext, ext)).IsTrue();
    }


    [Test]
    public async Task Equals_BothNull_IsTrue()
        => await Assert.That(Comparer.Equals(null, null)).IsTrue();


    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task Equals_OneSideNull_IsFalse(bool nullOnLeft)
    {
        var ext = BasicConstraints();

        await Assert.That(nullOnLeft ? Comparer.Equals(null, ext) : Comparer.Equals(ext, null)).IsFalse();
    }


    [Test]
    public async Task Equals_SameOidDifferentInstances_IsTrue()
        => await Assert.That(Comparer.Equals(BasicConstraints(), BasicConstraints(pathLength: 7))).IsTrue();


    [Test]
    public async Task Equals_DifferentOids_IsFalse()
        => await Assert.That(Comparer.Equals(BasicConstraints(), KeyUsage())).IsFalse();


    /// <summary>
    /// A certificate carries at most one extension per OID, so a strongly typed extension and a raw
    /// <see cref="X509Extension"/> under that OID are the same extension. Were they not, both would reach
    /// <see cref="CertificateRequest"/> and it would throw on the duplicate.
    /// </summary>
    [Test]
    public async Task Equals_SameOidDifferentTypes_IsTrue()
    {
        var typed = BasicConstraints();
        var raw = new X509Extension(typed.Oid!, typed.RawData, typed.Critical);

        await Assert.That(Comparer.Equals(typed, raw)).IsTrue();
        await Assert.That(Comparer.Equals(raw, typed)).IsTrue();
        await Assert.That(Comparer.GetHashCode(raw)).IsEqualTo(Comparer.GetHashCode(typed));
    }


    /// <summary>
    /// <see cref="AsnEncodedData.Oid"/> is publicly settable and nullable, so both the comparison and the
    /// hash have to read through a missing OID rather than dereference it.
    /// </summary>
    [Test]
    public async Task Equals_ExtensionWithNoOid_ComparesOnTheMissingValue()
    {
        var first = RawExtension();
        var second = RawExtension();
        var withOid = RawExtension(BasicConstraintsOid);

        await Assert.That(Comparer.Equals(first, second)).IsTrue();
        await Assert.That(Comparer.Equals(first, withOid)).IsFalse();
        await Assert.That(Comparer.Equals(withOid, first)).IsFalse();
    }


    [Test]
    public async Task GetHashCode_ExtensionWithNoOid_DoesNotThrow()
        => await Assert.That(Comparer.GetHashCode(RawExtension())).IsEqualTo(Comparer.GetHashCode(RawExtension()));


    [Test]
    public async Task GetHashCode_MatchesForSameOid()
        => await Assert.That(Comparer.GetHashCode(BasicConstraints()))
            .IsEqualTo(Comparer.GetHashCode(BasicConstraints(pathLength: 7)));


    private const string BasicConstraintsOid = "2.5.29.19";

    //DER NULL as the payload; the comparer reads nothing but the OID
    private static X509Extension RawExtension(string? oid = null)
        => new(new Oid(BasicConstraintsOid), [0x05, 0x00], false) { Oid = oid == null ? null : new Oid(oid) };

    private static readonly X509ExtensionOidEqualityComparer Comparer = new();

    private static X509BasicConstraintsExtension BasicConstraints(int pathLength = 0)
        => new(false, pathLength > 0, pathLength, true);

    private static X509KeyUsageExtension KeyUsage()
        => new(X509KeyUsageFlags.DigitalSignature, true);
}
