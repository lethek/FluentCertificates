using System.Reflection;
using System.Security.Cryptography;


namespace FluentCertificates;

/// <summary>
/// <see cref="Oid"/> does not override equality, so comparing two of them by reference silently answers the
/// wrong question. <see cref="Oids.ValueEquals"/> is what callers are meant to reach for instead.
/// </summary>
public class OidsTests
{
    [Test]
    public async Task ValueEquals_SameInstance_IsTrue()
    {
        var oid = new Oid(Oids.Rsa);

        await Assert.That(oid.ValueEquals(oid)).IsTrue();
    }


    [Test]
    public async Task ValueEquals_SameValueDifferentInstances_IsTrue()
    {
        //Reference equality would say false here, which is the whole reason this method exists
        await Assert.That(new Oid(Oids.Rsa).ValueEquals(new Oid(Oids.Rsa))).IsTrue();
    }


    [Test]
    public async Task ValueEquals_SameValueDifferentFriendlyName_IsTrue()
    {
        //Only the value is compared, so a differing friendly name makes no difference
        await Assert
            .That(new Oid(Oids.Rsa, "one").ValueEquals(new Oid(Oids.Rsa, "another")))
            .IsTrue();
    }


    [Test]
    public async Task ValueEquals_DifferentValues_IsFalse()
    {
        await Assert.That(new Oid(Oids.Rsa).ValueEquals(new Oid(Oids.EcPublicKey))).IsFalse();
    }


    [Test]
    public async Task ValueEquals_Null_IsFalse()
    {
        await Assert.That(new Oid(Oids.Rsa).ValueEquals(null)).IsFalse();
    }


    [Test]
    public async Task ValueEquals_ValuelessOid_IsFalseEvenAgainstAnotherValuelessOne()
    {
        //An Oid carrying only a friendly name has no value to compare, so it matches nothing but itself
        var valueless = new Oid { FriendlyName = "no value here" };

        await Assert.That(valueless.Value).IsNull();
        await Assert.That(valueless.ValueEquals(new Oid { FriendlyName = "no value here" })).IsFalse();
        await Assert.That(valueless.ValueEquals(new Oid(Oids.Rsa))).IsFalse();
        await Assert.That(valueless.ValueEquals(valueless)).IsTrue();
    }


    [Test]
    public async Task NoCachedOid_IsExposedAsAField()
    {
        //A member declared with `=` instead of `=>` becomes a public mutable static field that any
        //consumer can reassign for the whole process, and is initialised eagerly rather than cached lazily
        var fields = typeof(Oids)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(x => x.FieldType == typeof(Oid))
            .Select(x => x.Name);

        await Assert.That(fields).IsEmpty();
    }


    [Test]
    public async Task EveryCachedOid_IsReadOnlyAndReturnsTheOneInstance()
    {
        var properties = typeof(Oids)
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(x => x.PropertyType == typeof(Oid))
            .ToList();

        await Assert.That(properties).IsNotEmpty();
        foreach (var property in properties) {
            await Assert.That(property.CanWrite).IsFalse();
            await Assert.That(property.GetValue(null)).IsSameReferenceAs(property.GetValue(null));
        }
    }
}
