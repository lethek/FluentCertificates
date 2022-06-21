// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// ReSharper disable SuggestVarOrType_BuiltInTypes

using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace FluentCertificates.Internals;

/// <summary>
/// Class for building DSA encoded signatures for X.509 certificates.
/// </summary>
/// <remarks>Original copy sourced under the MIT license from: <see href="https://github.com/dotnet/runtime/blob/425fedc0fb005af24765faa3ed423222a7dbd963/src/libraries/System.Security.Cryptography.X509Certificates/tests/CertificateCreation/DSAX509SignatureGenerator.cs"/></remarks>
internal sealed class DSAX509SignatureGenerator : X509SignatureGenerator
{
    private readonly DSA _key;

    public DSAX509SignatureGenerator(DSA key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        _key = key;
    }

    public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA1) {
            return Tools.ConvertFromHexString("300906072A8648CE380403");
        }

        if (hashAlgorithm == HashAlgorithmName.SHA256) {
            return Tools.ConvertFromHexString("300B0609608648016503040302");
        }

        throw new InvalidOperationException();
    }

    private static byte[] EncodeLength(int length)
    {
        Debug.Assert(length >= 0);

        byte low = unchecked((byte)length);

        // If the length value fits in 7 bits, it's an answer all by itself.
        if (length < 0x80) {
            return new[] { low };
        }

        if (length <= 0xFF) {
            return new byte[] { 0x81, low };
        }

        int remainder = length >> 8;
        byte midLow = unchecked((byte)remainder);

        if (length <= 0xFFFF) {
            return new byte[] { 0x82, midLow, low };
        }

        remainder >>= 8;
        byte midHigh = unchecked((byte)remainder);

        if (length <= 0xFFFFFF) {
            return new byte[] { 0x83, midHigh, midLow, low };
        }

        remainder >>= 8;
        byte high = unchecked((byte)remainder);

        // Since we know this was a non-negative signed number, the highest
        // legal value here is 0x7F.
        Debug.Assert(remainder < 0x80);

        return new byte[] { 0x84, high, midHigh, midLow, low };
    }

    private byte[] EncodeUnsignedInteger(byte[] data)
    {
        return EncodeUnsignedInteger(data, 0, data.Length);
    }

    private byte[] EncodeUnsignedInteger(byte[] data, int offset, int count)
    {
        int length = count;
        int realOffset = offset;
        bool paddingByte = false;

        if (count == 0 || data[offset] >= 0x80) {
            paddingByte = true;
        } else {
            while (length > 1 && data[realOffset] == 0) {
                realOffset++;
                length--;
            }
        }

        byte encodedLength = (byte)length;

        if (paddingByte) {
            encodedLength++;
        }

        IEnumerable<byte> bytes = new byte[] { 0x02 };
        bytes = bytes.Concat(EncodeLength(encodedLength));

        if (paddingByte) {
            bytes = bytes.Concat(new byte[1]);
        }

        bytes = bytes.Concat(data.Skip(realOffset).Take(length));

        return bytes.ToArray();
    }

    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        byte[] ieeeFormat = _key.SignData(data, hashAlgorithm);

        Debug.Assert(ieeeFormat.Length % 2 == 0);
        int segmentLength = ieeeFormat.Length / 2;

        byte[] r = EncodeUnsignedInteger(ieeeFormat, 0, segmentLength);
        byte[] s = EncodeUnsignedInteger(ieeeFormat, segmentLength, segmentLength);

        return
            new byte[] { 0x30 }.
                Concat(EncodeLength(r.Length + s.Length)).
                Concat(r).
                Concat(s).
                ToArray();
    }

    protected override PublicKey BuildPublicKey()
    {
        // DSA
        Oid oid = new Oid("1.2.840.10040.4.1");

        DSAParameters dsaParameters = _key.ExportParameters(false);

        // Dss-Parms ::= SEQUENCE {
        //   p INTEGER,
        //   q INTEGER,
        //   g INTEGER
        // }

        byte[] p = EncodeUnsignedInteger(dsaParameters.P!);
        byte[] q = EncodeUnsignedInteger(dsaParameters.Q!);
        byte[] g = EncodeUnsignedInteger(dsaParameters.G!);

        byte[] algParameters =
            new byte[] { 0x30 }.
                Concat(EncodeLength(p.Length + q.Length + g.Length)).
                Concat(p).
                Concat(q).
                Concat(g).
                ToArray();

        byte[] keyValue = EncodeUnsignedInteger(dsaParameters.Y!);

        return new PublicKey(
            oid,
            new AsnEncodedData(oid, algParameters),
            new AsnEncodedData(oid, keyValue));
    }
}