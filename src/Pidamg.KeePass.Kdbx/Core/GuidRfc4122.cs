using System;
using System.Buffers.Binary;

namespace Pidamg.KeePass.Kdbx;

// Conversion between .NET mixed-endian Guid and RFC 4122 big-endian bytes,
// as used in the KDBX binary format (header UUIDs and KDF parameter maps).
internal static class GuidRfc4122
{

    // .NET layout: data1(LE4) | data2(LE2) | data3(LE2) | data4(8 bytes, big-endian)
    public static byte[] ToBytes(Guid g)
    {
        var buf = g.ToByteArray();
        var result = new byte[16];
        result[0] = buf[3]; result[1] = buf[2]; result[2] = buf[1]; result[3] = buf[0]; // data1 LE→BE
        result[4] = buf[5]; result[5] = buf[4];                                          // data2 LE→BE
        result[6] = buf[7]; result[7] = buf[6];                                          // data3 LE→BE
        Array.Copy(buf, 8, result, 8, 8);                                                // data4 as-is
        return result;
    }

    public static Guid FromBytes(byte[] b) => new Guid(
        BinaryPrimitives.ReadUInt32BigEndian(b),
        BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(4)),
        BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(6)),
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    );
}
