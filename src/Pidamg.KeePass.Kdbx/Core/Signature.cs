using System;
using System.IO;

namespace Pidamg.KeePass;

internal sealed class Signature : IEquatable<Signature>
{

    public readonly UInt32 Sign1;
    public readonly UInt32 Sign2;

    public bool IsZero => Sign1 == 0 && Sign2 == 0;

    public Signature()
    {
        Sign1 = Sign2 = 0;
    }

    public Signature(UInt32 sign1, UInt32 sign2)
    {
        Sign1 = sign1;
        Sign2 = sign2;
    }

    public bool Equals(Signature? other)
    {
        if (other is null) return false;
        return Sign1 == other.Sign1 && Sign2 == other.Sign2;
    }

    public override bool Equals(object? other)
    {
        return other is Signature s && Equals(s);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Sign1, Sign2);
    }

    public static Signature Read(BinaryReader reader)
    {
        uint sign1 = reader.ReadUInt32();
        uint sign2 = reader.ReadUInt32();
        return new Signature(sign1, sign2);
    }

    public static Signature Read(Stream stream)
    {
        using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        return Read(reader);
    }

    public void Write(BinaryWriter writer)
    {
        writer.Write(Sign1);
        writer.Write(Sign2);
    }

    public void Write(Stream stream)
    {
        using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        Write(writer);
    }

    public static bool operator ==(Signature? s1, Signature? s2)
    {
        if (s1 is null) return s2 is null;
        return s1.Equals(s2);
    }

    public static bool operator !=(Signature? s1, Signature? s2) => !(s1 == s2);
}
