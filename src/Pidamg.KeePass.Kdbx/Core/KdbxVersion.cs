using System;
using System.IO;

namespace Pidamg.KeePass.Kdbx;

public sealed class KdbxVersion : IEquatable<KdbxVersion>, IComparable<KdbxVersion>
{

    public ushort Major { get; }
    public ushort Minor { get; }
    public bool IsZero => Major == 0 && Minor == 0;

    public KdbxVersion()
    {
        Major = Minor = 0;
    }

    public KdbxVersion(ushort major, ushort minor)
    {
        Major = major;
        Minor = minor;
    }

    public int CompareTo(KdbxVersion? other)
    {
        if (other is null) return 1;
        // compare major
        if (Major > other.Major) return 1;
        if (Major < other.Major) return -1;
        // same major, compare minor
        if (Minor > other.Minor) return 1;
        if (Minor < other.Minor) return -1;
        // same major, same minor
        return 0;
    }

    public bool Equals(KdbxVersion? other)
    {
        if (other is null) return false;
        return Major == other.Major && Minor == other.Minor;
    }

    public override bool Equals(object? other)
    {
        return other is KdbxVersion v && Equals(v);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Major, Minor);
    }

    public override string ToString()
    {
        return $"{Major}.{Minor}";
    }

    // In KDBX the version field is [Minor LE16][Major LE16]
    internal static KdbxVersion Read(BinaryReader reader)
    {
        ushort minor = reader.ReadUInt16();
        ushort major = reader.ReadUInt16();
        return new KdbxVersion(major, minor);
    }

    internal static KdbxVersion Read(Stream stream)
    {
        using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        return Read(reader);
    }

    internal void Write(BinaryWriter writer)
    {
        writer.Write(Minor);
        writer.Write(Major);
    }

    internal void Write(Stream stream)
    {
        using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        Write(writer);
    }

    public static bool operator ==(KdbxVersion? v1, KdbxVersion? v2)
    {
        if (v1 is null) return v2 is null;
        return v1.Equals(v2);
    }

    public static bool operator !=(KdbxVersion? v1, KdbxVersion? v2) => !(v1 == v2);

    public static bool operator >(KdbxVersion v1, KdbxVersion v2)
    {
        return v1.CompareTo(v2) > 0;
    }

    public static bool operator >=(KdbxVersion v1, KdbxVersion v2)
    {
        return v1.CompareTo(v2) >= 0;
    }

    public static bool operator <(KdbxVersion v1, KdbxVersion v2)
    {
        return v1.CompareTo(v2) < 0;
    }

    public static bool operator <=(KdbxVersion v1, KdbxVersion v2)
    {
        return v1.CompareTo(v2) <= 0;
    }
}
