using System;
using System.IO;

namespace Pidamg.KeePass.Kdbx;

/// <summary>
/// Represents the major and minor version of a KDBX file.
/// </summary>
public sealed class KdbxVersion : IEquatable<KdbxVersion>, IComparable<KdbxVersion>
{

    /// <summary>
    /// Gets the major version number.
    /// </summary>
    public ushort Major { get; }

    /// <summary>
    /// Gets the minor version number.
    /// </summary>
    public ushort Minor { get; }

    /// <summary>
    /// Gets a value indicating whether both version components are zero.
    /// </summary>
    public bool IsZero => Major == 0 && Minor == 0;

    /// <summary>
    /// Initializes a zero version.
    /// </summary>
    public KdbxVersion()
    {
        Major = Minor = 0;
    }

    /// <summary>
    /// Initializes a version with the specified components.
    /// </summary>
    /// <param name="major">The major version number.</param>
    /// <param name="minor">The minor version number.</param>
    public KdbxVersion(ushort major, ushort minor)
    {
        Major = major;
        Minor = minor;
    }

    /// <summary>
    /// Compares this version with another version.
    /// </summary>
    /// <param name="other">The version to compare with this instance.</param>
    /// <returns>A value indicating the relative ordering of the versions.</returns>
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

    /// <summary>
    /// Determines whether this instance and another version have equal components.
    /// </summary>
    /// <param name="other">The version to compare with this instance.</param>
    /// <returns><see langword="true"/> when the versions are equal; otherwise, <see langword="false"/>.</returns>
    public bool Equals(KdbxVersion? other)
    {
        if (other is null) return false;
        return Major == other.Major && Minor == other.Minor;
    }

    /// <inheritdoc/>
    public override bool Equals(object? other)
    {
        return other is KdbxVersion v && Equals(v);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Major, Minor);
    }

    /// <summary>
    /// Returns the version in <c>major.minor</c> form.
    /// </summary>
    /// <returns>The formatted version.</returns>
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

    /// <summary>
    /// Determines whether two versions are equal.
    /// </summary>
    /// <param name="v1">The first version.</param>
    /// <param name="v2">The second version.</param>
    /// <returns><see langword="true"/> when the versions are equal; otherwise, <see langword="false"/>.</returns>
    public static bool operator ==(KdbxVersion? v1, KdbxVersion? v2)
    {
        if (v1 is null) return v2 is null;
        return v1.Equals(v2);
    }

    /// <summary>
    /// Determines whether two versions are not equal.
    /// </summary>
    /// <param name="v1">The first version.</param>
    /// <param name="v2">The second version.</param>
    /// <returns><see langword="true"/> when the versions differ; otherwise, <see langword="false"/>.</returns>
    public static bool operator !=(KdbxVersion? v1, KdbxVersion? v2) => !(v1 == v2);

    /// <summary>
    /// Determines whether the first version is greater than the second.
    /// </summary>
    /// <param name="v1">The first version.</param>
    /// <param name="v2">The second version.</param>
    /// <returns><see langword="true"/> when <paramref name="v1"/> is greater; otherwise, <see langword="false"/>.</returns>
    public static bool operator >(KdbxVersion v1, KdbxVersion v2)
    {
        return v1.CompareTo(v2) > 0;
    }

    /// <summary>
    /// Determines whether the first version is greater than or equal to the second.
    /// </summary>
    /// <param name="v1">The first version.</param>
    /// <param name="v2">The second version.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="v1"/> is greater than or equal to
    /// <paramref name="v2"/>; otherwise, <see langword="false"/>.
    /// </returns>
    public static bool operator >=(KdbxVersion v1, KdbxVersion v2)
    {
        return v1.CompareTo(v2) >= 0;
    }

    /// <summary>
    /// Determines whether the first version is less than the second.
    /// </summary>
    /// <param name="v1">The first version.</param>
    /// <param name="v2">The second version.</param>
    /// <returns><see langword="true"/> when <paramref name="v1"/> is less; otherwise, <see langword="false"/>.</returns>
    public static bool operator <(KdbxVersion v1, KdbxVersion v2)
    {
        return v1.CompareTo(v2) < 0;
    }

    /// <summary>
    /// Determines whether the first version is less than or equal to the second.
    /// </summary>
    /// <param name="v1">The first version.</param>
    /// <param name="v2">The second version.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="v1"/> is less than or equal to
    /// <paramref name="v2"/>; otherwise, <see langword="false"/>.
    /// </returns>
    public static bool operator <=(KdbxVersion v1, KdbxVersion v2)
    {
        return v1.CompareTo(v2) <= 0;
    }
}
