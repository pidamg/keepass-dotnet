using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Pidamg.KeePass;

/// <summary>
/// Builds the composite key used to unlock a KDBX database.
/// </summary>
/// <remarks>
/// A composite key can contain password and key-file components. Components are combined in the
/// order in which they are added.
/// </remarks>
public class CompositeKey
{

    private readonly List<byte[]> _components = [];

    /// <summary>
    /// Initializes an empty composite key.
    /// </summary>
    public CompositeKey() { }

    /// <summary>
    /// Initializes a composite key with a password component.
    /// </summary>
    /// <param name="password">The database password.</param>
    public CompositeKey(string password)
    {
        AddPassword(password);
    }

    /// <summary>
    /// Initializes a composite key with password and key-file components.
    /// </summary>
    /// <param name="password">The database password.</param>
    /// <param name="keyFile">The path to a KeePass key file.</param>
    /// <exception cref="IOException">The key file cannot be read.</exception>
    public CompositeKey(string password, string keyFile)
    {
        AddPassword(password);
        AddKeyFile(keyFile);
    }

    /// <summary>
    /// Adds a password component.
    /// </summary>
    /// <param name="password">The database password.</param>
    /// <returns>This instance, for fluent composition.</returns>
    public CompositeKey AddPassword(string password)
    {
        _components.Add(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
        return this;
    }

    /// <summary>
    /// Adds a component read from a KeePass key file.
    /// </summary>
    /// <param name="path">The path to the key file.</param>
    /// <returns>This instance, for fluent composition.</returns>
    /// <exception cref="IOException">The key file cannot be read.</exception>
    /// <exception cref="InvalidDataException">The file is a malformed KeePass XML key file.</exception>
    public CompositeKey AddKeyFile(string path)
    {
        _components.Add(ReadKeyFile(path));
        return this;
    }

    internal void Zeroize()
    {
        foreach (var c in _components)
            Array.Clear(c);
        _components.Clear();
    }

    internal byte[] GetRawKey()
    {
        if (_components.Count == 0)
            throw new InvalidOperationException("CompositeKey has no components.");

        var buffer = new byte[_components.Count * 32];
        int offset = 0;
        foreach (var c in _components)
        {
            c.CopyTo(buffer, offset);
            offset += 32;
        }
        return SHA256.HashData(buffer);
    }

    private static byte[] ReadKeyFile(string path)
    {
        var data = File.ReadAllBytes(path);

        if (TryParseXmlKeyFile(data, out var xmlKey))
            return xmlKey!;

        // 64 ASCII hex chars → 32 bytes
        if (data.Length == 64 && TryParseHex(data, out var hexKey))
            return hexKey!;

        // Raw 32-byte binary key
        if (data.Length == 32)
            return data;

        return SHA256.HashData(data);
    }

    private static bool TryParseXmlKeyFile(byte[] data, out byte[]? key)
    {
        key = null;

        XDocument doc;
        try
        {
            doc = XDocument.Parse(Encoding.UTF8.GetString(data).TrimStart('\uFEFF'));
        }
        catch (XmlException)
        {
            return false;
        }

        if (doc.Root?.Name.LocalName != "KeyFile")
            return false;

        var dataElement = doc.Root.Element("Key")?.Element("Data")
            ?? throw new InvalidDataException("The KeePass XML key file does not contain key data.");
        var version = doc.Root.Element("Meta")?.Element("Version")?.Value.Trim();

        try
        {
            key = version?.StartsWith("2.", StringComparison.Ordinal) == true
                ? Convert.FromHexString(string.Concat(dataElement.Value.Where(c => !char.IsWhiteSpace(c))))
                : Convert.FromBase64String(dataElement.Value.Trim());
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("The KeePass XML key file contains invalid key data.", ex);
        }

        if (key.Length != 32)
            throw new InvalidDataException("A KeePass XML key file must contain a 32-byte key.");

        if (version?.StartsWith("2.", StringComparison.Ordinal) == true)
            ValidateXmlV2Hash(dataElement, key);

        return true;
    }

    private static void ValidateXmlV2Hash(XElement dataElement, byte[] key)
    {
        var actualHash = dataElement.Attribute("Hash")?.Value.Trim()
            ?? throw new InvalidDataException("A KeePass XML v2 key file must contain a key hash.");
        var expectedHash = Convert.ToHexString(SHA256.HashData(key).AsSpan(0, 4));

        if (!actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The KeePass XML v2 key-file hash is invalid.");
    }

    private static bool TryParseHex(byte[] data, out byte[]? key)
    {
        key = null;
        try
        {
            key = Convert.FromHexString(Encoding.ASCII.GetString(data).Trim());
            return key.Length == 32;
        }
        catch
        {
            return false;
        }
    }
}
