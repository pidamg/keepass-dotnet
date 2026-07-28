using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
        try
        {
            var doc = XDocument.Parse(Encoding.UTF8.GetString(data));
            var dataElement = doc.Root?.Element("Key")?.Element("Data");
            if (dataElement is null) return false;
            key = Convert.FromBase64String(dataElement.Value.Trim());
            return key.Length == 32;
        }
        catch
        {
            return false;
        }
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
