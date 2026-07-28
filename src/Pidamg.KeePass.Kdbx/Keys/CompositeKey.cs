using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Pidamg.KeePass.Kdbx;

// Composite key = SHA256(component₁ ∥ component₂ ∥ …)
// Each component is 32 bytes:
//   password  → SHA256(UTF8(password))
//   key file  → 32-byte key extracted from the file (XML, hex, raw, or SHA256 fallback)
public class CompositeKey
{

    private readonly List<byte[]> _components = [];

    public CompositeKey() { }

    public CompositeKey(string password)
    {
        AddPassword(password);
    }

    public CompositeKey(string password, string keyFile)
    {
        AddPassword(password);
        AddKeyFile(keyFile);
    }

    public CompositeKey AddPassword(string password)
    {
        _components.Add(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
        return this;
    }

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
