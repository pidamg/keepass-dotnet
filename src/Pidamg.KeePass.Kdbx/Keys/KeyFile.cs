using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Pidamg.KeePass.Kdbx;

/// <summary>
/// Identifies the serialization format of a generated key file.
/// </summary>
public enum KeyFileFormat
{
    /// <summary>
    /// KeePass XML key-file format version 1.0.
    /// </summary>
    Xml,

    /// <summary>
    /// A raw 32-byte key.
    /// </summary>
    Raw
}

/// <summary>
/// Provides methods for generating KeePass key files.
/// </summary>
public static class KeyFile
{

    /// <summary>
    /// Generates a new random key file and writes it to <paramref name="path"/>.
    /// </summary>
    /// <param name="path">The path at which to create or overwrite the key file.</param>
    /// <param name="format">The key-file format.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is not supported.</exception>
    /// <exception cref="IOException">The key file cannot be written.</exception>
    public static void Generate(string path, KeyFileFormat format = KeyFileFormat.Xml)
    {
        var key32 = RandomNumberGenerator.GetBytes(32);
        var bytes = format switch
        {
            KeyFileFormat.Xml => BuildXml(key32),
            KeyFileFormat.Raw => key32,
            _ => throw new ArgumentOutOfRangeException(nameof(format)),
        };
        File.WriteAllBytes(path, bytes);
    }

    private static byte[] BuildXml(byte[] key32)
    {
        var doc = new XDocument(
            new XDeclaration("1.0", "utf-8", null),
            new XElement("KeyFile",
                new XElement("Meta",
                    new XElement("Version", "1.0")),
                new XElement("Key",
                    new XElement("Data", Convert.ToBase64String(key32)))));

        using var ms = new MemoryStream();
        using (var writer = new System.Xml.XmlTextWriter(ms, Encoding.UTF8) { Formatting = System.Xml.Formatting.Indented })
            doc.Save(writer);
        return ms.ToArray();
    }
}
