namespace Pidamg.KeePass;

/// <summary>
/// Represents a binary attachment stored in an entry.
/// </summary>
public class EntryBinary
{
    /// <summary>
    /// Initializes an empty binary attachment.
    /// </summary>
    public EntryBinary() { }

    /// <summary>
    /// Gets or sets the attachment name.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Gets or sets the attachment data.
    /// </summary>
    public byte[] Data { get; set; } = [];

    /// <summary>
    /// Gets or sets a value indicating whether the attachment is protected in the KDBX XML.
    /// </summary>
    public bool IsProtected { get; set; }
}
