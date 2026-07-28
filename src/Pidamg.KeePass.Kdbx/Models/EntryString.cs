namespace Pidamg.KeePass.Kdbx;

/// <summary>
/// Represents a named string value stored in an entry.
/// </summary>
public class EntryString
{
    /// <summary>
    /// Initializes an empty, unprotected string value.
    /// </summary>
    public EntryString() { }

    /// <summary>
    /// Gets or sets the string value.
    /// </summary>
    public string Value { get; set; } = "";

    /// <summary>
    /// Gets or sets a value indicating whether the value is protected in the KDBX XML.
    /// </summary>
    public bool Protected { get; set; }
}
