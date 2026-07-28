using System;

namespace Pidamg.KeePass;

/// <summary>
/// Represents a custom icon stored in database metadata.
/// </summary>
public class CustomIcon
{
    /// <summary>
    /// Initializes a custom icon with a new identifier.
    /// </summary>
    public CustomIcon() { }

    /// <summary>
    /// Gets or sets the icon identifier.
    /// </summary>
    public Guid Uuid { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets the PNG-encoded icon data.
    /// </summary>
    public byte[] Data { get; set; } = [];

    /// <summary>
    /// Gets or sets the icon name.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Gets or sets the optional last modification time.
    /// </summary>
    public DateTime? LastModificationTime { get; set; }
}
