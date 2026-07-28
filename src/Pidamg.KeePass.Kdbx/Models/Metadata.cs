using System;
using System.Collections.Generic;

namespace Pidamg.KeePass;

/// <summary>
/// Represents database-wide KDBX metadata.
/// </summary>
public class Metadata
{
    /// <summary>
    /// Initializes database metadata with default history and recycle-bin settings.
    /// </summary>
    public Metadata() { }

    /// <summary>
    /// Gets or sets the database name.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Gets or sets the database description.
    /// </summary>
    public string Description { get; set; } = "";

    /// <summary>
    /// Gets or sets the default user name for new entries.
    /// </summary>
    public string DefaultUserName { get; set; } = "";

    /// <summary>
    /// Gets or sets a value indicating whether the recycle bin is enabled.
    /// </summary>
    public bool RecycleBinEnabled { get; set; } = true;

    /// <summary>
    /// Gets or sets the identifier of the recycle-bin group.
    /// </summary>
    public Guid RecycleBinUuid { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of history items retained per entry.
    /// </summary>
    public int HistoryMaxItems { get; set; } = 10;

    /// <summary>
    /// Gets or sets the maximum history size, in bytes.
    /// </summary>
    public long HistoryMaxSize { get; set; } = 6_291_456;

    /// <summary>
    /// Gets or sets a value indicating whether password fields are protected in the KDBX XML.
    /// </summary>
    public bool ProtectPassword { get; set; } = true;

    /// <summary>
    /// Gets or sets the custom icons stored by the database.
    /// </summary>
    public List<CustomIcon> CustomIcons { get; set; } = [];
}
