using System;

namespace Pidamg.KeePass.Kdbx;

/// <summary>
/// Represents creation, access, modification, expiration, and location timestamps for a KDBX item.
/// </summary>
public class Times
{
    /// <summary>
    /// Initializes an empty timestamp set.
    /// </summary>
    public Times() { }

    /// <summary>
    /// Gets or sets the creation time.
    /// </summary>
    public DateTime CreationTime { get; set; }

    /// <summary>
    /// Gets or sets the last modification time.
    /// </summary>
    public DateTime LastModificationTime { get; set; }

    /// <summary>
    /// Gets or sets the last access time.
    /// </summary>
    public DateTime LastAccessTime { get; set; }

    /// <summary>
    /// Gets or sets the expiration time.
    /// </summary>
    public DateTime ExpiryTime { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the item expires.
    /// </summary>
    public bool Expires { get; set; }

    /// <summary>
    /// Gets or sets the usage count.
    /// </summary>
    public int UsageCount { get; set; }

    /// <summary>
    /// Gets or sets the time at which the item was last moved.
    /// </summary>
    public DateTime LocationChanged { get; set; }

    /// <summary>
    /// Creates timestamps initialized with the current UTC time for creation and modification.
    /// </summary>
    /// <returns>The initialized timestamps.</returns>
    public static Times Create()
    {
        var now = DateTime.UtcNow;
        return new Times
        {
            CreationTime = now,
            LastModificationTime = now,
        };
    }

    /// <summary>
    /// Creates a copy of this timestamp set.
    /// </summary>
    /// <returns>The copied timestamps.</returns>
    public Times Clone() => new()
    {
        CreationTime = this.CreationTime,
        LastModificationTime = this.LastModificationTime,
        LastAccessTime = this.LastAccessTime,
        ExpiryTime = this.ExpiryTime,
        Expires = this.Expires,
        UsageCount = this.UsageCount,
        LocationChanged = this.LocationChanged,
    };

}
