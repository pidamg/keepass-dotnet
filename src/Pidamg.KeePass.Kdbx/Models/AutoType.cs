using System.Collections.Generic;
using System.Linq;

namespace Pidamg.KeePass;

/// <summary>
/// Associates an auto-type sequence with a target window.
/// </summary>
public class AutoTypeAssociation
{
    /// <summary>
    /// Initializes an empty auto-type association.
    /// </summary>
    public AutoTypeAssociation() { }

    /// <summary>
    /// Gets or sets the window-title pattern.
    /// </summary>
    public string Window { get; set; } = "";

    /// <summary>
    /// Gets or sets the auto-type sequence used for matching windows.
    /// </summary>
    public string Sequence { get; set; } = "";
}

/// <summary>
/// Describes the auto-type configuration of an entry.
/// </summary>
public class AutoType
{
    /// <summary>
    /// Initializes an enabled auto-type configuration.
    /// </summary>
    public AutoType() { }

    /// <summary>
    /// Gets or sets a value indicating whether auto-type is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Gets or sets the KeePass data-transfer obfuscation mode.
    /// </summary>
    public int DataTransferObfuscation { get; set; }

    /// <summary>
    /// Gets or sets the default auto-type sequence.
    /// </summary>
    public string DefaultSequence { get; set; } = "";

    /// <summary>
    /// Gets or sets window-specific auto-type associations.
    /// </summary>
    public List<AutoTypeAssociation> Associations { get; set; } = [];

    /// <summary>
    /// Creates a deep copy of this auto-type configuration.
    /// </summary>
    /// <returns>The copied configuration.</returns>
    public AutoType Clone() => new()
    {
        Enabled = this.Enabled,
        DataTransferObfuscation = this.DataTransferObfuscation,
        DefaultSequence = this.DefaultSequence,
        Associations = this.Associations
            .Select(a => new AutoTypeAssociation { Window = a.Window, Sequence = a.Sequence })
            .ToList(),
    };
}
