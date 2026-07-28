using System;
using System.Collections.Generic;
using System.Linq;

namespace Pidamg.KeePass.Kdbx;

/// <summary>
/// Represents a credential entry in a KDBX database.
/// </summary>
public class Entry
{

    private KdbxDatabase? _db = null;
    private Group? _pg = null;

    /// <summary>
    /// Initializes a detached entry with a new identifier and current timestamps.
    /// </summary>
    public Entry() { }

    /// <summary>
    /// Gets the database containing this entry, or <see langword="null"/> when it is detached.
    /// </summary>
    public KdbxDatabase? Database => _db;

    /// <summary>
    /// Gets the group containing this entry, or <see langword="null"/> when it is detached.
    /// </summary>
    public Group? ParentGroup => _pg;

    /// <summary>
    /// Gets or sets the entry identifier.
    /// </summary>
    public Guid Uuid { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets the standard KeePass icon identifier.
    /// </summary>
    public int IconId { get; set; }

    /// <summary>
    /// Gets or sets the custom icon identifier.
    /// </summary>
    public Guid CustomIconUuid { get; set; }

    /// <summary>
    /// Gets or sets the foreground color in KDBX color notation.
    /// </summary>
    public string ForegroundColor { get; set; } = "";

    /// <summary>
    /// Gets or sets the background color in KDBX color notation.
    /// </summary>
    public string BackgroundColor { get; set; } = "";

    /// <summary>
    /// Gets or sets the URL override used by KeePass.
    /// </summary>
    public string OverrideUrl { get; set; } = "";

    /// <summary>
    /// Gets or sets the entry tags in their KDBX serialized form.
    /// </summary>
    public string Tags { get; set; } = "";

    /// <summary>
    /// Gets or sets the entry timestamps.
    /// </summary>
    public Times Times { get; set; } = Times.Create();

    /// <summary>
    /// Gets or sets the entry's named string fields.
    /// </summary>
    public Dictionary<string, EntryString> Strings { get; set; } = new();

    /// <summary>
    /// Gets or sets the binary attachments.
    /// </summary>
    public List<EntryBinary> Binaries { get; set; } = [];

    /// <summary>
    /// Gets or sets the auto-type configuration.
    /// </summary>
    public AutoType AutoType { get; set; } = new();

    /// <summary>
    /// Gets or sets previous snapshots of the entry.
    /// </summary>
    public List<Entry> History { get; set; } = [];

    /// <summary>
    /// Gets or sets the standard <c>Title</c> field.
    /// </summary>
    public string Title
    {
        get => Strings.GetValueOrDefault("Title")?.Value ?? "";
        set => SetString("Title", value, defaultProtected: false);
    }
    /// <summary>
    /// Gets or sets the standard <c>UserName</c> field.
    /// </summary>
    public string UserName
    {
        get => Strings.GetValueOrDefault("UserName")?.Value ?? "";
        set => SetString("UserName", value, defaultProtected: false);
    }
    /// <summary>
    /// Gets or sets the standard <c>Password</c> field.
    /// </summary>
    /// <remarks>New password fields are protected by default.</remarks>
    public string Password
    {
        get => Strings.GetValueOrDefault("Password")?.Value ?? "";
        set => SetString("Password", value, defaultProtected: true);
    }
    /// <summary>
    /// Gets or sets the standard <c>URL</c> field.
    /// </summary>
    public string Url
    {
        get => Strings.GetValueOrDefault("URL")?.Value ?? "";
        set => SetString("URL", value, defaultProtected: false);
    }
    /// <summary>
    /// Gets or sets the standard <c>Notes</c> field.
    /// </summary>
    public string Notes
    {
        get => Strings.GetValueOrDefault("Notes")?.Value ?? "";
        set => SetString("Notes", value, defaultProtected: false);
    }

    private void SetString(string key, string value, bool defaultProtected)
    {
        if (Strings.TryGetValue(key, out var existing))
            existing.Value = value;
        else
            Strings[key] = new EntryString { Value = value, Protected = defaultProtected };
    }

    // ── CRUD ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Removes the entry from its group, moving it to the recycle bin when enabled.
    /// </summary>
    /// <remarks>This method has no effect when the entry is detached.</remarks>
    public void Delete()
    {
        if (_pg == null) return;
        if (_db?.IsRecycleBinEnabled() == true)
        {
            MoveTo(_db.GetOrCreateRecycleBin());
        }
        else
        {
            _pg.RemoveEntry(this);
        }
    }

    /// <summary>
    /// Moves the entry to another group.
    /// </summary>
    /// <param name="group">The destination group.</param>
    /// <exception cref="InvalidOperationException">The destination group cannot accept the entry.</exception>
    public void MoveTo(Group group)
    {
        _pg?.RemoveEntry(this);
        group.AddEntry(this);
    }

    /// <summary>
    /// Applies an update and records the previous state in entry history.
    /// </summary>
    /// <param name="update">The update to apply.</param>
    public void Update(Action<Entry> update)
    {
        var snapshot = DeepCopy();
        update(this);
        History.Add(snapshot);
        TrimHistory();
        _db?.SetChanged();
    }

    /// <summary>
    /// Creates a detached deep copy with a new identifier and no history.
    /// </summary>
    /// <returns>The cloned entry.</returns>
    public Entry Clone()
    {
        var clone = DeepCopy();
        clone.Uuid = Guid.NewGuid();
        clone.History.Clear();
        return clone;
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    internal void SetDatabase(KdbxDatabase? db) { _db = db; }
    internal void SetParentGroup(Group? group) { _pg = group; }

    // ── Private ───────────────────────────────────────────────────────────────

    // Full copy preserving UUID — used for history snapshots and as base for Clone.
    // Does not copy _db/_pg references.
    private Entry DeepCopy()
    {
        var copy = new Entry
        {
            Uuid = this.Uuid,
            IconId = this.IconId,
            CustomIconUuid = this.CustomIconUuid,
            ForegroundColor = this.ForegroundColor,
            BackgroundColor = this.BackgroundColor,
            OverrideUrl = this.OverrideUrl,
            Tags = this.Tags,
            Times = this.Times.Clone(),
            AutoType = CloneAutoType(this.AutoType),
        };
        foreach (var (k, v) in this.Strings)
            copy.Strings[k] = new EntryString { Value = v.Value, Protected = v.Protected };
        foreach (var b in this.Binaries)
            copy.Binaries.Add(new EntryBinary { Name = b.Name, Data = b.Data[..], IsProtected = b.IsProtected });
        // History is intentionally not copied — snapshots must not nest.
        return copy;
    }

    private void TrimHistory()
    {
        int maxItems = _db?.Metadata?.HistoryMaxItems ?? 10;
        while (History.Count > maxItems)
            History.RemoveAt(0);
    }

    private static AutoType CloneAutoType(AutoType at) => new()
    {
        Enabled = at.Enabled,
        DataTransferObfuscation = at.DataTransferObfuscation,
        DefaultSequence = at.DefaultSequence,
        Associations = at.Associations
            .Select(a => new AutoTypeAssociation { Window = a.Window, Sequence = a.Sequence })
            .ToList(),
    };
}
