using System;
using System.Collections.Generic;
using System.Linq;

namespace Pidamg.KeePass.Kdbx;

public class Entry
{

    private KdbxDatabase? _db = null;
    private Group? _pg = null;

    public KdbxDatabase? Database => _db;
    public Group? ParentGroup => _pg;

    public Guid Uuid { get; set; } = Guid.NewGuid();
    public int IconId { get; set; }
    public Guid CustomIconUuid { get; set; }
    public string ForegroundColor { get; set; } = "";
    public string BackgroundColor { get; set; } = "";
    public string OverrideUrl { get; set; } = "";
    public string Tags { get; set; } = "";
    public Times Times { get; set; } = Times.Create();
    public Dictionary<string, EntryString> Strings { get; set; } = new();
    public List<EntryBinary> Binaries { get; set; } = [];
    public AutoType AutoType { get; set; } = new();
    public List<Entry> History { get; set; } = [];

    public string Title
    {
        get => Strings.GetValueOrDefault("Title")?.Value ?? "";
        set => SetString("Title", value, defaultProtected: false);
    }
    public string UserName
    {
        get => Strings.GetValueOrDefault("UserName")?.Value ?? "";
        set => SetString("UserName", value, defaultProtected: false);
    }
    public string Password
    {
        get => Strings.GetValueOrDefault("Password")?.Value ?? "";
        set => SetString("Password", value, defaultProtected: true);
    }
    public string Url
    {
        get => Strings.GetValueOrDefault("URL")?.Value ?? "";
        set => SetString("URL", value, defaultProtected: false);
    }
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

    public void MoveTo(Group group)
    {
        _pg?.RemoveEntry(this);
        group.AddEntry(this);
    }

    public void Update(Action<Entry> update)
    {
        var snapshot = DeepCopy();
        update(this);
        History.Add(snapshot);
        TrimHistory();
        _db?.SetChanged();
    }

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
