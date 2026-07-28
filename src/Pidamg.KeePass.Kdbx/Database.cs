using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Pidamg.KeePass.Kdbx;

public class Database : IDisposable
{

    public FileInfo? FileInfo { get; private set; }
    public Metadata Metadata => _data?.Metadata ?? throw new InvalidOperationException("Database is not open.");
    public Group RootGroup => _data?.RootGroup ?? throw new InvalidOperationException("Database is not open.");

    private DatabaseData? _data;
    public Settings Settings { get; set; } = new();
    public Version Version { get; internal set; } = new();
    public bool HasChanges { get; private set; }

    private CompositeKey _key = new();

    internal CompositeKey Key => _key;

    private readonly Dictionary<Guid, Entry> _entryIndex = new();

    // ── Constructors ──────────────────────────────────────────────────────────

    public Database() { }

    public Database(CompositeKey key)
    {
        _key = key;
    }

    public Database(string path)
    {
        FileInfo = new(path);
    }

    public Database(string path, CompositeKey key)
    {
        FileInfo = new(path);
        _key = key;
    }

    public Database(string path, string password)
    {
        FileInfo = new(path);
        _key = new(password);
    }

    public Database(string path, string password, string keyFile)
    {
        FileInfo = new(path);
        _key = new(password, keyFile);
    }

    // ── Factory ───────────────────────────────────────────────────────────────

    public static Database Create(string password, Settings? settings = null)
    {
        var db = new Database(new CompositeKey(password));
        db.Settings = settings ?? new Settings();
        db.Version = db.Settings.Format == KdbxFormat.Kdbx4 ? new Version(4, 1) : new Version(3, 1);
        db._data = new DatabaseData(new Metadata(), new Group { Name = "Root" });
        db.RootGroup.SetDatabase(db);
        return db;
    }

    public static Database Create(string password, string keyFile, Settings? settings = null)
    {
        var db = new Database(new CompositeKey(password, keyFile));
        db.Settings = settings ?? new Settings();
        db.Version = db.Settings.Format == KdbxFormat.Kdbx4 ? new Version(4, 1) : new Version(3, 1);
        db._data = new DatabaseData(new Metadata(), new Group { Name = "Root" });
        db.RootGroup.SetDatabase(db);
        return db;
    }

    // ── Read / Write ──────────────────────────────────────────────────────────

    public static Database Open(string path, string password, string? keyFile = null)
    {
        var db = keyFile != null
               ? new Database(path, password, keyFile)
               : new Database(path, password);
        db.Open();
        return db;
    }

    public void Open()
    {
        if (FileInfo == null)
            throw new InvalidOperationException("No file path set.");

        using var stream = FileInfo.OpenRead();
        new KdbxReader(this).ReadFrom(stream);
        HasChanges = false;
    }

    public void Save()
    {
        if (FileInfo == null)
            throw new InvalidOperationException("No file path set.");

        using var stream = FileInfo.Open(FileMode.Create);
        new KdbxWriter(this).WriteTo(stream);
        HasChanges = false;
    }

    public void SaveAs(string path)
    {
        FileInfo = new FileInfo(path);
        Save();
    }

    public async Task OpenAsync(CancellationToken ct = default)
    {
        if (FileInfo == null)
            throw new InvalidOperationException("No file path set.");
        byte[] bytes = await File.ReadAllBytesAsync(FileInfo.FullName, ct);
        new KdbxReader(this).ReadFrom(new MemoryStream(bytes));
        HasChanges = false;
    }

    public async Task SaveAsync(CancellationToken ct = default)
    {
        if (FileInfo == null)
            throw new InvalidOperationException("No file path set.");
        using var ms = new MemoryStream();
        new KdbxWriter(this).WriteTo(ms);
        await File.WriteAllBytesAsync(FileInfo.FullName, ms.ToArray(), ct);
        HasChanges = false;
    }

    public async Task SaveAsAsync(string path, CancellationToken ct = default)
    {
        FileInfo = new FileInfo(path);
        await SaveAsync(ct);
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key.Zeroize();
            _data = null;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    // ── Reference resolution ──────────────────────────────────────────────────

    // Resolves the value of a field, following {REF:...} references.
    // Returns the raw value if it is not a reference or if resolution fails.
    internal string ResolveField(Entry entry, string fieldName, int maxDepth = 10)
    {
        var value = entry.Strings.GetValueOrDefault(fieldName)?.Value ?? "";
        return ResolveValue(value, maxDepth);
    }

    // ── Index management ──────────────────────────────────────────────────────

    internal void SetChanged() => HasChanges = true;

    internal void IndexEntry(Entry entry)
    {
        _entryIndex[entry.Uuid] = entry;
    }

    internal void UnindexEntry(Entry entry)
    {
        _entryIndex.Remove(entry.Uuid);
    }

    // Indexes entries inside a group (db/pg references already set by AddGroup).
    internal void IndexGroup(Group group)
    {
        foreach (var entry in group.Entries)
            _entryIndex[entry.Uuid] = entry;
        foreach (var sub in group.Groups)
            IndexGroup(sub);
    }

    internal void UnindexGroup(Group group)
    {
        foreach (var entry in group.Entries)
            _entryIndex.Remove(entry.Uuid);
        foreach (var sub in group.Groups)
            UnindexGroup(sub);
    }

    // ── Recycle Bin ───────────────────────────────────────────────────────────

    // ── Search ────────────────────────────────────────────────────────────────

    public Entry? FindEntry(string title) => RootGroup.FindEntry(title);
    public Entry? FindEntry(Func<Entry, bool> predicate) => RootGroup.FindEntry(predicate);
    public IEnumerable<Entry> FindAllEntries(Func<Entry, bool> predicate) => RootGroup.FindAllEntries(predicate);
    public Group? FindGroup(string name) => RootGroup.FindGroup(name);
    public Group? FindGroup(Func<Group, bool> predicate) => RootGroup.FindGroup(predicate);
    public IEnumerable<Group> FindAllGroups(Func<Group, bool> predicate) => RootGroup.FindAllGroups(predicate);

    // ── Recycle Bin ───────────────────────────────────────────────────────────

    public bool IsRecycleBinEnabled() =>
        Metadata.RecycleBinEnabled;

    public Group? GetRecycleBin()
    {
        if (!IsRecycleBinEnabled() || Metadata.RecycleBinUuid == Guid.Empty)
            return null;
        return FindGroup(Metadata.RecycleBinUuid, RootGroup);
    }

    internal Group GetOrCreateRecycleBin()
    {
        var bin = FindGroup(Metadata.RecycleBinUuid, RootGroup);
        if (bin != null) return bin;

        bin = new Group
        {
            Uuid = Metadata.RecycleBinUuid,
            Name = "Recycle Bin",
            IsExpanded = false,
        };
        RootGroup.AddGroup(bin);
        return bin;
    }

    // ── Load wiring ───────────────────────────────────────────────────────────

    // Called by KdbxXmlReader after parsing. Sets _data, wires _db references,
    // and populates _entryIndex. The _pg references are already set during parsing
    // via Group.AddEntry / Group.AddGroup.
    internal void SetupLoadedData(DatabaseData data)
    {
        _data = data;
        _entryIndex.Clear();
        WireDatabase(data.RootGroup);
    }

    // Recursively sets _db on all groups/entries and populates _entryIndex.
    private void WireDatabase(Group group)
    {
        group.SetDatabase(this);
        foreach (var entry in group.Entries)
        {
            entry.SetDatabase(this);
            _entryIndex[entry.Uuid] = entry;
        }
        foreach (var sub in group.Groups)
            WireDatabase(sub);
    }

    private static Group? FindGroup(Guid uuid, Group? root)
    {
        if (root == null) return null;
        if (root.Uuid == uuid) return root;
        foreach (var sub in root.Groups)
        {
            var found = FindGroup(uuid, sub);
            if (found != null) return found;
        }
        return null;
    }

    private string ResolveValue(string value, int depth)
    {
        if (depth <= 0 || !FieldReference.TryParse(value, out var refInfo))
            return value;

        var target = FindReferencedEntry(refInfo);
        if (target == null) return value;

        var fieldKey = FieldReference.FieldCodeToKey(refInfo.WantedField);
        if (fieldKey == null) return value;

        var resolved = target.Strings.GetValueOrDefault(fieldKey)?.Value ?? "";
        return ResolveValue(resolved, depth - 1);
    }

    private Entry? FindReferencedEntry(FieldReference refInfo)
    {
        if (refInfo.SearchIn == 'I')
        {
            if (TryParseHexGuid(refInfo.SearchValue, out var uuid))
                return _entryIndex.GetValueOrDefault(uuid);
            return null;
        }

        var fieldKey = FieldReference.FieldCodeToKey(refInfo.SearchIn);
        if (fieldKey == null) return null;

        return _entryIndex.Values.FirstOrDefault(e =>
            e.Strings.GetValueOrDefault(fieldKey)?.Value == refInfo.SearchValue);
    }

    // KeePass reference UUIDs are 32 uppercase hex chars (no dashes, no braces).
    private static bool TryParseHexGuid(string hex, out Guid result)
    {
        result = Guid.Empty;
        if (hex.Length != 32) return false;
        var formatted = $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
        return Guid.TryParse(formatted, out result);
    }
}
