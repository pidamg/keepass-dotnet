using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Pidamg.KeePass;

/// <summary>
/// Represents a KeePass KDBX database and provides operations for creating, opening, searching,
/// and saving it.
/// </summary>
public sealed class KdbxDatabase : IDisposable
{

    /// <summary>
    /// Gets the file associated with the database, or <see langword="null"/> when no path is set.
    /// </summary>
    public FileInfo? FileInfo { get; private set; }

    /// <summary>
    /// Gets the database metadata.
    /// </summary>
    /// <exception cref="InvalidOperationException">The database has not been created or opened.</exception>
    public Metadata Metadata => _data?.Metadata ?? throw new InvalidOperationException("Database is not open.");

    /// <summary>
    /// Gets the root group.
    /// </summary>
    /// <exception cref="InvalidOperationException">The database has not been created or opened.</exception>
    public Group RootGroup => _data?.RootGroup ?? throw new InvalidOperationException("Database is not open.");

    private DatabaseData? _data;

    /// <summary>
    /// Gets or sets the settings used when saving the database.
    /// </summary>
    public KdbxSettings Settings { get; set; } = new();

    /// <summary>
    /// Gets the version read from the database or selected for a newly created database.
    /// </summary>
    public KdbxVersion Version { get; internal set; } = new();

    /// <summary>
    /// Gets a value indicating whether tracked database content has changed since it was opened or saved.
    /// </summary>
    public bool HasChanges { get; private set; }

    private CompositeKey _key = new();

    internal CompositeKey Key => _key;

    private readonly Dictionary<Guid, Entry> _entryIndex = new();

    // ── Constructors ──────────────────────────────────────────────────────────

    /// <summary>
    /// Initializes a database without a file path or key.
    /// </summary>
    public KdbxDatabase() { }

    /// <summary>
    /// Initializes a database with a composite key.
    /// </summary>
    /// <param name="key">The composite key used to unlock the database.</param>
    public KdbxDatabase(CompositeKey key)
    {
        _key = key;
    }

    /// <summary>
    /// Initializes a database associated with a file path.
    /// </summary>
    /// <param name="path">The path to the KDBX file.</param>
    public KdbxDatabase(string path)
    {
        FileInfo = new(path);
    }

    /// <summary>
    /// Initializes a database associated with a file path and composite key.
    /// </summary>
    /// <param name="path">The path to the KDBX file.</param>
    /// <param name="key">The composite key used to unlock the database.</param>
    public KdbxDatabase(string path, CompositeKey key)
    {
        FileInfo = new(path);
        _key = key;
    }

    /// <summary>
    /// Initializes a database associated with a file path and password.
    /// </summary>
    /// <param name="path">The path to the KDBX file.</param>
    /// <param name="password">The database password.</param>
    public KdbxDatabase(string path, string password)
    {
        FileInfo = new(path);
        _key = new(password);
    }

    /// <summary>
    /// Initializes a database associated with a file path, password, and key file.
    /// </summary>
    /// <param name="path">The path to the KDBX file.</param>
    /// <param name="password">The database password.</param>
    /// <param name="keyFile">The path to the key file.</param>
    /// <exception cref="IOException">The key file cannot be read.</exception>
    public KdbxDatabase(string path, string password, string keyFile)
    {
        FileInfo = new(path);
        _key = new(password, keyFile);
    }

    // ── Factory ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a new in-memory database protected by a password.
    /// </summary>
    /// <param name="password">The database password.</param>
    /// <returns>The initialized database.</returns>
    public static KdbxDatabase Create(string password) => Create(password, settings: null);

    /// <summary>
    /// Creates a new in-memory database protected by a password.
    /// </summary>
    /// <param name="password">The database password.</param>
    /// <param name="settings">The database settings, or <see langword="null"/> to use defaults.</param>
    /// <returns>The initialized database.</returns>
    public static KdbxDatabase Create(string password, KdbxSettings? settings)
    {
        var db = new KdbxDatabase(new CompositeKey(password));
        db.Settings = settings ?? new KdbxSettings();
        db.Version = db.Settings.Format == KdbxFormat.Kdbx4 ? new KdbxVersion(4, 1) : new KdbxVersion(3, 1);
        db._data = new DatabaseData(new Metadata(), new Group { Name = "Root" });
        db.RootGroup.SetDatabase(db);
        return db;
    }

    /// <summary>
    /// Creates a new in-memory database protected by a password and key file.
    /// </summary>
    /// <param name="password">The database password.</param>
    /// <param name="keyFile">The path to the key file.</param>
    /// <returns>The initialized database.</returns>
    /// <exception cref="IOException">The key file cannot be read.</exception>
    public static KdbxDatabase Create(string password, string keyFile) => Create(password, keyFile, settings: null);

    /// <summary>
    /// Creates a new in-memory database protected by a password and key file.
    /// </summary>
    /// <param name="password">The database password.</param>
    /// <param name="keyFile">The path to the key file.</param>
    /// <param name="settings">The database settings, or <see langword="null"/> to use defaults.</param>
    /// <returns>The initialized database.</returns>
    /// <exception cref="IOException">The key file cannot be read.</exception>
    public static KdbxDatabase Create(string password, string keyFile, KdbxSettings? settings)
    {
        var db = new KdbxDatabase(new CompositeKey(password, keyFile));
        db.Settings = settings ?? new KdbxSettings();
        db.Version = db.Settings.Format == KdbxFormat.Kdbx4 ? new KdbxVersion(4, 1) : new KdbxVersion(3, 1);
        db._data = new DatabaseData(new Metadata(), new Group { Name = "Root" });
        db.RootGroup.SetDatabase(db);
        return db;
    }

    // ── Read / Write ──────────────────────────────────────────────────────────

    /// <summary>
    /// Opens a database from a file using a password and optional key file.
    /// </summary>
    /// <param name="path">The path to the KDBX file.</param>
    /// <param name="password">The database password.</param>
    /// <param name="keyFile">The optional path to a key file.</param>
    /// <returns>The opened database.</returns>
    /// <exception cref="IOException">The database or key file cannot be read.</exception>
    /// <exception cref="InvalidDataException">The file is not a valid or supported KDBX database.</exception>
    /// <exception cref="CryptographicException">The database cannot be decrypted.</exception>
    public static KdbxDatabase Open(string path, string password, string? keyFile = null)
    {
        var db = keyFile != null
               ? new KdbxDatabase(path, password, keyFile)
               : new KdbxDatabase(path, password);
        db.Open();
        return db;
    }

    /// <summary>
    /// Opens the database from <see cref="FileInfo"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">No file path is associated with the database.</exception>
    /// <exception cref="IOException">The database file cannot be read.</exception>
    /// <exception cref="InvalidDataException">The file is not a valid or supported KDBX database.</exception>
    /// <exception cref="CryptographicException">The database cannot be decrypted.</exception>
    public void Open()
    {
        if (FileInfo == null)
            throw new InvalidOperationException("No file path set.");

        using var stream = FileInfo.OpenRead();
        new KdbxReader(this).ReadFrom(stream);
        HasChanges = false;
    }

    /// <summary>
    /// Saves the database to <see cref="FileInfo"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// No file path is associated with the database, or the settings are invalid for the selected format.
    /// </exception>
    /// <exception cref="IOException">The database file cannot be written.</exception>
    public void Save()
    {
        if (FileInfo == null)
            throw new InvalidOperationException("No file path set.");

        using var stream = FileInfo.Open(FileMode.Create);
        new KdbxWriter(this).WriteTo(stream);
        HasChanges = false;
    }

    /// <summary>
    /// Associates the database with a new path and saves it.
    /// </summary>
    /// <param name="path">The destination file path.</param>
    /// <exception cref="InvalidOperationException">The settings are invalid for the selected format.</exception>
    /// <exception cref="IOException">The database file cannot be written.</exception>
    public void SaveAs(string path)
    {
        FileInfo = new FileInfo(path);
        Save();
    }

    /// <summary>
    /// Asynchronously opens the database from <see cref="FileInfo"/>.
    /// </summary>
    /// <param name="ct">A token used to cancel file reading.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    /// <exception cref="InvalidOperationException">No file path is associated with the database.</exception>
    /// <exception cref="IOException">The database file cannot be read.</exception>
    /// <exception cref="InvalidDataException">The file is not a valid or supported KDBX database.</exception>
    /// <exception cref="CryptographicException">The database cannot be decrypted.</exception>
    /// <exception cref="OperationCanceledException">The operation is canceled.</exception>
    public async Task OpenAsync(CancellationToken ct = default)
    {
        if (FileInfo == null)
            throw new InvalidOperationException("No file path set.");
        byte[] bytes = await File.ReadAllBytesAsync(FileInfo.FullName, ct);
        new KdbxReader(this).ReadFrom(new MemoryStream(bytes));
        HasChanges = false;
    }

    /// <summary>
    /// Asynchronously saves the database to <see cref="FileInfo"/>.
    /// </summary>
    /// <param name="ct">A token used to cancel file writing.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    /// <exception cref="InvalidOperationException">
    /// No file path is associated with the database, or the settings are invalid for the selected format.
    /// </exception>
    /// <exception cref="IOException">The database file cannot be written.</exception>
    /// <exception cref="OperationCanceledException">The operation is canceled.</exception>
    public async Task SaveAsync(CancellationToken ct = default)
    {
        if (FileInfo == null)
            throw new InvalidOperationException("No file path set.");
        using var ms = new MemoryStream();
        new KdbxWriter(this).WriteTo(ms);
        await File.WriteAllBytesAsync(FileInfo.FullName, ms.ToArray(), ct);
        HasChanges = false;
    }

    /// <summary>
    /// Associates the database with a new path and asynchronously saves it.
    /// </summary>
    /// <param name="path">The destination file path.</param>
    /// <param name="ct">A token used to cancel file writing.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    /// <exception cref="InvalidOperationException">The settings are invalid for the selected format.</exception>
    /// <exception cref="IOException">The database file cannot be written.</exception>
    /// <exception cref="OperationCanceledException">The operation is canceled.</exception>
    public async Task SaveAsAsync(string path, CancellationToken ct = default)
    {
        FileInfo = new FileInfo(path);
        await SaveAsync(ct);
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    private void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key.Zeroize();
            _data = null;
        }
    }

    /// <summary>
    /// Releases sensitive key material and database data held by this instance.
    /// </summary>
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

    /// <summary>
    /// Finds the first entry whose title exactly matches the specified value.
    /// </summary>
    /// <param name="title">The title to find.</param>
    /// <returns>The first matching entry, or <see langword="null"/> if no match is found.</returns>
    public Entry? FindEntry(string title) => RootGroup.FindEntry(title);

    /// <summary>
    /// Finds the first entry that satisfies a predicate.
    /// </summary>
    /// <param name="predicate">The condition used to select an entry.</param>
    /// <returns>The first matching entry, or <see langword="null"/> if no match is found.</returns>
    public Entry? FindEntry(Func<Entry, bool> predicate) => RootGroup.FindEntry(predicate);

    /// <summary>
    /// Enumerates all entries that satisfy a predicate.
    /// </summary>
    /// <param name="predicate">The condition used to select entries.</param>
    /// <returns>A recursive, depth-first sequence of matching entries.</returns>
    public IEnumerable<Entry> FindAllEntries(Func<Entry, bool> predicate) => RootGroup.FindAllEntries(predicate);

    /// <summary>
    /// Finds the first group whose name exactly matches the specified value.
    /// </summary>
    /// <param name="name">The group name to find.</param>
    /// <returns>The first matching group, or <see langword="null"/> if no match is found.</returns>
    public Group? FindGroup(string name) => RootGroup.FindGroup(name);

    /// <summary>
    /// Finds the first group that satisfies a predicate.
    /// </summary>
    /// <param name="predicate">The condition used to select a group.</param>
    /// <returns>The first matching group, or <see langword="null"/> if no match is found.</returns>
    public Group? FindGroup(Func<Group, bool> predicate) => RootGroup.FindGroup(predicate);

    /// <summary>
    /// Enumerates all groups that satisfy a predicate.
    /// </summary>
    /// <param name="predicate">The condition used to select groups.</param>
    /// <returns>A recursive, depth-first sequence of matching groups.</returns>
    public IEnumerable<Group> FindAllGroups(Func<Group, bool> predicate) => RootGroup.FindAllGroups(predicate);

    // ── Recycle Bin ───────────────────────────────────────────────────────────

    /// <summary>
    /// Determines whether the recycle bin is enabled in the database metadata.
    /// </summary>
    /// <returns><see langword="true"/> when the recycle bin is enabled; otherwise, <see langword="false"/>.</returns>
    public bool IsRecycleBinEnabled() =>
        Metadata.RecycleBinEnabled;

    /// <summary>
    /// Gets the configured recycle-bin group.
    /// </summary>
    /// <returns>The recycle-bin group, or <see langword="null"/> if it is disabled or cannot be found.</returns>
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
