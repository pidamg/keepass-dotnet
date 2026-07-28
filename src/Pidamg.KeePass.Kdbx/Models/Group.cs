using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Pidamg.KeePass;

/// <summary>
/// Represents a group of entries and child groups in a KDBX database.
/// </summary>
public class Group
{

    private KdbxDatabase? _db = null;
    private Group? _pg = null;

    /// <summary>
    /// Initializes a detached group with a new identifier and current timestamps.
    /// </summary>
    public Group() { }

    /// <summary>
    /// Gets the database containing this group, or <see langword="null"/> when it is detached.
    /// </summary>
    public KdbxDatabase? Database => _db;

    /// <summary>
    /// Gets the parent group, or <see langword="null"/> for a root or detached group.
    /// </summary>
    public Group? ParentGroup => _pg;

    /// <summary>
    /// Gets or sets the group identifier.
    /// </summary>
    public Guid Uuid { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets the group name.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Gets or sets the group notes.
    /// </summary>
    public string Notes { get; set; } = "";

    /// <summary>
    /// Gets or sets the standard KeePass icon identifier.
    /// </summary>
    public int IconId { get; set; }

    /// <summary>
    /// Gets or sets the custom icon identifier.
    /// </summary>
    public Guid CustomIconUuid { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the group is expanded in the user interface.
    /// </summary>
    public bool IsExpanded { get; set; } = true;

    /// <summary>
    /// Gets or sets the nullable auto-type policy inherited by descendants.
    /// </summary>
    public bool? EnableAutoType { get; set; }

    /// <summary>
    /// Gets or sets the nullable search policy inherited by descendants.
    /// </summary>
    public bool? EnableSearching { get; set; }

    /// <summary>
    /// Gets or sets the group timestamps.
    /// </summary>
    public Times Times { get; set; } = Times.Create();

    private readonly List<Entry> _entries = [];
    private readonly List<Group> _groups = [];

    /// <summary>
    /// Gets a read-only view of the entries directly contained by this group.
    /// </summary>
    public ReadOnlyCollection<Entry> Entries => _entries.AsReadOnly();

    /// <summary>
    /// Gets a read-only view of the child groups directly contained by this group.
    /// </summary>
    public ReadOnlyCollection<Group> Groups => _groups.AsReadOnly();

    // ── CRUD ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Adds a detached entry to this group.
    /// </summary>
    /// <param name="entry">The entry to add.</param>
    /// <exception cref="InvalidOperationException">The entry already belongs to a group.</exception>
    public void AddEntry(Entry entry)
    {
        if (entry.ParentGroup != null)
            throw new InvalidOperationException("Entry is already in a group.");
        _entries.Add(entry);
        entry.SetDatabase(_db);
        entry.SetParentGroup(this);
        if (_db != null)
        {
            _db.IndexEntry(entry);
            _db.SetChanged();
        }
    }

    /// <summary>
    /// Removes an entry from this group.
    /// </summary>
    /// <param name="entry">The entry to remove.</param>
    /// <exception cref="InvalidOperationException">The entry does not belong to this group.</exception>
    public void RemoveEntry(Entry entry)
    {
        if (entry.ParentGroup != this)
            throw new InvalidOperationException("Entry is not in this group.");
        _entries.Remove(entry);
        entry.SetParentGroup(null);
        if (_db != null)
        {
            _db.UnindexEntry(entry);
            entry.SetDatabase(null);
            _db.SetChanged();
        }
    }

    /// <summary>
    /// Adds a detached child group to this group.
    /// </summary>
    /// <param name="group">The child group to add.</param>
    /// <exception cref="InvalidOperationException">The group already has a parent.</exception>
    public void AddGroup(Group group)
    {
        if (group.ParentGroup != null)
            throw new InvalidOperationException("Group is already in a group.");
        _groups.Add(group);
        group.SetParentGroup(this);
        group.SetDatabaseRecursive(_db);
        if (_db != null)
        {
            _db.IndexGroup(group);
            _db.SetChanged();
        }
    }

    /// <summary>
    /// Removes a child group from this group.
    /// </summary>
    /// <param name="group">The child group to remove.</param>
    /// <exception cref="InvalidOperationException">The group is not a child of this group.</exception>
    public void RemoveGroup(Group group)
    {
        if (group.ParentGroup != this)
            throw new InvalidOperationException("Group is not in this group.");
        _groups.Remove(group);
        group.SetParentGroup(null);
        if (_db != null)
        {
            _db.UnindexGroup(group);
            group.SetDatabaseRecursive(null);
            _db.SetChanged();
        }
    }

    // ── Navigation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Removes the group from its parent, moving it to the recycle bin when enabled.
    /// </summary>
    /// <remarks>This method has no effect when the group has no parent.</remarks>
    public void Delete()
    {
        if (_pg == null) return;
        if (_db?.IsRecycleBinEnabled() == true)
        {
            MoveTo(_db.GetOrCreateRecycleBin());
        }
        else
        {
            _pg.RemoveGroup(this);
        }
    }

    /// <summary>
    /// Moves the group under another parent.
    /// </summary>
    /// <param name="parent">The destination parent group.</param>
    /// <exception cref="InvalidOperationException">
    /// The destination is this group or one of its descendants, or cannot accept the group.
    /// </exception>
    public void MoveTo(Group parent)
    {
        if (parent == this)
            throw new InvalidOperationException("Cannot move a group into itself.");
        if (this.IsAncestorOf(parent))
            throw new InvalidOperationException("Cannot move a group into one of its descendants.");
        _pg?.RemoveGroup(this);
        parent.AddGroup(this);
    }

    /// <summary>
    /// Creates a detached deep copy of this group and all descendants with new identifiers.
    /// </summary>
    /// <returns>The cloned group hierarchy.</returns>
    public Group Clone()
    {
        var clone = new Group
        {
            Uuid = Guid.NewGuid(),
            Name = this.Name,
            Notes = this.Notes,
            IconId = this.IconId,
            CustomIconUuid = this.CustomIconUuid,
            IsExpanded = this.IsExpanded,
            EnableAutoType = this.EnableAutoType,
            EnableSearching = this.EnableSearching,
            Times = this.Times.Clone(),
        };
        foreach (var entry in this.Entries)
            clone.AddEntry(entry.Clone());
        foreach (var group in this.Groups)
            clone.AddGroup(group.Clone());
        return clone;
    }

    // ── Search ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Finds the first descendant entry whose title exactly matches the specified value.
    /// </summary>
    /// <param name="title">The title to find.</param>
    /// <returns>The first matching entry, or <see langword="null"/> if no match is found.</returns>
    public Entry? FindEntry(string title) =>
        FindEntry(e => e.Title == title);

    /// <summary>
    /// Finds the first descendant entry that satisfies a predicate.
    /// </summary>
    /// <param name="predicate">The condition used to select an entry.</param>
    /// <returns>The first matching entry, or <see langword="null"/> if no match is found.</returns>
    public Entry? FindEntry(Func<Entry, bool> predicate)
    {
        foreach (var entry in _entries)
            if (predicate(entry)) return entry;
        foreach (var sub in _groups)
        {
            var found = sub.FindEntry(predicate);
            if (found != null) return found;
        }
        return null;
    }

    /// <summary>
    /// Enumerates all descendant entries that satisfy a predicate.
    /// </summary>
    /// <param name="predicate">The condition used to select entries.</param>
    /// <returns>A depth-first sequence of matching entries.</returns>
    public IEnumerable<Entry> FindAllEntries(Func<Entry, bool> predicate)
    {
        foreach (var entry in _entries)
            if (predicate(entry)) yield return entry;
        foreach (var sub in _groups)
            foreach (var e in sub.FindAllEntries(predicate))
                yield return e;
    }

    /// <summary>
    /// Finds the first descendant group whose name exactly matches the specified value.
    /// </summary>
    /// <param name="name">The group name to find.</param>
    /// <returns>The first matching group, or <see langword="null"/> if no match is found.</returns>
    public Group? FindGroup(string name) =>
        FindGroup(g => g.Name == name);

    /// <summary>
    /// Finds the first descendant group that satisfies a predicate.
    /// </summary>
    /// <param name="predicate">The condition used to select a group.</param>
    /// <returns>The first matching group, or <see langword="null"/> if no match is found.</returns>
    public Group? FindGroup(Func<Group, bool> predicate)
    {
        foreach (var sub in _groups)
        {
            if (predicate(sub)) return sub;
            var found = sub.FindGroup(predicate);
            if (found != null) return found;
        }
        return null;
    }

    /// <summary>
    /// Enumerates all descendant groups that satisfy a predicate.
    /// </summary>
    /// <param name="predicate">The condition used to select groups.</param>
    /// <returns>A depth-first sequence of matching groups.</returns>
    public IEnumerable<Group> FindAllGroups(Func<Group, bool> predicate)
    {
        foreach (var sub in _groups)
        {
            if (predicate(sub)) yield return sub;
            foreach (var g in sub.FindAllGroups(predicate))
                yield return g;
        }
    }

    /// <summary>
    /// Determines whether this group is an ancestor of another group.
    /// </summary>
    /// <param name="group">The possible descendant.</param>
    /// <returns><see langword="true"/> if this group is an ancestor; otherwise, <see langword="false"/>.</returns>
    public bool IsAncestorOf(Group group)
    {
        var current = group;
        while (current._pg != null)
        {
            if (current == this) return true;
            current = current._pg;
        }
        return false;
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    internal void SetDatabase(KdbxDatabase? db) { _db = db; }
    internal void SetParentGroup(Group? group) { _pg = group; }

    internal void SetDatabaseRecursive(KdbxDatabase? db)
    {
        _db = db;
        foreach (var entry in _entries)
            entry.SetDatabase(db);
        foreach (var sub in _groups)
            sub.SetDatabaseRecursive(db);
    }
}
