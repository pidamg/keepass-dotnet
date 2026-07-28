using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Pidamg.KeePass.Kdbx;

public class Group
{

    private KdbxDatabase? _db = null;
    private Group? _pg = null;

    public KdbxDatabase? Database => _db;
    public Group? ParentGroup => _pg;

    public Guid Uuid { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Notes { get; set; } = "";
    public int IconId { get; set; }
    public Guid CustomIconUuid { get; set; }
    public bool IsExpanded { get; set; } = true;
    public bool? EnableAutoType { get; set; }
    public bool? EnableSearching { get; set; }
    public Times Times { get; set; } = Times.Create();

    private readonly List<Entry> _entries = [];
    private readonly List<Group> _groups = [];

    public ReadOnlyCollection<Entry> Entries => _entries.AsReadOnly();
    public ReadOnlyCollection<Group> Groups => _groups.AsReadOnly();

    // ── CRUD ──────────────────────────────────────────────────────────────────

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

    public void MoveTo(Group parent)
    {
        if (parent == this)
            throw new InvalidOperationException("Cannot move a group into itself.");
        if (this.IsAncestorOf(parent))
            throw new InvalidOperationException("Cannot move a group into one of its descendants.");
        _pg?.RemoveGroup(this);
        parent.AddGroup(this);
    }

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

    public Entry? FindEntry(string title) =>
        FindEntry(e => e.Title == title);

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

    public IEnumerable<Entry> FindAllEntries(Func<Entry, bool> predicate)
    {
        foreach (var entry in _entries)
            if (predicate(entry)) yield return entry;
        foreach (var sub in _groups)
            foreach (var e in sub.FindAllEntries(predicate))
                yield return e;
    }

    public Group? FindGroup(string name) =>
        FindGroup(g => g.Name == name);

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

    public IEnumerable<Group> FindAllGroups(Func<Group, bool> predicate)
    {
        foreach (var sub in _groups)
        {
            if (predicate(sub)) yield return sub;
            foreach (var g in sub.FindAllGroups(predicate))
                yield return g;
        }
    }

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
