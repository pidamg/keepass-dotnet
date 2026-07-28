using System;
using System.Linq;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class CrudTests
{

    private static Database MakeDb() => Database.Create("pass");
    private static Entry NewEntry(string title = "E") => new() { Title = title };
    private static Group NewGroup(string name = "G") => new() { Name = name };

    // ── Entry : AddEntry / RemoveEntry ────────────────────────────────────────

    [Fact]
    public void AddEntry_SetsParentGroupAndDatabase()
    {
        var db = MakeDb();
        var entry = NewEntry();

        db.RootGroup.AddEntry(entry);

        Assert.Same(db.RootGroup, entry.ParentGroup);
        Assert.Same(db, entry.Database);
    }

    [Fact]
    public void AddEntry_Throws_WhenAlreadyInGroup()
    {
        var db = MakeDb();
        var entry = NewEntry();
        db.RootGroup.AddEntry(entry);

        Assert.Throws<InvalidOperationException>(() => db.RootGroup.AddEntry(entry));
    }

    [Fact]
    public void RemoveEntry_DetachesFromGroupAndDatabase()
    {
        var db = MakeDb();
        var entry = NewEntry();
        db.RootGroup.AddEntry(entry);

        db.RootGroup.RemoveEntry(entry);

        Assert.Empty(db.RootGroup.Entries);
        Assert.Null(entry.ParentGroup);
        Assert.Null(entry.Database);
    }

    [Fact]
    public void RemoveEntry_Throws_WhenNotInGroup()
    {
        var db = MakeDb();
        var entry = NewEntry();

        Assert.Throws<InvalidOperationException>(() => db.RootGroup.RemoveEntry(entry));
    }

    // ── Entry.Delete ──────────────────────────────────────────────────────────

    [Fact]
    public void Entry_Delete_WithoutRecycleBin_RemovesFromGroup()
    {
        var db = MakeDb();
        db.Metadata.RecycleBinEnabled = false;
        var entry = NewEntry();
        db.RootGroup.AddEntry(entry);

        entry.Delete();

        Assert.Empty(db.RootGroup.Entries);
        Assert.Null(entry.ParentGroup);
    }

    [Fact]
    public void Entry_Delete_WithRecycleBin_MovesToBin()
    {
        var db = MakeDb();
        var binUuid = Guid.NewGuid();
        db.Metadata.RecycleBinEnabled = true;
        db.Metadata.RecycleBinUuid = binUuid;
        var bin = new Group { Uuid = binUuid, Name = "Recycle Bin" };
        db.RootGroup.AddGroup(bin);

        var entry = NewEntry();
        db.RootGroup.AddEntry(entry);

        entry.Delete();

        Assert.Empty(db.RootGroup.Entries);
        Assert.Single(bin.Entries);
        Assert.Same(entry, bin.Entries[0]);
    }

    // ── Entry.MoveTo ──────────────────────────────────────────────────────────

    [Fact]
    public void Entry_MoveTo_ChangesParentGroup()
    {
        var db = MakeDb();
        var sub = NewGroup("Sub");
        db.RootGroup.AddGroup(sub);

        var entry = NewEntry();
        db.RootGroup.AddEntry(entry);

        entry.MoveTo(sub);

        Assert.Empty(db.RootGroup.Entries);
        Assert.Single(sub.Entries);
        Assert.Same(sub, entry.ParentGroup);
    }

    // ── Entry.Update ──────────────────────────────────────────────────────────

    [Fact]
    public void Entry_Update_AppliesChangeAndAddsSnapshotToHistory()
    {
        var db = MakeDb();
        var entry = NewEntry("Original");
        db.RootGroup.AddEntry(entry);

        entry.Update(e => e.Title = "Updated");

        Assert.Equal("Updated", entry.Title);
        Assert.Single(entry.History);
        Assert.Equal("Original", entry.History[0].Title);
    }

    [Fact]
    public void Entry_Update_TrimsHistoryToMaxItems()
    {
        var db = MakeDb();
        db.Metadata.HistoryMaxItems = 3;
        var entry = NewEntry();
        db.RootGroup.AddEntry(entry);

        for (int i = 0; i < 5; i++)
            entry.Update(e => e.Title = $"v{i}");

        Assert.Equal(3, entry.History.Count);
    }

    // ── Entry.Clone ───────────────────────────────────────────────────────────

    [Fact]
    public void Entry_Clone_HasNewUuid_AndCopiesData()
    {
        var db = MakeDb();
        var entry = NewEntry("Original");
        entry.UserName = "alice";
        entry.Binaries.Add(new EntryBinary { Name = "f.bin", Data = [1, 2, 3] });
        db.RootGroup.AddEntry(entry);

        var clone = entry.Clone();

        Assert.NotEqual(entry.Uuid, clone.Uuid);
        Assert.Equal("Original", clone.Title);
        Assert.Equal("alice", clone.UserName);
        Assert.Single(clone.Binaries);
        Assert.Equal("f.bin", clone.Binaries[0].Name);
    }

    [Fact]
    public void Entry_Clone_HistoryIsEmpty()
    {
        var db = MakeDb();
        var entry = NewEntry();
        db.RootGroup.AddEntry(entry);
        entry.Update(e => e.Title = "v2");

        var clone = entry.Clone();

        Assert.Empty(clone.History);
    }

    [Fact]
    public void Entry_Clone_IsIndependent()
    {
        var db = MakeDb();
        var entry = NewEntry("Original");
        db.RootGroup.AddEntry(entry);

        var clone = entry.Clone();
        clone.Title = "Modified";

        Assert.Equal("Original", entry.Title);
    }

    // ── Group : AddGroup / RemoveGroup ────────────────────────────────────────

    [Fact]
    public void AddGroup_SetsParentGroupAndDatabase()
    {
        var db = MakeDb();
        var sub = NewGroup("Sub");

        db.RootGroup.AddGroup(sub);

        Assert.Same(db.RootGroup, sub.ParentGroup);
        Assert.Same(db, sub.Database);
    }

    [Fact]
    public void AddGroup_Throws_WhenAlreadyInGroup()
    {
        var db = MakeDb();
        var sub = NewGroup();
        db.RootGroup.AddGroup(sub);

        Assert.Throws<InvalidOperationException>(() => db.RootGroup.AddGroup(sub));
    }

    [Fact]
    public void RemoveGroup_DetachesFromParentAndDatabase()
    {
        var db = MakeDb();
        var sub = NewGroup("Sub");
        db.RootGroup.AddGroup(sub);

        db.RootGroup.RemoveGroup(sub);

        Assert.Empty(db.RootGroup.Groups);
        Assert.Null(sub.ParentGroup);
        Assert.Null(sub.Database);
    }

    // ── Group.Delete ──────────────────────────────────────────────────────────

    [Fact]
    public void Group_Delete_WithoutRecycleBin_RemovesFromParent()
    {
        var db = MakeDb();
        db.Metadata.RecycleBinEnabled = false;
        var sub = NewGroup("Sub");
        db.RootGroup.AddGroup(sub);

        sub.Delete();

        Assert.Empty(db.RootGroup.Groups);
        Assert.Null(sub.ParentGroup);
    }

    [Fact]
    public void Group_Delete_WithRecycleBin_MovesToBin()
    {
        var db = MakeDb();
        var binUuid = Guid.NewGuid();
        db.Metadata.RecycleBinEnabled = true;
        db.Metadata.RecycleBinUuid = binUuid;
        var bin = new Group { Uuid = binUuid, Name = "Recycle Bin" };
        db.RootGroup.AddGroup(bin);

        var sub = NewGroup("ToDelete");
        db.RootGroup.AddGroup(sub);

        sub.Delete();

        Assert.DoesNotContain(sub, db.RootGroup.Groups);
        Assert.Contains(sub, bin.Groups);
    }

    // ── Group.MoveTo ──────────────────────────────────────────────────────────

    [Fact]
    public void Group_MoveTo_ChangesParent()
    {
        var db = MakeDb();
        var a = NewGroup("A");
        var b = NewGroup("B");
        db.RootGroup.AddGroup(a);
        db.RootGroup.AddGroup(b);

        a.MoveTo(b);

        Assert.DoesNotContain(a, db.RootGroup.Groups);
        Assert.Contains(a, b.Groups);
        Assert.Same(b, a.ParentGroup);
    }

    [Fact]
    public void Group_MoveTo_Self_Throws()
    {
        var db = MakeDb();
        var g = NewGroup();
        db.RootGroup.AddGroup(g);

        Assert.Throws<InvalidOperationException>(() => g.MoveTo(g));
    }

    [Fact]
    public void Group_MoveTo_Descendant_Throws()
    {
        var db = MakeDb();
        var parent = NewGroup("Parent");
        var child = NewGroup("Child");
        db.RootGroup.AddGroup(parent);
        parent.AddGroup(child);

        Assert.Throws<InvalidOperationException>(() => parent.MoveTo(child));
    }

    // ── Group.Clone ───────────────────────────────────────────────────────────

    [Fact]
    public void Group_Clone_HasNewUuid_AndCopiesChildrenDeep()
    {
        var db = MakeDb();
        var original = NewGroup("Original");
        var entry = NewEntry("E1");
        original.AddEntry(entry);
        var sub = NewGroup("Sub");
        original.AddGroup(sub);
        db.RootGroup.AddGroup(original);

        var clone = original.Clone();

        Assert.NotEqual(original.Uuid, clone.Uuid);
        Assert.Equal("Original", clone.Name);
        Assert.Single(clone.Entries);
        Assert.NotEqual(entry.Uuid, clone.Entries[0].Uuid);
        Assert.Equal("E1", clone.Entries[0].Title);
        Assert.Single(clone.Groups);
        Assert.Equal("Sub", clone.Groups[0].Name);
    }

    // ── Group.IsAncestorOf ────────────────────────────────────────────────────

    [Fact]
    public void Group_IsAncestorOf_ReturnsTrueForDirectAndIndirectChildren()
    {
        var db = MakeDb();
        var parent = NewGroup("Parent");
        var child = NewGroup("Child");
        var grandchild = NewGroup("Grandchild");
        db.RootGroup.AddGroup(parent);
        parent.AddGroup(child);
        child.AddGroup(grandchild);

        Assert.True(parent.IsAncestorOf(child));
        Assert.True(parent.IsAncestorOf(grandchild));
        Assert.True(child.IsAncestorOf(grandchild));
    }

    [Fact]
    public void Group_IsAncestorOf_ReturnsFalseForParentOrSibling()
    {
        var db = MakeDb();
        var parent = NewGroup("Parent");
        var child = NewGroup("Child");
        var sibling = NewGroup("Sibling");
        db.RootGroup.AddGroup(parent);
        parent.AddGroup(child);
        parent.AddGroup(sibling);

        Assert.False(child.IsAncestorOf(parent));
        Assert.False(child.IsAncestorOf(sibling));
    }

    // ── Database ──────────────────────────────────────────────────────────────

    [Fact]
    public void Database_HasChanges_FalseAfterCreate_TrueAfterCrud()
    {
        var db = MakeDb();
        Assert.False(db.HasChanges);

        db.RootGroup.AddEntry(NewEntry());

        Assert.True(db.HasChanges);
    }

    [Fact]
    public void Database_IsRecycleBinEnabled_TrueByDefault()
    {
        var db = MakeDb();
        Assert.True(db.IsRecycleBinEnabled());
    }

    [Fact]
    public void Database_IsRecycleBinEnabled_FalseWhenDisabled()
    {
        var db = MakeDb();
        db.Metadata.RecycleBinEnabled = false;
        Assert.False(db.IsRecycleBinEnabled());
    }

    [Fact]
    public void Database_GetRecycleBin_NullWhenUuidNotSet()
    {
        var db = MakeDb(); // RecycleBinUuid = Guid.Empty by default
        Assert.Null(db.GetRecycleBin());
    }

    [Fact]
    public void Database_GetRecycleBin_ReturnsGroup_WhenUuidSet()
    {
        var db = MakeDb();
        var binUuid = Guid.NewGuid();
        db.Metadata.RecycleBinUuid = binUuid;
        var bin = new Group { Uuid = binUuid, Name = "Trash" };
        db.RootGroup.AddGroup(bin);

        Assert.Same(bin, db.GetRecycleBin());
    }
}
