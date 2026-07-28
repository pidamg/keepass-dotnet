using System.Linq;
using Pidamg.KeePass;

namespace Pidamg.KeePass.Kdbx.Tests;

public class FindTests
{

    private static KdbxDatabase MakeDb()
    {
        var db = KdbxDatabase.Create("pass");
        var sub = new Group { Name = "Work" };
        var deep = new Group { Name = "Dev" };

        var e1 = new Entry(); e1.Title = "GitHub"; e1.UserName = "alice"; db.RootGroup.AddEntry(e1);
        var e2 = new Entry(); e2.Title = "Gmail"; e2.UserName = "alice"; db.RootGroup.AddEntry(e2);
        var e3 = new Entry(); e3.Title = "Jira"; e3.UserName = "bob"; sub.AddEntry(e3);
        var e4 = new Entry(); e4.Title = "Bitbucket"; e4.UserName = "bob"; deep.AddEntry(e4);

        sub.AddGroup(deep);
        db.RootGroup.AddGroup(sub);
        return db;
    }

    // ── FindEntry(string) ─────────────────────────────────────────────────────

    [Fact]
    public void FindEntry_ByTitle_FoundInRoot()
    {
        var db = MakeDb();
        var entry = db.FindEntry("GitHub");
        Assert.NotNull(entry);
        Assert.Equal("GitHub", entry!.Title);
    }

    [Fact]
    public void FindEntry_ByTitle_FoundInNestedGroup()
    {
        var db = MakeDb();
        var entry = db.FindEntry("Bitbucket");
        Assert.NotNull(entry);
        Assert.Equal("Bitbucket", entry!.Title);
    }

    [Fact]
    public void FindEntry_ByTitle_NotFound_ReturnsNull()
    {
        var db = MakeDb();
        Assert.Null(db.FindEntry("NotExisting"));
    }

    // ── FindEntry(Func<>) ─────────────────────────────────────────────────────

    [Fact]
    public void FindEntry_ByPredicate_FoundInSubGroup()
    {
        var db = MakeDb();
        var entry = db.FindEntry(e => e.UserName == "bob");
        Assert.NotNull(entry);
        Assert.Equal("bob", entry!.UserName);
    }

    [Fact]
    public void FindEntry_ByPredicate_NotFound_ReturnsNull()
    {
        var db = MakeDb();
        Assert.Null(db.FindEntry(e => e.UserName == "nobody"));
    }

    // ── FindAllEntries(Func<>) ────────────────────────────────────────────────

    [Fact]
    public void FindAllEntries_ReturnsAllMatching()
    {
        var db = MakeDb();
        var results = db.FindAllEntries(e => e.UserName == "alice").ToList();
        Assert.Equal(2, results.Count);
        Assert.Contains(results, e => e.Title == "GitHub");
        Assert.Contains(results, e => e.Title == "Gmail");
    }

    [Fact]
    public void FindAllEntries_ReturnsAllAcrossDepths()
    {
        var db = MakeDb();
        var results = db.FindAllEntries(e => e.UserName == "bob").ToList();
        Assert.Equal(2, results.Count);
        Assert.Contains(results, e => e.Title == "Jira");
        Assert.Contains(results, e => e.Title == "Bitbucket");
    }

    [Fact]
    public void FindAllEntries_NoMatch_ReturnsEmpty()
    {
        var db = MakeDb();
        Assert.Empty(db.FindAllEntries(e => e.Title == "Nothing"));
    }

    // ── FindGroup(string) ─────────────────────────────────────────────────────

    [Fact]
    public void FindGroup_ByName_FoundDirect()
    {
        var db = MakeDb();
        var group = db.FindGroup("Work");
        Assert.NotNull(group);
        Assert.Equal("Work", group!.Name);
    }

    [Fact]
    public void FindGroup_ByName_FoundNested()
    {
        var db = MakeDb();
        var group = db.FindGroup("Dev");
        Assert.NotNull(group);
        Assert.Equal("Dev", group!.Name);
    }

    [Fact]
    public void FindGroup_ByName_NotFound_ReturnsNull()
    {
        var db = MakeDb();
        Assert.Null(db.FindGroup("NotExisting"));
    }

    // ── FindGroup(Func<>) ─────────────────────────────────────────────────────

    [Fact]
    public void FindGroup_ByPredicate_Found()
    {
        var db = MakeDb();
        var group = db.FindGroup(g => g.Name.StartsWith("De"));
        Assert.NotNull(group);
        Assert.Equal("Dev", group!.Name);
    }

    [Fact]
    public void FindGroup_ByPredicate_NotFound_ReturnsNull()
    {
        var db = MakeDb();
        Assert.Null(db.FindGroup(g => g.Name == "Nobody"));
    }

    // ── FindAllGroups(Func<>) ─────────────────────────────────────────────────

    [Fact]
    public void FindAllGroups_ReturnsAllMatching()
    {
        var db = MakeDb();
        var results = db.FindAllGroups(g => g.Name.Length > 2).ToList();
        Assert.Equal(2, results.Count);
        Assert.Contains(results, g => g.Name == "Work");
        Assert.Contains(results, g => g.Name == "Dev");
    }

    [Fact]
    public void FindAllGroups_NoMatch_ReturnsEmpty()
    {
        var db = MakeDb();
        Assert.Empty(db.FindAllGroups(g => g.Name == "Nothing"));
    }

    // ── Directly on Group ────────────────────────────────────────────────────

    [Fact]
    public void Group_FindEntry_SearchesOnlySubtree()
    {
        var db = MakeDb();
        var work = db.FindGroup("Work")!;

        // "GitHub" is in Root, not in Work
        Assert.Null(work.FindEntry("GitHub"));
        // "Jira" is in Work
        Assert.NotNull(work.FindEntry("Jira"));
    }

    [Fact]
    public void Group_FindGroup_DoesNotReturnSelf()
    {
        var db = MakeDb();
        var work = db.FindGroup("Work")!;

        // FindGroup on Work should not return Work itself
        Assert.Null(work.FindGroup("Work"));
        // But should find its child Dev
        Assert.NotNull(work.FindGroup("Dev"));
    }
}
