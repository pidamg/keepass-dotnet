using System;
using System.IO;
using System.Linq;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class AutoTypeTests
{

    private static Database RoundTrip(Database writeDb)
    {
        using var ms = new MemoryStream();
        new KdbxWriter(writeDb).WriteTo(ms);
        ms.Position = 0;
        var readDb = new Database(new CompositeKey().AddPassword("pass"));
        new KdbxReader(readDb).ReadFrom(ms);
        return readDb;
    }

    private static (Database db, Entry entry) MakeDbWithEntry()
    {
        var db = Database.Create("pass");
        var entry = new Entry();
        db.RootGroup.AddEntry(entry);
        return (db, entry);
    }

    // ── AutoType.Enabled ─────────────────────────────────────────────────────

    [Fact]
    public void AutoType_Enabled_True_RoundTrip()
    {
        var (db, entry) = MakeDbWithEntry();
        entry.AutoType.Enabled = true;

        var read = RoundTrip(db).RootGroup.Entries[0];

        Assert.True(read.AutoType.Enabled);
    }

    [Fact]
    public void AutoType_Enabled_False_RoundTrip()
    {
        var (db, entry) = MakeDbWithEntry();
        entry.AutoType.Enabled = false;

        var read = RoundTrip(db).RootGroup.Entries[0];

        Assert.False(read.AutoType.Enabled);
    }

    // ── AutoType.DefaultSequence ──────────────────────────────────────────────

    [Fact]
    public void AutoType_DefaultSequence_RoundTrip()
    {
        var (db, entry) = MakeDbWithEntry();
        entry.AutoType.DefaultSequence = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

        var read = RoundTrip(db).RootGroup.Entries[0];

        Assert.Equal("{USERNAME}{TAB}{PASSWORD}{ENTER}", read.AutoType.DefaultSequence);
    }

    [Fact]
    public void AutoType_DefaultSequence_Empty_RoundTrip()
    {
        var (db, entry) = MakeDbWithEntry();
        entry.AutoType.DefaultSequence = "";

        var read = RoundTrip(db).RootGroup.Entries[0];

        Assert.Equal("", read.AutoType.DefaultSequence);
    }

    // ── AutoType.DataTransferObfuscation ──────────────────────────────────────

    [Fact]
    public void AutoType_DataTransferObfuscation_RoundTrip()
    {
        var (db, entry) = MakeDbWithEntry();
        entry.AutoType.DataTransferObfuscation = 1;

        var read = RoundTrip(db).RootGroup.Entries[0];

        Assert.Equal(1, read.AutoType.DataTransferObfuscation);
    }

    // ── AutoTypeAssociation ───────────────────────────────────────────────────

    [Fact]
    public void AutoType_SingleAssociation_RoundTrip()
    {
        var (db, entry) = MakeDbWithEntry();
        entry.AutoType.Associations.Add(new AutoTypeAssociation
        {
            Window = "Firefox*",
            Sequence = "{PASSWORD}{ENTER}",
        });

        var read = RoundTrip(db).RootGroup.Entries[0];

        Assert.Single(read.AutoType.Associations);
        Assert.Equal("Firefox*", read.AutoType.Associations[0].Window);
        Assert.Equal("{PASSWORD}{ENTER}", read.AutoType.Associations[0].Sequence);
    }

    [Fact]
    public void AutoType_MultipleAssociations_RoundTrip()
    {
        var (db, entry) = MakeDbWithEntry();
        entry.AutoType.Associations.Add(new AutoTypeAssociation { Window = "Firefox*", Sequence = "{PASSWORD}{ENTER}" });
        entry.AutoType.Associations.Add(new AutoTypeAssociation { Window = "Chrome*", Sequence = "{USERNAME}{TAB}{PASSWORD}" });
        entry.AutoType.Associations.Add(new AutoTypeAssociation { Window = "Terminal*", Sequence = "{PASSWORD}" });

        var read = RoundTrip(db).RootGroup.Entries[0];

        Assert.Equal(3, read.AutoType.Associations.Count);
        Assert.Equal("Firefox*", read.AutoType.Associations[0].Window);
        Assert.Equal("Chrome*", read.AutoType.Associations[1].Window);
        Assert.Equal("Terminal*", read.AutoType.Associations[2].Window);
    }

    [Fact]
    public void AutoType_NoAssociations_RoundTrip()
    {
        var (db, entry) = MakeDbWithEntry();
        // Default AutoType — no associations

        var read = RoundTrip(db).RootGroup.Entries[0];

        Assert.Empty(read.AutoType.Associations);
    }

    // ── All fields together ───────────────────────────────────────────────────

    [Fact]
    public void AutoType_AllFields_RoundTrip()
    {
        var (db, entry) = MakeDbWithEntry();
        entry.AutoType = new AutoType
        {
            Enabled = false,
            DataTransferObfuscation = 1,
            DefaultSequence = "{USERNAME}{TAB}{PASSWORD}",
            Associations = [
                new AutoTypeAssociation { Window = "App1*", Sequence = "{PASSWORD}" },
                new AutoTypeAssociation { Window = "App2*", Sequence = "{USERNAME}" },
            ],
        };

        var read = RoundTrip(db).RootGroup.Entries[0];

        Assert.False(read.AutoType.Enabled);
        Assert.Equal(1, read.AutoType.DataTransferObfuscation);
        Assert.Equal("{USERNAME}{TAB}{PASSWORD}", read.AutoType.DefaultSequence);
        Assert.Equal(2, read.AutoType.Associations.Count);
        Assert.Equal("App1*", read.AutoType.Associations[0].Window);
        Assert.Equal("App2*", read.AutoType.Associations[1].Window);
    }
}
