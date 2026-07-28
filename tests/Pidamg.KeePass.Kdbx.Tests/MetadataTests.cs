using System;
using System.IO;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class MetadataTests
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

    private static Database MakeDb() => Database.Create("pass");

    // ── Description ───────────────────────────────────────────────────────────

    [Fact]
    public void Metadata_Description_RoundTrip()
    {
        var db = MakeDb();
        db.Metadata.Description = "My password database";

        var read = RoundTrip(db);

        Assert.Equal("My password database", read.Metadata.Description);
    }

    [Fact]
    public void Metadata_Description_Empty_RoundTrip()
    {
        var db = MakeDb();
        db.Metadata.Description = "";

        var read = RoundTrip(db);

        Assert.Equal("", read.Metadata.Description);
    }

    // ── DefaultUserName ───────────────────────────────────────────────────────

    [Fact]
    public void Metadata_DefaultUserName_RoundTrip()
    {
        var db = MakeDb();
        db.Metadata.DefaultUserName = "alice";

        var read = RoundTrip(db);

        Assert.Equal("alice", read.Metadata.DefaultUserName);
    }

    // ── HistoryMaxSize ────────────────────────────────────────────────────────

    [Fact]
    public void Metadata_HistoryMaxSize_RoundTrip()
    {
        var db = MakeDb();
        db.Metadata.HistoryMaxSize = 10_485_760; // 10 MiB

        var read = RoundTrip(db);

        Assert.Equal(10_485_760, read.Metadata.HistoryMaxSize);
    }

    [Fact]
    public void Metadata_HistoryMaxSize_Default_RoundTrip()
    {
        var db = MakeDb(); // default = 6 MiB

        var read = RoundTrip(db);

        Assert.Equal(6_291_456, read.Metadata.HistoryMaxSize);
    }

    // ── HistoryMaxItems ───────────────────────────────────────────────────────

    [Fact]
    public void Metadata_HistoryMaxItems_RoundTrip()
    {
        var db = MakeDb();
        db.Metadata.HistoryMaxItems = 25;

        var read = RoundTrip(db);

        Assert.Equal(25, read.Metadata.HistoryMaxItems);
    }

    // ── RecycleBinEnabled ─────────────────────────────────────────────────────

    [Fact]
    public void Metadata_RecycleBinEnabled_False_RoundTrip()
    {
        var db = MakeDb();
        db.Metadata.RecycleBinEnabled = false;

        var read = RoundTrip(db);

        Assert.False(read.Metadata.RecycleBinEnabled);
    }

    [Fact]
    public void Metadata_RecycleBinUuid_RoundTrip()
    {
        var db = MakeDb();
        var binUuid = Guid.NewGuid();
        db.Metadata.RecycleBinUuid = binUuid;

        var read = RoundTrip(db);

        Assert.Equal(binUuid, read.Metadata.RecycleBinUuid);
    }

    // ── All fields together ───────────────────────────────────────────────────

    [Fact]
    public void Metadata_AllFields_RoundTrip()
    {
        var db = MakeDb();
        db.Metadata.Name = "Production";
        db.Metadata.Description = "Main database";
        db.Metadata.DefaultUserName = "bob";
        db.Metadata.HistoryMaxItems = 5;
        db.Metadata.HistoryMaxSize = 2_097_152; // 2 MiB
        db.Metadata.ProtectPassword = false;
        db.Metadata.RecycleBinEnabled = false;

        var read = RoundTrip(db);

        Assert.Equal("Production", read.Metadata.Name);
        Assert.Equal("Main database", read.Metadata.Description);
        Assert.Equal("bob", read.Metadata.DefaultUserName);
        Assert.Equal(5, read.Metadata.HistoryMaxItems);
        Assert.Equal(2_097_152, read.Metadata.HistoryMaxSize);
        Assert.False(read.Metadata.ProtectPassword);
        Assert.False(read.Metadata.RecycleBinEnabled);
    }
}
