using System;
using System.IO;
using System.Security.Cryptography;
using Pidamg.KeePass;

namespace Pidamg.KeePass.Kdbx.Tests;

public class SaveTests : IDisposable
{

    private readonly string _tempDir;

    public SaveTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);

    private string TempFile(string name = "test.kdbx") => Path.Combine(_tempDir, name);

    // ── SaveAs ────────────────────────────────────────────────────────────────

    [Fact]
    public void SaveAs_CreatesFile()
    {
        var db = KdbxDatabase.Create("pass");
        var path = TempFile();

        db.SaveAs(path);

        Assert.True(File.Exists(path));
        Assert.True(new FileInfo(path).Length > 0);
    }

    [Fact]
    public void SaveAs_ClearsHasChanges()
    {
        var db = KdbxDatabase.Create("pass");
        db.RootGroup.AddEntry(new Entry { Title = "E" });
        Assert.True(db.HasChanges);

        db.SaveAs(TempFile());

        Assert.False(db.HasChanges);
    }

    [Fact]
    public void SaveAs_SetsFileInfo()
    {
        var db = KdbxDatabase.Create("pass");
        var path = TempFile();

        db.SaveAs(path);

        Assert.NotNull(db.FileInfo);
        Assert.Equal(path, db.FileInfo!.FullName);
    }

    [Fact]
    public void SaveAs_ThenOpen_RoundTrip_V4()
    {
        var path = TempFile();

        var writeDb = KdbxDatabase.Create("hunter2");
        writeDb.Metadata.Name = "SavedV4";
        var entry = new Entry();
        entry.Title = "GitHub";
        entry.UserName = "alice";
        entry.Password = "s3cr3t!";
        writeDb.RootGroup.AddEntry(entry);
        writeDb.SaveAs(path);

        var readDb = KdbxDatabase.Open(path, "hunter2");

        Assert.Equal("SavedV4", readDb.Metadata.Name);
        Assert.Single(readDb.RootGroup.Entries);
        var readEntry = readDb.RootGroup.Entries[0];
        Assert.Equal("GitHub", readEntry.Title);
        Assert.Equal("alice", readEntry.UserName);
        Assert.Equal("s3cr3t!", readEntry.Password);
    }

    [Fact]
    public void SaveAs_ThenOpen_RoundTrip_V3()
    {
        var path = TempFile();
        var settings = new KdbxSettings
        {
            Format = KdbxFormat.Kdbx3,
            Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL),
        };

        var writeDb = KdbxDatabase.Create("pass", settings);
        writeDb.Metadata.Name = "SavedV3";
        writeDb.SaveAs(path);

        var readDb = KdbxDatabase.Open(path, "pass");

        Assert.Equal("SavedV3", readDb.Metadata.Name);
    }

    [Fact]
    public void SaveAs_WrongPassword_Throws()
    {
        var path = TempFile();
        KdbxDatabase.Create("correctpass").SaveAs(path);

        Assert.ThrowsAny<Exception>(() => KdbxDatabase.Open(path, "wrongpass"));
    }

    // ── Save ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Save_OverwritesExistingFile()
    {
        var path = TempFile();

        var db = KdbxDatabase.Create("pass");
        db.Metadata.Name = "v1";
        db.SaveAs(path);
        long sizeV1 = new FileInfo(path).Length;

        db.Metadata.Name = "version2-with-longer-name";
        db.Save();

        var readDb = KdbxDatabase.Open(path, "pass");
        Assert.Equal("version2-with-longer-name", readDb.Metadata.Name);
    }

    [Fact]
    public void Save_WithoutFileInfo_Throws()
    {
        var db = new KdbxDatabase(new CompositeKey().AddPassword("pass"));

        Assert.Throws<InvalidOperationException>(() => db.Save());
    }

    // ── SaveAs + re-open with multiple entries ───────────────────────────────

    [Fact]
    public void SaveAs_MultipleEntries_AllPreserved()
    {
        var path = TempFile();

        var writeDb = KdbxDatabase.Create("pass");
        for (int i = 0; i < 5; i++)
        {
            var e = new Entry();
            e.Title = $"Entry {i}";
            e.Password = $"pw{i}";
            writeDb.RootGroup.AddEntry(e);
        }
        writeDb.SaveAs(path);

        var readDb = KdbxDatabase.Open(path, "pass");

        Assert.Equal(5, readDb.RootGroup.Entries.Count);
        for (int i = 0; i < 5; i++)
            Assert.Equal($"pw{i}", readDb.RootGroup.Entries[i].Password);
    }

    [Fact]
    public void SaveAs_WithSubGroups_AllPreserved()
    {
        var path = TempFile();

        var writeDb = KdbxDatabase.Create("pass");
        var sub = new Group { Name = "Work" };
        var entry = new Entry();
        entry.Title = "Laptop";
        sub.AddEntry(entry);
        writeDb.RootGroup.AddGroup(sub);
        writeDb.SaveAs(path);

        var readDb = KdbxDatabase.Open(path, "pass");

        Assert.Single(readDb.RootGroup.Groups);
        Assert.Equal("Work", readDb.RootGroup.Groups[0].Name);
        Assert.Single(readDb.RootGroup.Groups[0].Entries);
        Assert.Equal("Laptop", readDb.RootGroup.Groups[0].Entries[0].Title);
    }
}
