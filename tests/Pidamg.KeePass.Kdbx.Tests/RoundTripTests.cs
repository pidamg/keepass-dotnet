using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class RoundTripTests
{

    private static KdbxDatabase MakeDb(string password, KdbxFormat format = KdbxFormat.Kdbx4)
    {
        var settings = new KdbxSettings { Format = format };
        if (format == KdbxFormat.Kdbx3) settings.Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL);
        return KdbxDatabase.Create(password, settings);
    }

    // ── KDBX 4.x ─────────────────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_V4_ChaCha20_Argon2id()
    {
        var writeDb = MakeDb("hunter2");
        writeDb.Metadata.Name = "TestV4";

        using var ms = new MemoryStream();
        new KdbxWriter(writeDb).WriteTo(ms);

        ms.Position = 0;
        var readDb = new KdbxDatabase(new CompositeKey().AddPassword("hunter2"));
        new KdbxReader(readDb).ReadFrom(ms);

        Assert.Equal("TestV4", readDb.Metadata.Name);
    }

    // ── KDBX 3.x ─────────────────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_V3_ChaCha20_AesKdf()
    {
        var writeDb = MakeDb("correcthorsebatterystaple", KdbxFormat.Kdbx3);
        writeDb.Metadata.Name = "TestV3";

        using var ms = new MemoryStream();
        new KdbxWriter(writeDb).WriteTo(ms);

        ms.Position = 0;
        var readDb = new KdbxDatabase(new CompositeKey().AddPassword("correcthorsebatterystaple"));
        new KdbxReader(readDb).ReadFrom(ms);

        Assert.Equal("TestV3", readDb.Metadata.Name);
    }

    // ── Protected fields ─────────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_V4_ProtectedField_EncryptDecrypt()
    {
        var writeDb = MakeDb("pass");
        var entry = new Entry();
        entry.Strings["Password"] = new EntryString { Value = "MySecretPassword", Protected = true };
        writeDb.RootGroup.AddEntry(entry);

        using var ms = new MemoryStream();
        new KdbxWriter(writeDb).WriteTo(ms);

        ms.Position = 0;
        var readDb = new KdbxDatabase(new CompositeKey().AddPassword("pass"));
        new KdbxReader(readDb).ReadFrom(ms);

        var readEntry = readDb.RootGroup.Entries.First(e => e.Uuid == entry.Uuid);
        Assert.Equal("MySecretPassword", readEntry.Password);
    }

    // ── Empty database ────────────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_V4_EmptyDatabase()
    {
        var writeDb = MakeDb("");

        using var ms = new MemoryStream();
        new KdbxWriter(writeDb).WriteTo(ms);

        ms.Position = 0;
        var readDb = new KdbxDatabase(new CompositeKey().AddPassword(""));
        new KdbxReader(readDb).ReadFrom(ms);

        Assert.Equal("Root", readDb.RootGroup.Name);
    }
}
