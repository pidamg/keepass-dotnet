using System.Collections.Generic;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class RealFileTests
{

    // ── KDBX 4.x ─────────────────────────────────────────────────────────────

    [Fact]
    public void Read_SimplePasswordV4_ParsesXml()
    {
        var db = KdbxDatabase.Open(Helpers.Rsc("SimplePasswordV4.kdbx"), "password123");

        Assert.NotNull(db.Metadata);
        Assert.NotNull(db.RootGroup);
    }

    [Fact]
    public void Read_SimplePasswordV4_ContainsEntries()
    {
        var db = KdbxDatabase.Open(Helpers.Rsc("SimplePasswordV4.kdbx"), "password123");

        var entries = new List<Entry>();
        Helpers.CollectEntries(db.RootGroup, entries);
        Assert.NotEmpty(entries);
    }

    [Fact]
    public void Read_SimplePasswordV4_ProtectedFieldsDecrypt()
    {
        var db = KdbxDatabase.Open(Helpers.Rsc("SimplePasswordV4.kdbx"), "password123");

        var entries = new List<Entry>();
        Helpers.CollectEntries(db.RootGroup, entries);
        Assert.Contains(entries, e => !string.IsNullOrEmpty(e.Password));
    }

    [Fact]
    public void Read_WrongPassword_Throws()
    {
        Assert.ThrowsAny<System.Exception>(() =>
            KdbxDatabase.Open(Helpers.Rsc("SimplePasswordV4.kdbx"), "wrong_password"));
    }

    // ── KDBX 3.x ─────────────────────────────────────────────────────────────

    [Fact]
    public void Read_SimplePasswordV3_ChaCha20_ParsesXml()
    {
        var db = KdbxDatabase.Open(Helpers.Rsc("SimplePasswordV3_ChaCha20.kdbx"), "password123");

        Assert.NotNull(db.Metadata);
        Assert.NotNull(db.RootGroup);
    }

    [Fact]
    public void Read_SimplePasswordV3_ChaCha20_ContainsEntries()
    {
        var db = KdbxDatabase.Open(Helpers.Rsc("SimplePasswordV3_ChaCha20.kdbx"), "password123");

        var entries = new List<Entry>();
        Helpers.CollectEntries(db.RootGroup, entries);
        Assert.NotEmpty(entries);
    }

    [Fact]
    public void Read_SimplePasswordV3_ChaCha20_ProtectedFieldsDecrypt()
    {
        var db = KdbxDatabase.Open(Helpers.Rsc("SimplePasswordV3_ChaCha20.kdbx"), "password123");

        var entries = new List<Entry>();
        Helpers.CollectEntries(db.RootGroup, entries);
        Assert.Contains(entries, e => !string.IsNullOrEmpty(e.Password));
    }
}
