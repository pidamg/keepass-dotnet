using System.IO;
using System.Security.Cryptography;
using Pidamg.KeePass;

namespace Pidamg.KeePass.Kdbx.Tests;

public class KdbxVersionTests
{

    // ── new KdbxDatabase() ────────────────────────────────────────────────────────

    [Fact]
    public void Version_IsZero_BeforeOpen()
    {
        var db = new KdbxDatabase();
        Assert.True(db.Version.IsZero);
    }

    // ── KdbxDatabase.Create() ─────────────────────────────────────────────────────

    [Fact]
    public void Version_IsV4_AfterCreate_Default()
    {
        var db = KdbxDatabase.Create("pass");
        Assert.Equal(new KdbxVersion(4, 1), db.Version);
    }

    [Fact]
    public void Version_IsV3_AfterCreate_V3Settings()
    {
        var settings = new KdbxSettings
        {
            Format = KdbxFormat.Kdbx3,
            Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL),
        };
        var db = KdbxDatabase.Create("pass", settings);
        Assert.Equal(new KdbxVersion(3, 1), db.Version);
    }

    // ── After roundtrip ───────────────────────────────────────────────────────

    [Fact]
    public void Version_IsV4_AfterRoundTrip_V4()
    {
        var writeDb = KdbxDatabase.Create("pass");

        using var ms = new MemoryStream();
        new KdbxWriter(writeDb).WriteTo(ms);
        ms.Position = 0;

        var readDb = new KdbxDatabase(new CompositeKey().AddPassword("pass"));
        new KdbxReader(readDb).ReadFrom(ms);

        Assert.Equal(new KdbxVersion(4, 1), readDb.Version);
    }

    [Fact]
    public void Version_IsV3_AfterRoundTrip_V3()
    {
        var settings = new KdbxSettings
        {
            Format = KdbxFormat.Kdbx3,
            Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL),
        };
        var writeDb = KdbxDatabase.Create("pass", settings);

        using var ms = new MemoryStream();
        new KdbxWriter(writeDb).WriteTo(ms);
        ms.Position = 0;

        var readDb = new KdbxDatabase(new CompositeKey().AddPassword("pass"));
        new KdbxReader(readDb).ReadFrom(ms);

        Assert.Equal(new KdbxVersion(3, 1), readDb.Version);
    }

    // ── Comparison operators ──────────────────────────────────────────────────

    [Fact]
    public void Version_Comparison_Works()
    {
        var v4 = new KdbxVersion(4, 1);
        var v3 = new KdbxVersion(3, 1);

        Assert.True(v4 > v3);
        Assert.True(v3 < v4);
        Assert.True(v4 >= new KdbxVersion(4, 1));
        Assert.Equal(new KdbxVersion(4, 1), v4);
    }
}
