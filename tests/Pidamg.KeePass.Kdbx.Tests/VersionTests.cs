using System.IO;
using System.Security.Cryptography;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class VersionTests
{

    // ── new Database() ────────────────────────────────────────────────────────

    [Fact]
    public void Version_IsZero_BeforeOpen()
    {
        var db = new Database();
        Assert.True(db.Version.IsZero);
    }

    // ── Database.Create() ─────────────────────────────────────────────────────

    [Fact]
    public void Version_IsV4_AfterCreate_Default()
    {
        var db = Database.Create("pass");
        Assert.Equal(new Version(4, 1), db.Version);
    }

    [Fact]
    public void Version_IsV3_AfterCreate_V3Settings()
    {
        var settings = new Settings
        {
            Format = KdbxFormat.Kdbx3,
            Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL),
        };
        var db = Database.Create("pass", settings);
        Assert.Equal(new Version(3, 1), db.Version);
    }

    // ── After roundtrip ───────────────────────────────────────────────────────

    [Fact]
    public void Version_IsV4_AfterRoundTrip_V4()
    {
        var writeDb = Database.Create("pass");

        using var ms = new MemoryStream();
        new KdbxWriter(writeDb).WriteTo(ms);
        ms.Position = 0;

        var readDb = new Database(new CompositeKey().AddPassword("pass"));
        new KdbxReader(readDb).ReadFrom(ms);

        Assert.Equal(new Version(4, 1), readDb.Version);
    }

    [Fact]
    public void Version_IsV3_AfterRoundTrip_V3()
    {
        var settings = new Settings
        {
            Format = KdbxFormat.Kdbx3,
            Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL),
        };
        var writeDb = Database.Create("pass", settings);

        using var ms = new MemoryStream();
        new KdbxWriter(writeDb).WriteTo(ms);
        ms.Position = 0;

        var readDb = new Database(new CompositeKey().AddPassword("pass"));
        new KdbxReader(readDb).ReadFrom(ms);

        Assert.Equal(new Version(3, 1), readDb.Version);
    }

    // ── Comparison operators ──────────────────────────────────────────────────

    [Fact]
    public void Version_Comparison_Works()
    {
        var v4 = new Version(4, 1);
        var v3 = new Version(3, 1);

        Assert.True(v4 > v3);
        Assert.True(v3 < v4);
        Assert.True(v4 >= new Version(4, 1));
        Assert.Equal(new Version(4, 1), v4);
    }
}
