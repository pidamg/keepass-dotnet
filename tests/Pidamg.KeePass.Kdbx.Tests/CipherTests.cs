using System;
using System.IO;
using System.Security.Cryptography;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class CipherTests
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

    private static Settings V4(CipherAlgorithm cipher) => new()
    {
        Format = KdbxFormat.Kdbx4,
        Cipher = cipher,
    };

    private static Settings V3(CipherAlgorithm cipher,
                                ProtectedStreamAlgorithm inner = ProtectedStreamAlgorithm.ChaCha20) => new()
                                {
                                    Format = KdbxFormat.Kdbx3,
                                    Cipher = cipher,
                                    InnerStreamAlgorithm = inner,
                                    Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL),
                                };

    // ── AES-256-CBC ───────────────────────────────────────────────────────────

    [Fact]
    public void Cipher_Aes256Cbc_V4_RoundTrip()
    {
        var db = Database.Create("pass", V4(CipherAlgorithm.Aes256Cbc));
        db.Metadata.Name = "AES256-V4";
        var entry = new Entry();
        entry.Password = "secret";
        db.RootGroup.AddEntry(entry);

        var read = RoundTrip(db);

        Assert.Equal("AES256-V4", read.Metadata.Name);
        Assert.Equal("secret", read.RootGroup.Entries[0].Password);
    }

    [Fact]
    public void Cipher_Aes256Cbc_V3_RoundTrip()
    {
        var db = Database.Create("pass", V3(CipherAlgorithm.Aes256Cbc));
        db.Metadata.Name = "AES256-V3";
        var entry = new Entry();
        entry.Password = "secret";
        db.RootGroup.AddEntry(entry);

        var read = RoundTrip(db);

        Assert.Equal("AES256-V3", read.Metadata.Name);
        Assert.Equal("secret", read.RootGroup.Entries[0].Password);
    }

    // ── Twofish-256-CBC ───────────────────────────────────────────────────────

    [Fact]
    public void Cipher_Twofish256Cbc_V4_RoundTrip()
    {
        var db = Database.Create("pass", V4(CipherAlgorithm.Twofish256Cbc));
        db.Metadata.Name = "Twofish-V4";
        var entry = new Entry();
        entry.Password = "secret";
        db.RootGroup.AddEntry(entry);

        var read = RoundTrip(db);

        Assert.Equal("Twofish-V4", read.Metadata.Name);
        Assert.Equal("secret", read.RootGroup.Entries[0].Password);
    }

    [Fact]
    public void Cipher_Twofish256Cbc_V3_RoundTrip()
    {
        var db = Database.Create("pass", V3(CipherAlgorithm.Twofish256Cbc));
        db.Metadata.Name = "Twofish-V3";
        var entry = new Entry();
        entry.Password = "secret";
        db.RootGroup.AddEntry(entry);

        var read = RoundTrip(db);

        Assert.Equal("Twofish-V3", read.Metadata.Name);
        Assert.Equal("secret", read.RootGroup.Entries[0].Password);
    }

    // ── ProtectedStream Salsa20 (V3 only) ────────────────────────────────────

    [Fact]
    public void ProtectedStream_Salsa20_V3_RoundTrip()
    {
        var db = Database.Create("pass", V3(CipherAlgorithm.ChaCha20, ProtectedStreamAlgorithm.Salsa20));
        var entry = new Entry();
        entry.Password = "salsa-secret";
        db.RootGroup.AddEntry(entry);

        var read = RoundTrip(db);

        Assert.Equal("salsa-secret", read.RootGroup.Entries[0].Password);
    }

    [Fact]
    public void ProtectedStream_Salsa20_V3_MultipleEntries_RoundTrip()
    {
        var db = Database.Create("pass", V3(CipherAlgorithm.ChaCha20, ProtectedStreamAlgorithm.Salsa20));
        for (int i = 0; i < 3; i++)
        {
            var e = new Entry();
            e.Password = $"pw{i}";
            db.RootGroup.AddEntry(e);
        }

        var read = RoundTrip(db);

        for (int i = 0; i < 3; i++)
            Assert.Equal($"pw{i}", read.RootGroup.Entries[i].Password);
    }

    // ── Settings.Cipher preserved after roundtrip ────────────────────────────

    [Fact]
    public void Settings_Cipher_Twofish_Preserved_V4()
    {
        var db = Database.Create("pass", V4(CipherAlgorithm.Twofish256Cbc));
        var read = RoundTrip(db);
        Assert.Equal(CipherAlgorithm.Twofish256Cbc, read.Settings.Cipher);
        Assert.Equal(KdbxFormat.Kdbx4, read.Settings.Format);
    }

    [Fact]
    public void Settings_Cipher_Aes256_Preserved_V3()
    {
        var db = Database.Create("pass", V3(CipherAlgorithm.Aes256Cbc));
        var read = RoundTrip(db);
        Assert.Equal(CipherAlgorithm.Aes256Cbc, read.Settings.Cipher);
        Assert.Equal(KdbxFormat.Kdbx3, read.Settings.Format);
    }

    [Fact]
    public void Settings_InnerStream_Salsa20_Preserved_V3()
    {
        var db = Database.Create("pass", V3(CipherAlgorithm.ChaCha20, ProtectedStreamAlgorithm.Salsa20));
        var read = RoundTrip(db);
        Assert.Equal(ProtectedStreamAlgorithm.Salsa20, read.Settings.InnerStreamAlgorithm);
    }

    // ── V3 invalid with Argon2 ───────────────────────────────────────────────

    [Fact]
    public void Settings_V3_WithArgon2_Throws()
    {
        var db = Database.Create("pass");  // V4 + Argon2 by default
        db.Settings.Format = KdbxFormat.Kdbx3;   // force V3 without changing KDF

        Assert.Throws<InvalidOperationException>(() =>
        {
            using var ms = new MemoryStream();
            new KdbxWriter(db).WriteTo(ms);
        });
    }
}
