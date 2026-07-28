using System.Security.Cryptography;
using Pidamg.KeePass;

namespace Pidamg.KeePass.Kdbx.IntegrationTests;

public sealed class PublicApiTests : IDisposable
{
    private readonly string _tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    public PublicApiTests()
    {
        Directory.CreateDirectory(_tempDirectory);
    }

    [Fact]
    public void PasswordDatabase_CanBeCreatedSavedAndOpened()
    {
        string path = GetPath("password.kdbx");

        using (var database = KdbxDatabase.Create("password"))
        {
            database.Metadata.Name = "Integration database";
            database.RootGroup.AddEntry(new Entry
            {
                Title = "GitHub",
                UserName = "alice",
                Password = "secret",
            });

            database.SaveAs(path);
        }

        using var reopened = KdbxDatabase.Open(path, "password");

        Assert.Equal("Integration database", reopened.Metadata.Name);
        Assert.Equal(new KdbxVersion(4, 1), reopened.Version);

        Entry entry = Assert.IsType<Entry>(reopened.FindEntry("GitHub"));
        Assert.Equal("alice", entry.UserName);
        Assert.Equal("secret", entry.Password);
    }

    [Fact]
    public void KeyFileDatabase_CanBeCreatedSavedAndOpened()
    {
        string databasePath = GetPath("key-file.kdbx");
        string keyFilePath = GetPath("key-file.keyx");
        KeyFile.Generate(keyFilePath);

        using (var database = KdbxDatabase.Create("password", keyFilePath))
        {
            database.RootGroup.AddEntry(new Entry { Title = "Protected entry" });
            database.SaveAs(databasePath);
        }

        using var reopened = KdbxDatabase.Open(databasePath, "password", keyFilePath);

        Assert.NotNull(reopened.FindEntry("Protected entry"));
    }

    [Fact]
    public async Task Kdbx3Database_SupportsPublicSettingsAndAsyncIo()
    {
        string path = GetPath("legacy.kdbx");
        var settings = new KdbxSettings
        {
            Format = KdbxFormat.Kdbx3,
            Cipher = CipherAlgorithm.Aes256Cbc,
            Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), rounds: 100),
        };

        using (var database = KdbxDatabase.Create("password", settings))
        {
            database.RootGroup.AddGroup(new Group { Name = "Legacy" });
            await database.SaveAsAsync(path);
        }

        using var reopened = new KdbxDatabase(path, "password");
        await reopened.OpenAsync();

        Assert.Equal(KdbxFormat.Kdbx3, reopened.Settings.Format);
        Assert.Equal(new KdbxVersion(3, 1), reopened.Version);
        Assert.NotNull(reopened.FindGroup("Legacy"));
    }

    public void Dispose()
    {
        Directory.Delete(_tempDirectory, recursive: true);
    }

    private string GetPath(string fileName) => Path.Combine(_tempDirectory, fileName);
}
