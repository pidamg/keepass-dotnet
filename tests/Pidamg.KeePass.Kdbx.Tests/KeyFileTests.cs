using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class KeyFileTests : IDisposable {

	private readonly string _tempDir;

	public KeyFileTests() {
		_tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
		Directory.CreateDirectory(_tempDir);
	}

	public void Dispose() => Directory.Delete(_tempDir, recursive: true);

	// ── Helpers ───────────────────────────────────────────────────────────────

	private string TempPath(string name) => Path.Combine(_tempDir, name);

	private string WriteXmlKeyFile(byte[] key32) {
		var xml = $"""
			<?xml version="1.0" encoding="utf-8"?>
			<KeyFile>
			  <Meta><Version>1.0</Version></Meta>
			  <Key><Data>{Convert.ToBase64String(key32)}</Data></Key>
			</KeyFile>
			""";
		var path = TempPath("key.xml");
		File.WriteAllText(path, xml, Encoding.UTF8);
		return path;
	}

	private string WriteHexKeyFile(byte[] key32) {
		// 64 uppercase ASCII hex chars → exactly 64 bytes
		var path = TempPath("key.hex");
		File.WriteAllText(path, Convert.ToHexString(key32), Encoding.ASCII);
		return path;
	}

	private string WriteRawKeyFile(byte[] key32) {
		var path = TempPath("key.bin");
		File.WriteAllBytes(path, key32);
		return path;
	}

	private string WriteArbitraryKeyFile(byte[] content) {
		var path = TempPath("key.dat");
		File.WriteAllBytes(path, content);
		return path;
	}

	private static Database MemoryRoundTrip(Database writeDb, CompositeKey readKey) {
		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);
		ms.Position = 0;
		var readDb = new Database(readKey);
		new KdbxReader(readDb).ReadFrom(ms);
		return readDb;
	}

	// ── Formats de key file ───────────────────────────────────────────────────

	[Fact]
	public void RoundTrip_XmlKeyFile() {
		var key32   = RandomNumberGenerator.GetBytes(32);
		var keyPath = WriteXmlKeyFile(key32);

		var writeDb = Database.Create("pass", keyPath);
		writeDb.Metadata.Name = "XmlKey";

		var readDb = MemoryRoundTrip(writeDb,
			new CompositeKey().AddPassword("pass").AddKeyFile(keyPath));

		Assert.Equal("XmlKey", readDb.Metadata.Name);
	}

	[Fact]
	public void RoundTrip_HexKeyFile() {
		var key32   = RandomNumberGenerator.GetBytes(32);
		var keyPath = WriteHexKeyFile(key32);

		var writeDb = Database.Create("pass", keyPath);
		writeDb.Metadata.Name = "HexKey";

		var readDb = MemoryRoundTrip(writeDb,
			new CompositeKey().AddPassword("pass").AddKeyFile(keyPath));

		Assert.Equal("HexKey", readDb.Metadata.Name);
	}

	[Fact]
	public void RoundTrip_RawBinaryKeyFile() {
		var key32   = RandomNumberGenerator.GetBytes(32);
		var keyPath = WriteRawKeyFile(key32);

		var writeDb = Database.Create("pass", keyPath);
		writeDb.Metadata.Name = "RawKey";

		var readDb = MemoryRoundTrip(writeDb,
			new CompositeKey().AddPassword("pass").AddKeyFile(keyPath));

		Assert.Equal("RawKey", readDb.Metadata.Name);
	}

	[Fact]
	public void RoundTrip_ArbitraryFile_Sha256Fallback() {
		// Any file (> 32 bytes, non-hex) → SHA256 used as key
		var content = Encoding.UTF8.GetBytes("This is an arbitrary key file with some random content.");
		var keyPath = WriteArbitraryKeyFile(content);

		var writeDb = Database.Create("pass", keyPath);
		writeDb.Metadata.Name = "ArbitraryKey";

		var readDb = MemoryRoundTrip(writeDb,
			new CompositeKey().AddPassword("pass").AddKeyFile(keyPath));

		Assert.Equal("ArbitraryKey", readDb.Metadata.Name);
	}

	// ── Error cases ───────────────────────────────────────────────────────────

	[Fact]
	public void WrongKeyFile_CorrectPassword_Throws() {
		var keyPath      = TempPath("correct.bin");
		var wrongKeyPath = TempPath("wrong.bin");
		File.WriteAllBytes(keyPath,      RandomNumberGenerator.GetBytes(32));
		File.WriteAllBytes(wrongKeyPath, RandomNumberGenerator.GetBytes(32));

		var writeDb = Database.Create("pass", keyPath);

		Assert.ThrowsAny<Exception>(() =>
			MemoryRoundTrip(writeDb,
				new CompositeKey().AddPassword("pass").AddKeyFile(wrongKeyPath)));
	}

	[Fact]
	public void CorrectKeyFile_WrongPassword_Throws() {
		var key32   = RandomNumberGenerator.GetBytes(32);
		var keyPath = WriteRawKeyFile(key32);

		var writeDb = Database.Create("correctpass", keyPath);

		Assert.ThrowsAny<Exception>(() =>
			MemoryRoundTrip(writeDb,
				new CompositeKey().AddPassword("wrongpass").AddKeyFile(keyPath)));
	}

	[Fact]
	public void MissingKeyFile_WhenRequired_Throws() {
		var key32   = RandomNumberGenerator.GetBytes(32);
		var keyPath = WriteRawKeyFile(key32);

		var writeDb = Database.Create("pass", keyPath);

		// Reading without key file → decryption must fail
		Assert.ThrowsAny<Exception>(() =>
			MemoryRoundTrip(writeDb,
				new CompositeKey().AddPassword("pass")));
	}

	[Fact]
	public void KeyFileOnly_EmptyPassword_RoundTrip() {
		var key32   = RandomNumberGenerator.GetBytes(32);
		var keyPath = WriteRawKeyFile(key32);

		// Empty password + key file only
		var writeDb = Database.Create("", keyPath);
		writeDb.Metadata.Name = "EmptyPwKeyFile";

		var readDb = MemoryRoundTrip(writeDb,
			new CompositeKey().AddPassword("").AddKeyFile(keyPath));

		Assert.Equal("EmptyPwKeyFile", readDb.Metadata.Name);
	}

	// ── Database.Create / Database.Open with key file ────────────────────────

	[Fact]
	public void Database_Create_WithKeyFile_RoundTrip() {
		var key32   = RandomNumberGenerator.GetBytes(32);
		var keyPath = WriteXmlKeyFile(key32);

		var writeDb = Database.Create("pass", keyPath);
		writeDb.Metadata.Name = "WithKeyFile";

		var path = TempPath("db.kdbx");
		writeDb.SaveAs(path);

		var readDb = Database.Open(path, "pass", keyPath);
		Assert.Equal("WithKeyFile", readDb.Metadata.Name);
	}

	[Fact]
	public void Database_Open_WithKeyFile_WrongPassword_Throws() {
		var key32   = RandomNumberGenerator.GetBytes(32);
		var keyPath = WriteRawKeyFile(key32);
		var path    = TempPath("db.kdbx");
		Database.Create("correct", keyPath).SaveAs(path);

		Assert.ThrowsAny<Exception>(() => Database.Open(path, "wrong", keyPath));
	}

	// ── KeyFile.Generate ──────────────────────────────────────────────────────

	[Fact]
	public void KeyFile_Generate_Xml_CreatesValidFile() {
		var path = TempPath("generated.xml");

		KeyFile.Generate(path);

		Assert.True(File.Exists(path));
		// Must be parseable as KeePass XML
		var text = File.ReadAllText(path);
		Assert.Contains("<KeyFile>", text);
		Assert.Contains("<Data>",    text);
	}

	[Fact]
	public void KeyFile_Generate_Xml_ProducesUnique32ByteKey() {
		var path1 = TempPath("key1.xml");
		var path2 = TempPath("key2.xml");

		KeyFile.Generate(path1, KeyFileFormat.Xml);
		KeyFile.Generate(path2, KeyFileFormat.Xml);

		// Two independently generated files must be different
		Assert.NotEqual(File.ReadAllText(path1), File.ReadAllText(path2));
	}

	[Fact]
	public void KeyFile_Generate_Raw_Creates32ByteFile() {
		var path = TempPath("generated.bin");

		KeyFile.Generate(path, KeyFileFormat.Raw);

		Assert.True(File.Exists(path));
		Assert.Equal(32, new FileInfo(path).Length);
	}

	[Fact]
	public void KeyFile_Generate_Raw_ProducesUniqueContent() {
		var path1 = TempPath("raw1.bin");
		var path2 = TempPath("raw2.bin");

		KeyFile.Generate(path1, KeyFileFormat.Raw);
		KeyFile.Generate(path2, KeyFileFormat.Raw);

		Assert.NotEqual(File.ReadAllBytes(path1), File.ReadAllBytes(path2));
	}

	[Fact]
	public void KeyFile_Generate_Xml_UsableForRoundTrip() {
		var keyPath = TempPath("gen.xml");
		KeyFile.Generate(keyPath, KeyFileFormat.Xml);

		var writeDb = Database.Create("pass", keyPath);
		writeDb.Metadata.Name = "GeneratedXmlKey";

		var readDb = MemoryRoundTrip(writeDb,
			new CompositeKey().AddPassword("pass").AddKeyFile(keyPath));

		Assert.Equal("GeneratedXmlKey", readDb.Metadata.Name);
	}

	[Fact]
	public void KeyFile_Generate_Raw_UsableForRoundTrip() {
		var keyPath = TempPath("gen.bin");
		KeyFile.Generate(keyPath, KeyFileFormat.Raw);

		var writeDb = Database.Create("pass", keyPath);
		writeDb.Metadata.Name = "GeneratedRawKey";

		var readDb = MemoryRoundTrip(writeDb,
			new CompositeKey().AddPassword("pass").AddKeyFile(keyPath));

		Assert.Equal("GeneratedRawKey", readDb.Metadata.Name);
	}
}
