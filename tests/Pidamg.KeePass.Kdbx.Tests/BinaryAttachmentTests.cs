using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class BinaryAttachmentTests {

	private static byte[] MakeData(int seed, int length) {
		var data = new byte[length];
		for (int i = 0; i < length; i++) data[i] = (byte)((seed + i) % 256);
		return data;
	}

	private static Settings MakeV3Settings() => new() {
		Format = KdbxFormat.Kdbx3,
		Kdf    = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL),
	};

	// ── V4 ────────────────────────────────────────────────────────────────────

	[Fact]
	public void RoundTrip_V4_SingleBinary() {
		byte[] payload = MakeData(42, 256);

		var writeDb = Database.Create("pass");
		var entry = new Entry { Title = "WithAttachment" };
		entry.Binaries.Add(new EntryBinary { Name = "file.bin", Data = payload });
		writeDb.RootGroup.AddEntry(entry);

		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);

		ms.Position = 0;
		var readDb = new Database(new CompositeKey().AddPassword("pass"));
		new KdbxReader(readDb).ReadFrom(ms);

		var readEntry = readDb.RootGroup.Entries.First(e => e.Uuid == entry.Uuid);
		Assert.Single(readEntry.Binaries);
		Assert.Equal("file.bin", readEntry.Binaries[0].Name);
		Assert.Equal(payload,    readEntry.Binaries[0].Data);
	}

	[Fact]
	public void RoundTrip_V4_MultipleBinariesPerEntry() {
		byte[] d1 = MakeData(1, 64);
		byte[] d2 = MakeData(2, 128);
		byte[] d3 = MakeData(3, 32);

		var writeDb = Database.Create("pass");
		var entry = new Entry();
		entry.Binaries.Add(new EntryBinary { Name = "one.txt",   Data = d1 });
		entry.Binaries.Add(new EntryBinary { Name = "two.bin",   Data = d2 });
		entry.Binaries.Add(new EntryBinary { Name = "three.dat", Data = d3 });
		writeDb.RootGroup.AddEntry(entry);

		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);

		ms.Position = 0;
		var readDb = new Database(new CompositeKey().AddPassword("pass"));
		new KdbxReader(readDb).ReadFrom(ms);

		var readEntry = readDb.RootGroup.Entries[0];
		Assert.Equal(3, readEntry.Binaries.Count);
		Assert.Equal(d1, readEntry.Binaries.First(b => b.Name == "one.txt").Data);
		Assert.Equal(d2, readEntry.Binaries.First(b => b.Name == "two.bin").Data);
		Assert.Equal(d3, readEntry.Binaries.First(b => b.Name == "three.dat").Data);
	}

	[Fact]
	public void RoundTrip_V4_DeduplicatedBinaries() {
		byte[] shared = MakeData(7, 128);

		var writeDb = Database.Create("pass");
		var e1 = new Entry();
		e1.Binaries.Add(new EntryBinary { Name = "a.bin", Data = shared });
		var e2 = new Entry();
		e2.Binaries.Add(new EntryBinary { Name = "b.bin", Data = shared });
		writeDb.RootGroup.AddEntry(e1);
		writeDb.RootGroup.AddEntry(e2);

		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);

		ms.Position = 0;
		var readDb = new Database(new CompositeKey().AddPassword("pass"));
		new KdbxReader(readDb).ReadFrom(ms);

		Assert.Equal(shared, readDb.RootGroup.Entries[0].Binaries[0].Data);
		Assert.Equal(shared, readDb.RootGroup.Entries[1].Binaries[0].Data);
	}

	[Fact]
	public void RoundTrip_V4_IsProtected_Preserved() {
		var writeDb = Database.Create("pass");
		var entry = new Entry();
		entry.Binaries.Add(new EntryBinary { Name = "secret.bin", Data = MakeData(1, 32), IsProtected = true  });
		entry.Binaries.Add(new EntryBinary { Name = "public.bin", Data = MakeData(2, 32), IsProtected = false });
		writeDb.RootGroup.AddEntry(entry);

		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);

		ms.Position = 0;
		var readDb = new Database(new CompositeKey().AddPassword("pass"));
		new KdbxReader(readDb).ReadFrom(ms);

		var readEntry = readDb.RootGroup.Entries[0];
		Assert.True(readEntry.Binaries.First(b => b.Name == "secret.bin").IsProtected);
		Assert.False(readEntry.Binaries.First(b => b.Name == "public.bin").IsProtected);
	}

	// ── V3 ────────────────────────────────────────────────────────────────────

	[Fact]
	public void RoundTrip_V3_SingleBinary() {
		byte[] payload = MakeData(99, 512);

		var writeDb = Database.Create("pass", MakeV3Settings());
		var entry = new Entry();
		entry.Binaries.Add(new EntryBinary { Name = "doc.pdf", Data = payload });
		writeDb.RootGroup.AddEntry(entry);

		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);

		ms.Position = 0;
		var readDb = new Database(new CompositeKey().AddPassword("pass"));
		new KdbxReader(readDb).ReadFrom(ms);

		var readEntry = readDb.RootGroup.Entries[0];
		Assert.Single(readEntry.Binaries);
		Assert.Equal("doc.pdf", readEntry.Binaries[0].Name);
		Assert.Equal(payload,   readEntry.Binaries[0].Data);
	}
}
