using System;
using System.Collections.Generic;
using System.IO;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class XmlLayerTests {

	// ── Reading Meta from a real V4 file ──────────────────────────────────────

	[Fact]
	public void XmlReader_ParsesMeta() {
		var db = Database.Open(Helpers.Rsc("SimplePasswordV4.kdbx"), "password123");

		Assert.NotEmpty(db.Metadata.Name);
		Assert.True(db.Metadata.ProtectPassword);
	}

	// ── Decryption of protected fields from a real V4 file ───────────────────

	[Fact]
	public void XmlReader_ParsesEntries() {
		var db = Database.Open(Helpers.Rsc("SimplePasswordV4.kdbx"), "password123");

		var entries = new List<Entry>();
		Helpers.CollectEntries(db.RootGroup, entries);

		Assert.NotEmpty(entries);
		Assert.NotEmpty(entries[0].Title);
		Assert.NotEmpty(entries[0].Password);
	}

	// ── Round-trip Write → Read ───────────────────────────────────────────────

	[Fact]
	public void XmlRoundTrip() {
		var writeDb = Database.Create("testpass", new Settings { Format = KdbxFormat.Kdbx4 });
		writeDb.Metadata.Name = "MyDatabase";
		writeDb.Metadata.ProtectPassword = true;

		var entry = new Entry();
		entry.Strings["Title"]    = new EntryString { Value = "MySite",              Protected = false };
		entry.Strings["UserName"] = new EntryString { Value = "alice",               Protected = false };
		entry.Strings["Password"] = new EntryString { Value = "s3cr3t!",             Protected = true  };
		entry.Strings["URL"]      = new EntryString { Value = "https://example.com", Protected = false };
		entry.Strings["Notes"]    = new EntryString { Value = "",                    Protected = false };
		writeDb.RootGroup.AddEntry(entry);

		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);

		ms.Position = 0;
		var readDb = new Database(new CompositeKey().AddPassword("testpass"));
		new KdbxReader(readDb).ReadFrom(ms);

		Assert.Equal("MyDatabase", readDb.Metadata.Name);
		Assert.True(readDb.Metadata.ProtectPassword);

		Assert.Single(readDb.RootGroup.Entries);
		var readEntry = readDb.RootGroup.Entries[0];
		Assert.Equal("MySite",              readEntry.Title);
		Assert.Equal("alice",               readEntry.UserName);
		Assert.Equal("s3cr3t!",             readEntry.Password);
		Assert.Equal("https://example.com", readEntry.Url);
	}
}
