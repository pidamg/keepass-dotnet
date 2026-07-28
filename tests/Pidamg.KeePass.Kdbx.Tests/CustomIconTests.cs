using System;
using System.IO;
using System.Linq;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class CustomIconTests {

	private static readonly byte[] PngA = [0x89, 0x50, 0x4E, 0x47, 0x01]; // fake PNG A
	private static readonly byte[] PngB = [0x89, 0x50, 0x4E, 0x47, 0x02]; // fake PNG B

	private static Database RoundTrip(Database writeDb, KdbxFormat format = KdbxFormat.Kdbx4) {
		var settings = new Settings { Format = format };
		if (format == KdbxFormat.Kdbx3)
			settings.Kdf = new AesKdf(new byte[32], 1000);
		writeDb.Settings = settings;

		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);
		ms.Position = 0;
		var readDb = new Database(new CompositeKey().AddPassword("pass"));
		new KdbxReader(readDb).ReadFrom(ms);
		return readDb;
	}

	private static Database MakeDb() => Database.Create("pass");

	// ── Icon list ─────────────────────────────────────────────────────────────

	[Fact]
	public void CustomIcons_EmptyByDefault() {
		var db = MakeDb();
		Assert.Empty(db.Metadata.CustomIcons);
	}

	[Fact]
	public void CustomIcons_SingleIcon_RoundTrip_V4() {
		var db   = MakeDb();
		var uuid = Guid.NewGuid();
		db.Metadata.CustomIcons.Add(new CustomIcon { Uuid = uuid, Data = PngA });

		var read = RoundTrip(db);

		Assert.Single(read.Metadata.CustomIcons);
		Assert.Equal(uuid, read.Metadata.CustomIcons[0].Uuid);
		Assert.Equal(PngA, read.Metadata.CustomIcons[0].Data);
	}

	[Fact]
	public void CustomIcons_MultipleIcons_RoundTrip_V4() {
		var db    = MakeDb();
		var uuidA = Guid.NewGuid();
		var uuidB = Guid.NewGuid();
		db.Metadata.CustomIcons.Add(new CustomIcon { Uuid = uuidA, Data = PngA });
		db.Metadata.CustomIcons.Add(new CustomIcon { Uuid = uuidB, Data = PngB });

		var read = RoundTrip(db);

		Assert.Equal(2, read.Metadata.CustomIcons.Count);
		Assert.Equal(uuidA, read.Metadata.CustomIcons[0].Uuid);
		Assert.Equal(uuidB, read.Metadata.CustomIcons[1].Uuid);
		Assert.Equal(PngA,  read.Metadata.CustomIcons[0].Data);
		Assert.Equal(PngB,  read.Metadata.CustomIcons[1].Data);
	}

	[Fact]
	public void CustomIcons_NoIcons_ProducesEmptyList_V4() {
		var db   = MakeDb();
		var read = RoundTrip(db);
		Assert.Empty(read.Metadata.CustomIcons);
	}

	// ── Name and LastModificationTime ─────────────────────────────────────────

	[Fact]
	public void CustomIcons_Name_RoundTrip_V4() {
		var db = MakeDb();
		db.Metadata.CustomIcons.Add(new CustomIcon { Data = PngA, Name = "folder" });

		var read = RoundTrip(db);

		Assert.Equal("folder", read.Metadata.CustomIcons[0].Name);
	}

	[Fact]
	public void CustomIcons_EmptyName_NotWritten_V4() {
		var db = MakeDb();
		db.Metadata.CustomIcons.Add(new CustomIcon { Data = PngA, Name = "" });

		var read = RoundTrip(db);

		// Empty name → element omitted → reads back as ""
		Assert.Equal("", read.Metadata.CustomIcons[0].Name);
	}

	[Fact]
	public void CustomIcons_LastModificationTime_V4_RoundTrip() {
		var db  = MakeDb();
		var ts  = new DateTime(2024, 6, 15, 12, 0, 0, DateTimeKind.Utc);
		db.Metadata.CustomIcons.Add(new CustomIcon {
			Data                 = PngA,
			LastModificationTime = ts,
		});

		var read = RoundTrip(db);

		var got = read.Metadata.CustomIcons[0].LastModificationTime;
		Assert.NotNull(got);
		Assert.Equal(ts, got!.Value.ToUniversalTime());
	}

	[Fact]
	public void CustomIcons_NullLastModificationTime_NotWritten_V4() {
		var db = MakeDb();
		db.Metadata.CustomIcons.Add(new CustomIcon {
			Data                 = PngA,
			LastModificationTime = null,
		});

		var read = RoundTrip(db);

		Assert.Null(read.Metadata.CustomIcons[0].LastModificationTime);
	}

	// ── V3 roundtrip ─────────────────────────────────────────────────────────

	[Fact]
	public void CustomIcons_SingleIcon_RoundTrip_V3() {
		var db   = MakeDb();
		var uuid = Guid.NewGuid();
		db.Metadata.CustomIcons.Add(new CustomIcon { Uuid = uuid, Data = PngA });

		var read = RoundTrip(db, KdbxFormat.Kdbx3);

		Assert.Single(read.Metadata.CustomIcons);
		Assert.Equal(uuid, read.Metadata.CustomIcons[0].Uuid);
		Assert.Equal(PngA, read.Metadata.CustomIcons[0].Data);
	}

	// ── Entry CustomIconUuid ──────────────────────────────────────────────────

	[Fact]
	public void Entry_CustomIconUuid_DefaultIsEmpty() {
		var entry = new Entry();
		Assert.Equal(Guid.Empty, entry.CustomIconUuid);
	}

	[Fact]
	public void Entry_CustomIconUuid_RoundTrip_V4() {
		var db     = MakeDb();
		var iconId = Guid.NewGuid();
		db.Metadata.CustomIcons.Add(new CustomIcon { Uuid = iconId, Data = PngA });
		var entry = new Entry { Title = "e1", CustomIconUuid = iconId };
		db.RootGroup.AddEntry(entry);

		var read  = RoundTrip(db);
		var found = read.FindEntry("e1")!;

		Assert.Equal(iconId, found.CustomIconUuid);
	}

	[Fact]
	public void Entry_CustomIconUuid_Empty_NotWritten_V4() {
		var db    = MakeDb();
		var entry = new Entry { Title = "e1" }; // CustomIconUuid = Guid.Empty
		db.RootGroup.AddEntry(entry);

		var read  = RoundTrip(db);
		var found = read.FindEntry("e1")!;

		Assert.Equal(Guid.Empty, found.CustomIconUuid);
	}

	[Fact]
	public void Entry_CustomIconUuid_PreservedInUpdate() {
		var db     = MakeDb();
		var iconId = Guid.NewGuid();
		db.Metadata.CustomIcons.Add(new CustomIcon { Uuid = iconId, Data = PngA });
		var entry = new Entry { Title = "e1", CustomIconUuid = iconId };
		db.RootGroup.AddEntry(entry);

		entry.Update(e => e.Title = "e1-updated");

		// Current entry still has icon
		Assert.Equal(iconId, entry.CustomIconUuid);
		// History snapshot also preserved it
		Assert.Equal(iconId, entry.History.Last().CustomIconUuid);
	}

	// ── Group CustomIconUuid ──────────────────────────────────────────────────

	[Fact]
	public void Group_CustomIconUuid_DefaultIsEmpty() {
		var g = new Group();
		Assert.Equal(Guid.Empty, g.CustomIconUuid);
	}

	[Fact]
	public void Group_CustomIconUuid_RoundTrip_V4() {
		var db     = MakeDb();
		var iconId = Guid.NewGuid();
		db.Metadata.CustomIcons.Add(new CustomIcon { Uuid = iconId, Data = PngA });
		var group = new Group { Name = "Work", CustomIconUuid = iconId };
		db.RootGroup.AddGroup(group);

		var read  = RoundTrip(db);
		var found = read.FindGroup("Work")!;

		Assert.Equal(iconId, found.CustomIconUuid);
	}

	[Fact]
	public void Group_CustomIconUuid_PreservedInClone() {
		var iconId = Guid.NewGuid();
		var group  = new Group { Name = "Work", CustomIconUuid = iconId };
		var clone  = group.Clone();

		Assert.Equal(iconId, clone.CustomIconUuid);
	}
}
