using System;
using System.IO;
using System.Security.Cryptography;
using Pidamg.KeePass.Kdbx;

namespace Pidamg.KeePass.Kdbx.Tests;

public class TimesTests {

	// V4 truncates to second (LE Int64) — using UTC datetimes without fractional seconds.
	private static DateTime Utc(int year, int month, int day, int h = 0, int m = 0, int s = 0)
		=> new(year, month, day, h, m, s, DateTimeKind.Utc);

	private static Entry RoundTripEntry(Entry entry, KdbxFormat format = KdbxFormat.Kdbx4) {
		var settings = format == KdbxFormat.Kdbx4
			? new Settings { Format = KdbxFormat.Kdbx4 }
			: new Settings { Format = KdbxFormat.Kdbx3, Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL) };

		var writeDb = Database.Create("pass", settings);
		writeDb.RootGroup.AddEntry(entry);

		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);

		ms.Position = 0;
		var readDb = new Database(new CompositeKey().AddPassword("pass"));
		new KdbxReader(readDb).ReadFrom(ms);
		return readDb.RootGroup.Entries[0];
	}

	private static Group RoundTripGroup(Group group, KdbxFormat format = KdbxFormat.Kdbx4) {
		var settings = format == KdbxFormat.Kdbx4
			? new Settings { Format = KdbxFormat.Kdbx4 }
			: new Settings { Format = KdbxFormat.Kdbx3, Kdf = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL) };

		var writeDb = Database.Create("pass", settings);
		writeDb.RootGroup.AddGroup(group);

		using var ms = new MemoryStream();
		new KdbxWriter(writeDb).WriteTo(ms);

		ms.Position = 0;
		var readDb = new Database(new CompositeKey().AddPassword("pass"));
		new KdbxReader(readDb).ReadFrom(ms);
		return readDb.RootGroup.Groups[0];
	}

	// ── Entry Times V4 ────────────────────────────────────────────────────────

	[Fact]
	public void EntryTimes_V4_AllDateFields_RoundTrip() {
		var creation    = Utc(2024, 3, 15,  8, 30,  0);
		var modified    = Utc(2024, 6, 20, 14,  0,  0);
		var accessed    = Utc(2024, 9,  1, 12,  0,  0);
		var expiry      = Utc(2025, 1,  1,  0,  0,  0);
		var locChanged  = Utc(2024, 3, 15,  8, 30,  0);

		var entry = new Entry {
			Times = new Times {
				CreationTime         = creation,
				LastModificationTime = modified,
				LastAccessTime       = accessed,
				ExpiryTime           = expiry,
				LocationChanged      = locChanged,
				Expires              = true,
				UsageCount           = 42,
			},
		};

		var read = RoundTripEntry(entry, KdbxFormat.Kdbx4);

		Assert.Equal(creation,   read.Times.CreationTime);
		Assert.Equal(modified,   read.Times.LastModificationTime);
		Assert.Equal(accessed,   read.Times.LastAccessTime);
		Assert.Equal(expiry,     read.Times.ExpiryTime);
		Assert.Equal(locChanged, read.Times.LocationChanged);
		Assert.True(read.Times.Expires);
		Assert.Equal(42, read.Times.UsageCount);
	}

	[Fact]
	public void EntryTimes_V4_Expires_False_Preserved() {
		var entry = new Entry {
			Times = new Times { Expires = false, ExpiryTime = Utc(2099, 1, 1) },
		};

		var read = RoundTripEntry(entry, KdbxFormat.Kdbx4);

		Assert.False(read.Times.Expires);
	}

	[Fact]
	public void EntryTimes_V4_UsageCount_Zero_RoundTrip() {
		var entry = new Entry {
			Times = new Times { UsageCount = 0 },
		};

		var read = RoundTripEntry(entry, KdbxFormat.Kdbx4);

		Assert.Equal(0, read.Times.UsageCount);
	}

	// ── Entry Times V3 ────────────────────────────────────────────────────────

	[Fact]
	public void EntryTimes_V3_AllDateFields_RoundTrip() {
		var creation = Utc(2023, 1,  1,  9,  0,  0);
		var modified = Utc(2023, 6, 15, 10, 30,  0);
		var expiry   = Utc(2024, 12, 31, 23, 59, 59);

		var entry = new Entry {
			Times = new Times {
				CreationTime         = creation,
				LastModificationTime = modified,
				ExpiryTime           = expiry,
				Expires              = true,
				UsageCount           = 7,
			},
		};

		var read = RoundTripEntry(entry, KdbxFormat.Kdbx3);

		Assert.Equal(creation, read.Times.CreationTime);
		Assert.Equal(modified, read.Times.LastModificationTime);
		Assert.Equal(expiry,   read.Times.ExpiryTime);
		Assert.True(read.Times.Expires);
		Assert.Equal(7, read.Times.UsageCount);
	}

	[Fact]
	public void EntryTimes_V3_Expires_False_Preserved() {
		var entry = new Entry {
			Times = new Times { Expires = false },
		};

		var read = RoundTripEntry(entry, KdbxFormat.Kdbx3);

		Assert.False(read.Times.Expires);
	}

	// ── Group Times ───────────────────────────────────────────────────────────

	[Fact]
	public void GroupTimes_V4_RoundTrip() {
		var creation = Utc(2022, 5, 10,  7,  0, 0);
		var modified = Utc(2023, 11, 20, 15, 45, 0);

		var group = new Group {
			Name  = "G",
			Times = new Times {
				CreationTime         = creation,
				LastModificationTime = modified,
			},
		};

		var read = RoundTripGroup(group, KdbxFormat.Kdbx4);

		Assert.Equal(creation, read.Times.CreationTime);
		Assert.Equal(modified, read.Times.LastModificationTime);
	}

	[Fact]
	public void GroupTimes_V3_RoundTrip() {
		var creation = Utc(2020, 1,  1,  0,  0, 0);
		var modified = Utc(2021, 6, 15, 12,  0, 0);

		var group = new Group {
			Name  = "G",
			Times = new Times {
				CreationTime         = creation,
				LastModificationTime = modified,
			},
		};

		var read = RoundTripGroup(group, KdbxFormat.Kdbx3);

		Assert.Equal(creation, read.Times.CreationTime);
		Assert.Equal(modified, read.Times.LastModificationTime);
	}

	// ── DateTimeKind ──────────────────────────────────────────────────────────

	[Fact]
	public void EntryTimes_V4_RoundTrip_PreservesUtcKind() {
		var entry = new Entry {
			Times = new Times { CreationTime = Utc(2024, 1, 1) },
		};

		var read = RoundTripEntry(entry, KdbxFormat.Kdbx4);

		Assert.Equal(DateTimeKind.Utc, read.Times.CreationTime.Kind);
	}

	[Fact]
	public void EntryTimes_V3_RoundTrip_PreservesUtcKind() {
		var entry = new Entry {
			Times = new Times { CreationTime = Utc(2024, 1, 1) },
		};

		var read = RoundTripEntry(entry, KdbxFormat.Kdbx3);

		Assert.Equal(DateTimeKind.Utc, read.Times.CreationTime.Kind);
	}
}
