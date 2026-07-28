using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Xml.Linq;

namespace Pidamg.KeePass.Kdbx;

public class KdbxXmlReader
{

    private readonly Database _db;
    private readonly ProtectedStream _ps;
    private readonly bool _isV4;
    private readonly IReadOnlyList<(bool IsProtected, byte[] Data)> _binaryPool; // V4: from inner header

    // _pool is set in ReadFrom: either _binaryPool (V4) or parsed from <Meta><Binaries> (V3)
    private List<(bool IsProtected, byte[] Data)> _pool = [];

    public KdbxXmlReader(Database db, ProtectedStream ps, bool isV4,
                         IReadOnlyList<(bool IsProtected, byte[] Data)>? binaryPool = null)
    {
        _db = db;
        _ps = ps;
        _isV4 = isV4;
        _binaryPool = binaryPool ?? [];
    }

    public void ReadFrom(Stream stream)
    {
        var xml = XDocument.Load(stream);
        var keePassFile = xml.Root
            ?? throw new InvalidDataException("Missing root XML element.");

        if (_isV4)
        {
            _pool = [.. _binaryPool];
        }
        else
        {
            // V3: binary pool is stored in <Meta><Binaries>
            _pool = ParseMetaBinaries(keePassFile.Element("Meta"));
        }

        var meta = ParseMeta(keePassFile.Element("Meta"));

        var rootGroupEl = keePassFile.Element("Root")?.Element("Group")
            ?? throw new InvalidDataException("Missing <Root><Group> element.");

        var root = ParseGroup(rootGroupEl);
        _db.SetupLoadedData(new DatabaseData(meta, root));
    }

    // ── Meta ─────────────────────────────────────────────────────────────────

    private Metadata ParseMeta(XElement? el)
    {
        if (el == null) return new Metadata();
        return new Metadata
        {
            Name = el.Element("DatabaseName")?.Value ?? "",
            Description = el.Element("DatabaseDescription")?.Value ?? "",
            DefaultUserName = el.Element("DefaultUserName")?.Value ?? "",
            RecycleBinEnabled = ParseBool(el.Element("RecycleBinEnabled")?.Value, true),
            RecycleBinUuid = ParseUuid(el.Element("RecycleBinUUID")?.Value),
            HistoryMaxItems = ParseInt(el.Element("HistoryMaxItems")?.Value, 10),
            HistoryMaxSize = ParseLong(el.Element("HistoryMaxSize")?.Value, 6_291_456),
            ProtectPassword = ParseBool(
                el.Element("MemoryProtection")?.Element("ProtectPassword")?.Value, true),
            CustomIcons = ParseCustomIcons(el.Element("CustomIcons")),
        };
    }

    // ── Custom icons ──────────────────────────────────────────────────────────
    // <CustomIcons><Icon><UUID>…</UUID><Name>…</Name><Data>…</Data></Icon></CustomIcons>

    private List<CustomIcon> ParseCustomIcons(XElement? el)
    {
        var list = new List<CustomIcon>();
        if (el == null) return list;
        foreach (var iconEl in el.Elements("Icon"))
        {
            var uuid = ParseUuid(iconEl.Element("UUID")?.Value);
            var data = iconEl.Element("Data")?.Value;
            if (data == null) continue;
            list.Add(new CustomIcon
            {
                Uuid = uuid,
                Data = Convert.FromBase64String(data),
                Name = iconEl.Element("Name")?.Value ?? "",
                LastModificationTime = ParseDateNullable(iconEl.Element("LastModificationTime")?.Value),
            });
        }
        return list;
    }

    // ── Binary pool (KDBX 3.x) ───────────────────────────────────────────────
    // <Meta><Binaries><Binary ID="N" Compressed="True/False">base64data</Binary></Binaries></Meta>
    // V3 has no in-memory protection flag for binaries → IsProtected = false.

    private static List<(bool IsProtected, byte[] Data)> ParseMetaBinaries(XElement? metaEl)
    {
        var pool = new List<(bool IsProtected, byte[] Data)>();
        var binariesEl = metaEl?.Element("Binaries");
        if (binariesEl == null) return pool;

        foreach (var el in binariesEl.Elements("Binary"))
        {
            var idAttr = el.Attribute("ID");
            if (idAttr == null || !int.TryParse(idAttr.Value, out int id)) continue;

            byte[] data = Convert.FromBase64String(el.Value);

            bool compressed = el.Attribute("Compressed")?.Value
                .Equals("True", StringComparison.OrdinalIgnoreCase) ?? false;
            if (compressed) data = Decompress(data);

            // Ensure pool has enough slots (IDs may not be contiguous in theory)
            while (pool.Count <= id) pool.Add((false, []));
            pool[id] = (false, data);
        }

        return pool;
    }

    // ── Group (recursive, document order) ────────────────────────────────────

    private Group ParseGroup(XElement el)
    {
        var group = new Group
        {
            Uuid = ParseUuid(el.Element("UUID")?.Value),
            Name = el.Element("Name")?.Value ?? "",
            Notes = el.Element("Notes")?.Value ?? "",
            IconId = ParseInt(el.Element("IconID")?.Value, 0),
            CustomIconUuid = ParseUuid(el.Element("CustomIconUUID")?.Value),
            IsExpanded = ParseBool(el.Element("IsExpanded")?.Value, true),
            EnableAutoType = ParseBoolNullable(el.Element("EnableAutoType")?.Value),
            EnableSearching = ParseBoolNullable(el.Element("EnableSearching")?.Value),
            Times = ParseTimes(el.Element("Times")),
        };

        // Iterate children in document order so ProtectedStream position stays consistent
        foreach (var child in el.Elements())
        {
            if (child.Name == "Entry")
                group.AddEntry(ParseEntry(child));
            else if (child.Name == "Group")
                group.AddGroup(ParseGroup(child));
        }

        return group;
    }

    // ── Entry ─────────────────────────────────────────────────────────────────

    private Entry ParseEntry(XElement el)
    {
        var entry = new Entry
        {
            Uuid = ParseUuid(el.Element("UUID")?.Value),
            IconId = ParseInt(el.Element("IconID")?.Value, 0),
            CustomIconUuid = ParseUuid(el.Element("CustomIconUUID")?.Value),
            ForegroundColor = el.Element("ForegroundColor")?.Value ?? "",
            BackgroundColor = el.Element("BackgroundColor")?.Value ?? "",
            OverrideUrl = el.Element("OverrideURL")?.Value ?? "",
            Tags = el.Element("Tags")?.Value ?? "",
            Times = ParseTimes(el.Element("Times")),
            AutoType = ParseAutoType(el.Element("AutoType")),
        };

        foreach (var strEl in el.Elements("String"))
        {
            var key = strEl.Element("Key")?.Value ?? "";
            var valEl = strEl.Element("Value");
            if (valEl == null) continue;

            bool isProtected = valEl.Attribute("Protected")?.Value
                .Equals("True", StringComparison.OrdinalIgnoreCase) ?? false;

            string value;
            if (isProtected)
            {
                byte[] cipher = Convert.FromBase64String(valEl.Value);
                byte[] plain = _ps.Process(cipher);
                value = Encoding.UTF8.GetString(plain);
            }
            else
            {
                value = valEl.Value;
            }

            entry.Strings[key] = new EntryString { Value = value, Protected = isProtected };
        }

        // Binaries — resolve pool index from <Value Ref="N"/>
        foreach (var binEl in el.Elements("Binary"))
        {
            var key = binEl.Element("Key")?.Value ?? "";
            var valEl = binEl.Element("Value");
            if (valEl == null) continue;

            var refAttr = valEl.Attribute("Ref");
            if (refAttr == null || !int.TryParse(refAttr.Value, out int idx)) continue;
            if (idx < 0 || idx >= _pool.Count) continue;

            var (isProtected, data) = _pool[idx];
            entry.Binaries.Add(new EntryBinary { Name = key, Data = data, IsProtected = isProtected });
        }

        // History — parsed after current entry's strings so the ProtectedStream
        // advances through current-entry fields before historical ones, preserving
        // document order and preventing keystream desynchronisation.
        var historyEl = el.Element("History");
        if (historyEl != null)
        {
            foreach (var histEntry in historyEl.Elements("Entry"))
                entry.History.Add(ParseEntry(histEntry));
        }

        return entry;
    }

    // ── AutoType ──────────────────────────────────────────────────────────────

    private static AutoType ParseAutoType(XElement? el)
    {
        if (el == null) return new AutoType();
        var at = new AutoType
        {
            Enabled = ParseBool(el.Element("Enabled")?.Value, true),
            DataTransferObfuscation = ParseInt(el.Element("DataTransferObfuscation")?.Value, 0),
            DefaultSequence = el.Element("DefaultSequence")?.Value ?? "",
        };
        foreach (var assoc in el.Elements("Association"))
        {
            at.Associations.Add(new AutoTypeAssociation
            {
                Window = assoc.Element("Window")?.Value ?? "",
                Sequence = assoc.Element("KeystrokeSequence")?.Value ?? "",
            });
        }
        return at;
    }

    // ── Times ─────────────────────────────────────────────────────────────────

    private Times ParseTimes(XElement? el)
    {
        if (el == null) return new Times();
        return new Times
        {
            CreationTime = ParseDate(el.Element("CreationTime")?.Value),
            LastModificationTime = ParseDate(el.Element("LastModificationTime")?.Value),
            LastAccessTime = ParseDate(el.Element("LastAccessTime")?.Value),
            ExpiryTime = ParseDate(el.Element("ExpiryTime")?.Value),
            Expires = ParseBool(el.Element("Expires")?.Value, false),
            UsageCount = ParseInt(el.Element("UsageCount")?.Value, 0),
            LocationChanged = ParseDate(el.Element("LocationChanged")?.Value),
        };
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static readonly DateTime KdbxV4Epoch = new(1, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private DateTime? ParseDateNullable(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        return ParseDate(value);
    }

    private DateTime ParseDate(string? value)
    {
        if (string.IsNullOrEmpty(value)) return DateTime.MinValue;
        if (_isV4)
        {
            byte[] bytes = Convert.FromBase64String(value);
            long seconds = BinaryPrimitives.ReadInt64LittleEndian(bytes);
            return KdbxV4Epoch.AddSeconds(seconds);
        }
        return DateTime.Parse(value, null, DateTimeStyles.RoundtripKind);
    }

    private static Guid ParseUuid(string? value)
    {
        if (string.IsNullOrEmpty(value)) return Guid.Empty;
        try
        {
            return new Guid(Convert.FromBase64String(value));
        }
        catch
        {
            return Guid.Empty;
        }
    }

    private static bool ParseBool(string? value, bool defaultValue)
    {
        if (string.IsNullOrEmpty(value)) return defaultValue;
        return value.Equals("True", StringComparison.OrdinalIgnoreCase);
    }

    private static bool? ParseBoolNullable(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        return value.Equals("True", StringComparison.OrdinalIgnoreCase);
    }

    private static int ParseInt(string? value, int defaultValue) =>
        int.TryParse(value, out int n) ? n : defaultValue;

    private static long ParseLong(string? value, long defaultValue) =>
        long.TryParse(value, out long n) ? n : defaultValue;

    private static byte[] Decompress(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);
        return output.ToArray();
    }
}
