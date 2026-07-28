using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace Pidamg.KeePass.Kdbx;

public class KdbxXmlWriter
{

    private readonly KdbxDatabase _db;
    private readonly ProtectedStream _ps;
    private readonly bool _isV4;
    private readonly List<(bool IsProtected, byte[] Data)> _binaryPool;

    // Exposed for KdbxWriter.WriteV4 so it can write binaries to the inner header
    // before calling WriteTo(). Pool is built eagerly in the constructor.
    public IReadOnlyList<(bool IsProtected, byte[] Data)> BinaryPool => _binaryPool;

    public KdbxXmlWriter(KdbxDatabase db, ProtectedStream ps, bool isV4)
    {
        _db = db;
        _ps = ps;
        _isV4 = isV4;
        _binaryPool = BuildBinaryPool();
    }

    public void WriteTo(Stream stream)
    {
        var xml = new XDocument(
            new XElement("KeePassFile",
                WriteMeta(_db.Metadata!),
                new XElement("Root", WriteGroup(_db.RootGroup!))
            )
        );
        xml.Save(stream);
    }

    // ── Meta ──────────────────────────────────────────────────────────────────

    private XElement WriteMeta(Metadata meta)
    {
        var el = new XElement("Meta",
            new XElement("DatabaseName", meta.Name),
            new XElement("DatabaseDescription", meta.Description),
            new XElement("DefaultUserName", meta.DefaultUserName),
            new XElement("RecycleBinEnabled", meta.RecycleBinEnabled ? "True" : "False"),
            new XElement("RecycleBinUUID", GuidToBase64(meta.RecycleBinUuid)),
            new XElement("HistoryMaxItems", meta.HistoryMaxItems),
            new XElement("HistoryMaxSize", meta.HistoryMaxSize),
            new XElement("MemoryProtection",
                new XElement("ProtectPassword", meta.ProtectPassword ? "True" : "False")
            )
        );

        if (meta.CustomIcons.Count > 0)
        {
            var iconsEl = new XElement("CustomIcons");
            foreach (var icon in meta.CustomIcons)
            {
                var iconEl = new XElement("Icon",
                    new XElement("UUID", GuidToBase64(icon.Uuid)),
                    new XElement("Data", Convert.ToBase64String(icon.Data))
                );
                if (!string.IsNullOrEmpty(icon.Name))
                    iconEl.Add(new XElement("Name", icon.Name));
                if (icon.LastModificationTime.HasValue)
                    iconEl.Add(new XElement("LastModificationTime",
                        FormatDate(icon.LastModificationTime.Value)));
                iconsEl.Add(iconEl);
            }
            el.Add(iconsEl);
        }

        // V3: binary pool lives in <Meta><Binaries>; V4: it goes in the inner header
        if (!_isV4 && _binaryPool.Count > 0)
        {
            var binariesEl = new XElement("Binaries");
            for (int i = 0; i < _binaryPool.Count; i++)
            {
                byte[] compressed = CompressGzip(_binaryPool[i].Data);
                binariesEl.Add(new XElement("Binary",
                    new XAttribute("ID", i),
                    new XAttribute("Compressed", "True"),
                    Convert.ToBase64String(compressed)
                ));
            }
            el.Add(binariesEl);
        }

        return el;
    }

    // ── Group (recursive, entries before sub-groups) ──────────────────────────

    private XElement WriteGroup(Group group)
    {
        var el = new XElement("Group",
            new XElement("UUID", GuidToBase64(group.Uuid)),
            new XElement("Name", group.Name),
            new XElement("Notes", group.Notes),
            new XElement("IconID", group.IconId),
            new XElement("IsExpanded", group.IsExpanded ? "True" : "False"),
            WriteTimes(group.Times)
        );
        if (group.CustomIconUuid != Guid.Empty)
            el.Add(new XElement("CustomIconUUID", GuidToBase64(group.CustomIconUuid)));
        if (group.EnableAutoType.HasValue)
            el.Add(new XElement("EnableAutoType", group.EnableAutoType.Value ? "True" : "False"));
        if (group.EnableSearching.HasValue)
            el.Add(new XElement("EnableSearching", group.EnableSearching.Value ? "True" : "False"));

        foreach (var entry in group.Entries)
            el.Add(WriteEntry(entry));

        foreach (var sub in group.Groups)
            el.Add(WriteGroup(sub));

        return el;
    }

    // ── Entry ─────────────────────────────────────────────────────────────────

    private XElement WriteEntry(Entry entry)
    {
        var el = new XElement("Entry",
            new XElement("UUID", GuidToBase64(entry.Uuid)),
            new XElement("IconID", entry.IconId),
            new XElement("ForegroundColor", entry.ForegroundColor),
            new XElement("BackgroundColor", entry.BackgroundColor),
            new XElement("OverrideURL", entry.OverrideUrl),
            new XElement("Tags", entry.Tags),
            WriteTimes(entry.Times)
        );
        if (entry.CustomIconUuid != Guid.Empty)
            el.Add(new XElement("CustomIconUUID", GuidToBase64(entry.CustomIconUuid)));

        foreach (var (key, entryStr) in entry.Strings)
        {
            XElement valEl;
            if (entryStr.Protected)
            {
                byte[] plain = Encoding.UTF8.GetBytes(entryStr.Value);
                byte[] cipher = _ps.Process(plain);
                valEl = new XElement("Value", Convert.ToBase64String(cipher));
                valEl.SetAttributeValue("Protected", "True");
            }
            else
            {
                valEl = new XElement("Value", entryStr.Value);
            }

            el.Add(new XElement("String",
                new XElement("Key", key),
                valEl
            ));
        }

        // Binaries — write pool index as <Value Ref="N"/>
        foreach (var bin in entry.Binaries)
        {
            int idx = GetBinaryIndex(bin.Data);
            if (idx < 0) continue; // should never happen if pool was built correctly
            el.Add(new XElement("Binary",
                new XElement("Key", bin.Name),
                new XElement("Value", new XAttribute("Ref", idx))
            ));
        }

        el.Add(WriteAutoType(entry.AutoType));

        // History — written after current entry's strings so the ProtectedStream
        // keystream position matches the read path (document order).
        if (entry.History.Count > 0)
        {
            var historyEl = new XElement("History");
            foreach (var hist in entry.History)
                historyEl.Add(WriteEntry(hist));
            el.Add(historyEl);
        }

        return el;
    }

    // ── AutoType ──────────────────────────────────────────────────────────────

    private static XElement WriteAutoType(AutoType at)
    {
        var el = new XElement("AutoType",
            new XElement("Enabled", at.Enabled ? "True" : "False"),
            new XElement("DataTransferObfuscation", at.DataTransferObfuscation),
            new XElement("DefaultSequence", at.DefaultSequence)
        );
        foreach (var assoc in at.Associations)
        {
            el.Add(new XElement("Association",
                new XElement("Window", assoc.Window),
                new XElement("KeystrokeSequence", assoc.Sequence)
            ));
        }
        return el;
    }

    // ── Times ─────────────────────────────────────────────────────────────────

    private XElement WriteTimes(Times times) =>
        new("Times",
            new XElement("CreationTime", FormatDate(times.CreationTime)),
            new XElement("LastModificationTime", FormatDate(times.LastModificationTime)),
            new XElement("LastAccessTime", FormatDate(times.LastAccessTime)),
            new XElement("ExpiryTime", FormatDate(times.ExpiryTime)),
            new XElement("Expires", times.Expires ? "True" : "False"),
            new XElement("UsageCount", times.UsageCount),
            new XElement("LocationChanged", FormatDate(times.LocationChanged))
        );

    // ── Binary pool ───────────────────────────────────────────────────────────

    // Pre-scan all entries (including history) to collect unique binary data.
    // Deduplication is by value (SequenceEqual); order = first occurrence.
    private List<(bool IsProtected, byte[] Data)> BuildBinaryPool()
    {
        var pool = new List<(bool IsProtected, byte[] Data)>();
        if (_db.RootGroup != null)
            CollectGroupBinaries(_db.RootGroup, pool);
        return pool;
    }

    private static void CollectGroupBinaries(Group group, List<(bool IsProtected, byte[] Data)> pool)
    {
        foreach (var entry in group.Entries)
        {
            CollectEntryBinaries(entry, pool);
            foreach (var hist in entry.History)
                CollectEntryBinaries(hist, pool);
        }
        foreach (var sub in group.Groups)
            CollectGroupBinaries(sub, pool);
    }

    private static void CollectEntryBinaries(Entry entry, List<(bool IsProtected, byte[] Data)> pool)
    {
        foreach (var bin in entry.Binaries)
            if (!pool.Any(p => p.Data.SequenceEqual(bin.Data)))
                pool.Add((bin.IsProtected, bin.Data));
    }

    private int GetBinaryIndex(byte[] data)
    {
        for (int i = 0; i < _binaryPool.Count; i++)
            if (_binaryPool[i].Data.SequenceEqual(data)) return i;
        return -1;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static readonly DateTime KdbxV4Epoch = new(1, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private string FormatDate(DateTime dt)
    {
        if (_isV4)
        {
            long seconds = (long)(dt.ToUniversalTime() - KdbxV4Epoch).TotalSeconds;
            byte[] buf = new byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(buf, seconds);
            return Convert.ToBase64String(buf);
        }
        return dt.ToUniversalTime().ToString("O");
    }

    private static string GuidToBase64(Guid g) =>
        Convert.ToBase64String(g.ToByteArray());

    private static byte[] CompressGzip(byte[] data)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionMode.Compress, leaveOpen: true))
        {
            gzip.Write(data);
        }
        return output.ToArray();
    }
}
