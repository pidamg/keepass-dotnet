using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Pidamg.KeePass.Kdbx;

public class KdbxWriter
{

    private const int BlockSize = 1024 * 1024; // 1 MiB

    private readonly Database _db;

    public KdbxWriter(Database db)
    {
        _db = db;
    }

    public void WriteTo(Stream stream)
    {
        var header = _db.Settings.ToHeader();
        var psKey = RandomNumberGenerator.GetBytes(64);
        var ps = new ProtectedStream(_db.Settings.InnerStreamAlgorithm, psKey);

        var kdf = header.CreateKdf();
        var derived = DerivedKey.Derive(_db.Key, kdf);
        var encKey = new EncryptionKey(header.MasterSeed, derived);

        if (header.IsVersion4) WriteV4(stream, header, encKey, ps);
        else WriteV3(stream, header, encKey, ps);
    }

    // ── KDBX 3.x ─────────────────────────────────────────────────────────────
    // File: [Header][SymmetricCipher([StreamStartBytes(32)][HashedBlockStream][XML])]

    private void WriteV3(Stream stream, IHeader header, EncryptionKey encKey, ProtectedStream ps)
    {
        // Patch inner-stream fields into the header before writing it
        header.SetInnerStream(ps.Algorithm, ps.Key);

        var headerWriter = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        header.Write(headerWriter);
        headerWriter.Flush();

        using var xmlMs = new MemoryStream();
        // V3: binary pool is written into <Meta><Binaries> by KdbxXmlWriter
        new KdbxXmlWriter(_db, ps, isV4: false).WriteTo(xmlMs);
        byte[] xml = xmlMs.ToArray();
        if (header.IsCompressed) xml = CompressGzip(xml);

        // Build plaintext: StreamStartBytes + HashedBlocks
        using var plainMem = new MemoryStream();
        plainMem.Write(header.StreamStartBytes!);
        WriteHashedBlocks(plainMem, xml);
        byte[] plaintext = plainMem.ToArray();

        // Encrypt into a buffer, then copy to output stream
        var cipher = header.CreateCipher(encKey.GetKey());
        using var cipherMem = new MemoryStream();
        using (var encStream = cipher.CreateEncryptingStream(cipherMem))
        {
            encStream.Write(plaintext);
        }
        stream.Write(cipherMem.ToArray());
    }

    // ── KDBX 4.x ─────────────────────────────────────────────────────────────
    // File: [Header][SHA256(32)][HMAC(32)][HmacBlockStream([SymmetricCipher([InnerHeader][XML])])]

    private void WriteV4(Stream stream, IHeader header, EncryptionKey encKey, ProtectedStream ps)
    {
        // Serialize outer header to capture bytes for SHA256 / HMAC
        using var headerMs = new MemoryStream();
        var headerWriter = new BinaryWriter(headerMs, Encoding.UTF8, leaveOpen: true);
        header.Write(headerWriter);
        headerWriter.Flush();
        byte[] headerBytes = headerMs.ToArray();

        stream.Write(headerBytes);
        stream.Write(SHA256.HashData(headerBytes));

        byte[] headerHmacKey = BlockKey(ulong.MaxValue, encKey.GetHmacKey());
        using (var h = new HMACSHA256(headerHmacKey))
        {
            stream.Write(h.ComputeHash(headerBytes));
        }

        // Build payload: [InnerHeader][XML], then optionally compress
        // The XML writer pre-scans all entries to build the binary pool first,
        // so we can write the inner header (which includes binaries) before the XML.
        var xmlWriter = new KdbxXmlWriter(_db, ps, isV4: true);

        using var payloadMs = new MemoryStream();
        WriteInnerHeader(payloadMs, ps.Algorithm, ps.Key, xmlWriter.BinaryPool);
        xmlWriter.WriteTo(payloadMs);
        byte[] payload = payloadMs.ToArray();

        if (header.IsCompressed) payload = CompressGzip(payload);

        // Encrypt
        var cipher = header.CreateCipher(encKey.GetKey());
        using var cipherMs = new MemoryStream();
        using (var encStream = cipher.CreateEncryptingStream(cipherMs))
        {
            encStream.Write(payload);
        }

        // Write as HMAC-authenticated blocks
        WriteHmacBlocks(stream, cipherMs.ToArray(), encKey.GetHmacKey());
    }

    // ── HashedBlockStream (KDBX 3.x) ─────────────────────────────────────────
    // Block: [Index (4 LE)][SHA256 (32)][Size (4 LE)][Data]
    // Terminates with a block of Size == 0.

    private static void WriteHashedBlocks(Stream output, byte[] data)
    {
        var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        int blockIndex = 0;
        int offset = 0;

        while (offset < data.Length)
        {
            int size = Math.Min(BlockSize, data.Length - offset);
            byte[] block = data[offset..(offset + size)];

            writer.Write((uint)blockIndex);
            writer.Write(SHA256.HashData(block));
            writer.Write((uint)size);
            writer.Write(block);

            offset += size;
            blockIndex++;
        }

        // Terminator block (size = 0, zero hash)
        writer.Write((uint)blockIndex);
        writer.Write(new byte[32]);
        writer.Write((uint)0);
        writer.Flush();
    }

    // ── HmacBlockStream (KDBX 4.x) ───────────────────────────────────────────
    // Block: [HMAC-SHA256 (32)][Size (4 LE signed)][Data]
    // Last block (Size == 0) is also HMAC-verified.

    private static void WriteHmacBlocks(Stream output, byte[] data, byte[] hmacKey64)
    {
        var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        ulong blockIndex = 0;
        int offset = 0;

        while (offset < data.Length)
        {
            int size = Math.Min(BlockSize, data.Length - offset);
            byte[] block = data[offset..(offset + size)];
            byte[] blockKey = BlockKey(blockIndex, hmacKey64);
            byte[] hmac = BlockHmac(blockIndex, size, block, blockKey);

            writer.Write(hmac);
            writer.Write(size);
            writer.Write(block);

            offset += size;
            blockIndex++;
        }

        // Terminator block (HMAC-verified empty block)
        byte[] termKey = BlockKey(blockIndex, hmacKey64);
        byte[] termHmac = BlockHmac(blockIndex, 0, [], termKey);
        writer.Write(termHmac);
        writer.Write(0); // size = 0
        writer.Flush();
    }

    // ── Inner header (KDBX 4.x) ──────────────────────────────────────────────
    // Field: [ID (1)][Length (4 LE)][Data]
    // 0x01 = InnerRandomStreamId
    // 0x02 = InnerRandomStreamKey
    // 0x03 = Binary  →  [flags (1)][data]  (flags bit0 = isProtected, we write 0x00)
    // 0x00 = EndOfHeader

    private static void WriteInnerHeader(Stream output, ProtectedStreamAlgorithm algo, byte[] key, IReadOnlyList<(bool IsProtected, byte[] Data)> binaries)
    {
        var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);

        // 0x01: InnerRandomStreamId
        var algoBytes = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(algoBytes, (uint)algo);
        writer.Write((byte)0x01);
        writer.Write((uint)algoBytes.Length);
        writer.Write(algoBytes);

        // 0x02: InnerRandomStreamKey
        writer.Write((byte)0x02);
        writer.Write((uint)key.Length);
        writer.Write(key);

        // 0x03: Binaries (one entry per pool item)
        // Format: [flags (1)][data]  —  flags bit0 = isProtected
        foreach (var (isProtected, data) in binaries)
        {
            var payload = new byte[1 + data.Length];
            payload[0] = isProtected ? (byte)0x01 : (byte)0x00;
            data.CopyTo(payload, 1);
            writer.Write((byte)0x03);
            writer.Write((uint)payload.Length);
            writer.Write(payload);
        }

        // 0x00: EndOfHeader
        writer.Write((byte)0x00);
        writer.Write((uint)0);
        writer.Flush();
    }

    // ── HMAC helpers (mirror of KdbxReader) ──────────────────────────────────

    // blockKey = SHA512(blockIndex_LE64 ∥ hmacKey64)
    private static byte[] BlockKey(ulong blockIndex, byte[] hmacKey64)
    {
        var buf = new byte[8 + hmacKey64.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(buf, blockIndex);
        hmacKey64.CopyTo(buf, 8);
        return SHA512.HashData(buf);
    }

    // blockHmac = HMAC-SHA256(blockIndex_LE64 ∥ blockSize_LE32 ∥ data, blockKey)
    private static byte[] BlockHmac(ulong blockIndex, int blockSize, byte[] data, byte[] blockKey)
    {
        var msg = new byte[8 + 4 + data.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(msg, blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(msg.AsSpan(8), blockSize);
        data.CopyTo(msg, 12);
        using var hmac = new HMACSHA256(blockKey);
        return hmac.ComputeHash(msg);
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

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
