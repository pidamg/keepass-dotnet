using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;

namespace Pidamg.KeePass;

internal class KdbxReader
{

    private readonly KdbxDatabase _db;

    public KdbxReader(KdbxDatabase db)
    {
        _db = db;
    }

    public void ReadFrom(Stream stream)
    {
        // RecordingStream captures header bytes needed for KDBX 4.x verification
        var recording = new RecordingStream(stream);
        var header = KdbxHeader.Read(new BinaryReader(recording));
        byte[] headerBytes = recording.GetRecordedBytes();

        _db.Version = header.Version;

        var kdf = header.CreateKdf();
        var derived = DerivedKey.Derive(_db.Key, kdf);
        var encKey = new EncryptionKey(header.MasterSeed, derived);

        if (header.IsVersion4) ReadV4(header, encKey, headerBytes, stream);
        else ReadV3(header, encKey, stream);
    }

    // ── KDBX 3.x ────────────────────────────────────────────────────────────────
    // File: [Header][SymmetricCipher([StreamStartBytes(32)][HashedBlockStream][XML])]

    private void ReadV3(KdbxHeader header, EncryptionKey encKey, Stream stream)
    {
        var cipher = header.CreateCipher(encKey.GetKey());
        using var decrypted = cipher.CreateDecryptingStream(stream);
        var reader = new BinaryReader(decrypted);

        // First 32 bytes of the decrypted stream must match StreamStartBytes from header
        byte[] startBytes = reader.ReadBytes(32);
        if (!startBytes.SequenceEqual(header.StreamStartBytes!))
            throw new InvalidDataException("StreamStartBytes verification failed.");

        byte[] plaintext = ReadHashedBlocks(reader);
        if (header.IsCompressed) plaintext = Decompress(plaintext);

        var ps = new ProtectedStream(header.InnerRandomStreamId, header.ProtectedStreamKey!);
        _db.Settings = KdbxSettings.FromHeader(header, header.InnerRandomStreamId);

        // V3: binary pool is parsed from <Meta><Binaries> inside the XML layer
        using var xmlStream = new MemoryStream(plaintext);
        new KdbxXmlReader(_db, ps, isV4: false).ReadFrom(xmlStream);
    }

    // ── KDBX 4.x ────────────────────────────────────────────────────────────────
    // File: [Header][SHA256(32)][HMAC(32)][HmacBlockStream([SymmetricCipher([InnerHeader][XML])])]

    private void ReadV4(KdbxHeader header, EncryptionKey encKey, byte[] headerBytes, Stream stream)
    {
        var fileReader = new BinaryReader(stream);

        // Verify SHA256 of the outer header
        byte[] sha = fileReader.ReadBytes(32);
        if (!sha.SequenceEqual(SHA256.HashData(headerBytes)))
            throw new InvalidDataException("Header SHA256 verification failed.");

        // Verify HMAC-SHA256 of the outer header (block key uses index = UInt64.MaxValue)
        byte[] headerHmac = fileReader.ReadBytes(32);
        byte[] headerHmacKey = BlockKey(ulong.MaxValue, encKey.GetHmacKey());
        using (var h = new HMACSHA256(headerHmacKey))
        {
            if (!headerHmac.SequenceEqual(h.ComputeHash(headerBytes)))
                throw new InvalidDataException("Header HMAC verification failed.");
        }

        // Read and verify the HmacBlockStream → ciphertext
        byte[] ciphertext = ReadHmacBlocks(fileReader, encKey.GetHmacKey());

        var cipher = header.CreateCipher(encKey.GetKey());
        using var decryptedStream = cipher.CreateDecryptingStream(new MemoryStream(ciphertext));

        // Copy decrypted (and optionally decompressed) bytes into a seekable MemoryStream
        using var plainStream = new MemoryStream();
        if (header.IsCompressed)
        {
            using var gzip = new GZipStream(decryptedStream, CompressionMode.Decompress);
            gzip.CopyTo(plainStream);
        }
        else
        {
            decryptedStream.CopyTo(plainStream);
        }
        plainStream.Position = 0;

        // Inner header: stream algorithm, key, and binary pool
        var innerReader = new BinaryReader(plainStream);
        var (algo, innerKey, binaries) = ReadInnerHeader(innerReader);

        var ps = new ProtectedStream(algo, innerKey);
        _db.Settings = KdbxSettings.FromHeader(header, algo);

        // plainStream is now positioned at the XML bytes
        new KdbxXmlReader(_db, ps, isV4: true, binaries).ReadFrom(plainStream);
    }

    // ── HashedBlockStream (KDBX 3.x) ────────────────────────────────────────────
    // Block: [Index (4 LE)][SHA256 (32)][Size (4 LE)][Data]
    // Terminates when Size == 0.

    private static byte[] ReadHashedBlocks(BinaryReader reader)
    {
        using var result = new MemoryStream();
        while (true)
        {
            reader.ReadUInt32();           // block index (sequential, not verified here)
            byte[] hash = reader.ReadBytes(32);
            int size = (int)reader.ReadUInt32();
            byte[] data = reader.ReadBytes(size);

            if (size == 0) break;

            if (!SHA256.HashData(data).SequenceEqual(hash))
                throw new InvalidDataException("Block hash verification failed.");

            result.Write(data);
        }
        return result.ToArray();
    }

    // ── HmacBlockStream (KDBX 4.x) ──────────────────────────────────────────────
    // Block: [HMAC-SHA256 (32)][Size (4 LE signed)][Data]
    // Terminates when Size == 0 (last block is still HMAC-verified).

    private static byte[] ReadHmacBlocks(BinaryReader reader, byte[] hmacKey64)
    {
        using var result = new MemoryStream();
        ulong blockIndex = 0;

        while (true)
        {
            byte[] hmac = reader.ReadBytes(32);
            int size = reader.ReadInt32();
            byte[] data = reader.ReadBytes(size);

            byte[] blockKey = BlockKey(blockIndex, hmacKey64);
            byte[] expectedHmac = BlockHmac(blockIndex, size, data, blockKey);
            if (!hmac.SequenceEqual(expectedHmac))
                throw new InvalidDataException($"Block {blockIndex} HMAC verification failed.");

            if (size == 0) break;
            result.Write(data);
            blockIndex++;
        }
        return result.ToArray();
    }

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

    // ── Decompression ────────────────────────────────────────────────────────────

    private static byte[] Decompress(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);
        return output.ToArray();
    }

    // ── Inner header (KDBX 4.x, inside the decrypted payload) ───────────────────
    // Field: [ID (1)][Length (4 LE)][Data]
    // 0x00 = EndOfHeader
    // 0x01 = InnerRandomStreamId
    // 0x02 = InnerRandomStreamKey
    // 0x03 = Binary  →  [flags (1)][data]  (flags bit0 = isProtected, ignored on read)

    private static (ProtectedStreamAlgorithm algo, byte[] key, List<(bool IsProtected, byte[] Data)> binaries) ReadInnerHeader(BinaryReader reader)
    {
        var algo = ProtectedStreamAlgorithm.ChaCha20;
        byte[]? key = null;
        var binaries = new List<(bool IsProtected, byte[] Data)>();

        while (true)
        {
            byte id = reader.ReadByte();
            int len = (int)reader.ReadUInt32();
            byte[] data = reader.ReadBytes(len);

            if (id == 0x00) break;
            switch (id)
            {
                case 0x01: algo = (ProtectedStreamAlgorithm)BinaryPrimitives.ReadUInt32LittleEndian(data); break;
                case 0x02: key = data; break;
                case 0x03:
                    // byte 0 = flags (bit0 = isProtected); remaining bytes = raw data
                    binaries.Add((IsProtected: (data[0] & 0x01) != 0, Data: data[1..]));
                    break;
            }
        }

        return (algo, key ?? [], binaries);
    }

    // ── RecordingStream ──────────────────────────────────────────────────────────
    // Wraps a stream and records every byte read through it.
    // Does NOT dispose the inner stream.

    private sealed class RecordingStream : Stream
    {

        private readonly Stream _inner;
        private readonly MemoryStream _buffer = new();

        public RecordingStream(Stream inner) => _inner = inner;

        public byte[] GetRecordedBytes() => _buffer.ToArray();

        public override bool CanRead => _inner.CanRead;
        public override bool CanWrite => false;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = _inner.Read(buffer, offset, count);
            _buffer.Write(buffer, offset, n);
            return n;
        }

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _buffer.Dispose();
            base.Dispose(disposing); // intentionally does NOT dispose _inner
        }
    }
}
