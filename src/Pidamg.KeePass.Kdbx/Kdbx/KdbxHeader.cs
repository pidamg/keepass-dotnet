using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Pidamg.KeePass.Kdbx;

public class KdbxHeader : IHeader
{

    public static readonly Signature ValidSignature = new(0x9AA2D903, 0xB54BFB67);

    private enum FieldId : byte
    {
        EndOfHeader = 0x00,
        Comment = 0x01,
        CipherId = 0x02,
        CompressionFlags = 0x03,
        MasterSeed = 0x04,
        TransformSeed = 0x05,
        TransformRounds = 0x06,
        EncryptionIV = 0x07,
        ProtectedStreamKey = 0x08,
        StreamStartBytes = 0x09,
        InnerRandomStreamId = 0x0A,
        KdfParameters = 0x0B,
        PublicCustomData = 0x0C,
    }

    public Signature Signature { get; private set; } = new();
    public Version Version { get; private set; } = new();
    public bool IsVersion4 => Version.Major == 4;

    public Guid CipherId { get; private set; }
    public bool IsCompressed { get; private set; }
    public byte[] MasterSeed { get; private set; } = [];
    public byte[] EncryptionIV { get; private set; } = [];

    // KDBX 3.x fields (also used by AES-KDF in 4.x via KdfParameters)
    public byte[]? TransformSeed { get; private set; }
    public ulong TransformRounds { get; private set; }

    // KDBX 3.x inner stream (replaced by inner header in 4.x)
    public byte[]? ProtectedStreamKey { get; private set; }
    public byte[]? StreamStartBytes { get; private set; }
    public ProtectedStreamAlgorithm InnerRandomStreamId { get; private set; }

    // KDBX 4.x
    public VariantMap? KdfParameters { get; private set; }

    private KdbxHeader() { }

    // ── Factories ─────────────────────────────────────────────────────────────

    internal static KdbxHeader CreateNewV3(CipherAlgorithm cipher, ProtectedStreamAlgorithm algo, ulong rounds, bool compress)
    {
        var h = new KdbxHeader();
        h.Signature = ValidSignature;
        h.Version = new(3, 1);
        h.CipherId = SymmetricCipher.UuidFromAlgorithm(cipher);
        h.IsCompressed = compress;
        h.MasterSeed = RandomBytes(32);
        h.EncryptionIV = RandomBytes(ProtectedStream.GetIvSize(cipher));
        h.TransformSeed = RandomBytes(32);
        h.TransformRounds = rounds;
        h.StreamStartBytes = RandomBytes(32);
        h.InnerRandomStreamId = algo;
        h.ProtectedStreamKey = RandomBytes(32);
        return h;
    }

    internal static KdbxHeader CreateNewV4(CipherAlgorithm cipher, IKdf? kdf, bool compress)
    {
        var h = new KdbxHeader();
        h.Signature = ValidSignature;
        h.Version = new(4, 1);
        h.CipherId = SymmetricCipher.UuidFromAlgorithm(cipher);
        h.IsCompressed = compress;
        h.MasterSeed = RandomBytes(32);
        h.EncryptionIV = RandomBytes(ProtectedStream.GetIvSize(cipher));
        h.KdfParameters = kdf?.Parameters() ?? new VariantMap(new Dictionary<string, object>
        {
            ["$UUID"] = GuidRfc4122.ToBytes(Argon2Kdf.Argon2idUuid),
            ["S"] = RandomBytes(32),
            ["P"] = (uint)2,
            ["M"] = (ulong)(64 * 1024 * 1024), // 64 MiB stored as bytes (KDBX convention)
            ["I"] = (ulong)2,
            ["V"] = (uint)0x13,
        });
        return h;
    }

    public static KdbxHeader CreateNew(
        bool v4 = true,
        CipherAlgorithm cipher = CipherAlgorithm.ChaCha20,
        bool compress = true,
        ProtectedStreamAlgorithm innerAlgo = ProtectedStreamAlgorithm.ChaCha20)
    {

        return v4
            ? CreateNewV4(cipher, kdf: null, compress)
            : CreateNewV3(cipher, innerAlgo, rounds: 6000, compress);
    }

    // ── Deserialization ───────────────────────────────────────────────────────

    public static KdbxHeader Read(BinaryReader reader)
    {
        var h = new KdbxHeader();

        h.Signature = Signature.Read(reader);
        if (h.Signature != ValidSignature)
            throw new FormatException("Invalid KDBX file signatures.");

        h.Version = Version.Read(reader);
        if (h.Version.Major != 3 && h.Version.Major != 4)
            throw new NotSupportedException($"Unsupported KDBX version: {h.Version}");

        bool v4 = h.Version.Major == 4;

        while (true)
        {
            var fieldId = (FieldId)reader.ReadByte();
            int length = v4 ? (int)reader.ReadUInt32() : (int)reader.ReadUInt16();
            byte[] data = reader.ReadBytes(length);

            switch (fieldId)
            {
                case FieldId.EndOfHeader: return h;
                case FieldId.CipherId: h.CipherId = GuidRfc4122.FromBytes(data); break;
                case FieldId.CompressionFlags: h.IsCompressed = BinaryPrimitives.ReadUInt32LittleEndian(data) != 0; break;
                case FieldId.MasterSeed: h.MasterSeed = data; break;
                case FieldId.TransformSeed: h.TransformSeed = data; break;
                case FieldId.TransformRounds: h.TransformRounds = BinaryPrimitives.ReadUInt64LittleEndian(data); break;
                case FieldId.EncryptionIV: h.EncryptionIV = data; break;
                case FieldId.ProtectedStreamKey: h.ProtectedStreamKey = data; break;
                case FieldId.StreamStartBytes: h.StreamStartBytes = data; break;
                case FieldId.InnerRandomStreamId: h.InnerRandomStreamId = (ProtectedStreamAlgorithm)BinaryPrimitives.ReadUInt32LittleEndian(data); break;
                case FieldId.KdfParameters: h.KdfParameters = VariantMap.Read(data); break;
                    // Comment and PublicCustomData are ignored
            }
        }
    }

    // ── IHeader ───────────────────────────────────────────────────────────────

    public IKdf CreateKdf()
    {
        if (!IsVersion4)
        {
            if (TransformSeed == null)
                throw new InvalidOperationException("TransformSeed missing from header.");
            return new AesKdf(TransformSeed, TransformRounds);
        }

        if (KdfParameters == null || !KdfParameters.TryGetValue("$UUID", out var uuidBytes))
            throw new InvalidOperationException("KdfParameters missing or has no $UUID.");

        var kdfId = GuidRfc4122.FromBytes((byte[])uuidBytes!);

        if (kdfId == Argon2Kdf.Argon2dUuid || kdfId == Argon2Kdf.Argon2idUuid)
        {
            var salt = (byte[])KdfParameters["S"];
            var parallelism = (int)(uint)KdfParameters["P"];
            var memoryKib = (int)((ulong)KdfParameters["M"] / 1024); // M is stored as bytes in KDBX
            var iterations = (int)(ulong)KdfParameters["I"];
            var type = kdfId == Argon2Kdf.Argon2idUuid ? Argon2Type.Id : Argon2Type.D;
            return new Argon2Kdf(salt, parallelism, memoryKib, iterations, type);
        }

        if (kdfId == AesKdf.UuidKdbx3 || kdfId == AesKdf.UuidKdbx4)
        {
            var seed = (byte[])KdfParameters["S"];
            var rounds = (ulong)KdfParameters["R"];
            return new AesKdf(seed, rounds);
        }

        throw new NotSupportedException($"Unknown KDF UUID: {kdfId}");
    }

    public SymmetricCipher CreateCipher(byte[] key)
        => new SymmetricCipher(SymmetricCipher.FromUuid(CipherId), key, EncryptionIV);

    public ProtectedStreamAlgorithm InnerStreamAlgorithm
        => IsVersion4 ? ProtectedStreamAlgorithm.ChaCha20 : InnerRandomStreamId;

    // Updates the V3 outer-header inner-stream fields to match the ProtectedStream
    // that will be used for the XML payload. Must be called before Write() when
    // reusing an existing header with a freshly generated ProtectedStream.
    public void SetInnerStream(ProtectedStreamAlgorithm algorithm, byte[] key)
    {
        InnerRandomStreamId = algorithm;
        ProtectedStreamKey = key;
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    public void Write(BinaryWriter writer)
    {
        bool v4 = IsVersion4;

        this.Signature.Write(writer);
        this.Version.Write(writer);

        WriteField(writer, FieldId.CipherId, GuidRfc4122.ToBytes(CipherId), v4);
        WriteField(writer, FieldId.CompressionFlags, GetUInt32LE(IsCompressed ? 1u : 0u), v4);
        WriteField(writer, FieldId.MasterSeed, MasterSeed, v4);

        if (!v4)
        {
            WriteField(writer, FieldId.TransformSeed, TransformSeed!, v4);
            WriteField(writer, FieldId.TransformRounds, GetUInt64LE(TransformRounds), v4);
            WriteField(writer, FieldId.EncryptionIV, EncryptionIV, v4);
            WriteField(writer, FieldId.ProtectedStreamKey, ProtectedStreamKey!, v4);
            WriteField(writer, FieldId.StreamStartBytes, StreamStartBytes!, v4);
            WriteField(writer, FieldId.InnerRandomStreamId, GetUInt32LE((uint)InnerRandomStreamId), v4);
        }
        else
        {
            WriteField(writer, FieldId.EncryptionIV, EncryptionIV, v4);
            WriteField(writer, FieldId.KdfParameters, KdfParameters!.Serialize(), v4);
        }

        WriteField(writer, FieldId.EndOfHeader, [], v4);
    }

    public void Write(Stream stream)
    {
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        Write(writer);
    }

    public string Dump()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Signature     : {Signature.Sign1:X8} {Signature.Sign2:X8}");
        sb.AppendLine($"Version       : {Version} ({(IsVersion4 ? "KDBX 4.x" : "KDBX 3.x")})");
        sb.AppendLine($"CipherId      : {CipherId}");
        sb.AppendLine($"IsCompressed  : {IsCompressed}");
        sb.AppendLine($"MasterSeed    : {Hex(MasterSeed)}");
        sb.AppendLine($"EncryptionIV  : {Hex(EncryptionIV)}");
        if (!IsVersion4)
        {
            sb.AppendLine($"TransformSeed : {Hex(TransformSeed)}");
            sb.AppendLine($"Rounds        : {TransformRounds}");
            sb.AppendLine($"StreamStartB  : {Hex(StreamStartBytes)}");
            sb.AppendLine($"InnerStreamId : {InnerRandomStreamId}");
            sb.AppendLine($"InnerStreamKey: {Hex(ProtectedStreamKey)}");
        }
        else if (KdfParameters != null)
        {
            sb.AppendLine("KdfParameters :");
            sb.Append(KdfParameters.Dump());
        }
        return sb.ToString();

        static string Hex(byte[]? b) => b == null ? "(null)" : BitConverter.ToString(b);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static void WriteField(BinaryWriter w, FieldId id, byte[] data, bool v4)
    {
        w.Write((byte)id);
        if (v4) w.Write((uint)data.Length);
        else w.Write((ushort)data.Length);
        w.Write(data);
    }

    private static byte[] GetUInt32LE(uint value)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        return b;
    }

    private static byte[] GetUInt64LE(ulong value)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, value);
        return b;
    }

    private static byte[] RandomBytes(int count)
    {
        var b = new byte[count];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}
