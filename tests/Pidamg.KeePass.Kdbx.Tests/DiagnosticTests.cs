using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Pidamg.KeePass;
using Xunit.Abstractions;

namespace Pidamg.KeePass.Kdbx.Tests;

// Manual diagnostic tests — excluded from normal runs via Skip.
// Remove Skip to run occasionally.
public class DiagnosticTests
{

    private readonly ITestOutputHelper _out;
    public DiagnosticTests(ITestOutputHelper output) => _out = output;

    [Fact(Skip = "Manual — remove Skip to run")]
    public void Dump_RealFileV4_KeyDerivationPipeline()
    {
        const string password = "password123";

        // ── 1. Read header recording raw bytes ───────────────────────────────
        byte[] fileBytes = File.ReadAllBytes(Helpers.Rsc("SimplePasswordV4.kdbx"));

        using var ms = new MemoryStream(fileBytes);
        using var recorder = new MemoryStream();
        using var tee = new TeeStream(ms, recorder);

        var header = KdbxHeader.Read(new BinaryReader(tee));
        byte[] headerBytes = recorder.ToArray();

        _out.WriteLine("=== HEADER ===");
        _out.WriteLine(header.Dump());
        _out.WriteLine($"headerBytes length : {headerBytes.Length}");
        _out.WriteLine($"headerBytes SHA256  : {Hex(SHA256.HashData(headerBytes))}");

        byte[] fileSha = fileBytes[headerBytes.Length..(headerBytes.Length + 32)];
        byte[] fileHmac = fileBytes[(headerBytes.Length + 32)..(headerBytes.Length + 64)];
        _out.WriteLine($"file SHA256 (stored): {Hex(fileSha)}");
        _out.WriteLine($"file HMAC   (stored): {Hex(fileHmac)}");

        // ── 2. Composite key derivation ──────────────────────────────────────
        var compositeKey = new CompositeKey().AddPassword(password);
        byte[] rawKey = compositeKey.GetRawKey();
        _out.WriteLine("\n=== KEY DERIVATION ===");
        _out.WriteLine($"rawKey (SHA256²pw) : {Hex(rawKey)}");

        // ── 3. KDF ────────────────────────────────────────────────────────────
        var kdf = header.CreateKdf();
        _out.WriteLine($"KDF type           : {kdf.GetType().Name}");
        var derived = DerivedKey.Derive(compositeKey, kdf);
        byte[] derivedBytes = derived.GetRawKey();
        _out.WriteLine($"derivedKey         : {Hex(derivedBytes)}");

        // ── 4. EncryptionKey ──────────────────────────────────────────────────
        var encKey = new EncryptionKey(header.MasterSeed, derived);
        _out.WriteLine($"cipherKey (32B)    : {Hex(encKey.GetKey())}");
        _out.WriteLine($"hmacKey   (64B)    : {Hex(encKey.GetHmacKey())}");

        // ── 5. Raw key detail ─────────────────────────────────────────────────
        byte[] pw = Encoding.UTF8.GetBytes(password);
        byte[] hash1 = SHA256.HashData(pw);
        byte[] hash2 = SHA256.HashData(hash1);
        _out.WriteLine("\n=== RAW KEY DETAIL ===");
        _out.WriteLine($"SHA256(password)   : {Hex(hash1)}");
        _out.WriteLine($"SHA256²(password)  : {Hex(hash2)}  match={hash2.SequenceEqual(rawKey)}");

        // ── 6. HMAC variants ──────────────────────────────────────────────────
        _out.WriteLine("\n=== HMAC FORMULA VARIANTS ===");
        byte[] seed = header.MasterSeed;

        void TryHmac(string label, byte[] hmacKey64)
        {
            byte[] bk = BlockKey(ulong.MaxValue, hmacKey64);
            byte[] hm; using (var h = new HMACSHA256(bk)) hm = h.ComputeHash(headerBytes);
            _out.WriteLine($"{label}: {Hex(hm)}  {(hm.SequenceEqual(fileHmac) ? "✓ MATCH" : "✗")}");
        }

        TryHmac("A +0x01 (current)    ", encKey.GetHmacKey());

        {
            var b = new byte[seed.Length + derivedBytes.Length];
            seed.CopyTo(b, 0); derivedBytes.CopyTo(b, seed.Length);
            TryHmac("B no suffix          ", SHA512.HashData(b));
        }

        {
            byte[] derived1 = kdf.Transform(hash1);
            _out.WriteLine($"  derived (single): {Hex(derived1)}");
            var bH = new byte[seed.Length + derived1.Length + 1];
            seed.CopyTo(bH, 0); derived1.CopyTo(bH, seed.Length); bH[^1] = 0x01;
            TryHmac("C single-hash pw     ", SHA512.HashData(bH));
        }

        {
            byte[] transformed = SHA256.HashData(derivedBytes);
            _out.WriteLine($"  SHA256(derived)  : {Hex(transformed)}");
            var bH = new byte[seed.Length + transformed.Length + 1];
            seed.CopyTo(bH, 0); transformed.CopyTo(bH, seed.Length); bH[^1] = 0x01;
            TryHmac("D SHA256(derived)+0x01", SHA512.HashData(bH));
        }

        _out.WriteLine($"\nfile HMAC (expected): {Hex(fileHmac)}");
        Assert.Fail("Full diagnostic — see output.");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string Hex(byte[] b) => BitConverter.ToString(b);

    private static byte[] BlockKey(ulong blockIndex, byte[] hmacKey64)
    {
        var buf = new byte[8 + hmacKey64.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(buf, blockIndex);
        hmacKey64.CopyTo(buf, 8);
        return SHA512.HashData(buf);
    }

    private sealed class TeeStream(Stream source, Stream copy) : Stream
    {
        public override bool CanRead => true;
        public override bool CanWrite => false;
        public override bool CanSeek => false;
        public override long Length => throw new System.NotSupportedException();
        public override long Position
        {
            get => throw new System.NotSupportedException();
            set => throw new System.NotSupportedException();
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = source.Read(buffer, offset, count);
            if (n > 0) copy.Write(buffer, offset, n);
            return n;
        }
        public override void Write(byte[] buffer, int offset, int count) => throw new System.NotSupportedException();
        public override void Flush() => source.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new System.NotSupportedException();
        public override void SetLength(long value) => throw new System.NotSupportedException();
    }
}
