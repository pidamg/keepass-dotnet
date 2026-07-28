using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Pidamg.KeePass.Kdbx;

/// <summary>
/// Identifies a cipher used to encrypt KDBX database content.
/// </summary>
public enum CipherAlgorithm
{
    /// <summary>
    /// AES-128 in CBC mode.
    /// </summary>
    Aes128Cbc,

    /// <summary>
    /// AES-256 in CBC mode.
    /// </summary>
    Aes256Cbc,

    /// <summary>
    /// ChaCha20.
    /// </summary>
    ChaCha20,

    /// <summary>
    /// Twofish-256 in CBC mode.
    /// </summary>
    Twofish256Cbc
}

internal class SymmetricCipher
{

    // CipherID UUIDs from the KDBX header (RFC 4122 big-endian, converted via ReadUuid)
    // Reference: https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KeePass2.cpp
    public static readonly Guid Aes128Uuid = new("61ab05a1-9464-41c3-8d74-3a563df8dd35");
    public static readonly Guid Aes256Uuid = new("31c1f2e6-bf71-4350-be58-05216afc5aff");
    public static readonly Guid ChaCha20Uuid = new("d6038a2b-8b6f-4cb5-a524-339a31dbb59a");
    public static readonly Guid TwofishUuid = new("ad68f29f-576f-4bb9-a36a-d47af965346c");

    private readonly CipherAlgorithm _algorithm;
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public SymmetricCipher(CipherAlgorithm algorithm, byte[] key, byte[] iv)
    {
        _algorithm = algorithm;
        _key = key;
        _iv = iv;
    }

    public static CipherAlgorithm FromUuid(Guid uuid)
    {
        if (uuid == Aes128Uuid) return CipherAlgorithm.Aes128Cbc;
        if (uuid == Aes256Uuid) return CipherAlgorithm.Aes256Cbc;
        if (uuid == ChaCha20Uuid) return CipherAlgorithm.ChaCha20;
        if (uuid == TwofishUuid) return CipherAlgorithm.Twofish256Cbc;
        throw new NotSupportedException($"Unknown cipher UUID: {uuid}");
    }

    public static Guid UuidFromAlgorithm(CipherAlgorithm algorithm) => algorithm switch
    {
        CipherAlgorithm.Aes128Cbc => Aes128Uuid,
        CipherAlgorithm.Aes256Cbc => Aes256Uuid,
        CipherAlgorithm.ChaCha20 => ChaCha20Uuid,
        CipherAlgorithm.Twofish256Cbc => TwofishUuid,
        _ => throw new NotSupportedException($"Unknown cipher algorithm: {algorithm}")
    };

    public Stream CreateDecryptingStream(Stream source) => CreateStream(source, encrypt: false);
    public Stream CreateEncryptingStream(Stream target) => CreateStream(target, encrypt: true);

    private Stream CreateStream(Stream inner, bool encrypt) => _algorithm switch
    {
        CipherAlgorithm.Aes128Cbc => CreateAes128Stream(inner, encrypt),
        CipherAlgorithm.Aes256Cbc => CreateAes256Stream(inner, encrypt),
        CipherAlgorithm.ChaCha20 => CreateChaCha20Stream(inner, encrypt),
        CipherAlgorithm.Twofish256Cbc => CreateTwofishStream(inner, encrypt),
        _ => throw new NotSupportedException()
    };

    private Stream CreateAes128Stream(Stream inner, bool encrypt)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = _key[..16];
        aes.IV = _iv;
        var transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
        return new CryptoStream(inner, transform, encrypt ? CryptoStreamMode.Write : CryptoStreamMode.Read);
    }

    private Stream CreateAes256Stream(Stream inner, bool encrypt)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = _key;
        aes.IV = _iv;
        var transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
        return new CryptoStream(inner, transform, encrypt ? CryptoStreamMode.Write : CryptoStreamMode.Read);
    }

    private Stream CreateChaCha20Stream(Stream inner, bool encrypt)
    {
        // RFC 7539 variant — 32-byte key, 12-byte nonce
        var engine = new ChaCha7539Engine();
        engine.Init(encrypt, new ParametersWithIV(new KeyParameter(_key), _iv));
        return new ChaCha20CipherStream(inner, engine);
    }

    private Stream CreateTwofishStream(Stream inner, bool encrypt)
    {
        var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new TwofishEngine()));
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(_key), _iv));
        return new TwoFishCipherStream(inner, cipher, encrypt);
    }

    // Wraps a BouncyCastle IStreamCipher (ChaCha20) as a .NET Stream
    private sealed class ChaCha20CipherStream : Stream
    {

        private readonly Stream _inner;
        private readonly IStreamCipher _cipher;

        public ChaCha20CipherStream(Stream inner, IStreamCipher cipher)
        {
            _inner = inner;
            _cipher = cipher;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanWrite => _inner.CanWrite;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var tmp = new byte[count];
            int n = _inner.Read(tmp, 0, count);
            if (n > 0) _cipher.ProcessBytes(tmp, 0, n, buffer, offset);
            return n;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            var output = new byte[count];
            _cipher.ProcessBytes(buffer, offset, count, output, 0);
            _inner.Write(output, 0, count);
        }

        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }

    // Wraps a BouncyCastle PaddedBufferedBlockCipher (Twofish-CBC+PKCS7) as a .NET Stream.
    // Encryption: buffers all writes, flushes with DoFinal (PKCS7 pad) on Dispose.
    // Decryption: reads all ciphertext eagerly, decrypts with DoFinal (PKCS7 strip) on first Read.
    private sealed class TwoFishCipherStream : Stream
    {

        private readonly Stream _inner;
        private readonly PaddedBufferedBlockCipher _cipher;
        private readonly bool _encrypt;
        private readonly MemoryStream _writeBuffer;
        private MemoryStream? _readBuffer;
        private bool _disposed;

        public TwoFishCipherStream(Stream inner, PaddedBufferedBlockCipher cipher, bool encrypt)
        {
            _inner = inner;
            _cipher = cipher;
            _encrypt = encrypt;
            _writeBuffer = new MemoryStream();
        }

        public override bool CanRead => !_encrypt;
        public override bool CanWrite => _encrypt;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_readBuffer == null)
            {
                // Decrypt all ciphertext at once to handle PKCS7 padding correctly.
                using var ms = new MemoryStream();
                _inner.CopyTo(ms);
                byte[] ct = ms.ToArray();
                byte[] out_ = new byte[_cipher.GetOutputSize(ct.Length)];
                int n = _cipher.ProcessBytes(ct, 0, ct.Length, out_, 0);
                n += _cipher.DoFinal(out_, n);
                _readBuffer = new MemoryStream(out_, 0, n);
            }
            return _readBuffer.Read(buffer, offset, count);
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            _writeBuffer.Write(buffer, offset, count);

        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                _disposed = true;
                if (_encrypt)
                {
                    // Encrypt all buffered data with PKCS7 padding.
                    byte[] input = _writeBuffer.ToArray();
                    byte[] output = new byte[_cipher.GetOutputSize(input.Length)];
                    int n = _cipher.ProcessBytes(input, 0, input.Length, output, 0);
                    n += _cipher.DoFinal(output, n);
                    _inner.Write(output, 0, n);
                }
                _writeBuffer.Dispose();
                _readBuffer?.Dispose();
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
