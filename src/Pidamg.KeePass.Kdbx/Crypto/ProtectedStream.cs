using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Pidamg.KeePass.Kdbx;

/// <summary>
/// Identifies the inner stream cipher used for protected XML values.
/// </summary>
public enum ProtectedStreamAlgorithm
{
    /// <summary>
    /// The Salsa20 inner stream cipher.
    /// </summary>
    Salsa20 = 2,

    /// <summary>
    /// The ChaCha20 inner stream cipher.
    /// </summary>
    ChaCha20 = 3
}

// Stateful XOR stream used to encrypt/decrypt Protected="True" XML fields.
// The keystream position advances with each call to Process() — fields must be
// processed in the same order during read and write.
internal class ProtectedStream
{

    private readonly IStreamCipher _cipher;

    public ProtectedStreamAlgorithm Algorithm { get; }
    public byte[] Key { get; }

    public ProtectedStream(ProtectedStreamAlgorithm algorithm, byte[] key)
    {
        Algorithm = algorithm;
        Key = key;
        _cipher = algorithm switch
        {
            ProtectedStreamAlgorithm.Salsa20 => InitSalsa20(key),
            ProtectedStreamAlgorithm.ChaCha20 => InitChaCha20(key),
            _ => throw new NotSupportedException($"Unknown protected stream algorithm: {algorithm}")
        };
    }

    public static int GetIvSize(CipherAlgorithm cipher) => cipher == CipherAlgorithm.ChaCha20 ? 12 : 16;

    // XOR data with the next keystream bytes (same operation for encrypt and decrypt)
    public byte[] Process(byte[] data)
    {
        var output = new byte[data.Length];
        _cipher.ProcessBytes(data, 0, data.Length, output, 0);
        return output;
    }

    private static IStreamCipher InitSalsa20(byte[] key)
    {
        var engine = new Salsa20Engine();
        engine.Init(true, new ParametersWithIV(
            new KeyParameter(SHA256.HashData(key)),
            new byte[] { 0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A }
        ));
        return engine;
    }

    private static IStreamCipher InitChaCha20(byte[] key)
    {
        var hash = SHA512.HashData(key);
        var engine = new ChaCha7539Engine();
        engine.Init(true, new ParametersWithIV(
            new KeyParameter(hash[..32]),
            hash[32..44]  // 12-byte nonce
        ));
        return engine;
    }
}
