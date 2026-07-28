using System;
using System.Security.Cryptography;

namespace Pidamg.KeePass.Kdbx;

public class Settings
{

    public KdbxFormat Format { get; set; } = KdbxFormat.Kdbx4;
    public CipherAlgorithm Cipher { get; set; } = CipherAlgorithm.ChaCha20;
    public bool IsCompressed { get; set; } = true;
    public ProtectedStreamAlgorithm InnerStreamAlgorithm { get; set; } = ProtectedStreamAlgorithm.ChaCha20;
    public IKdf Kdf { get; set; } = DefaultArgon2id();

    // ── Internal helpers ──────────────────────────────────────────────────────

    internal static Settings FromHeader(IHeader header, ProtectedStreamAlgorithm innerAlgo) =>
        new()
        {
            Format = header.IsVersion4 ? KdbxFormat.Kdbx4 : KdbxFormat.Kdbx3,
            Cipher = SymmetricCipher.FromUuid(header.CipherId),
            IsCompressed = header.IsCompressed,
            InnerStreamAlgorithm = innerAlgo,
            Kdf = header.CreateKdf(),
        };

    // Validates the settings and builds a fresh KdbxHeader (new random MasterSeed, IV, etc.).
    // Throws InvalidOperationException if the configuration is invalid (e.g. Argon2 with V3).
    internal KdbxHeader ToHeader()
    {
        if (Format == KdbxFormat.Kdbx4)
            return KdbxHeader.CreateNewV4(Cipher, Kdf, IsCompressed);

        if (Kdf is not AesKdf aesKdf)
            throw new InvalidOperationException(
                "KDBX 3.x only supports AES-KDF. Set Kdf to an AesKdf instance.");

        return KdbxHeader.CreateNewV3(Cipher, InnerStreamAlgorithm, aesKdf.Rounds, IsCompressed);
    }

    internal static Argon2Kdf DefaultArgon2id() => new(
        salt: RandomNumberGenerator.GetBytes(32),
        parallelism: 2,
        memoryKib: 64 * 1024,
        iterations: 2,
        type: Argon2Type.Id
    );
}
