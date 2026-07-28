using System;
using System.Security.Cryptography;

namespace Pidamg.KeePass;

/// <summary>
/// Configures the format and cryptographic algorithms used when saving a KDBX database.
/// </summary>
public class KdbxSettings
{

    /// <summary>
    /// Initializes settings with KDBX 4, ChaCha20, compression, and Argon2id defaults.
    /// </summary>
    public KdbxSettings() { }

    /// <summary>
    /// Gets or sets the KDBX format generation.
    /// </summary>
    public KdbxFormat Format { get; set; } = KdbxFormat.Kdbx4;

    /// <summary>
    /// Gets or sets the database content cipher.
    /// </summary>
    public CipherAlgorithm Cipher { get; set; } = CipherAlgorithm.ChaCha20;

    /// <summary>
    /// Gets or sets a value indicating whether database content is compressed.
    /// </summary>
    public bool IsCompressed { get; set; } = true;

    /// <summary>
    /// Gets or sets the cipher used for protected XML values.
    /// </summary>
    /// <remarks>KDBX 4.x stores the selected algorithm in its inner header.</remarks>
    public ProtectedStreamAlgorithm InnerStreamAlgorithm { get; set; } = ProtectedStreamAlgorithm.ChaCha20;

    /// <summary>
    /// Gets or sets the key derivation function.
    /// </summary>
    /// <remarks>KDBX 3.x requires an <see cref="AesKdf"/> instance.</remarks>
    public IKdf Kdf { get; set; } = DefaultArgon2id();

    // ── Internal helpers ──────────────────────────────────────────────────────

    internal static KdbxSettings FromHeader(IHeader header, ProtectedStreamAlgorithm innerAlgo) =>
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
