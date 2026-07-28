using System.Collections.Generic;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Pidamg.KeePass.Kdbx;

/// <summary>
/// Identifies the Argon2 variant used for key derivation.
/// </summary>
public enum Argon2Type
{
    /// <summary>
    /// The data-dependent Argon2d variant.
    /// </summary>
    D,

    /// <summary>
    /// The hybrid Argon2id variant.
    /// </summary>
    Id
}

/// <summary>
/// Implements Argon2 key derivation for KDBX 4.x databases.
/// </summary>
public class Argon2Kdf : IKdf
{

    internal static readonly System.Guid Argon2dUuid = new("ef636ddf-8c29-444b-91f7-a9a403e30a0c");
    internal static readonly System.Guid Argon2idUuid = new("9e298b19-6db4-4830-bda5-57f0f7ca20c7");

    /// <summary>
    /// Gets the salt used for key derivation.
    /// </summary>
    public byte[] Salt { get; }

    /// <summary>
    /// Gets the degree of parallelism.
    /// </summary>
    public int Parallelism { get; }

    /// <summary>
    /// Gets the requested memory usage, in kibibytes.
    /// </summary>
    public int MemoryKib { get; }

    /// <summary>
    /// Gets the number of iterations.
    /// </summary>
    public int Iterations { get; }

    /// <summary>
    /// Gets the Argon2 variant.
    /// </summary>
    public Argon2Type Type { get; }

    /// <summary>
    /// Initializes an Argon2 key derivation function.
    /// </summary>
    /// <param name="salt">The salt used for key derivation.</param>
    /// <param name="parallelism">The degree of parallelism.</param>
    /// <param name="memoryKib">The requested memory usage, in kibibytes.</param>
    /// <param name="iterations">The number of iterations.</param>
    /// <param name="type">The Argon2 variant.</param>
    public Argon2Kdf(byte[] salt, int parallelism, int memoryKib, int iterations, Argon2Type type = Argon2Type.Id)
    {
        Salt = salt;
        Parallelism = parallelism;
        MemoryKib = memoryKib;
        Iterations = iterations;
        Type = type;
    }

    /// <inheritdoc/>
    public byte[] Transform(byte[] rawKey)
    {
        int bcType = Type == Argon2Type.Id
            ? Argon2Parameters.Argon2id
            : Argon2Parameters.Argon2d;

        var parameters = new Argon2Parameters.Builder(bcType)
            .WithSalt(Salt)
            .WithParallelism(Parallelism)
            .WithMemoryAsKB(MemoryKib)
            .WithIterations(Iterations)
            .WithVersion(Argon2Parameters.Version13)
            .Build();

        var gen = new Argon2BytesGenerator();
        gen.Init(parameters);

        byte[] result = new byte[32];
        gen.GenerateBytes(rawKey, result);
        return result;
    }

    internal VariantMap Parameters() => new(new Dictionary<string, object>
    {
        ["$UUID"] = GuidRfc4122.ToBytes(Type == Argon2Type.Id ? Argon2idUuid : Argon2dUuid),
        ["S"] = Salt,
        ["P"] = (uint)Parallelism,
        ["M"] = (ulong)(MemoryKib * 1024L), // stored as bytes in KDBX
        ["I"] = (ulong)Iterations,
        ["V"] = (uint)0x13,
    });
}
