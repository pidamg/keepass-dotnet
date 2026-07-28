using System.Collections.Generic;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;

namespace Pidamg.KeePass.Kdbx;

public enum Argon2Type { D, Id }

public class Argon2Kdf : IKdf {

	public static readonly System.Guid Argon2dUuid  = new("ef636ddf-8c29-444b-91f7-a9a403e30a0c");
	public static readonly System.Guid Argon2idUuid = new("9e298b19-6db4-4830-bda5-57f0f7ca20c7");

	public byte[]     Salt        { get; }
	public int        Parallelism { get; }
	public int        MemoryKib   { get; }
	public int        Iterations  { get; }
	public Argon2Type Type        { get; }

	public Argon2Kdf(byte[] salt, int parallelism, int memoryKib, int iterations, Argon2Type type = Argon2Type.Id) {
		Salt        = salt;
		Parallelism = parallelism;
		MemoryKib   = memoryKib;
		Iterations  = iterations;
		Type        = type;
	}

	public byte[] Transform(byte[] rawKey) {
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

	public VariantMap Parameters() => new(new Dictionary<string, object> {
		["$UUID"] = GuidRfc4122.ToBytes(Type == Argon2Type.Id ? Argon2idUuid : Argon2dUuid),
		["S"]     = Salt,
		["P"]     = (uint)Parallelism,
		["M"]     = (ulong)(MemoryKib * 1024L), // stored as bytes in KDBX
		["I"]     = (ulong)Iterations,
		["V"]     = (uint)0x13,
	});
}
