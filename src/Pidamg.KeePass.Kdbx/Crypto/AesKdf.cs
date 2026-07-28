using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Pidamg.KeePass.Kdbx;

public class AesKdf : IKdf {

	// UUID used in KDBX 3.x KdfParameters (and by some KDBX 4.x writers for compatibility)
	public static readonly Guid UuidKdbx3 = new("c9d9f39a-628a-4460-bf74-0d08c18a4fea");
	// UUID used in KDBX 4.x KdfParameters
	public static readonly Guid UuidKdbx4 = new("7c02bb82-79a7-4ac0-927d-114a00648238");

	public byte[] Seed   { get; }
	public ulong  Rounds { get; }

	public AesKdf(byte[] seed, ulong rounds) {
		Seed   = seed;
		Rounds = rounds;
	}

	// DerivedKey = SHA256(ECB(left, seed, rounds) ∥ ECB(right, seed, rounds))
	// where left = rawKey[0..16], right = rawKey[16..32]
	public byte[] Transform(byte[] rawKey) {
		using var aes = Aes.Create();
		aes.Mode = CipherMode.ECB;
		aes.Padding = PaddingMode.None;
		aes.Key = Seed;

		var left    = rawKey[..16];
		var right   = rawKey[16..];
		var leftBuf = new byte[16];
		var rightBuf = new byte[16];

		using var encryptor = aes.CreateEncryptor();
		for (ulong i = 0; i < Rounds; i++) {
			encryptor.TransformBlock(left,  0, 16, leftBuf,  0);
			encryptor.TransformBlock(right, 0, 16, rightBuf, 0);
			(left, leftBuf)   = (leftBuf,  left);
			(right, rightBuf) = (rightBuf, right);
		}

		var combined = new byte[32];
		left.CopyTo(combined, 0);
		right.CopyTo(combined, 16);
		return SHA256.HashData(combined);
	}

	public VariantMap Parameters() => new(new Dictionary<string, object> {
		["$UUID"] = GuidRfc4122.ToBytes(UuidKdbx4),
		["S"]     = Seed,
		["R"]     = Rounds,
	});
}
