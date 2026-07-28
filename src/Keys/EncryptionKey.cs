using System;
using System.Security.Cryptography;

namespace Pidamg.KeePass.Kdbx;

public class EncryptionKey {

	private readonly byte[] _key;
	private readonly byte[] _hmacKey;

	public EncryptionKey(byte[] masterSeed, DerivedKey derivedKey) {
		var derived = derivedKey.GetRawKey();

		// SHA256(masterSeed ∥ derivedKey)  — cipher key (no suffix)
		var buf = new byte[masterSeed.Length + derived.Length];
		masterSeed.CopyTo(buf, 0);
		derived.CopyTo(buf, masterSeed.Length);
		_key = SHA256.HashData(buf);

		// SHA512(masterSeed ∥ derivedKey ∥ 0x01)  — KDBX 4
		var bufHmac = new byte[masterSeed.Length + derived.Length + 1];
		masterSeed.CopyTo(bufHmac, 0);
		derived.CopyTo(bufHmac, masterSeed.Length);
		bufHmac[^1] = 0x01;
		_hmacKey = SHA512.HashData(bufHmac);
	}

	// 32-byte key used to encrypt/decrypt the payload (AES-CBC, ChaCha20, Twofish)
	public byte[] GetKey() => _key;

	// 64-byte key used for HMAC-SHA512 block integrity (KDBX 4 only)
	public byte[] GetHmacKey() => _hmacKey;
}
