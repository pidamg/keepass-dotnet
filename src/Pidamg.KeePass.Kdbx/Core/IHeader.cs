using System;
using System.IO;

namespace Pidamg.KeePass.Kdbx;

public interface IHeader
{

    Signature Signature { get; }
    KdbxVersion Version { get; }
    Guid CipherId { get; }
    bool IsVersion4 { get; }
    bool IsCompressed { get; }
    byte[] MasterSeed { get; }

    // V3 only — null for KDBX 4.x
    byte[]? StreamStartBytes { get; }

    // Inner protected-stream algorithm.
    // V3: stored in the outer header (InnerRandomStreamId field).
    // V4: always ChaCha20 — the actual value is in the inner header, written by KdbxWriter.
    ProtectedStreamAlgorithm InnerStreamAlgorithm { get; }

    IKdf CreateKdf();
    SymmetricCipher CreateCipher(byte[] key);

    // Patches the outer-header inner-stream fields (V3 only).
    // Call before Write() when reusing an existing header with a fresh ProtectedStream.
    void SetInnerStream(ProtectedStreamAlgorithm algorithm, byte[] key);

    void Write(BinaryWriter writer);
    void Write(Stream stream);
}
