namespace Pidamg.KeePass.Kdbx;

public interface IKdf
{
    // Transforms the 32-byte composite key into the 32-byte derived key.
    byte[] Transform(byte[] rawKey);
    VariantMap Parameters();
}
