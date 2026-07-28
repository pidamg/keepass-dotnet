namespace Pidamg.KeePass;

/// <summary>
/// Defines a key derivation function used to transform a composite KDBX key.
/// </summary>
public interface IKdf
{
    /// <summary>
    /// Transforms a 32-byte composite key into a 32-byte derived key.
    /// </summary>
    /// <param name="rawKey">The 32-byte composite key.</param>
    /// <returns>The 32-byte derived key.</returns>
    byte[] Transform(byte[] rawKey);
}
