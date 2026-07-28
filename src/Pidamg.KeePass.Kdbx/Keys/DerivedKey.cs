namespace Pidamg.KeePass.Kdbx;

internal class DerivedKey
{

    private readonly byte[] _key;

    private DerivedKey(byte[] key) => _key = key;

    public static DerivedKey Derive(CompositeKey compositeKey, IKdf kdf)
        => new(kdf.Transform(compositeKey.GetRawKey()));

    public byte[] GetRawKey() => _key;
}
