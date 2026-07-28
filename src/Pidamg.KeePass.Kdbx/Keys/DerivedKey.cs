namespace Pidamg.KeePass.Kdbx;

public class DerivedKey {

	private readonly byte[] _key;

	private DerivedKey(byte[] key) => _key = key;

	public static DerivedKey Derive(CompositeKey compositeKey, IKdf kdf)
		=> new(kdf.Transform(compositeKey.GetRawKey()));

	public byte[] GetRawKey() => _key;
}
