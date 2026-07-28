namespace Pidamg.KeePass.Kdbx;

public class EntryBinary {
	public string Name        { get; set; } = "";
	public byte[] Data        { get; set; } = [];
	public bool   IsProtected { get; set; }
}
