namespace Pidamg.KeePass.Kdbx;

public class DatabaseData {
	public Metadata Metadata  { get; }
	public Group    RootGroup { get; }

	public DatabaseData(Metadata metadata, Group rootGroup) {
		Metadata  = metadata;
		RootGroup = rootGroup;
	}
}
