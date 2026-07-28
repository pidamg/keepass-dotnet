namespace Pidamg.KeePass.Kdbx;

internal class DatabaseData
{
    public Metadata Metadata { get; }
    public Group RootGroup { get; }

    public DatabaseData(Metadata metadata, Group rootGroup)
    {
        Metadata = metadata;
        RootGroup = rootGroup;
    }
}
