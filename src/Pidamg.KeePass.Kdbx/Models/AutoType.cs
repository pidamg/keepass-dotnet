using System.Collections.Generic;
using System.Linq;

namespace Pidamg.KeePass.Kdbx;

public class AutoTypeAssociation
{
    public string Window { get; set; } = "";
    public string Sequence { get; set; } = "";
}

public class AutoType
{
    public bool Enabled { get; set; } = true;
    public int DataTransferObfuscation { get; set; }
    public string DefaultSequence { get; set; } = "";
    public List<AutoTypeAssociation> Associations { get; set; } = [];

    public AutoType Clone() => new()
    {
        Enabled = this.Enabled,
        DataTransferObfuscation = this.DataTransferObfuscation,
        DefaultSequence = this.DefaultSequence,
        Associations = this.Associations
            .Select(a => new AutoTypeAssociation { Window = a.Window, Sequence = a.Sequence })
            .ToList(),
    };
}
