using System;

namespace Pidamg.KeePass.Kdbx;

public class CustomIcon {
	public Guid      Uuid                 { get; set; } = Guid.NewGuid();
	public byte[]    Data                 { get; set; } = [];   // PNG bytes
	public string    Name                 { get; set; } = "";
	public DateTime? LastModificationTime { get; set; }
}
