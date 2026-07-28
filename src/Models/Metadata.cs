using System;
using System.Collections.Generic;

namespace Pidamg.KeePass.Kdbx;

public class Metadata {
	public string             Name              { get; set; } = "";
	public string             Description       { get; set; } = "";
	public string             DefaultUserName   { get; set; } = "";
	public bool               RecycleBinEnabled { get; set; } = true;
	public Guid               RecycleBinUuid    { get; set; }
	public int                HistoryMaxItems   { get; set; } = 10;
	public long               HistoryMaxSize    { get; set; } = 6_291_456; // 6 MiB
	public bool               ProtectPassword   { get; set; } = true;
	public List<CustomIcon>   CustomIcons       { get; set; } = [];
}
