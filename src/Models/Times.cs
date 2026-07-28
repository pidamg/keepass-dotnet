using System;

namespace Pidamg.KeePass.Kdbx;

public class Times {
	public DateTime CreationTime         { get; set; }
	public DateTime LastModificationTime { get; set; }
	public DateTime LastAccessTime       { get; set; }
	public DateTime ExpiryTime           { get; set; }
	public bool     Expires              { get; set; }
	public int      UsageCount           { get; set; }
	public DateTime LocationChanged      { get; set; }

	public static Times Create() {
		var now = DateTime.UtcNow;
		return new Times {
			CreationTime         = now,
			LastModificationTime = now,
		};
	}

	public Times Clone() => new() {
		CreationTime         = this.CreationTime,
		LastModificationTime = this.LastModificationTime,
		LastAccessTime       = this.LastAccessTime,
		ExpiryTime           = this.ExpiryTime,
		Expires              = this.Expires,
		UsageCount           = this.UsageCount,
		LocationChanged      = this.LocationChanged,
	};

}
