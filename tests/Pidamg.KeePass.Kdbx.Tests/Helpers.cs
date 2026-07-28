using System.Collections.Generic;
using System.IO;
using Pidamg.KeePass;

namespace Pidamg.KeePass.Kdbx.Tests;

internal static class Helpers
{

    // Path to test resource files
    public static string Rsc(string name) =>
        Path.Combine(AppContext.BaseDirectory, "rsc", name);

    // Recursively collect all entries from a group
    public static void CollectEntries(Group group, List<Entry> all)
    {
        all.AddRange(group.Entries);
        foreach (var sub in group.Groups)
            CollectEntries(sub, all);
    }
}
