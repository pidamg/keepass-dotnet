using System;

namespace Pidamg.KeePass;

// Parses KeePass field references: {REF:WantedField@SearchIn:SearchValue}
// WantedField / SearchIn: T=Title, U=UserName, P=Password, A=URL, N=Notes, I=UUID
internal readonly struct FieldReference
{

    public char WantedField { get; }
    public char SearchIn { get; }
    public string SearchValue { get; }

    private FieldReference(char wantedField, char searchIn, string searchValue)
    {
        WantedField = wantedField;
        SearchIn = searchIn;
        SearchValue = searchValue;
    }

    public static bool TryParse(string value, out FieldReference result)
    {
        result = default;

        // Must be wrapped in {REF:...}
        if (!value.StartsWith("{REF:", StringComparison.OrdinalIgnoreCase) || !value.EndsWith('}'))
            return false;

        var inner = value[5..^1]; // "P@I:SearchValue"
        if (inner.Length < 4)    // minimum: "X@Y:z"
            return false;

        char wantedField = char.ToUpperInvariant(inner[0]);
        if (inner[1] != '@') return false;
        char searchIn = char.ToUpperInvariant(inner[2]);
        if (inner[3] != ':') return false;
        string searchValue = inner[4..];

        result = new FieldReference(wantedField, searchIn, searchValue);
        return true;
    }

    // Maps a single-char field code to its String dictionary key.
    public static string? FieldCodeToKey(char code) => char.ToUpperInvariant(code) switch
    {
        'T' => "Title",
        'U' => "UserName",
        'P' => "Password",
        'A' => "URL",
        'N' => "Notes",
        _ => null,
    };
}
