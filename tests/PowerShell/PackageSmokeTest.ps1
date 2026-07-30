param(
    [Parameter(Mandatory)]
    [string] $AssemblyPath,

    [Parameter(Mandatory)]
    [string] $DependencyPath
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion -lt [version] '7.4') {
    throw "PowerShell 7.4 or later is required; found $($PSVersionTable.PSVersion)."
}

Add-Type -Path (Resolve-Path $DependencyPath)
Add-Type -Path (Resolve-Path $AssemblyPath)

$databasePath = Join-Path ([System.IO.Path]::GetTempPath()) "$([guid]::NewGuid()).kdbx"

try {
    $database = [Pidamg.KeePass.KdbxDatabase]::Create('password')
    try {
        $database.Metadata.Name = 'PowerShell smoke test'

        $entry = [Pidamg.KeePass.Entry]::new()
        $entry.Title = 'GitHub'
        $entry.UserName = 'alice'
        $entry.Password = 'secret'
        $database.RootGroup.AddEntry($entry)
        $database.SaveAs($databasePath)
    }
    finally {
        $database.Dispose()
    }

    $reopened = [Pidamg.KeePass.KdbxDatabase]::Open($databasePath, 'password')
    try {
        $reopenedEntry = $reopened.FindEntry('GitHub')

        if ($null -eq $reopenedEntry -or $reopenedEntry.UserName -ne 'alice') {
            throw 'The database entry was not preserved after reopening the database.'
        }
    }
    finally {
        $reopened.Dispose()
    }
}
finally {
    Remove-Item -LiteralPath $databasePath -Force -ErrorAction SilentlyContinue
}
