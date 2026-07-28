# Pidamg.KeePass.Kdbx — KeePass KDBX library for .NET

**English** | [Français](https://github.com/pidamg/keepass-dotnet/blob/main/README.fr.md)

A .NET library for reading, creating, modifying, and saving
[KeePass](https://keepass.info/) password databases in the KDBX format.

> [!IMPORTANT]
> This project is currently a preview and targets .NET 10. The public API may still change before
> the stable `1.0.0` release.

## Features

- Read and write KDBX 3.x and 4.x databases
- Protect databases with a password, a key file, or both
- Synchronous and asynchronous APIs
- Entries, groups, metadata, history, and recycle-bin operations
- Recursive entry and group search
- Binary attachments, custom icons, and Auto-Type configuration
- AES-128/256-CBC, ChaCha20, and Twofish-256-CBC
- AES-KDF, Argon2d, and Argon2id
- GZip compression and protected XML values

## Installation

Preview packages are published to
[GitHub Packages](https://github.com/pidamg/keepass-dotnet/packages) and attached to
[GitHub Releases](https://github.com/pidamg/keepass-dotnet/releases).

GitHub Packages requires an authenticated NuGet source, including for public packages. After
[configuring GitHub Packages authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-nuget-registry),
install the preview package with:

```bash
dotnet add package Pidamg.KeePass.Kdbx --prerelease
```

Stable releases will also be published to NuGet.org.

## Quick start

```csharp
using Pidamg.KeePass;

using (var database = KdbxDatabase.Create("correct horse battery staple"))
{
    database.Metadata.Name = "My vault";
    database.RootGroup.AddEntry(new Entry
    {
        Title = "GitHub",
        UserName = "alice",
        Password = "s3cr3t!",
        Url = "https://github.com",
    });

    database.SaveAs("vault.kdbx");
}

using var reopened = KdbxDatabase.Open(
    "vault.kdbx",
    "correct horse battery staple");

var entry = reopened.FindEntry("GitHub");
Console.WriteLine(entry?.UserName);
```

`KdbxDatabase` implements `IDisposable`. Use `using` to release the loaded database data and
clear the composite-key components held by the instance.

## Open and modify a database

```csharp
using var database = KdbxDatabase.Open("vault.kdbx", "password");

var work = database.FindGroup("Work");
var matches = database.FindAllEntries(
    entry => entry.UserName.Equals("alice", StringComparison.OrdinalIgnoreCase));

var github = database.FindEntry("GitHub");
if (github is not null)
{
    github.Update(entry => entry.Password = "new password");
}

database.Save();
```

`Entry.Update()` adds the previous entry state to its history. `FindEntry`, `FindAllEntries`,
`FindGroup`, and `FindAllGroups` search recursively.

## Key files

```csharp
KeyFile.Generate("vault.keyx");

using var database = KdbxDatabase.Create("password", "vault.keyx");
database.SaveAs("vault.kdbx");

using var reopened = KdbxDatabase.Open(
    "vault.kdbx",
    "password",
    "vault.keyx");
```

`KeyFile.Generate()` creates a KeePass XML v1 key file by default. Use `KeyFileFormat.Raw` to
generate a random raw 32-byte key.

## Asynchronous API

```csharp
using var database = new KdbxDatabase("vault.kdbx", "password");
await database.OpenAsync(cancellationToken);

database.RootGroup.AddEntry(new Entry { Title = "Example" });
await database.SaveAsync(cancellationToken);
```

`OpenAsync`, `SaveAsync`, and `SaveAsAsync` accept a `CancellationToken`.

## Customize the format and cryptography

New databases default to KDBX 4.1, ChaCha20, Argon2id, GZip compression, and ChaCha20 for
protected values.

```csharp
using System.Security.Cryptography;
using Pidamg.KeePass;

var settings = new KdbxSettings
{
    Format = KdbxFormat.Kdbx3,
    Cipher = CipherAlgorithm.Aes256Cbc,
    Kdf = new AesKdf(
        RandomNumberGenerator.GetBytes(32),
        rounds: 100_000),
};

using var database = KdbxDatabase.Create("password", settings);
database.SaveAs("legacy.kdbx");
```

KDBX 3.x requires `AesKdf`. KDBX 4.x supports `AesKdf` and `Argon2Kdf` with Argon2d or
Argon2id.

## Supported formats and algorithms

| Capability | Read | Write |
|---|:---:|:---:|
| KDBX 4.x | Yes | Yes |
| KDBX 3.x | Yes | Yes |
| GZip compression | Yes | Yes |
| Binary attachments | Yes | Yes |
| Protected values | Yes | Yes |
| XML v1/v2, raw, and legacy key files | Yes | XML v1 and raw |

| Role | Algorithms |
|---|---|
| Content encryption | AES-128/256-CBC, ChaCha20, Twofish-256-CBC |
| Key derivation | AES-KDF, Argon2d, Argon2id |
| Protected-value stream | ChaCha20, Salsa20 |

The only published runtime dependency is
[`BouncyCastle.Cryptography`](https://www.nuget.org/packages/BouncyCastle.Cryptography).

## Current limitations

- The project does not merge concurrent changes to a KDBX file. Saving replaces the target file.
- Some advanced `<Meta>` fields do not yet have a dedicated API.
- Passwords exposed as .NET strings cannot be reliably zeroed by the library.

See the [issues](https://github.com/pidamg/keepass-dotnet/issues) and
[changelog](https://github.com/pidamg/keepass-dotnet/blob/main/CHANGELOG.md) for planned and
released changes.

## Development

```bash
dotnet restore Pidamg.KeePass.Kdbx.slnx
dotnet build Pidamg.KeePass.Kdbx.slnx
dotnet test Pidamg.KeePass.Kdbx.slnx
dotnet format Pidamg.KeePass.Kdbx.slnx --verify-no-changes
```

See [`CONTRIBUTING.md`](https://github.com/pidamg/keepass-dotnet/blob/main/CONTRIBUTING.md) for
contribution, public API compatibility, and release guidelines.

## License

This project is available under the
[MIT License](https://github.com/pidamg/keepass-dotnet/blob/main/LICENSE).

KeePass is a trademark of Dominik Reichl. This project is independent and is neither affiliated
with nor endorsed by the KeePass project. [KeePassXC](https://github.com/keepassxreboot/keepassxc)
is used as an interoperability reference implementation.
