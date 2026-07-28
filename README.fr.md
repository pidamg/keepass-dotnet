# Pidamg.KeePass.Kdbx — Bibliothèque KeePass KDBX pour .NET

[English](README.md) | **Français**

Bibliothèque .NET pour lire, créer, modifier et enregistrer des bases de mots de passe
[KeePass](https://keepass.info/) au format KDBX.

> [!IMPORTANT]
> Le projet est actuellement en préversion et cible .NET 10. L'API publique peut encore évoluer
> avant la version stable `1.0.0`.

## Fonctionnalités

- Lecture et écriture des formats KDBX 3.x et 4.x
- Protection par mot de passe, fichier de clé, ou combinaison des deux
- API synchrones et asynchrones
- Entrées, groupes, métadonnées, historique et corbeille
- Recherche récursive dans les entrées et les groupes
- Pièces jointes binaires, icônes personnalisées et configuration Auto-Type
- AES-128/256-CBC, ChaCha20 et Twofish-256-CBC
- AES-KDF, Argon2d et Argon2id
- Compression GZip et champs XML protégés

## Installation

Les préversions sont publiées dans
[GitHub Packages](https://github.com/pidamg/lib-dotnet-keepass/packages) et jointes aux
[GitHub Releases](https://github.com/pidamg/lib-dotnet-keepass/releases).

GitHub Packages nécessite une source NuGet authentifiée, y compris pour les packages publics.
Après avoir [configuré l'authentification à GitHub Packages](https://docs.github.com/fr/packages/working-with-a-github-packages-registry/working-with-the-nuget-registry),
installez la préversion avec :

```bash
dotnet add package Pidamg.KeePass.Kdbx --prerelease
```

Les versions stables seront également publiées sur NuGet.org.

## Démarrage rapide

```csharp
using Pidamg.KeePass;

using (var database = KdbxDatabase.Create("correct horse battery staple"))
{
    database.Metadata.Name = "Mon coffre-fort";
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

`KdbxDatabase` implémente `IDisposable`. Utilisez `using` afin de libérer les données de la base
et d'effacer les composants de la clé composite détenus par l'instance.

## Ouvrir et modifier une base

```csharp
using var database = KdbxDatabase.Open("vault.kdbx", "password");

var work = database.FindGroup("Travail");
var matches = database.FindAllEntries(
    entry => entry.UserName.Equals("alice", StringComparison.OrdinalIgnoreCase));

var github = database.FindEntry("GitHub");
if (github is not null)
{
    github.Update(entry => entry.Password = "new password");
}

database.Save();
```

`Entry.Update()` ajoute l'état précédent de l'entrée à son historique. Les méthodes
`FindEntry`, `FindAllEntries`, `FindGroup` et `FindAllGroups` effectuent une recherche récursive.

## Fichiers de clé

```csharp
KeyFile.Generate("vault.keyx");

using var database = KdbxDatabase.Create("password", "vault.keyx");
database.SaveAs("vault.kdbx");

using var reopened = KdbxDatabase.Open(
    "vault.kdbx",
    "password",
    "vault.keyx");
```

`KeyFile.Generate()` crée par défaut un fichier XML KeePass v1. Utilisez
`KeyFileFormat.Raw` pour générer une clé brute aléatoire de 32 octets.

## API asynchrone

```csharp
using var database = new KdbxDatabase("vault.kdbx", "password");
await database.OpenAsync(cancellationToken);

database.RootGroup.AddEntry(new Entry { Title = "Example" });
await database.SaveAsync(cancellationToken);
```

Les méthodes `OpenAsync`, `SaveAsync` et `SaveAsAsync` acceptent un `CancellationToken`.

## Personnaliser le format et la cryptographie

Les nouvelles bases utilisent par défaut KDBX 4.1, ChaCha20, Argon2id, la compression GZip et
ChaCha20 pour les champs protégés.

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

KDBX 3.x nécessite `AesKdf`. KDBX 4.x prend en charge `AesKdf`, `Argon2Kdf` avec Argon2d ou
Argon2id.

## Formats et algorithmes pris en charge

| Capacité | Lecture | Écriture |
|---|:---:|:---:|
| KDBX 4.x | Oui | Oui |
| KDBX 3.x | Oui | Oui |
| Compression GZip | Oui | Oui |
| Pièces jointes binaires | Oui | Oui |
| Champs protégés | Oui | Oui |
| Fichiers de clé XML v1/v2, bruts et hérités | Oui | XML v1 et brut |

| Rôle | Algorithmes |
|---|---|
| Chiffrement du contenu | AES-128/256-CBC, ChaCha20, Twofish-256-CBC |
| Dérivation de clé | AES-KDF, Argon2d, Argon2id |
| Flux des champs protégés | ChaCha20, Salsa20 |

La seule dépendance d'exécution publiée est
[`BouncyCastle.Cryptography`](https://www.nuget.org/packages/BouncyCastle.Cryptography).

## Limites actuelles

- Le projet ne fusionne pas les modifications concurrentes d'un fichier KDBX. Un enregistrement
  remplace le fichier cible.
- Certains champs avancés de `<Meta>` ne disposent pas encore d'une API dédiée.
- Les mots de passe exposés comme chaînes .NET ne peuvent pas être effacés de façon garantie par
  la bibliothèque.

Consultez les [issues](https://github.com/pidamg/lib-dotnet-keepass/issues) et le
[changelog](CHANGELOG.md) pour suivre les évolutions.

## Développement

```bash
dotnet restore Pidamg.KeePass.Kdbx.slnx
dotnet build Pidamg.KeePass.Kdbx.slnx
dotnet test Pidamg.KeePass.Kdbx.slnx
dotnet format Pidamg.KeePass.Kdbx.slnx --verify-no-changes
```

Les règles de contribution, de compatibilité d'API et de publication sont décrites dans
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Licence

Ce projet est distribué sous [licence MIT](LICENSE).

KeePass est une marque de Dominik Reichl. Ce projet est indépendant et n'est ni affilié à, ni
approuvé par le projet KeePass. [KeePassXC](https://github.com/keepassxreboot/keepassxc) est
utilisé comme implémentation de référence pour l'interopérabilité.
