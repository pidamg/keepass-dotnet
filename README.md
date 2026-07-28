# Pidamg.KeePass.Kdbx

Bibliothèque .NET pour lire et écrire les fichiers de mots de passe KeePass (`.kdbx`).
Inspirée de [KeePassXC](https://github.com/keepassxreboot/keepassxc), utilisé comme implémentation de référence.

## Installation

```bash
dotnet add package Pidamg.KeePass.Kdbx
```

## Démarrage rapide

```csharp
using Pidamg.KeePass;

// Ouvrir une base existante
var db = KdbxDatabase.Open("vault.kdbx", "password");

// Créer une nouvelle base
var db = KdbxDatabase.Create("password");
db.Metadata.Name = "Mon coffre-fort";

// Lire les entrées
foreach (var entry in db.RootGroup.Entries)
    Console.WriteLine($"{entry.Title} — {entry.UserName}");

// Rechercher
var entry = db.FindEntry("GitHub");
var all   = db.FindAllEntries(e => e.UserName == "alice").ToList();
var work  = db.FindGroup("Travail");

// Ajouter une entrée
var entry = new Entry();   // UUID auto-généré
entry.Title    = "GitHub";
entry.UserName = "alice";
entry.Password = "s3cr3t!";   // Protected = true par défaut
db.RootGroup.AddEntry(entry);

// Ajouter une pièce jointe binaire
entry.Binaries.Add(new EntryBinary { Name = "id_rsa.pub", Data = File.ReadAllBytes("id_rsa.pub") });

// Sauvegarder
db.SaveAs("vault.kdbx");

// Générer un fichier de clé
KeyFile.Generate("vault.keyx");                        // KeePass XML v1 (défaut)
KeyFile.Generate("vault.key", KeyFileFormat.Raw);      // 32 octets aléatoires bruts

// Ouvrir une base protégée par mot de passe + fichier de clé
var db = KdbxDatabase.Open("vault.kdbx", "password", "vault.keyx");
```

## API publique

### `KdbxDatabase`

Point d'entrée principal de la bibliothèque. Implémente `IDisposable` — appeler `Dispose()` efface les clés cryptographiques en mémoire (`CompositeKey.Zeroize()`) et libère toutes les données.

```csharp
// Constructeurs
new KdbxDatabase()
new KdbxDatabase(CompositeKey key)
new KdbxDatabase(string path)
new KdbxDatabase(string path, CompositeKey key)
new KdbxDatabase(string path, string password)
new KdbxDatabase(string path, string password, string keyFile)

// Factories
KdbxDatabase.Create(string password)
KdbxDatabase.Create(string password, KdbxSettings? settings)
KdbxDatabase.Create(string password, string keyFile)
KdbxDatabase.Create(string password, string keyFile, KdbxSettings? settings)
KdbxDatabase.Open(string path, string password, string? keyFile = null)

// Propriétés
Metadata   Metadata   { get; }   // lève InvalidOperationException si la base n'est pas ouverte
Group      RootGroup  { get; }   // lève InvalidOperationException si la base n'est pas ouverte
KdbxVersion    Version    { get; }   // 0.0 avant ouverture, ex. 4.1 / 3.1 après
KdbxSettings   Settings   { get; set; }
FileInfo?  FileInfo   { get; }
bool       HasChanges { get; }

// Méthodes synchrones
void Open()
void Save()
void SaveAs(string path)

// Méthodes asynchrones
Task OpenAsync(CancellationToken ct = default)
Task SaveAsync(CancellationToken ct = default)
Task SaveAsAsync(string path, CancellationToken ct = default)

bool   IsRecycleBinEnabled()
Group? GetRecycleBin()

// Recherche (délègue à RootGroup)
Entry?             FindEntry(string title)
Entry?             FindEntry(Func<Entry, bool> predicate)
IEnumerable<Entry> FindAllEntries(Func<Entry, bool> predicate)
Group?             FindGroup(string name)
Group?             FindGroup(Func<Group, bool> predicate)
IEnumerable<Group> FindAllGroups(Func<Group, bool> predicate)
```

### `Entry`

```csharp
// Propriétés
KdbxDatabase? Database    { get; }
Group?    ParentGroup { get; }
Guid      Uuid           { get; set; }
int       IconId         { get; set; }   // index d'icône intégrée
Guid      CustomIconUuid { get; set; }   // Guid.Empty = aucune
string    Tags           { get; set; }
Times     Times       { get; set; }
AutoType  AutoType    { get; set; }
Dictionary<string, EntryString> Strings  { get; set; }
List<EntryBinary>               Binaries { get; set; }
List<Entry>                     History  { get; set; }

// Raccourcis pour les 5 champs standard (lecture + écriture)
// Les setters conservent le flag Protected existant ; Password est Protected par défaut.
string Title    { get; set; }
string UserName { get; set; }
string Password { get; set; }
string Url      { get; set; }
string Notes    { get; set; }

// Opérations
void  Delete()            // déplace dans la corbeille si activée, sinon supprime
void  MoveTo(Group group)
void  Update(Action<Entry> update)  // snapshot → application → ajout à l'historique
Entry Clone()             // copie profonde avec nouvel UUID et historique vide
```

### `Group`

```csharp
// Propriétés
KdbxDatabase? Database        { get; }
Group?    ParentGroup     { get; }
Guid      Uuid            { get; set; }
string    Name            { get; set; }
string    Notes           { get; set; }
int       IconId          { get; set; }   // index d'icône intégrée
Guid      CustomIconUuid  { get; set; }   // Guid.Empty = aucune
bool      IsExpanded      { get; set; }
bool?     EnableAutoType  { get; set; }
bool?     EnableSearching { get; set; }
Times     Times           { get; set; }
ReadOnlyCollection<Entry> Entries { get; }
ReadOnlyCollection<Group> Groups  { get; }

// Opérations
void  AddEntry(Entry entry)
void  RemoveEntry(Entry entry)
void  AddGroup(Group group)
void  RemoveGroup(Group group)
void  Delete()            // déplace dans la corbeille si activée, sinon supprime
void  MoveTo(Group parent)
Group Clone()
bool  IsAncestorOf(Group group)

// Recherche (récursive dans le sous-arbre)
Entry?             FindEntry(string title)
Entry?             FindEntry(Func<Entry, bool> predicate)
IEnumerable<Entry> FindAllEntries(Func<Entry, bool> predicate)
Group?             FindGroup(string name)
Group?             FindGroup(Func<Group, bool> predicate)
IEnumerable<Group> FindAllGroups(Func<Group, bool> predicate)
```

### `CustomIcon`

Icônes personnalisées stockées dans `<Meta><CustomIcons>`. Chaque icône possède un UUID référencé par les entrées et groupes via leur propriété `CustomIconUuid`.

```csharp
public class CustomIcon {
    Guid      Uuid                 { get; set; }  // auto-généré si non défini
    byte[]    Data                 { get; set; }  // octets PNG
    string    Name                 { get; set; }  // optionnel (extension KeePassXC)
    DateTime? LastModificationTime { get; set; }  // optionnel (extension KeePassXC)
}
```

Utilisation :

```csharp
// Ajouter une icône personnalisée à la base
var icon = new CustomIcon { Data = File.ReadAllBytes("icon.png"), Name = "github" };
db.Metadata.CustomIcons.Add(icon);

// L'assigner à une entrée ou un groupe
entry.CustomIconUuid = icon.Uuid;
group.CustomIconUuid = icon.Uuid;

// Retrouver une icône par UUID
var icon = db.Metadata.CustomIcons.FirstOrDefault(i => i.Uuid == entry.CustomIconUuid);
```

### `KdbxSettings`

Configuration du format de la base. À passer à `KdbxDatabase.Create()` pour personnaliser.

```csharp
KdbxFormat               Format               // KdbxFormat.Kdbx4 (défaut) ou KdbxFormat.Kdbx3
CipherAlgorithm          Cipher               // AES256, ChaCha20 (défaut), Twofish
bool                     IsCompressed         // GZip (true par défaut)
ProtectedStreamAlgorithm InnerStreamAlgorithm // ChaCha20 (défaut) ou Salsa20
IKdf                     Kdf                  // Argon2id (défaut) ou AesKdf
```

Exemple — créer une base KDBX 3.x avec AES-KDF :

```csharp
var settings = new KdbxSettings {
    Format = KdbxFormat.Kdbx3,
    Cipher = CipherAlgorithm.ChaCha20,
    Kdf    = new AesKdf(RandomNumberGenerator.GetBytes(32), 100_000UL),
};
var db = KdbxDatabase.Create("password", settings);
```

### `KdbxVersion`

Version du format KDBX. Initialisée à `0.0` (`IsZero == true`) avant ouverture, puis renseignée depuis l'en-tête lors de la lecture, ou déduite de `KdbxSettings.Format` lors d'un `Create()`.

```csharp
ushort Major   // 3 ou 4
ushort Minor   // ex. 1
bool   IsZero  // true si non initialisée

// Opérateurs : ==, !=, <, <=, >, >=
// ToString()  → "4.1"
```

Exemples :

```csharp
var db = KdbxDatabase.Create("pass");    // → db.Version == new KdbxVersion(4, 1)
var db = KdbxDatabase.Open("v.kdbx", "pass");
if (db.Version >= new KdbxVersion(4, 0))
    Console.WriteLine("KDBX 4.x");
```

### `CompositeKey`

```csharp
new CompositeKey()
new CompositeKey(string password)
new CompositeKey(string password, string keyFile)
CompositeKey AddPassword(string password)
CompositeKey AddKeyFile(string path)
```

### `KeyFile`

Génération de fichiers de clé. Formats de lecture pris en charge : KeePass XML v1, hexadécimal (64 caractères), 32 octets bruts, tout autre fichier (SHA-256 utilisé comme clé).

```csharp
// Génération
KeyFile.Generate(string path, KeyFileFormat format = KeyFileFormat.Xml)

// Formats
KeyFileFormat.Xml   // KeePass XML v1 — interopérable avec KeePassXC (défaut)
KeyFileFormat.Raw   // 32 octets aléatoires bruts
```

## Formats supportés

| Format | Lecture | Écriture |
|--------|:-------:|:--------:|
| KDBX 4.x | ✅ | ✅ |
| KDBX 3.x | ✅ | ✅ |
| Compression GZip | ✅ | ✅ |
| Blocs HMAC-SHA256 (v4) | ✅ | ✅ |
| Blocs hachés (v3) | ✅ | ✅ |
| Pièces jointes binaires (inner header v4) | ✅ | ✅ |
| Pièces jointes binaires (Meta pool v3) | ✅ | ✅ |
| Champs protégés (ProtectedStream) | ✅ | ✅ |

## Algorithmes cryptographiques

| Algorithme | Rôle |
|------------|------|
| Argon2d / Argon2id | KDF pour KDBX 4.x (défaut : Argon2id) |
| AES-KDF | KDF pour KDBX 3.x |
| AES-256-CBC | Chiffrement de la charge utile |
| ChaCha20 | Chiffrement de la charge utile (défaut) |
| Twofish | Chiffrement de la charge utile |
| ChaCha20 / Salsa20 | Flux protégé pour les champs XML |

Dépendance unique : **BouncyCastle.Cryptography** (Argon2, ChaCha20, Twofish).

## Architecture interne

```
KdbxDatabase
├── KdbxReader(db).ReadFrom(stream)
│   ├── KdbxHeader.Read()          — en-tête binaire + paramètres KDF
│   ├── DerivedKey.Derive()        — Argon2 / AES-KDF
│   ├── EncryptionKey              — clé de chiffrement + clé HMAC
│   └── KdbxXmlReader(db, ps, v4).ReadFrom(stream)
│       └── db.SetupLoadedData()   — câblage _db + index d'entrées
│
└── KdbxWriter(db).WriteTo(stream)
    ├── KdbxHeader.CreateNew()
    ├── KdbxXmlWriter(db, ps, v4).WriteTo(stream)
    └── Blocs HMAC (v4) / Blocs hachés (v3)
```

## Commandes de développement

```bash
dotnet build Pidamg.KeePass.Kdbx.slnx
dotnet test Pidamg.KeePass.Kdbx.slnx
dotnet format Pidamg.KeePass.Kdbx.slnx
dotnet pack src/Pidamg.KeePass.Kdbx/Pidamg.KeePass.Kdbx.csproj
```

## Structure du repository

```text
.
├── src/Pidamg.KeePass.Kdbx/
├── tests/Pidamg.KeePass.Kdbx.IntegrationTests/
├── tests/Pidamg.KeePass.Kdbx.Tests/
├── Directory.Build.props
├── Directory.Packages.props
└── Pidamg.KeePass.Kdbx.slnx
```

## Couverture des tests

152 tests passants, 1 ignoré (diagnostic manuel).

Les tests d'intégration compilent et exécutent les principaux scénarios en utilisant uniquement
l'API publique, sans accès aux membres `internal`.

### Couverts ✓

| Domaine | Ce qui est testé |
|---------|-----------------|
| Aller-retour V4 | Argon2id + ChaCha20, champs protégés, base vide |
| Aller-retour V3 | AES-KDF + ChaCha20 |
| Fichiers réels | `SimplePasswordV4.kdbx`, `SimplePasswordV3_ChaCha20.kdbx`, mauvais mot de passe |
| XML Meta | `Name`, `ProtectPassword` |
| Champs d'entrée | `Title`, `UserName`, `Password`, `Url` (lecture + écriture) |
| Binaires V4 | Unique, multiples, dédupliqués, `IsProtected` |
| Binaires V3 | Binaire unique via Meta pool |
| CRUD entrée | `Delete()` (avec/sans corbeille), `MoveTo()`, `Update()` + historique, `Clone()` |
| CRUD groupe | `AddEntry/Group`, `RemoveEntry/Group`, `Delete()`, `MoveTo()`, `Clone()`, `IsAncestorOf()` |
| KdbxDatabase | `HasChanges`, `IsRecycleBinEnabled()`, `GetRecycleBin()`, `Version` |
| Recherche | `FindEntry` / `FindAllEntries` / `FindGroup` / `FindAllGroups` — racine, imbriqué, prédicat, sous-arbre |
| Times V4 | Tous les champs de date, `Expires`, `UsageCount`, `DateTimeKind.Utc`, times de groupe |
| Times V3 | Tous les champs de date, `Expires`, `DateTimeKind.Utc`, times de groupe |
| `Save` / `SaveAs` | Création de fichier, écrasement, `HasChanges`, aller-retour V4/V3, sous-groupes |
| Fichier de clé | XML, hex, 32 octets bruts, fallback SHA-256, erreurs, `KeyFile.Generate()` V4/V3 |
| Metadata | `Description`, `DefaultUserName`, `HistoryMaxSize/Items`, `RecycleBinEnabled/Uuid` |
| AutoType | `Enabled`, `DefaultSequence`, `DataTransferObfuscation`, associations (0, 1, N) |
| Chiffrements | AES-256-CBC (V4/V3), Twofish-256-CBC (V4/V3), `Settings.Cipher` préservé |
| ProtectedStream | Salsa20 V3 (entrée unique + multiples), `Settings.InnerStreamAlgorithm` préservé |
| Icônes personnalisées | Ajout, lecture, écriture, assignation à entrée/groupe, UUID préservé |
| Validations | V3 + Argon2 lève `InvalidOperationException` |

### Non couverts ✗

*Aucune zone non couverte connue.*

## Feuille de route

- [x] Icônes personnalisées (`<Meta><CustomIcons>`)
- [ ] Champs `<Meta>` supplémentaires (`Generator`, `MasterKeyChanged`, `MemoryProtection` complet…)
- [x] `FindEntry()` / `FindGroup()` — recherche récursive sur `Group` et `KdbxDatabase`
- [ ] Synchronisation à la sauvegarde — détecter si le fichier a été modifié entre l'ouverture et la sauvegarde, fusionner les modifications au lieu d'écraser
