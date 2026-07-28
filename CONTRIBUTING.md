# Contribuer à Pidamg.KeePass.Kdbx

Merci de votre intérêt pour le projet.

## Prérequis

- SDK .NET défini dans [`global.json`](global.json)
- Git

Le repository utilise une solution SLNX et la gestion centralisée des dépendances NuGet.

```bash
dotnet restore Pidamg.KeePass.Kdbx.slnx
dotnet build Pidamg.KeePass.Kdbx.slnx
dotnet test Pidamg.KeePass.Kdbx.slnx
```

Les sorties de compilation sont centralisées dans le dossier `artifacts/`.

## Structure du repository

```text
src/Pidamg.KeePass.Kdbx/
tests/Pidamg.KeePass.Kdbx.Tests/
tests/Pidamg.KeePass.Kdbx.IntegrationTests/
Directory.Build.props
Directory.Packages.props
Pidamg.KeePass.Kdbx.slnx
```

- `Pidamg.KeePass.Kdbx.Tests` contient les tests unitaires et peut accéder aux membres
  `internal` grâce à `InternalsVisibleTo`.
- `Pidamg.KeePass.Kdbx.IntegrationTests` utilise uniquement l'API publique, comme un projet
  consommateur externe. Il référence le projet source par défaut et peut référencer un package
  construit en définissant la propriété MSBuild `TestPackageVersion`.

## Conventions de code

Le formatage et les conventions sont définis dans [`.editorconfig`](.editorconfig).

Avant de proposer une modification :

```bash
dotnet format Pidamg.KeePass.Kdbx.slnx
dotnet format Pidamg.KeePass.Kdbx.slnx --verify-no-changes
```

La documentation XML des types et membres publics est rédigée en anglais. Elle est obligatoire :
les avertissements `CS1591` sont traités comme des erreurs.

## Compatibilité de l'API publique

La surface publique est suivie par `Microsoft.CodeAnalysis.PublicApiAnalyzers` :

- `PublicAPI.Shipped.txt` contient l'API déjà publiée ;
- `PublicAPI.Unshipped.txt` contient les changements prévus pour la prochaine version.

Pour ajouter une nouvelle API publique :

```bash
dotnet format src/Pidamg.KeePass.Kdbx/Pidamg.KeePass.Kdbx.csproj \
  analyzers \
  --diagnostics RS0016
```

Vérifiez ensuite le contenu ajouté dans `PublicAPI.Unshipped.txt`. Une suppression ou une
modification incompatible doit être discutée avant son intégration.

La CI vérifie explicitement la conformité de l'API avec :

```bash
dotnet format src/Pidamg.KeePass.Kdbx/Pidamg.KeePass.Kdbx.csproj \
  analyzers \
  --verify-no-changes \
  --no-restore \
  --diagnostics RS0016 RS0017
```

## Tests

Toute correction ou nouvelle fonctionnalité doit être accompagnée de tests adaptés :

- tests unitaires pour les détails d'implémentation ;
- tests d'intégration pour les comportements visibles par les consommateurs.

Exécuter tous les tests :

```bash
dotnet test Pidamg.KeePass.Kdbx.slnx --configuration Release
```

Pour tester un package local avec les mêmes tests d'intégration :

```bash
dotnet restore tests/Pidamg.KeePass.Kdbx.IntegrationTests \
  -p:TestPackageVersion=0.1.0-alpha.1 \
  --source ./nupkgs \
  --source https://api.nuget.org/v3/index.json

dotnet test tests/Pidamg.KeePass.Kdbx.IntegrationTests \
  --configuration Release \
  --no-restore \
  -p:TestPackageVersion=0.1.0-alpha.1
```

## Création du package

```bash
dotnet pack src/Pidamg.KeePass.Kdbx/Pidamg.KeePass.Kdbx.csproj \
  --configuration Release \
  --output nupkgs/
```

Le package doit contenir :

- `Pidamg.KeePass.Kdbx.dll` ;
- la documentation XML pour IntelliSense ;
- l'icône `package-icon.png` ;
- les métadonnées du repository et de la licence ;
- un package de symboles `.snupkg`.

## Versionnement et publication

Les versions suivent [Semantic Versioning](https://semver.org/).

Exemples :

- préversion : `v0.1.0-alpha.1`, `v0.1.0-beta.1`, `v0.1.0-rc.1` ;
- version stable : `v0.1.0`.

Lorsqu'un tag `v*` est poussé :

1. la CI compile et teste la solution ;
2. elle valide la conformité de l'API publique ;
3. elle crée une seule fois les packages `.nupkg` et `.snupkg` ;
4. elle exécute les tests d'intégration contre le package `.nupkg` construit ;
5. elle publie toutes les versions sur GitHub Packages ;
6. elle publie également les versions stables sur NuGet.org.
7. elle crée une GitHub Release avec les notes extraites de `CHANGELOG.md` et les packages.

Les préversions ne sont jamais publiées sur NuGet.org.

La publication NuGet.org utilise :

- l'environnement GitHub protégé `nuget.org` ;
- une politique NuGet.org Trusted Publishing liée au repository, au workflow `ci.yml` et à
  l'environnement `nuget.org` ;
- le secret d'environnement `NUGET_USER`, qui contient le nom du profil NuGet.org et non une
  adresse e-mail.

Le job demande un jeton OIDC à GitHub, puis `NuGet/login@v1` l'échange contre une clé NuGet
temporaire. Aucune clé API permanente n'est stockée dans GitHub.

Le package construit est partagé entre les deux jobs de publication afin de garantir que GitHub
Packages et NuGet.org reçoivent exactement le même artefact.

Avant de créer un tag, ajoutez une section datée correspondant exactement à sa version dans
`CHANGELOG.md`. Par exemple, le tag `v0.1.0-beta.1` nécessite une section
`## [0.1.0-beta.1] - YYYY-MM-DD`.

## Pull requests

Une pull request doit :

- rester ciblée sur un changement cohérent ;
- expliquer le comportement modifié ;
- inclure les tests nécessaires ;
- préserver la compatibilité de l'API publique ou justifier explicitement la rupture ;
- réussir le formatage, la compilation, les tests et la validation d'API de la CI.
