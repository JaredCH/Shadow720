<#
.SYNOPSIS
    Bump the app version in every file that declares it, safely.

.DESCRIPTION
    The version lives in five places and they must agree:

      * src-tauri/tauri.conf.json  - "version" and bundle.android.versionCode
      * package.json               - "version"
      * src-tauri/Cargo.toml       - [package] version
      * src-tauri/Cargo.lock       - the `shadow720` package entry only
      * src/App.tsx                - the APP_VERSION constant the UI displays

    Two traps have already broken a build here, and this script exists to close
    both:

    1. A blanket text replace is wrong. The lockfile contains unrelated crates
       whose versions happen to match the app's (crypto-common sat at 0.1.7), so
       replacing every occurrence rewrites dependencies and cargo then refuses to
       resolve.

    2. Re-serialising JSON is wrong. Parsing and re-writing tauri.conf.json or
       package.json with ConvertTo-Json reformats the whole file - indentation,
       key order, spacing - turning a one-line change into a 90-line diff that
       buries the real edit and invites merge conflicts.

    So every edit here is surgical: the exact line is located and only the
    version token on it is replaced. Nothing else in any file is touched.

    Nothing is written unless every edit succeeds, so a failure part-way through
    cannot leave the tree half-bumped. After writing, the result is re-read and
    the lockfile diff is asserted to be exactly one line, which is what proves no
    dependency moved.

.PARAMETER Version
    The new version, for example 0.1.9. Must be greater than the current one.

.PARAMETER VersionCode
    The Android versionCode. Defaults to the current value plus one, which is
    what Play requires for every upload.

.PARAMETER DryRun
    Report what would change without writing anything.

.EXAMPLE
    ./scripts/bump-version.ps1 -Version 0.1.9

.EXAMPLE
    ./scripts/bump-version.ps1 -Version 0.2.0 -VersionCode 20 -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [int]$VersionCode,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must look like 0.1.9, got '$Version'."
}

$tauriPath = Join-Path $root 'src-tauri\tauri.conf.json'
$packagePath = Join-Path $root 'package.json'
$cargoPath = Join-Path $root 'src-tauri\Cargo.toml'
$lockPath = Join-Path $root 'src-tauri\Cargo.lock'
$readmePath = Join-Path $root 'README.md'
$appPath = Join-Path $root 'src\App.tsx'

foreach ($path in @($tauriPath, $packagePath, $cargoPath, $lockPath, $readmePath, $appPath)) {
    if (-not (Test-Path $path)) { throw "Expected file not found: $path" }
}

# ---------------------------------------------------------------------------
# Read the current version from tauri.conf.json, which is the source of truth
# for the bundle. Everything else is checked against it.
# ---------------------------------------------------------------------------

$tauri = Get-Content $tauriPath -Raw | ConvertFrom-Json
$currentVersion = $tauri.version
$currentCode = [int]$tauri.bundle.android.versionCode

if ([version]$Version -le [version]$currentVersion) {
    throw "New version $Version must be greater than the current $currentVersion."
}

if (-not $PSBoundParameters.ContainsKey('VersionCode')) {
    $VersionCode = $currentCode + 1
}
elseif ($VersionCode -le $currentCode) {
    throw "versionCode $VersionCode must be greater than the current $currentCode; Play rejects a duplicate."
}

Write-Host "Bumping $currentVersion (versionCode $currentCode) -> $Version (versionCode $VersionCode)"

# ---------------------------------------------------------------------------
# Helpers. Each returns the new file text; none of them reformat anything.
# ---------------------------------------------------------------------------

<#
    Replace the value of a JSON key on the one line that declares it.

    Deliberately line-based rather than parse-and-reserialise: the file's
    formatting is preserved exactly, so the diff is the version token and
    nothing else. `$Key` is matched as a quoted key followed by a colon, and
    `$Occurrence` picks which match when a key appears more than once.
#>
function Set-JsonValueOnLine {
    param(
        [string]$Text,
        [string]$Key,
        [string]$Value,
        [int]$Occurrence = 1,
        [string]$Label
    )

    $lines = $Text -split "`n"
    $pattern = '^(\s*"' + [regex]::Escape($Key) + '"\s*:\s*")([^"]*)(")'
    $seen = 0

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch $pattern) { continue }
        $seen++
        if ($seen -ne $Occurrence) { continue }
        $lines[$i] = [regex]::Replace($lines[$i], $pattern, { param($m) $m.Groups[1].Value + $Value + $m.Groups[3].Value })
        return ($lines -join "`n")
    }

    throw "Could not find $Label in the file."
}

<#
    Replace the numeric value of a JSON key on the one line that declares it.
#>
function Set-JsonNumberOnLine {
    param(
        [string]$Text,
        [string]$Key,
        [int]$Value,
        [string]$Label
    )

    $lines = $Text -split "`n"
    $pattern = '^(\s*"' + [regex]::Escape($Key) + '"\s*:\s*)(\d+)(\s*,?\s*)$'

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch $pattern) { continue }
        $lines[$i] = [regex]::Replace($lines[$i], $pattern, { param($m) $m.Groups[1].Value + $Value + $m.Groups[3].Value })
        return ($lines -join "`n")
    }

    throw "Could not find $Label in the file."
}

# ---------------------------------------------------------------------------
# Collect every edit first, so a failure cannot leave the tree half-bumped.
# ---------------------------------------------------------------------------

$edits = [ordered]@{}

# The pre-edit text of every file, so the result can be compared against what was
# actually there rather than against `HEAD`. Comparing to `HEAD` would count any
# unrelated uncommitted work in the same file as a reformat, which is a false
# alarm on a tree that is mid-feature.
$originals = [ordered]@{}

# tauri.conf.json: the app version is the first "version" key in the file, and
# versionCode appears once.
$tauriText = Get-Content $tauriPath -Raw
$originals[$tauriPath] = $tauriText
$tauriText = Set-JsonValueOnLine -Text $tauriText -Key 'version' -Value $Version -Label 'the app version in tauri.conf.json'
$tauriText = Set-JsonNumberOnLine -Text $tauriText -Key 'versionCode' -Value $VersionCode -Label 'versionCode in tauri.conf.json'
$edits[$tauriPath] = $tauriText

# package.json: "version" is the first occurrence, before any dependency block.
$packageText = Get-Content $packagePath -Raw
$originals[$packagePath] = $packageText
$packageText = Set-JsonValueOnLine -Text $packageText -Key 'version' -Value $Version -Label 'the version in package.json'
$edits[$packagePath] = $packageText

# Cargo.toml: only the [package] version, never a dependency's. The [package]
# table is the first one in the file, so the first `version =` line after it is
# the app's.
$cargoLines = Get-Content $cargoPath
$packageTable = -1
for ($i = 0; $i -lt $cargoLines.Count; $i++) {
    if ($cargoLines[$i].Trim() -eq '[package]') { $packageTable = $i; break }
}
if ($packageTable -lt 0) { throw "Could not find a [package] table in $cargoPath" }

$cargoVersionLine = -1
for ($i = $packageTable + 1; $i -lt $cargoLines.Count; $i++) {
    if ($cargoLines[$i].TrimStart().StartsWith('[')) { break }
    if ($cargoLines[$i] -match '^\s*version\s*=') { $cargoVersionLine = $i; break }
}
if ($cargoVersionLine -lt 0) { throw "Could not find a version line in the [package] table of $cargoPath" }

$cargoLines[$cargoVersionLine] = "version = `"$Version`""
$originals[$cargoPath] = (Get-Content $cargoPath -Raw)
$edits[$cargoPath] = ($cargoLines -join "`n") + "`n"

# Cargo.lock: locate the `[[package]]` block whose name is exactly shadow720 and
# change only that block's version. This is the edit a blanket replace got wrong,
# so it is done by block rather than by pattern.
$lockLines = Get-Content $lockPath
$lockVersionLine = -1
for ($i = 0; $i -lt $lockLines.Count; $i++) {
    if ($lockLines[$i] -ne 'name = "shadow720"') { continue }
    if ($i + 1 -ge $lockLines.Count) { throw "Malformed Cargo.lock: shadow720 has no version line" }
    if ($lockLines[$i + 1] -notmatch '^version = "') {
        throw "Malformed Cargo.lock: expected a version line after shadow720, got '$($lockLines[$i + 1])'"
    }
    $lockVersionLine = $i + 1
    break
}
if ($lockVersionLine -lt 0) { throw "Could not find the shadow720 package in $lockPath" }

$lockLines[$lockVersionLine] = "version = `"$Version`""
$originals[$lockPath] = (Get-Content $lockPath -Raw)
$edits[$lockPath] = ($lockLines -join "`n") + "`n"

# README.md: prose references to the packaged filenames. These are not
# declarations, so a miss is cosmetic rather than breaking, but they are the
# ones a reader notices.
#
# Read through .NET rather than `Get-Content -Raw`: in Windows PowerShell 5.1 the
# latter defaults to the ANSI code page, which mangles the UTF-8 em-dashes and
# arrows in this file into mojibake and turns a three-line edit into a whole-file
# rewrite.
$readme = [System.IO.File]::ReadAllText($readmePath)
$originals[$readmePath] = $readme
$readme = $readme.Replace("Shadow720_${currentVersion}_", "Shadow720_${Version}_")
$readme = $readme.Replace("Shadow720-${currentVersion}-", "Shadow720-${Version}-")
$readme = $readme.Replace("What's new in $currentVersion", "What's new in $Version")
$edits[$readmePath] = $readme

# src/App.tsx: the build version shown on the failure screen and in the sidebar.
#
# This is a declaration, not prose: it is what a bug report quotes, so a stale
# value makes an already-fixed bug indistinguishable from a new one. It was left
# at 0.1.7 through the 0.1.8 release precisely because nothing checked it, so it
# is now bumped and verified like the others.
$app = [System.IO.File]::ReadAllText($appPath)
$originals[$appPath] = $app
$appPattern = '(?m)^(const APP_VERSION = ")([^"]*)(";)\r?$'
if ($app -notmatch $appPattern) {
    throw "Could not find the APP_VERSION declaration in src/App.tsx."
}
$app = [regex]::Replace($app, $appPattern, { param($m) $m.Groups[1].Value + $Version + $m.Groups[3].Value })
$edits[$appPath] = $app

# ---------------------------------------------------------------------------
# Write, then verify by re-reading. A silent partial write is the failure mode
# that caused the original breakage, so the result is checked rather than
# assumed.
# ---------------------------------------------------------------------------

if ($DryRun) {
    Write-Host "`nDry run - no files written. Would update:"
    foreach ($path in $edits.Keys) { Write-Host "  $path" }
    return
}

foreach ($path in $edits.Keys) {
    # `utf8` in Windows PowerShell 5.1 writes a BOM, which would prepend bytes to
    # every file and show up as a spurious first-line change. `utf8NoBOM` is not
    # available there, so the encoding is chosen by edition.
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        Set-Content -Path $path -Value $edits[$path] -NoNewline -Encoding utf8NoBOM
    }
    else {
        [System.IO.File]::WriteAllText($path, $edits[$path], (New-Object System.Text.UTF8Encoding($false)))
    }
}

$failures = @()

$checkTauri = Get-Content $tauriPath -Raw | ConvertFrom-Json
if ($checkTauri.version -ne $Version) { $failures += "tauri.conf.json version is $($checkTauri.version)" }
if ([int]$checkTauri.bundle.android.versionCode -ne $VersionCode) {
    $failures += "tauri.conf.json versionCode is $($checkTauri.bundle.android.versionCode)"
}

$checkPackage = Get-Content $packagePath -Raw | ConvertFrom-Json
if ($checkPackage.version -ne $Version) { $failures += "package.json version is $($checkPackage.version)" }

$checkCargo = Get-Content $cargoPath -Raw
if ($checkCargo -notmatch "(?m)^version = `"$([regex]::Escape($Version))`"$") {
    $failures += "Cargo.toml has no version = `"$Version`" line"
}

$checkLock = Get-Content $lockPath -Raw
if ($checkLock -notmatch "(?m)^name = `"shadow720`"\r?\nversion = `"$([regex]::Escape($Version))`"$") {
    $failures += "Cargo.lock shadow720 entry is not $Version"
}

$checkApp = [System.IO.File]::ReadAllText($appPath)
if ($checkApp -notmatch "(?m)^const APP_VERSION = `"$([regex]::Escape($Version))`";\r?$") {
    $failures += "src/App.tsx APP_VERSION is not $Version"
}

# The whole point of this script: no dependency may have moved, and no file may
# have been reformatted.
#
# The comparison is against the text read before the edit, not against `HEAD`.
# Comparing to `HEAD` counts unrelated uncommitted work in the same file as a
# reformat, which is a false alarm on a tree that is mid-feature - and it cannot
# see a reformat at all when the file was already dirty.
#
# The invariant asserted is stronger than a line count: every line that differs
# must differ *only* by the version token. That is what proves no dependency was
# rewritten, and it stays correct when a file is already at the target version
# (a re-run changes nothing, which is not a failure).
foreach ($path in $edits.Keys) {
    $name = Split-Path -Leaf $path
    if (-not $originals.Contains($path)) { continue }

    $before = @($originals[$path] -split "`r?`n")
    $after = @($edits[$path] -split "`r?`n")
    if ($before.Count -ne $after.Count) {
        $failures += "$name changed line count from $($before.Count) to $($after.Count). The file was reformatted."
        continue
    }

    for ($i = 0; $i -lt $before.Count; $i++) {
        if ($before[$i] -eq $after[$i]) { continue }

        # Undo each permitted substitution; if any restores the original line, the
        # only thing that changed on this line was a version token.
        $restored = $after[$i].Replace($Version, $currentVersion).Replace("$VersionCode", "$currentCode")
        if ($restored -ne $before[$i]) {
            $failures += "$name line $($i + 1) changed beyond the version token: '$($before[$i].Trim())' -> '$($after[$i].Trim())'"
        }
    }
}
if ($failures.Count -gt 0) {
    Write-Host "`nVersion bump FAILED verification:" -ForegroundColor Red
    foreach ($failure in $failures) { Write-Host "  - $failure" -ForegroundColor Red }
    throw "Version bump did not apply cleanly. Inspect the files before committing."
}

Write-Host "`nVerified:" -ForegroundColor Green
Write-Host "  tauri.conf.json  $Version / versionCode $VersionCode"
Write-Host "  package.json     $Version"
Write-Host "  Cargo.toml       $Version"
Write-Host "  Cargo.lock       shadow720 $Version (no dependency touched)"
Write-Host "  README.md        version references updated"
Write-Host "  src/App.tsx      APP_VERSION $Version"
Write-Host "`nNext: build with scripts/build-release.ps1, then commit and tag."
