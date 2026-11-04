<#
.SYNOPSIS
    Build the downloadable Windows and Android packages into release/.

.DESCRIPTION
    Produces the two artifacts a user actually installs:

      * Windows  - NSIS installer and MSI, via `tauri build`
      * Android  - signed arm64 APK, via Gradle

    The Android APK must be signed or Android refuses to install it. The signing
    key is read from src-tauri/gen/android/keystore.properties, which is
    gitignored; see scripts/new-android-keystore.ps1 to create one.

.PARAMETER SkipWindows
    Build only the Android APK.

.PARAMETER SkipAndroid
    Build only the Windows installers.
#>
[CmdletBinding()]
param(
    [switch]$SkipWindows,
    [switch]$SkipAndroid
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$release = Join-Path $root 'release'
New-Item -ItemType Directory -Force -Path $release | Out-Null

$version = (Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).version
Write-Host "Building Shadow720 $version" -ForegroundColor Cyan

if (-not $SkipWindows) {
    Write-Host "`n== Windows installers ==" -ForegroundColor Cyan
    Push-Location $root
    try {
        npm run tauri build
        if ($LASTEXITCODE -ne 0) { throw "tauri build failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }

    $bundle = Join-Path $root 'src-tauri\target\release\bundle'
    foreach ($pattern in @('nsis\*.exe', 'msi\*.msi')) {
        Get-ChildItem -Path (Join-Path $bundle $pattern) -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $release $_.Name) -Force
            Write-Host "  staged $($_.Name)"
        }
    }
}

if (-not $SkipAndroid) {
    Write-Host "`n== Android APK ==" -ForegroundColor Cyan

    $sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "$env:LOCALAPPDATA\Android\Sdk" }
    $ndk = Get-ChildItem (Join-Path $sdk 'ndk') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $ndk) { throw "No Android NDK found under $sdk\ndk" }

    $env:ANDROID_HOME = $sdk
    $env:NDK_HOME = $ndk.FullName
    $toolchain = Join-Path $ndk.FullName 'toolchains\llvm\prebuilt\windows-x86_64\bin'
    $env:PATH = "$toolchain;$env:PATH"
    $env:CC_aarch64_linux_android = Join-Path $toolchain 'clang.exe'
    $env:CFLAGS_aarch64_linux_android = '--target=aarch64-linux-android26'
    $env:AR_aarch64_linux_android = Join-Path $toolchain 'llvm-ar.exe'

    # The Tauri CLI normally writes the resolved config into the APK's assets.
    # Building through Gradle directly skips that, and the notification plugin
    # reads it at startup via PluginManager.loadConfig, so without this file the
    # app throws during launch and closes immediately.
    $assetDir = Join-Path $root 'src-tauri\gen\android\app\src\main\assets'
    New-Item -ItemType Directory -Force -Path $assetDir | Out-Null
    $config = Get-Content (Join-Path $root 'src-tauri\tauri.conf.json') -Raw | ConvertFrom-Json
    $config | ConvertTo-Json -Depth 32 -Compress |
        Set-Content -Path (Join-Path $assetDir 'tauri.conf.json') -NoNewline -Encoding utf8
    Write-Host "  staged assets/tauri.conf.json"

    Push-Location (Join-Path $root 'src-tauri')
    try {
        cargo build --release --target aarch64-linux-android
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }

        # Gradle's rustBuild task re-invokes the Tauri CLI, which needs Developer
        # Mode for symlinks. Staging the .so first lets that task be skipped.
        $jni = 'gen\android\app\src\main\jniLibs\arm64-v8a'
        New-Item -ItemType Directory -Force -Path $jni | Out-Null
        Copy-Item 'target\aarch64-linux-android\release\libshadow720_lib.so' `
            (Join-Path $jni 'libshadow720_lib.so') -Force

        Push-Location 'gen\android'
        try {
            .\gradlew.bat assembleArm64Release -x rustBuildArm64Release
            if ($LASTEXITCODE -ne 0) { throw "gradle failed with exit code $LASTEXITCODE" }
        } finally {
            Pop-Location
        }
    } finally {
        Pop-Location
    }

    $apk = Join-Path $root 'src-tauri\gen\android\app\build\outputs\apk\arm64\release\app-arm64-release.apk'
    if (-not (Test-Path $apk)) { throw "Expected APK not found at $apk" }
    $target = Join-Path $release "Shadow720_${version}_arm64.apk"
    Copy-Item $apk $target -Force
    Write-Host "  staged $(Split-Path -Leaf $target)"
}

Write-Host "`nArtifacts in $release" -ForegroundColor Green
Get-ChildItem $release | Select-Object Name, @{n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }
