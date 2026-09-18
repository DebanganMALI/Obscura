param(
    [string]$Version = "0.1.0.0",
    [string]$Publisher = "CN=Debangan Mali"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))

cargo tauri build --no-bundle

$dist = "packaging\windows\dist"
$out = "packaging\out"

Remove-Item $dist -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$dist\Assets" | Out-Null
New-Item -ItemType Directory -Force -Path $out | Out-Null

Copy-Item target\release\obscura-app.exe "$dist\Obscura.exe"
Copy-Item packaging\windows\Assets\*.png "$dist\Assets\"

$manifest = [IO.File]::ReadAllText("packaging\windows\Package.appxmanifest")
$manifest = [regex]::Replace($manifest, 'Version="\d+\.\d+\.\d+\.\d+"', "Version=`"$Version`"")
[IO.File]::WriteAllText("$dist\Package.appxmanifest", $manifest)

winapp pack $dist --generate-cert --publisher $Publisher --output "$out\Obscura_${Version}_x64.msix"
