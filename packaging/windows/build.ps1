param(
    [string]$Version = "0.1.0.0",
    [string]$Publisher = "CN=C2CC4240-9984-420A-8B9F-E6FE73010A59"
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

$cert = "$out\DebanganMali.ObscuraVault_cert.pfx"
if (Test-Path $cert) {
    winapp pack $dist --cert $cert --output "$out\ObscuraVault_${Version}_x64.msix"
} else {
    winapp pack $dist --generate-cert --publisher $Publisher --output "$out\ObscuraVault_${Version}_x64.msix"
}
