<#
.SYNOPSIS
Builds netattrib in release mode and packages it for a GitHub release.

.DESCRIPTION
Writes, into a fresh dist\ directory:
  netattrib-v<version>-windows-x64.zip         netattrib.exe, README.md, README_RU.md, LICENSE
  netattrib-v<version>-windows-x64.zip.sha256  "<sha256>  <zip name>" (sha256sum format, so both
                                               `sha256sum -c` and Get-FileHash can check it)
The version comes from Cargo.toml, and the script refuses to package an exe that reports a
different one.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts\package-release.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $match = Select-String -Path 'Cargo.toml' -Pattern '^version\s*=\s*"([^"]+)"' |
        Select-Object -First 1
    if (-not $match) { throw 'No package version found in Cargo.toml' }
    $version = $match.Matches[0].Groups[1].Value
    $name = "netattrib-v$version-windows-x64"

    Write-Host "Building netattrib $version (release)..."
    # Cargo reports progress on stderr; Windows PowerShell would turn that into errors under
    # 'Stop' when the output is redirected. Success is judged by the exit code instead.
    $ErrorActionPreference = 'Continue'
    cargo build --release
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0) { throw "cargo build --release failed (exit code $code)" }

    $exe = Join-Path $root 'target\release\netattrib.exe'
    $reported = ((& $exe --version) -join ' ').Trim()
    if ($reported -ne "netattrib $version") {
        throw "The built exe reports '$reported', expected 'netattrib $version'"
    }

    $files = @($exe) + (@('README.md', 'README_RU.md', 'LICENSE') |
        ForEach-Object { Join-Path $root $_ })
    foreach ($f in $files) {
        if (-not (Test-Path $f -PathType Leaf)) { throw "Missing $f" }
    }

    $dist = Join-Path $root 'dist'
    if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
    New-Item -ItemType Directory -Path $dist | Out-Null

    # The four files sit at the root of the archive.
    $zip = Join-Path $dist "$name.zip"
    Compress-Archive -Path $files -DestinationPath $zip -CompressionLevel Optimal

    # .NET directly rather than Get-FileHash: Windows PowerShell started from PowerShell 7
    # inherits its module path and may fail to load the module Get-FileHash lives in.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($zip)
    try {
        $hash = -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $stream.Dispose()
        $sha.Dispose()
    }
    $sumFile = "$zip.sha256"
    [System.IO.File]::WriteAllText($sumFile, "$hash  $name.zip`n", [System.Text.Encoding]::ASCII)

    Write-Host ''
    Write-Host "Package: $zip ($((Get-Item $zip).Length) bytes)"
    Write-Host "SHA-256: $hash"
    Write-Host "Written: $sumFile"
}
finally {
    Pop-Location
}
