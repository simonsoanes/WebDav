<#
.SYNOPSIS
    Publishes Nullify.WebDav and installs it as a Windows service.

.DESCRIPTION
    Builds a self-contained single-file executable, copies it to -InstallDir and registers the
    "Nullify.WebDav" service running as the virtual account "NT SERVICE\Nullify.WebDav".
    Run from an elevated PowerShell prompt in the repository root. Re-running upgrades in place
    (the data directory is kept).

.EXAMPLE
    .\deploy\Install-NullifyWebDav.ps1 -CertificateSubject files.contoso.com
    Serves HTTPS on port 443 with the certificate for files.contoso.com from the LocalMachine\My store.

.EXAMPLE
    .\deploy\Install-NullifyWebDav.ps1 -Urls http://127.0.0.1:8080
    Plain HTTP on loopback, for use behind IIS/ARR or another reverse proxy.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\Nullify.WebDav",
    [string]$DataDir = "$env:ProgramData\Nullify.WebDav",
    [string]$FilesDir = "$env:ProgramData\Nullify.WebDav\files",
    [string]$Urls = "https://*:443",
    [string]$CertificateSubject = "",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$serviceName = "Nullify.WebDav"
$account = "NT SERVICE\$serviceName"
$repo = Split-Path -Parent $PSScriptRoot

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell prompt."
}
if ($Urls -like "https*" -and -not $CertificateSubject) {
    throw "HTTPS needs -CertificateSubject (a certificate in LocalMachine\My), or pass -Urls http://127.0.0.1:8080 to run behind a reverse proxy."
}

Write-Host "Publishing ($Runtime, self-contained single file)..."
$publish = Join-Path $repo "publish\$Runtime"
dotnet publish (Join-Path $repo "src\Nullify.WebDav\Nullify.WebDav.csproj") -c Release -r $Runtime --self-contained `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $publish
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne "Stopped") {
    Write-Host "Stopping the running service..."
    Stop-Service -Name $serviceName
}

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, $FilesDir | Out-Null
Copy-Item -Path (Join-Path $publish "*") -Destination $InstallDir -Recurse -Force

# Settings for this machine. appsettings.json from the build stays the defaults.
$settings = [ordered]@{
    Storage = [ordered]@{ DataDirectory = $DataDir; FilesDirectory = $FilesDir }
    Urls    = $Urls
}
if ($CertificateSubject) {
    $settings.Kestrel = @{ Certificates = @{ Default = @{ Subject = $CertificateSubject; Store = "My"; Location = "LocalMachine"; AllowInvalid = $false } } }
}
$settings | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $InstallDir "appsettings.Production.json")

if (-not $existing) {
    Write-Host "Registering the service..."
    New-Service -Name $serviceName -DisplayName "Nullify.WebDav" -Description "WebDAV file server" `
        -BinaryPathName "`"$InstallDir\Nullify.WebDav.exe`"" -StartupType Automatic | Out-Null
    sc.exe config $serviceName obj= $account | Out-Null
    sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
}

# The virtual account needs to write its data directory and the default storage.
foreach ($dir in $DataDir, $FilesDir) {
    icacls $dir /grant "${account}:(OI)(CI)M" /T /Q | Out-Null
}
if ($CertificateSubject) {
    # Allow the service account to use the certificate's private key.
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$CertificateSubject" -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) { throw "No certificate with subject CN=$CertificateSubject and a private key in LocalMachine\My." }
    $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $keyFile = Get-ChildItem "$env:ProgramData\Microsoft\Crypto" -Recurse -File -Filter $key.Key.UniqueName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($keyFile) { icacls $keyFile.FullName /grant "${account}:R" /Q | Out-Null }
    else { Write-Warning "Grant '$account' read access to the private key of $CertificateSubject (certlm.msc > Manage Private Keys)." }
}

Start-Service -Name $serviceName
Write-Host ""
Write-Host "Nullify.WebDav is running. Open $($Urls.Replace('*', 'localhost').Replace('+', 'localhost'))/ to create the administrator account."
Write-Host "Data directory: $DataDir   Default storage: $FilesDir"
