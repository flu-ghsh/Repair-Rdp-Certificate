#requires -RunAsAdministrator
<#
Repairs the RDP TLS certificate on the local Windows computer.

What it does:
1. Detects the local computer name and AD/workgroup domain.
2. Creates a new RSA/SHA-256 self-signed certificate.
3. Grants NETWORK SERVICE read access to the certificate private key.
4. Binds the certificate to the RDP-Tcp listener.
5. Restarts Remote Desktop Services.
6. Verifies that the new certificate thumbprint is active.

Run from an elevated PowerShell window:
  powershell.exe -ExecutionPolicy Bypass -File .\Repair-RdpCertificate.ps1
#>

[CmdletBinding()]
param(
    [int]$ValidYears = 2
)

$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Text)
    Write-Host "[OK] $Text" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Text)
    Write-Host "[ERROR] $Text" -ForegroundColor Red
}

try {
    # Confirm elevation even if #requires is bypassed by unusual launch methods.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from PowerShell as Administrator.'
    }

    $computerName = $env:COMPUTERNAME
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $domain = $computerSystem.Domain

    if ($computerSystem.PartOfDomain -and $domain -and $domain -ne 'WORKGROUP') {
        $fqdn = "$computerName.$domain"
    }
    else {
        try {
            $dnsName = [System.Net.Dns]::GetHostEntry($computerName).HostName
            $fqdn = if ($dnsName) { $dnsName } else { $computerName }
        }
        catch {
            $fqdn = $computerName
        }
    }

    Write-Step "Computer name: $computerName"
    Write-Step "DNS name:      $fqdn"

    $rdp = Get-WmiObject `
        -Namespace 'root\cimv2\terminalservices' `
        -Class Win32_TSGeneralSetting `
        -Filter "TerminalName='RDP-tcp'"

    if (-not $rdp) {
        throw 'RDP-Tcp listener was not found.'
    }

    $oldHash = [string]$rdp.SSLCertificateSHA1Hash
    Write-Step "Current RDP certificate: $oldHash"

    # The provider below worked on systems where Microsoft RSA SChannel
    # returned 0x80090008 (NTE_BAD_ALGID / invalid algorithm).
    $provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'

    Write-Step "Creating a new RSA certificate..."
    $cert = New-SelfSignedCertificate `
        -Subject "CN=$fqdn" `
        -DnsName @($fqdn, $computerName) `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -Provider $provider `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -KeySpec KeyExchange `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddYears($ValidYears)

    if (-not $cert -or -not $cert.HasPrivateKey) {
        throw 'The new certificate was not created with a private key.'
    }

    Write-Ok "Certificate created: $($cert.Thumbprint)"

    $keyName = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
    $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyName

    if (-not (Test-Path -LiteralPath $keyPath)) {
        throw "Private key file was not found: $keyPath"
    }

    Write-Step 'Granting NETWORK SERVICE read access to the private key...'
    & icacls.exe $keyPath /grant '*S-1-5-20:R' | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code $LASTEXITCODE."
    }

    Write-Step 'Binding the certificate to the RDP-Tcp listener...'
    $rdp.SSLCertificateSHA1Hash = $cert.Thumbprint
    $null = $rdp.Put()

    # Re-read the setting instead of trusting the Put() return type.
    $boundHash = [string](
        Get-WmiObject `
            -Namespace 'root\cimv2\terminalservices' `
            -Class Win32_TSGeneralSetting `
            -Filter "TerminalName='RDP-tcp'"
    ).SSLCertificateSHA1Hash

    if ($boundHash -ne $cert.Thumbprint) {
        throw "RDP binding verification failed. Expected $($cert.Thumbprint), got $boundHash."
    }

    Write-Ok 'Certificate binding verified.'

    Write-Step 'Restarting Remote Desktop Services...'
    Restart-Service -Name TermService -Force
    Start-Sleep -Seconds 5

    $finalHash = [string](
        Get-WmiObject `
            -Namespace 'root\cimv2\terminalservices' `
            -Class Win32_TSGeneralSetting `
            -Filter "TerminalName='RDP-tcp'"
    ).SSLCertificateSHA1Hash

    if ($finalHash -ne $cert.Thumbprint) {
        throw "The RDP certificate changed after service restart. Current hash: $finalHash"
    }

    Write-Host ''
    Write-Ok 'RDP certificate repair completed successfully.'
    Write-Host "Subject:       $($cert.Subject)"
    Write-Host "Thumbprint:    $($cert.Thumbprint)"
    Write-Host "Valid until:   $($cert.NotAfter)"
    Write-Host "Previous hash: $oldHash"
    Write-Host "Current hash:  $finalHash"
}
catch {
    Write-Host ''
    Write-Fail $_.Exception.Message
    exit 1
}
