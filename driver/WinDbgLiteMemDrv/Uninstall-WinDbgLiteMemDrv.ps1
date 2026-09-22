param(
    [string]$ServiceName = "WinDbgLiteMemDrv",
    [switch]$RemoveDriverFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required."
    }
}

function Invoke-Sc([string[]]$args) {
    & sc.exe @args
    return $LASTEXITCODE
}

Assert-Admin

$queryCode = Invoke-Sc @("query", $ServiceName)
if ($queryCode -eq 0) {
    [void](Invoke-Sc @("stop", $ServiceName))
    Start-Sleep -Milliseconds 400
    [void](Invoke-Sc @("delete", $ServiceName))
    Write-Host "Service removed: $ServiceName"
} else {
    Write-Host "Service not found: $ServiceName"
}

if ($RemoveDriverFile) {
    $driverPath = Join-Path $env:WINDIR "System32\drivers\$ServiceName.sys"
    if (Test-Path -LiteralPath $driverPath) {
        Remove-Item -LiteralPath $driverPath -Force
        Write-Host "Deleted file: $driverPath"
    } else {
        Write-Host "Driver file not found: $driverPath"
    }
}

