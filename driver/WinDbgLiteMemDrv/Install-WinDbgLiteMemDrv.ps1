param(
    [string]$DriverSysPath = "$(Join-Path $PSScriptRoot 'bin\x64\Release\WinDbgLiteMemDrv.sys')",
    [string]$ServiceName = "WinDbgLiteMemDrv",
    [switch]$StartNow
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
    $code = $LASTEXITCODE
    return $code
}

Assert-Admin

$resolvedSys = Resolve-Path -LiteralPath $DriverSysPath -ErrorAction Stop
$driverStorePath = Join-Path $env:WINDIR "System32\drivers\$ServiceName.sys"

Write-Host "Copying driver to $driverStorePath"
Copy-Item -LiteralPath $resolvedSys -Destination $driverStorePath -Force

$queryCode = Invoke-Sc @("query", $ServiceName)
if ($queryCode -eq 0) {
    Write-Host "Service $ServiceName exists, removing old instance..."
    [void](Invoke-Sc @("stop", $ServiceName))
    [void](Invoke-Sc @("delete", $ServiceName))
    Start-Sleep -Milliseconds 600
}

$createArgs = @(
    "create", $ServiceName,
    "type=", "kernel",
    "start=", "demand",
    "error=", "normal",
    "binPath=", $driverStorePath,
    "DisplayName=", "WinDbgLite Memory Driver"
)
$createCode = Invoke-Sc $createArgs
if ($createCode -ne 0) {
    throw "sc create failed with code $createCode"
}

if ($StartNow) {
    $startCode = Invoke-Sc @("start", $ServiceName)
    if ($startCode -ne 0) {
        throw "sc start failed with code $startCode"
    }
}

Write-Host "Driver service installed: $ServiceName"
Write-Host "Use 'sc start $ServiceName' to start it if needed."

