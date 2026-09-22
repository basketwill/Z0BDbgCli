param(
    [string]$DevicePath = "\\.\WinDbgLiteMem",
    [switch]$SkipMemory,
    [switch]$SkipThreadContext
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class WdblNative {
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessMemoryReadRequest {
        public UInt32 ProcessId;
        public UInt64 Address;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessMemoryWriteHeader {
        public UInt32 ProcessId;
        public UInt64 Address;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ThreadContextRequest {
        public UInt32 ThreadId;
        public UInt32 ContextFlags;
    }

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileW(
        string lpFileName,
        UInt32 dwDesiredAccess,
        UInt32 dwShareMode,
        IntPtr lpSecurityAttributes,
        UInt32 dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        UInt32 dwIoControlCode,
        byte[] lpInBuffer,
        UInt32 nInBufferSize,
        byte[] lpOutBuffer,
        UInt32 nOutBufferSize,
        out UInt32 lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern UInt32 GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    public static extern UInt32 GetCurrentThreadId();
}
"@

function Get-IoctlCode([int]$function) {
    $FILE_DEVICE_UNKNOWN = 0x22
    $METHOD_BUFFERED = 0
    $FILE_ANY_ACCESS = 0
    return (($FILE_DEVICE_UNKNOWN -shl 16) -bor ($FILE_ANY_ACCESS -shl 14) -bor ($function -shl 2) -bor $METHOD_BUFFERED)
}

$IOCTL_WDBL_READ_PROCESS_MEMORY = [uint32](Get-IoctlCode 0x801)
$IOCTL_WDBL_WRITE_PROCESS_MEMORY = [uint32](Get-IoctlCode 0x802)
$IOCTL_WDBL_PING = [uint32](Get-IoctlCode 0x803)
$IOCTL_WDBL_GET_THREAD_CONTEXT = [uint32](Get-IoctlCode 0x804)

function StructToBytes([Type]$type, $value) {
    $size = [Runtime.InteropServices.Marshal]::SizeOf($type)
    $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    try {
        [Runtime.InteropServices.Marshal]::StructureToPtr($value, $ptr, $false)
        $bytes = New-Object byte[] $size
        [Runtime.InteropServices.Marshal]::Copy($ptr, $bytes, 0, $size)
        return $bytes
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    }
}

function Invoke-DriverIoctl(
    [IntPtr]$Handle,
    [uint32]$Code,
    [byte[]]$InBytes,
    [int]$OutSize
) {
    $outBytes = New-Object byte[] $OutSize
    [uint32]$returned = 0
    $ok = [WdblNative]::DeviceIoControl(
        $Handle,
        $Code,
        $InBytes,
        [uint32]($InBytes.Length),
        $outBytes,
        [uint32]$OutSize,
        [ref]$returned,
        [IntPtr]::Zero)
    return [PSCustomObject]@{
        Ok = $ok
        LastError = if ($ok) { 0 } else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
        Returned = $returned
        Buffer = $outBytes
    }
}

function Assert-True($cond, [string]$message) {
    if (-not $cond) {
        throw $message
    }
}

$GENERIC_READ = 0x80000000
$GENERIC_WRITE = 0x40000000
$FILE_SHARE_READ = 0x1
$FILE_SHARE_WRITE = 0x2
$OPEN_EXISTING = 3

$h = [WdblNative]::CreateFileW(
    $DevicePath,
    [uint32]($GENERIC_READ -bor $GENERIC_WRITE),
    [uint32]($FILE_SHARE_READ -bor $FILE_SHARE_WRITE),
    [IntPtr]::Zero,
    [uint32]$OPEN_EXISTING,
    0,
    [IntPtr]::Zero)
if ($h -eq [WdblNative]::INVALID_HANDLE_VALUE) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "Open device failed: $DevicePath (Win32Error=$err)"
}

try {
    Write-Host "[Ping] testing driver ping..."
    $pingResult = Invoke-DriverIoctl -Handle $h -Code $IOCTL_WDBL_PING -InBytes ([byte[]]@()) -OutSize 4
    Assert-True $pingResult.Ok "Ping ioctl failed. Win32Error=$($pingResult.LastError)"
    Assert-True ($pingResult.Returned -ge 4) "Ping returned too few bytes: $($pingResult.Returned)"
    $pingValue = [BitConverter]::ToUInt32($pingResult.Buffer, 0)
    Assert-True ($pingValue -eq 1) "Unexpected ping value: $pingValue"
    Write-Host "[Ping] ok"

    if (-not $SkipMemory) {
        Write-Host "[Memory] testing process memory read/write..."

        $pid = [WdblNative]::GetCurrentProcessId()
        $mem = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
        try {
            [Runtime.InteropServices.Marshal]::WriteInt64($mem, [Int64]0x1122334455667788)

            $readReq = New-Object WdblNative+ProcessMemoryReadRequest
            $readReq.ProcessId = $pid
            $readReq.Address = [uint64]$mem.ToInt64()
            $readReq.Size = 8
            $readReqBytes = StructToBytes -type ([WdblNative+ProcessMemoryReadRequest]) -value $readReq

            $readResult = Invoke-DriverIoctl -Handle $h -Code $IOCTL_WDBL_READ_PROCESS_MEMORY -InBytes $readReqBytes -OutSize 8
            Assert-True $readResult.Ok "ReadProcessMemory ioctl failed. Win32Error=$($readResult.LastError)"
            Assert-True ($readResult.Returned -eq 8) "ReadProcessMemory returned $($readResult.Returned) bytes"
            $readValue = [BitConverter]::ToInt64($readResult.Buffer, 0)
            Assert-True ($readValue -eq [Int64]0x1122334455667788) ("Read value mismatch: 0x{0:X16}" -f $readValue)

            $newBytes = [BitConverter]::GetBytes([Int64]0x8877665544332211)
            $writeHeader = New-Object WdblNative+ProcessMemoryWriteHeader
            $writeHeader.ProcessId = $pid
            $writeHeader.Address = [uint64]$mem.ToInt64()
            $writeHeader.Size = 8
            $writeHeaderBytes = StructToBytes -type ([WdblNative+ProcessMemoryWriteHeader]) -value $writeHeader
            $writeIn = New-Object byte[] ($writeHeaderBytes.Length + $newBytes.Length)
            [Array]::Copy($writeHeaderBytes, 0, $writeIn, 0, $writeHeaderBytes.Length)
            [Array]::Copy($newBytes, 0, $writeIn, $writeHeaderBytes.Length, $newBytes.Length)

            $writeResult = Invoke-DriverIoctl -Handle $h -Code $IOCTL_WDBL_WRITE_PROCESS_MEMORY -InBytes $writeIn -OutSize 4
            Assert-True $writeResult.Ok "WriteProcessMemory ioctl failed. Win32Error=$($writeResult.LastError)"
            $written = [BitConverter]::ToUInt32($writeResult.Buffer, 0)
            Assert-True ($written -eq 8) "WriteProcessMemory reported $written bytes"
            $afterWrite = [Runtime.InteropServices.Marshal]::ReadInt64($mem)
            Assert-True ($afterWrite -eq [Int64]0x8877665544332211) ("Write verify mismatch: 0x{0:X16}" -f $afterWrite)
        } finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($mem)
        }

        Write-Host "[Memory] ok"
    } else {
        Write-Host "[Memory] skipped"
    }

    if (-not $SkipThreadContext) {
        Write-Host "[ThreadContext] testing GetThreadContext ioctl..."
        $ctxReq = New-Object WdblNative+ThreadContextRequest
        $ctxReq.ThreadId = [WdblNative]::GetCurrentThreadId()
        $ctxReq.ContextFlags = 0x00100001
        $ctxReqBytes = StructToBytes -type ([WdblNative+ThreadContextRequest]) -value $ctxReq
        $ctxResult = Invoke-DriverIoctl -Handle $h -Code $IOCTL_WDBL_GET_THREAD_CONTEXT -InBytes $ctxReqBytes -OutSize 4096
        if ($ctxResult.Ok) {
            Write-Host "[ThreadContext] ok (returned $($ctxResult.Returned) bytes)"
        } else {
            Write-Host "[ThreadContext] ioctl failed (Win32Error=$($ctxResult.LastError))"
        }
    } else {
        Write-Host "[ThreadContext] skipped"
    }

    Write-Host "Driver self-test finished."
} finally {
    [void][WdblNative]::CloseHandle($h)
}

