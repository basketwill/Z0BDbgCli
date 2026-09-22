#include "Debugger.h"

#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>

#define WDBL_ENABLE_DYNAMIC_WINAPI_MACROS
#include "WinApiDynamic.h"
#include <Zydis/Zydis.h>
#include "FloatSaveCompat.h"
#include "PseudoC.h"
#include "VehProtocol.h"

#include <algorithm>
#include <array>
#include <conio.h>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <sstream>
#include <vector>
#include <string>
namespace {

const DWORD STATUS_GUARD_PAGE_VIOLATION_VALUE = 0x80000001;
const DWORD WDBL_DBG_PRINTEXCEPTION_C = 0x40010006;
const DWORD WDBL_DBG_PRINTEXCEPTION_WIDE_C = 0x4001000A;
const NTSTATUS STATUS_INFO_LENGTH_MISMATCH_VALUE = static_cast<NTSTATUS>(0xC0000004);
const ULONG SystemExtendedHandleInformationClass = 64;
const DWORD kSymTagData = 7;
const DWORD kSymTagUDT = 11;
const DWORD kSymTagPointerType = 14;
const DWORD kSymTagArrayType = 15;
const DWORD kSymTagBaseType = 16;
const DWORD kBasicTypeChar = 2;
const DWORD kBasicTypeWChar = 3;
const DWORD kBasicTypeBool = 10;

typedef  NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
typedef  NTSTATUS(NTAPI* NtQueryInformationThread_t)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
typedef  NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct OBJECT_TYPE_INFORMATION_LOCAL {
    UNICODE_STRING TypeName;
};

struct CLIENT_ID_LOCAL {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX_LOCAL {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL Handles[1];
};

bool ReadProcessAnsiCString(HANDLE processHandle, uint64_t address, std::string& outText, size_t maxChars);

std::wstring QueryDuplicatedHandleTypeName(DWORD processId, uint64_t handleValue) {
    if (processId == 0 || handleValue > static_cast<uint64_t>((std::numeric_limits<ULONG_PTR>::max)())) {
        return L"";
    }

    HANDLE sourceProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (sourceProcess == nullptr) {
        sourceProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processId);
    }
    if (sourceProcess == nullptr) {
        return L"";
    }

    HANDLE duplicated = nullptr;
    const BOOL duplicatedOk = DuplicateHandle(
        sourceProcess,
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handleValue)),
        GetCurrentProcess(),
        &duplicated,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS);
    CloseHandle(sourceProcess);
    if (!duplicatedOk || duplicated == nullptr) {
        return L"";
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtQueryObject_t queryObject = ntdll == nullptr
        ? nullptr
        : reinterpret_cast<NtQueryObject_t>(GetProcAddress(ntdll, "NtQueryObject"));
    if (queryObject == nullptr) {
        CloseHandle(duplicated);
        return L"";
    }

    std::vector<uint8_t> buffer(4096, 0);
    ULONG returnedLength = 0;
    NTSTATUS status = queryObject(
        duplicated,
        2,
        buffer.data(),
        static_cast<ULONG>(buffer.size()),
        &returnedLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH_VALUE ||
        status == static_cast<NTSTATUS>(0xC0000023)) {
        const size_t requested = std::max<size_t>(buffer.size() * 2, returnedLength);
        buffer.assign(std::min<size_t>(requested, 64 * 1024), 0);
        status = queryObject(
            duplicated,
            2,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &returnedLength);
    }

    std::wstring result;
    if (NT_SUCCESS(status) && buffer.size() >= sizeof(OBJECT_TYPE_INFORMATION_LOCAL)) {
        const OBJECT_TYPE_INFORMATION_LOCAL* info =
            reinterpret_cast<const OBJECT_TYPE_INFORMATION_LOCAL*>(buffer.data());
        if (info->TypeName.Buffer != nullptr &&
            info->TypeName.Length != 0 &&
            info->TypeName.Length <= info->TypeName.MaximumLength &&
            info->TypeName.Length <= 512) {
            result.assign(info->TypeName.Buffer, info->TypeName.Length / sizeof(wchar_t));
        }
    }
    CloseHandle(duplicated);
    return result;
}

struct THREAD_BASIC_INFORMATION_LOCAL {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID_LOCAL ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
};

struct PROCESS_BASIC_INFORMATION_LOCAL {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
};

struct UNICODE_STRING32_LOCAL {
    USHORT Length;
    USHORT MaximumLength;
    uint32_t Buffer;
};

struct UNICODE_STRING64_LOCAL {
    USHORT Length;
    USHORT MaximumLength;
    uint32_t Padding;
    uint64_t Buffer;
};

struct DecodedInstruction {
    size_t length;
    std::wstring text;

	DecodedInstruction()
	{
		length = 1;
		text = L"db";
	}
};

std::wstring NowTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buffer[64] = {0};
    swprintf_s(
        buffer,
        sizeof(buffer) / sizeof(buffer[0]),
        L"%04u-%02u-%02u %02u:%02u:%02u",
        static_cast<unsigned>(st.wYear),
        static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay),
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond));
    return std::wstring(buffer);
}

std::wstring ToHex(uint64_t value, size_t width = 0) {
    std::wstringstream ss;
    ss << L"0x" << std::uppercase << std::hex << std::setfill(L'0');
    if (width != 0) {
        ss << std::setw(static_cast<int>(width));
    }
    ss << value;
    return ss.str();
}

template <typename T>
std::wstring ToWStringCompat(T value) {
    std::wstringstream ss;
    ss << value;
    return ss.str();
}

std::wstring ToHex128(const M128A& value) {
    std::wstringstream ss;
    ss << L"0x"
       << std::uppercase
       << std::hex
       << std::setfill(L'0')
       << std::setw(16) << static_cast<uint64_t>(value.High)
       << std::setw(16) << value.Low;
    return ss.str();
}

std::wstring ToHex128FromBytes(const uint8_t* bytes16) {
    if (bytes16 == nullptr) {
        return L"0x00000000000000000000000000000000";
    }
    uint64_t low = 0;
    uint64_t high = 0;
    memcpy(&low, bytes16, sizeof(low));
    memcpy(&high, bytes16 + sizeof(low), sizeof(high));

    M128A value = M128A();
    value.Low = low;
    value.High = static_cast<LONGLONG>(high);
    return ToHex128(value);
}

void PrintXmmRegistersFromFxsaveArea(const uint8_t* fxsave, size_t fxsaveSize, int xmmCount) {
    if (fxsave == nullptr || fxsaveSize < 160 + 16 || xmmCount <= 0) {
        return;
    }

    const size_t xmmBaseOffset = 160;  // FXSAVE XMM0 starts at 0xA0.
    const int maxCountBySize = static_cast<int>((fxsaveSize - xmmBaseOffset) / 16);
    const int count = std::max(0, std::min(xmmCount, maxCountBySize));
    for (int i = 0; i < count; ++i) {
        const uint8_t* regBytes = fxsave + xmmBaseOffset + static_cast<size_t>(i) * 16;
        std::wcout << L"XMM" << i << L"=" << ToHex128FromBytes(regBytes) << L"\n";
    }
}

bool IsWow64TargetProcess(HANDLE processHandle) {
#if defined(_M_X64)
    if (processHandle == nullptr) {
        return false;
    }

    typedef BOOL(WINAPI* IsWow64Process2Fn)(HANDLE, USHORT*, USHORT*);
    HMODULE kernel32Module = GetModuleHandleW(L"kernel32.dll");
    if (kernel32Module != NULL) {
        IsWow64Process2Fn isWow64Process2Fn =
            reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(kernel32Module, "IsWow64Process2"));
        if (isWow64Process2Fn != NULL) {
            USHORT processMachine = 0;
            USHORT nativeMachine = 0;
            if (isWow64Process2Fn(processHandle, &processMachine, &nativeMachine)) {
                return processMachine == IMAGE_FILE_MACHINE_I386;
            }
        }
    }

    BOOL wow64 = FALSE;
    return IsWow64Process(processHandle, &wow64) && wow64 == TRUE;
#else
    UNREFERENCED_PARAMETER(processHandle);
    return false;
#endif
}

bool CaptureWow64ThreadContextById(DWORD threadId, WOW64_CONTEXT& ctx) {
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = WOW64_CONTEXT_ALL;
    if (wdbl::winapi::DriverGetWow64ThreadContext(threadId, &ctx)) {
        return true;
    }

    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!thread) {
        return false;
    }
    const BOOL ok = Wow64GetThreadContext(thread, &ctx);
    CloseHandle(thread);
    return ok == TRUE;
}

bool ApplyWow64ThreadContextById(DWORD threadId, const WOW64_CONTEXT& ctx) {
    if (wdbl::winapi::DriverSetWow64ThreadContext(threadId, &ctx)) {
        return true;
    }

    HANDLE thread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!thread) {
        return false;
    }

    typedef BOOL(WINAPI* Wow64SetThreadContextFn)(HANDLE, const WOW64_CONTEXT*);
    BOOL ok = FALSE;
    HMODULE kernel32Module = GetModuleHandleW(L"kernel32.dll");
    if (kernel32Module != NULL) {
        Wow64SetThreadContextFn wow64SetThreadContextFn =
            reinterpret_cast<Wow64SetThreadContextFn>(GetProcAddress(kernel32Module, "Wow64SetThreadContext"));
        if (wow64SetThreadContextFn != NULL) {
            ok = wow64SetThreadContextFn(thread, &ctx);
        }
    }

    CloseHandle(thread);
    return ok == TRUE;
}

void PrintWow64RegisterInfo(const WOW64_CONTEXT& ctx) {
    std::wcout << L"ContextFlags=" << ToHex(ctx.ContextFlags, 8)
               << L"  EFLAGS=" << ToHex(ctx.EFlags, 8) << L"\n";
    std::wcout << L"CS=" << ToHex(ctx.SegCs, 4)
               << L"  DS=" << ToHex(ctx.SegDs, 4)
               << L"  ES=" << ToHex(ctx.SegEs, 4)
               << L"  FS=" << ToHex(ctx.SegFs, 4)
               << L"  GS=" << ToHex(ctx.SegGs, 4)
               << L"  SS=" << ToHex(ctx.SegSs, 4) << L"\n";
    std::wcout << L"DR0=" << ToHex(ctx.Dr0, 8) << L"  DR1=" << ToHex(ctx.Dr1, 8)
               << L"  DR2=" << ToHex(ctx.Dr2, 8) << L"  DR3=" << ToHex(ctx.Dr3, 8) << L"\n";
    std::wcout << L"DR6=" << ToHex(ctx.Dr6, 8) << L"  DR7=" << ToHex(ctx.Dr7, 8) << L"\n";
    std::wcout << L"EAX=" << ToHex(ctx.Eax, 8) << L"  EBX=" << ToHex(ctx.Ebx, 8)
               << L"  ECX=" << ToHex(ctx.Ecx, 8) << L"  EDX=" << ToHex(ctx.Edx, 8) << L"\n";
    std::wcout << L"ESI=" << ToHex(ctx.Esi, 8) << L"  EDI=" << ToHex(ctx.Edi, 8)
               << L"  EBP=" << ToHex(ctx.Ebp, 8) << L"  ESP=" << ToHex(ctx.Esp, 8) << L"\n";
    std::wcout << L"EIP=" << ToHex(ctx.Eip, 8) << L"\n";
    std::wcout << L"FloatControl=" << ToHex(ctx.FloatSave.ControlWord, 4)
               << L"  FloatStatus=" << ToHex(ctx.FloatSave.StatusWord, 4)
               << L"  FloatTag=" << ToHex(ctx.FloatSave.TagWord, 4) << L"\n";
    std::wcout << L"ErrorOffset=" << ToHex(ctx.FloatSave.ErrorOffset, 8)
               << L"  ErrorSelector=" << ToHex(ctx.FloatSave.ErrorSelector, 4) << L"\n";
    std::wcout << L"DataOffset=" << ToHex(ctx.FloatSave.DataOffset, 8)
               << L"  DataSelector=" << ToHex(ctx.FloatSave.DataSelector, 4);
    WDBL_PRINT_CR0NPXSTATE_COMPAT(std::wcout, ctx.FloatSave);
    for (int i = 0; i < 8; ++i) {
        const uint8_t* stBytes = &ctx.FloatSave.RegisterArea[i * 10];
        std::wcout << L"ST" << i << L"=0x";
        std::wcout << std::hex << std::setfill(L'0');
        for (int b = 9; b >= 0; --b) {
            std::wcout << std::setw(2) << static_cast<unsigned int>(stBytes[b]);
        }
        std::wcout << std::dec << L"\n";
    }
    PrintXmmRegistersFromFxsaveArea(
        reinterpret_cast<const uint8_t*>(ctx.ExtendedRegisters),
        sizeof(ctx.ExtendedRegisters),
        8);
}

std::wstring TrimWhitespace(const std::wstring& value) {
    size_t begin = 0;
    while (begin < value.size() && std::iswspace(value[begin])) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin && std::iswspace(value[end - 1])) {
        --end;
    }
    return value.substr(begin, end - begin);
}

std::wstring ToLowerLocal(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return value;
}

std::wstring ToUpperLocal(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towupper(c));
    });
    return value;
}

std::vector<std::wstring> SplitInstructionOperands(const std::wstring& rest) {
    std::vector<std::wstring> ops;
    std::wstring cur;
    int depth = 0;
    for (size_t i = 0; i < rest.size(); ++i) {
        const wchar_t ch = rest[i];
        if (ch == L'[' || ch == L'(') {
            ++depth;
            cur.push_back(ch);
        } else if (ch == L']' || ch == L')') {
            if (depth > 0) {
                --depth;
            }
            cur.push_back(ch);
        } else if (ch == L',' && depth == 0) {
            ops.push_back(TrimWhitespace(cur));
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }

    const std::wstring last = TrimWhitespace(cur);
    if (!last.empty()) {
        ops.push_back(last);
    }
    return ops;
}

size_t RegisterBitWidth(const std::wstring& operand) {
    std::wstring op = ToLowerLocal(TrimWhitespace(operand));
    const size_t bracket = op.find(L'[');
    if (bracket != std::wstring::npos) {
        op = TrimWhitespace(op.substr(0, bracket));
    }
    const size_t space = op.find_last_of(L" \t");
    if (space != std::wstring::npos) {
        op = op.substr(space + 1);
    }

    if (op.empty()) {
        return 0;
    }
    if (op.size() >= 3 && op[0] == L'x' && op[1] == L'm' && op[2] == L'm') {
        return 128;
    }
    if (op.size() >= 3 && op[0] == L'y' && op[1] == L'm' && op[2] == L'm') {
        return 256;
    }
    if (op.size() >= 3 && op[0] == L'z' && op[1] == L'm' && op[2] == L'm') {
        return 512;
    }
    if ((op.size() == 2 && op[0] == L'r') ||
        (op.size() >= 2 && op[0] == L'r' && op[1] >= L'8' && op[1] <= L'9') ||
        (op.size() >= 3 && op[0] == L'r' && op[1] >= L'1' && op[1] <= L'9') ||
        op == L"rax" || op == L"rbx" || op == L"rcx" || op == L"rdx" ||
        op == L"rsi" || op == L"rdi" || op == L"rbp" || op == L"rsp") {
        if (op.size() >= 1 && op[op.size() - 1] == L'd') {
            return 32;
        }
        if (op.size() >= 1 && op[op.size() - 1] == L'w') {
            return 16;
        }
        if (op.size() >= 1 && op[op.size() - 1] == L'b') {
            return 8;
        }
        return 64;
    }
    if (op == L"eax" || op == L"ebx" || op == L"ecx" || op == L"edx" ||
        op == L"esi" || op == L"edi" || op == L"ebp" || op == L"esp" ||
        op == L"eip") {
        return 32;
    }
    if (op == L"ax" || op == L"bx" || op == L"cx" || op == L"dx" ||
        op == L"si" || op == L"di" || op == L"bp" || op == L"sp" ||
        op == L"ip") {
        return 16;
    }
    if (op == L"al" || op == L"ah" || op == L"bl" || op == L"bh" ||
        op == L"cl" || op == L"ch" || op == L"dl" || op == L"dh" ||
        op == L"sil" || op == L"dil" || op == L"bpl" || op == L"spl") {
        return 8;
    }
    return 0;
}

const wchar_t* PointerSizePrefix(size_t bits) {
    switch (bits) {
        case 8: return L"byte ptr";
        case 16: return L"word ptr";
        case 32: return L"dword ptr";
        case 64: return L"qword ptr";
        case 128: return L"xmmword ptr";
        case 256: return L"ymmword ptr";
        case 512: return L"zmmword ptr";
        default: return L"";
    }
}

size_t ExistingMemorySizeKeywordBits(const std::wstring& operand, size_t& keywordLength) {
    const std::wstring op = ToLowerLocal(TrimWhitespace(operand));
    struct Keyword {
        const wchar_t* text;
        size_t bits;
    };
    static const Keyword kKeywords[] = {
        { L"byte", 8 },
        { L"word", 16 },
        { L"dword", 32 },
        { L"qword", 64 },
        { L"xmmword", 128 },
        { L"ymmword", 256 },
        { L"zmmword", 512 }
    };

    for (size_t i = 0; i < sizeof(kKeywords) / sizeof(kKeywords[0]); ++i) {
        const std::wstring key(kKeywords[i].text);
        if (op.rfind(key, 0) == 0 && op.size() > key.size() && std::iswspace(op[key.size()])) {
            keywordLength = key.size();
            return kKeywords[i].bits;
        }
    }
    keywordLength = 0;
    return 0;
}

std::wstring NormalizeExplicitMemoryOperands(const std::wstring& text) {
    const size_t sp = text.find_first_of(L" \t");
    if (sp == std::wstring::npos) {
        return text;
    }

    const std::wstring mnemonic = text.substr(0, sp);
    const std::wstring rest = TrimWhitespace(text.substr(sp));
    std::vector<std::wstring> ops = SplitInstructionOperands(rest);
    if (ops.empty()) {
        return text;
    }

    bool changed = false;
    for (size_t i = 0; i < ops.size(); ++i) {
        const std::wstring lowerOp = ToLowerLocal(ops[i]);
        if (ops[i].find(L'[') == std::wstring::npos || lowerOp.find(L"ptr") != std::wstring::npos) {
            continue;
        }

        size_t keywordLength = 0;
        size_t bits = ExistingMemorySizeKeywordBits(ops[i], keywordLength);
        if (bits != 0) {
            std::wstring rest = TrimWhitespace(TrimWhitespace(ops[i]).substr(keywordLength));
            ops[i] = std::wstring(PointerSizePrefix(bits)) + rest;
            changed = true;
            continue;
        }

        for (size_t j = 0; j < ops.size(); ++j) {
            if (j == i) {
                continue;
            }
            bits = RegisterBitWidth(ops[j]);
            if (bits != 0) {
                break;
            }
        }
        if (bits == 0) {
            bits = 64;
        }

        const wchar_t* prefix = PointerSizePrefix(bits);
        if (prefix[0] == L'\0') {
            continue;
        }
        ops[i] = std::wstring(prefix) + ops[i];
        changed = true;
    }
    if (!changed) {
        return text;
    }

    std::wstring normalized = mnemonic + L" ";
    for (size_t i = 0; i < ops.size(); ++i) {
        if (i != 0) {
            normalized += L", ";
        }
        normalized += ops[i];
    }
    return normalized;
}

std::wstring RemoveHexPrefixFromDisassemblyText(const std::wstring& text) {
    std::wstring out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (i + 2 < text.size() && text[i] == L'0' && (text[i + 1] == L'x' || text[i + 1] == L'X')) {
            const wchar_t next = text[i + 2];
            if (std::iswxdigit(next)) {
                ++i;
                continue;
            }
        }
        out.push_back(text[i]);
    }
    return out;
}

bool ParseUnsignedInteger(const std::wstring& text, uint64_t& value) {
    try {
        size_t idx = 0;
        const int base = (text.rfind(L"0x", 0) == 0 || text.rfind(L"0X", 0) == 0) ? 16 : 10;
        value = std::stoull(text, &idx, base);
        return idx == text.size();
    } catch (...) {
        return false;
    }
}

std::wstring RemoveWhitespace(std::wstring text) {
    text.erase(
        std::remove_if(
            text.begin(),
            text.end(),
            [](wchar_t ch) { return std::iswspace(ch) != 0; }),
        text.end());
    return text;
}

std::vector<std::wstring> SplitByAnd(const std::wstring& expression) {
    std::vector<std::wstring> clauses;
    size_t start = 0;
    while (start < expression.size()) {
        const size_t andPos = expression.find(L"&&", start);
        if (andPos == std::wstring::npos) {
            clauses.push_back(expression.substr(start));
            break;
        }
        clauses.push_back(expression.substr(start, andPos - start));
        start = andPos + 2;
    }
    if (clauses.empty()) {
        clauses.push_back(expression);
    }
    return clauses;
}

std::wstring BytesToHexList(const std::vector<uint8_t>& bytes) {
    std::wstringstream ss;
    ss << std::uppercase << std::hex << std::setfill(L'0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) {
            ss << L' ';
        }
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}

std::wstring BytesToHexPreview(const std::vector<uint8_t>& bytes, size_t maxBytes = 24) {
    if (bytes.empty()) {
        return L"(empty)";
    }
    const size_t count = std::min(bytes.size(), maxBytes);
    std::vector<uint8_t> view(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(count));
    std::wstring out = BytesToHexList(view);
    if (bytes.size() > count) {
        out += L" ... (+" + ToWStringCompat(bytes.size() - count) + L" byte(s))";
    }
    return out;
}

template <size_t N>
void CopyWideText(wchar_t (&dest)[N], const std::wstring& text) {
    if (N == 0) {
        return;
    }
    wcsncpy_s(dest, N, text.c_str(), _TRUNCATE);
}

bool ParseHexByteSequenceText(
    const std::wstring& sequence,
    std::vector<uint8_t>& bytes,
    std::wstring& error) {
    bytes.clear();
    error.clear();
    std::wstring token;

    auto flushToken = [&]() -> bool {
        if (token.empty()) {
            return true;
        }
        std::wstring work = token;
        if (work.rfind(L"0x", 0) == 0 || work.rfind(L"0X", 0) == 0) {
            work = work.substr(2);
        }
        if (work.empty()) {
            error = L"Invalid byte token: " + token;
            return false;
        }
        uint64_t value = 0;
        if (!ParseUnsignedInteger(L"0x" + work, value) || value > 0xFF) {
            error = L"Byte value out of range: " + token;
            return false;
        }
        bytes.push_back(static_cast<uint8_t>(value));
        token.clear();
        return true;
    };


	if(sequence.length() > 0 )
	{
		for (int i = 0 ;i < sequence.length();i++) {
			wchar_t ch = sequence[i];
			if (std::iswspace(ch) || ch == L',' || ch == L';' || ch == L'|') {
				if (!flushToken()) {
					return false;
				}
				continue;
			}
			token.push_back(ch);
		}
	}
    if (!flushToken()) {
        return false;
    }
    if (bytes.empty()) {
        error = L"No byte values were provided.";
        return false;
    }
    return true;
}

bool ReadBinaryFileSlice(
    const std::wstring& path,
    uint64_t offset,
    const std::optional<uint64_t>& sizeHint,
    std::vector<uint8_t>& bytes,
    std::wstring& error) {
    bytes.clear();
    error.clear();

    std::ifstream file;
    file.open(path.c_str(), std::ios::binary | std::ios::ate);
    if (!file) {
        error = L"Unable to open file: " + path;
        return false;
    }

    const std::streamoff streamSize = file.tellg();
    if (streamSize < 0) {
        error = L"Unable to determine file size: " + path;
        return false;
    }
    const uint64_t fileSize = static_cast<uint64_t>(streamSize);
    if (offset > fileSize) {
        error = L"Offset exceeds file size.";
        return false;
    }

    const uint64_t available = fileSize - offset;
    uint64_t readSize = available;
    if (sizeHint.has_value()) {
        readSize = *sizeHint;
        if (readSize == 0) {
            readSize = available;
        }
    }
    if (readSize == 0) {
        error = L"Selected file slice is empty.";
        return false;
    }
    if (readSize > available) {
        error = L"Requested size exceeds file bounds.";
        return false;
    }

    const uint64_t kMaxPatchFileBytes = 1ull << 20; // 1 MiB guardrail for interactive patching.
    if (readSize > kMaxPatchFileBytes) {
        error = L"Requested patch slice too large (max 1 MiB).";
        return false;
    }
    if (readSize > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        error = L"Requested patch slice is too large for this platform.";
        return false;
    }

    bytes.resize(static_cast<size_t>(readSize));
    file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(readSize))) {
        error = L"Failed to read requested bytes from file.";
        bytes.clear();
        return false;
    }
    return true;
}

std::wstring QueryDefaultSymbolCacheDirectory() {
    wchar_t localAppData[MAX_PATH] = {0};
    const DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::wstring(localAppData) + L"\\WinDbgLite\\symbols";
    }

    wchar_t currentDir[MAX_PATH] = {0};
    const DWORD cwdLen = GetCurrentDirectoryW(MAX_PATH, currentDir);
    if (cwdLen > 0 && cwdLen < MAX_PATH) {
        return std::wstring(currentDir) + L"\\symbols";
    }
    return L"symbols";
}

std::wstring TryGetPathFromHandle(HANDLE fileHandle) {
    if (fileHandle == nullptr || fileHandle == INVALID_HANDLE_VALUE) {
        return L"";
    }

    wchar_t buffer[2048] = {0};
    const DWORD copied = GetFinalPathNameByHandleW(
        fileHandle,
        buffer,
        static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])),
        FILE_NAME_NORMALIZED);
    if (copied == 0 || copied >= (sizeof(buffer) / sizeof(buffer[0]))) {
        return L"";
    }

    std::wstring path(buffer);
    const wchar_t extendedPrefix[] = L"\\\\?\\";
    const wchar_t uncPrefix[] = L"\\\\?\\UNC\\";
    if (path.rfind(uncPrefix, 0) == 0) {
        return L"\\" + path.substr(7);
    }
    if (path.rfind(extendedPrefix, 0) == 0) {
        return path.substr(4);
    }
    return path;
}

std::string WideToAnsi(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }

    const int required = WideCharToMultiByte(CP_ACP, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (required <= 1) {
        return std::string();
    }

    std::string buffer(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(CP_ACP, 0, value.c_str(), -1, &buffer[0], required, nullptr, nullptr);
    if (!buffer.empty() && buffer.back() == '\0') {
        buffer.pop_back();
    }
    return buffer;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }

    const int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (required <= 1) {
        return std::string();
    }

    std::string buffer(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &buffer[0], required, nullptr, nullptr);
    if (!buffer.empty() && buffer.back() == '\0') {
        buffer.pop_back();
    }
    return buffer;
}

std::wstring ParentDirectoryPath(const std::wstring& path);
bool EnsureDirectoryRecursive(const std::wstring& directoryPath, std::wstring* error);
std::wstring CanonicalizePathBestEffort(const std::wstring& value);

bool WriteWideTextUtf8File(const std::wstring& path, const std::wstring& text, std::wstring& error) {
    error.clear();
    const std::wstring outputPath = CanonicalizePathBestEffort(path);
    const std::wstring parentPath = ParentDirectoryPath(outputPath);
    if (!parentPath.empty()) {
        if (!EnsureDirectoryRecursive(parentPath, &error)) {
            if (error.empty()) {
                error = L"Failed to create output directory: " + parentPath;
            }
            return false;
        }
    }

    std::ofstream file;
    file.open(outputPath.c_str(), std::ios::binary | std::ios::trunc);
    if (!file) {
        error = L"Failed to open output file.";
        return false;
    }

    static const uint8_t kUtf8Bom[3] = {0xEF, 0xBB, 0xBF};
    file.write(reinterpret_cast<const char*>(kUtf8Bom), static_cast<std::streamsize>(sizeof(kUtf8Bom)));
    const std::string utf8 = WideToUtf8(text);
    file.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    if (!file.good()) {
        error = L"Failed to write output file.";
        return false;
    }
    return true;
}

std::wstring MultiByteToWide(const std::string& value, UINT codePage, DWORD flags) {
    if (value.empty()) {
        return std::wstring();
    }

    const int required = MultiByteToWideChar(
        codePage,
        flags,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0);
    if (required <= 0) {
        return std::wstring();
    }

    std::wstring wide(static_cast<size_t>(required), L'\0');
    MultiByteToWideChar(
        codePage,
        flags,
        value.data(),
        static_cast<int>(value.size()),
        &wide[0],
        required);
    return wide;
}

bool ReadTextFileToWide(const std::wstring& path, std::wstring& outText) {
    outText.clear();

    std::ifstream file;
    file.open(path.c_str(), std::ios::binary);
    if (!file) {
        return false;
    }

    std::string bytes(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    if (bytes.size() >= 3 &&
        static_cast<uint8_t>(bytes[0]) == 0xEF &&
        static_cast<uint8_t>(bytes[1]) == 0xBB &&
        static_cast<uint8_t>(bytes[2]) == 0xBF) {
        bytes.erase(0, 3);
    }

    outText = MultiByteToWide(bytes, CP_UTF8, MB_ERR_INVALID_CHARS);
    if (!outText.empty() || bytes.empty()) {
        return true;
    }

    outText = MultiByteToWide(bytes, CP_ACP, 0);
    return !outText.empty();
}

std::wstring ToLowerCopy(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

std::wstring NormalizeSnapshotKey(const std::wstring& value) {
    std::wstring key = ToLowerCopy(TrimWhitespace(value));
    if (key.empty()) {
        return L"default";
    }
    return key;
}

std::wstring FileNameFromPath(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

bool IsPathSeparator(wchar_t ch) {
    return ch == L'\\' || ch == L'/';
}

std::wstring NormalizePathSeparators(std::wstring path) {
    std::replace(path.begin(), path.end(), L'/', L'\\');
    return path;
}

static std::wstring ParentDirectoryPath(const std::wstring& path) {
    if (path.empty()) {
        return L"";
    }
    std::wstring normalized = NormalizePathSeparators(path);
    size_t end = normalized.size();
    while (end > 0 && IsPathSeparator(normalized[end - 1])) {
        --end;
    }
    if (end == 0) {
        return L"";
    }
    const size_t slash = normalized.find_last_of(L'\\', end - 1);
    if (slash == std::wstring::npos) {
        return L"";
    }
    if (slash == 2 && normalized.size() >= 3 && normalized[1] == L':') {
        return normalized.substr(0, 3);
    }
    return normalized.substr(0, slash);
}

std::wstring JoinPath(const std::wstring& left, const std::wstring& right) {
    if (left.empty()) {
        return right;
    }
    if (right.empty()) {
        return left;
    }
    if ((right.size() >= 2 && right[1] == L':') ||
        (right.size() >= 2 && IsPathSeparator(right[0]) && IsPathSeparator(right[1]))) {
        return right;
    }
    if (IsPathSeparator(left[left.size() - 1])) {
        return left + right;
    }
    return left + L"\\" + right;
}

bool PathExists(const std::wstring& path) {
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES;
}

bool DirectoryExists(const std::wstring& path) {
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool EnsureDirectoryRecursive(const std::wstring& directoryPath, std::wstring* error) {
    std::wstring path = NormalizePathSeparators(TrimWhitespace(directoryPath));
    if (path.empty() || DirectoryExists(path)) {
        return true;
    }

    size_t start = 0;
    if (path.size() >= 2 && path[1] == L':') {
        start = (path.size() >= 3 && IsPathSeparator(path[2])) ? 3 : 2;
    } else if (path.size() >= 2 && IsPathSeparator(path[0]) && IsPathSeparator(path[1])) {
        const size_t serverSlash = path.find(L'\\', 2);
        if (serverSlash == std::wstring::npos) {
            return true;
        }
        const size_t shareSlash = path.find(L'\\', serverSlash + 1);
        if (shareSlash == std::wstring::npos) {
            return true;
        }
        start = shareSlash + 1;
    }

    size_t pos = start;
    while (pos <= path.size()) {
        const size_t next = path.find(L'\\', pos);
        const std::wstring current = (next == std::wstring::npos) ? path : path.substr(0, next);
        if (!current.empty() && !DirectoryExists(current)) {
            if (!CreateDirectoryW(current.c_str(), nullptr)) {
                const DWORD lastError = GetLastError();
                if (lastError != ERROR_ALREADY_EXISTS) {
                    if (error != nullptr) {
                        *error = L"Failed to create directory: " + current +
                                 L" (error " + ToWStringCompat(lastError) + L")";
                    }
                    return false;
                }
            }
        }
        if (next == std::wstring::npos) {
            break;
        }
        pos = next + 1;
        while (pos < path.size() && IsPathSeparator(path[pos])) {
            ++pos;
        }
    }
    return DirectoryExists(path);
}

static std::wstring CanonicalizePathBestEffort(const std::wstring& value) {
    const std::wstring trimmed = TrimWhitespace(value);
    if (trimmed.empty()) {
        return L"";
    }

    DWORD required = GetFullPathNameW(trimmed.c_str(), 0, nullptr, nullptr);
    if (required == 0) {
        return trimmed;
    }

    std::vector<wchar_t> buffer(static_cast<size_t>(required) + 1, L'\0');
    const DWORD copied = GetFullPathNameW(trimmed.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (copied == 0 || copied >= buffer.size()) {
        return trimmed;
    }
    return std::wstring(buffer.data(), copied);
}

std::vector<std::wstring> SplitPathSegments(const std::wstring& path) {
    std::vector<std::wstring> segments;
    const std::wstring normalized = NormalizePathSeparators(path);
    size_t i = 0;
    while (i < normalized.size()) {
        while (i < normalized.size() && IsPathSeparator(normalized[i])) {
            ++i;
        }
        const size_t begin = i;
        while (i < normalized.size() && !IsPathSeparator(normalized[i])) {
            ++i;
        }
        if (i > begin) {
            segments.push_back(normalized.substr(begin, i - begin));
        }
    }
    return segments;
}

std::wstring FileExtension(const std::wstring& path) {
    const std::wstring fileName = FileNameFromPath(path);
    const size_t dot = fileName.find_last_of(L'.');
    if (dot == std::wstring::npos) {
        return L"";
    }
    return fileName.substr(dot);
}

std::wstring NormalizePathForCompare(std::wstring path) {
    std::transform(path.begin(), path.end(), path.begin(), [](wchar_t ch) -> wchar_t {
        if (ch == L'/') {
            return L'\\';
        }
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return path;
}

struct SourceBreakpointSearchContext {
    std::wstring queryLower;
    std::wstring queryFileLower;
    DWORD line;
    DWORD64 address;
    std::wstring file;
    bool exactPathMatch;

    SourceBreakpointSearchContext()
        : line(0),
          address(0),
          exactPathMatch(false) {
    }
};

BOOL CALLBACK FindSourceLineCallback(PSRCCODEINFOW info, PVOID userContext) {
    if (info == nullptr || userContext == nullptr || info->FileName == nullptr) {
        return TRUE;
    }

    auto* ctx = reinterpret_cast<SourceBreakpointSearchContext*>(userContext);
    if (info->LineNumber != ctx->line) {
        return TRUE;
    }

    const std::wstring fileLower = ToLowerCopy(info->FileName);
    const std::wstring fileNameLower = ToLowerCopy(FileNameFromPath(info->FileName));
    const bool exactPath = fileLower == ctx->queryLower;
    const bool basenameMatch = fileNameLower == ctx->queryFileLower;
    const bool partialMatch = !ctx->queryLower.empty() && fileLower.find(ctx->queryLower) != std::wstring::npos;
    if (!exactPath && !basenameMatch && !partialMatch) {
        return TRUE;
    }

    if (ctx->address == 0 || (!ctx->exactPathMatch && exactPath)) {
        ctx->address = info->Address;
        ctx->file = info->FileName;
        ctx->exactPathMatch = exactPath;
    }

    return exactPath ? FALSE : TRUE;
}

bool IsReadableProtection(DWORD protect) {
    const DWORD clean = protect & 0xFF;
    return clean == PAGE_READONLY ||
           clean == PAGE_READWRITE ||
           clean == PAGE_WRITECOPY ||
           clean == PAGE_EXECUTE_READ ||
           clean == PAGE_EXECUTE_READWRITE ||
           clean == PAGE_EXECUTE_WRITECOPY;
}

bool IsExecutableProtection(DWORD protect) {
    const DWORD clean = protect & 0xFF;
    return clean == PAGE_EXECUTE ||
           clean == PAGE_EXECUTE_READ ||
           clean == PAGE_EXECUTE_READWRITE ||
           clean == PAGE_EXECUTE_WRITECOPY;
}

std::wstring MemoryProtectionToString(DWORD protect) {
    const DWORD clean = protect & 0xFF;
    std::wstring text;
    switch (clean) {
        case PAGE_NOACCESS: text = L"NOACCESS"; break;
        case PAGE_READONLY: text = L"READONLY"; break;
        case PAGE_READWRITE: text = L"READWRITE"; break;
        case PAGE_WRITECOPY: text = L"WRITECOPY"; break;
        case PAGE_EXECUTE: text = L"EXECUTE"; break;
        case PAGE_EXECUTE_READ: text = L"EXECUTE_READ"; break;
        case PAGE_EXECUTE_READWRITE: text = L"EXECUTE_READWRITE"; break;
        case PAGE_EXECUTE_WRITECOPY: text = L"EXECUTE_WRITECOPY"; break;
        default: text = L"0x" + ToHex(clean, 8).substr(2); break;
    }
    if ((protect & PAGE_GUARD) != 0) {
        text += L"|GUARD";
    }
    if ((protect & PAGE_NOCACHE) != 0) {
        text += L"|NOCACHE";
    }
    if ((protect & PAGE_WRITECOMBINE) != 0) {
        text += L"|WRITECOMBINE";
    }
    return text;
}

std::wstring BytesToHex(const uint8_t* bytes, size_t len) {
    std::wstringstream ss;
    ss << std::uppercase;
    for (size_t i = 0; i < len; ++i) {
        if (i != 0) {
            ss << L' ';
        }
        ss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<unsigned>(bytes[i]);
    }
    return ss.str();
}

std::wstring ByteToBinary(uint8_t value) {
    std::wstring bits(8, L'0');
    for (int i = 0; i < 8; ++i) {
        if ((value & (1u << (7 - i))) != 0) {
            bits[i] = L'1';
        }
    }
    return bits;
}

uint8_t DetermineDisassemblyModeBits(HANDLE processHandle) {
#if defined(_M_X64)
    auto detectMainModuleMachine = [](HANDLE handle, USHORT& machine) -> bool {
        machine = 0;
        if (handle == nullptr) {
            return false;
        }

        const DWORD processId = GetProcessId(handle);
        if (processId == 0) {
            return false;
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        MODULEENTRY32W me = MODULEENTRY32W();
        me.dwSize = sizeof(me);
        const BOOL hasFirstModule = Module32FirstW(snapshot, &me);
        CloseHandle(snapshot);
        if (!hasFirstModule || me.modBaseAddr == nullptr) {
            return false;
        }

        const uint64_t moduleBase = reinterpret_cast<uint64_t>(me.modBaseAddr);
        IMAGE_DOS_HEADER dos = IMAGE_DOS_HEADER();
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(handle,
                               reinterpret_cast<LPCVOID>(moduleBase),
                               &dos,
                               sizeof(dos),
                               &bytesRead) ||
            bytesRead != sizeof(dos) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE ||
            dos.e_lfanew <= 0) {
            return false;
        }

        const uint64_t ntAddress = moduleBase + static_cast<uint64_t>(dos.e_lfanew);
        IMAGE_NT_HEADERS64 nt64 = IMAGE_NT_HEADERS64();
        if (!ReadProcessMemory(handle,
                               reinterpret_cast<LPCVOID>(ntAddress),
                               &nt64,
                               sizeof(nt64),
                               &bytesRead) ||
            bytesRead < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) ||
            nt64.Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        machine = nt64.FileHeader.Machine;
        return machine != 0;
    };

    uint8_t modeGuess = 64;
    if (processHandle != nullptr) {
        typedef BOOL(WINAPI* IsWow64Process2Fn)(HANDLE, USHORT*, USHORT*);
        HMODULE kernel32Module = GetModuleHandleW(L"kernel32.dll");
        if (kernel32Module != NULL) {
            IsWow64Process2Fn isWow64Process2Fn =
                reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(kernel32Module, "IsWow64Process2"));
            if (isWow64Process2Fn != NULL) {
                USHORT processMachine = 0;
                USHORT nativeMachine = 0;
                if (isWow64Process2Fn(processHandle, &processMachine, &nativeMachine)) {
                    if (processMachine == IMAGE_FILE_MACHINE_I386) {
                        modeGuess = 32;
                    } else {
                        modeGuess = 64;
                    }
                }
            }
        }

        BOOL wow64 = FALSE;
        if (IsWow64Process(processHandle, &wow64) && wow64 == TRUE) {
            modeGuess = 32;
        }

        USHORT mainMachine = 0;
        if (detectMainModuleMachine(processHandle, mainMachine)) {
            if (mainMachine == IMAGE_FILE_MACHINE_I386) {
                return 32;
            }
            if (mainMachine == IMAGE_FILE_MACHINE_AMD64 ||
                mainMachine == IMAGE_FILE_MACHINE_IA64) {
                return 64;
            }
        }
    }
    return modeGuess;
#else
    (void)processHandle;
    return 32;
#endif
}

DecodedInstruction DecodeInstruction(uint64_t address, const uint8_t* code, size_t maxLen, uint8_t modeBits) {
    if (maxLen == 0 || code == nullptr) {
        return DecodedInstruction();
    }

    const size_t kMaxInstructionBytes = 15;
    const size_t decodeLen = std::min(maxLen, kMaxInstructionBytes);

    ZydisMachineMode machineMode;
    ZydisStackWidth stackWidth;
    if (modeBits == 64) {
        machineMode = ZYDIS_MACHINE_MODE_LONG_64;
        stackWidth = ZYDIS_STACK_WIDTH_64;
    } else if (modeBits == 16) {
        machineMode = ZYDIS_MACHINE_MODE_LONG_COMPAT_16;
        stackWidth = ZYDIS_STACK_WIDTH_16;
    } else {
        machineMode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
        stackWidth = ZYDIS_STACK_WIDTH_32;
    }

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, machineMode, stackWidth))) {
        DecodedInstruction fallback;
        fallback.length = 1;
        fallback.text = L"db " + ToHex(code[0], 2);
        return fallback;
    }

    ZydisDecoderContext context;
    std::memset(&context, 0, sizeof(context));
    ZydisDecodedInstruction instruction;
    const ZyanStatus decodeStatus = ZydisDecoderDecodeInstruction(
        &decoder, &context, code, decodeLen, &instruction);
    if (!ZYAN_SUCCESS(decodeStatus) || instruction.length == 0) {
        DecodedInstruction fallback;
        fallback.length = 1;
        fallback.text = L"db " + ToHex(code[0], 2);
        return fallback;
    }

    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    std::memset(operands, 0, sizeof(operands));
    ZydisDecoderDecodeOperands(&decoder, &context, &instruction, operands, instruction.operand_count);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    char buffer[256] = {0};
    const ZyanStatus formatStatus = ZydisFormatterFormatInstruction(
        &formatter, &instruction, operands, instruction.operand_count_visible,
        buffer, sizeof(buffer), address, nullptr);

    std::wstring decodedText;
    if (ZYAN_SUCCESS(formatStatus) && buffer[0] != '\0') {
        decodedText = MultiByteToWide(std::string(buffer), CP_UTF8, 0);
        if (decodedText.empty()) {
            decodedText = MultiByteToWide(std::string(buffer), CP_ACP, 0);
        }
    }
    if (decodedText.empty()) {
        decodedText = L"db " + ToHex(code[0], 2);
    }

    const size_t safeLength = std::max<size_t>(1, std::min(static_cast<size_t>(instruction.length), maxLen));
    DecodedInstruction decoded;
    decoded.length = safeLength;
    decoded.text = RemoveHexPrefixFromDisassemblyText(ToUpperLocal(NormalizeExplicitMemoryOperands(decodedText)));
    return decoded;
}

} // namespace

extern HANDLE g_wdblVehPipe;
extern DWORD g_wdblVehProcessId;
extern bool g_wdblVehPreferred;
void CloseVehSession();
bool StartVehSession(DWORD processId, const std::wstring& dllPath, std::wstring* detail);
struct PreparedRemoteLdrLoadDll {
    LPVOID block;
    LPVOID parameter;
    LPVOID stub;

    PreparedRemoteLdrLoadDll() : block(nullptr), parameter(nullptr), stub(nullptr) {}
};
bool StartVehSessionWithProcessHandle(DWORD processId, HANDLE processHandle, const PreparedRemoteLdrLoadDll* preparedLoad, const std::wstring& dllPath, std::wstring* detail);
bool AllocateRemoteDllPath(HANDLE process, const std::wstring& dllPath, LPVOID* remotePath, std::wstring* detail);
bool PrepareRemoteLdrLoadDllBlock(HANDLE process, const std::wstring& dllPath, PreparedRemoteLdrLoadDll* prepared, std::wstring* detail);
bool StartRemoteThreadWithNtCreateThreadEx(
    HANDLE process, 
    LPVOID startAddress,
    LPVOID parameter, 
    HANDLE* thread, 
    std::wstring* detail);
#if 0 // -- old manual-mapping injection (disabled, replaced by CrossInject-style LdrLoadDll shellcode)
void DoBaseRelocationManual(
    PIMAGE_BASE_RELOCATION relocation, 
    DWORD_PTR memory, 
    DWORD_PTR dwDelta) {
    DWORD_PTR* patchAddress = nullptr;
    while (relocation->VirtualAddress) {
        PBYTE dest = (PBYTE)(memory + relocation->VirtualAddress);
        DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relocInfo = (WORD*)((DWORD_PTR)relocation + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < count; i++) {
            WORD type = relocInfo[i] >> 12;
            WORD offset = relocInfo[i] & 0xfff;
            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
            case IMAGE_REL_BASED_DIR64:
                patchAddress = (DWORD_PTR*)(dest + offset);
                *patchAddress += dwDelta;
                break;
            default:
                break;
            }
        }
        relocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocation + relocation->SizeOfBlock);
    }
}

DWORD ManualMapRvaToOffset(PIMAGE_NT_HEADERS pNtHdr, DWORD dwRVA) {
    PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
    for (WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
        if (pSectionHdr->VirtualAddress <= dwRVA &&
            (pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize) > dwRVA) {
            return dwRVA - pSectionHdr->VirtualAddress + pSectionHdr->PointerToRawData;
        }
        pSectionHdr++;
    }
    return 0;
}

uint64_t FindRemoteModuleBaseByHandle(HANDLE process, const std::wstring& moduleName);
uint64_t ResolveRemoteExportAddress(HANDLE process, uint64_t moduleBase, const char* exportName);
uint64_t WaitForRemoteModuleBaseWithProcessHandle(HANDLE process, DWORD processId, const std::wstring& moduleName, DWORD timeoutMilliseconds);
bool ManualMapResolveImports(HANDLE hProcess, PIMAGE_IMPORT_DESCRIPTOR pImport, DWORD_PTR module) {
    while (pImport->FirstThunk) {
        const char* moduleName = (const char*)(module + pImport->Name);
        std::wstring wideName = MultiByteToWide(std::string(moduleName), CP_ACP, 0);
        uint64_t remoteModule = FindRemoteModuleBaseByHandle(hProcess, wideName);
        if (remoteModule == 0) {
            remoteModule = FindRemoteModuleBaseByHandle(hProcess, ToLowerLocal(wideName));
        }
        if (remoteModule == 0) {
            return false;
        }
        PIMAGE_THUNK_DATA funcRef = (PIMAGE_THUNK_DATA)(module + pImport->FirstThunk);
        PIMAGE_THUNK_DATA thunkRef = pImport->OriginalFirstThunk
            ? (PIMAGE_THUNK_DATA)(module + pImport->OriginalFirstThunk)
            : funcRef;
        while (thunkRef->u1.Function) {
            uint64_t funcAddr = 0;
            if (IMAGE_SNAP_BY_ORDINAL(thunkRef->u1.Function)) {
                return false;
            } else {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(module + thunkRef->u1.AddressOfData);
                funcAddr = ResolveRemoteExportAddress(hProcess, remoteModule, (const char*)thunkData->Name);
            }
            if (funcAddr == 0) {
                return false;
            }
            funcRef->u1.Function = (DWORD_PTR)funcAddr;
            thunkRef++;
            funcRef++;
        }
        pImport++;
    }
    return true;
}

LPVOID ManualMapModuleToProcess(
    HANDLE hProcess, 
    BYTE* dllMemory, 
    bool wipeHeaders) {

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllMemory;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }
    IMAGE_DATA_DIRECTORY relocDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    bool relocatable = (pNtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    bool hasRelocDir = pNtHeader->OptionalHeader.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_BASERELOC &&
                       relocDir.VirtualAddress > 0 && relocDir.Size > 0;
    if (!hasRelocDir && (pNtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
        return nullptr;
    }
    ULONG_PTR headersBase = pNtHeader->OptionalHeader.ImageBase;
    LPVOID preferredBase = relocatable ? nullptr : (LPVOID)headersBase;
    LPVOID imageRemote = VirtualAllocEx(hProcess, preferredBase, pNtHeader->OptionalHeader.SizeOfImage,
                                        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LPVOID imageLocal = VirtualAlloc(nullptr, pNtHeader->OptionalHeader.SizeOfImage,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (imageLocal == nullptr || imageRemote == nullptr) {
        if (imageLocal) VirtualFree(imageLocal, 0, MEM_RELEASE);
        if (imageRemote) VirtualFreeEx(hProcess, imageRemote, 0, MEM_RELEASE);
        return nullptr;
    }
    if (relocatable && (ULONG_PTR)imageRemote != pNtHeader->OptionalHeader.ImageBase) {
        pNtHeader->OptionalHeader.ImageBase = (ULONG_PTR)imageRemote;
    }
    memcpy((LPVOID)imageLocal, (LPVOID)pDosHeader, pNtHeader->OptionalHeader.SizeOfHeaders);
    SIZE_T imageSize = pNtHeader->OptionalHeader.SizeOfImage;
    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        if (hasRelocDir && i == pNtHeader->FileHeader.NumberOfSections - 1 &&
            pSecHeader->VirtualAddress == relocDir.VirtualAddress &&
            (pSecHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {
            imageSize = pSecHeader->VirtualAddress;
        }
        memcpy((LPVOID)((DWORD_PTR)imageLocal + pSecHeader->VirtualAddress),
               (LPVOID)((DWORD_PTR)pDosHeader + pSecHeader->PointerToRawData),
               pSecHeader->SizeOfRawData);
        pSecHeader++;
    }
    if (hasRelocDir) {
        DWORD_PTR dwDelta = (DWORD_PTR)imageRemote - headersBase;
        DoBaseRelocationManual(
            (PIMAGE_BASE_RELOCATION)((DWORD_PTR)imageLocal + relocDir.VirtualAddress),
            (DWORD_PTR)imageLocal, dwDelta);
    }
    ManualMapResolveImports(
        hProcess,
        (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)imageLocal +
            pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
        (DWORD_PTR)imageLocal);
    SIZE_T skipBytes = wipeHeaders ? pNtHeader->OptionalHeader.SizeOfHeaders : 0;
    if (WriteProcessMemory(hProcess, (PVOID)((ULONG_PTR)imageRemote + skipBytes),
                           (PVOID)((ULONG_PTR)imageLocal + skipBytes),
                           imageSize - skipBytes, nullptr)) {
        VirtualFree(imageLocal, 0, MEM_RELEASE);
    } else {
        VirtualFree(imageLocal, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, imageRemote, 0, MEM_RELEASE);
        imageRemote = nullptr;
    }
    return imageRemote;
}

DWORD ManualMapGetEntryPointRva(BYTE* dllMemory) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllMemory;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
    return pNtHeader->OptionalHeader.AddressOfEntryPoint;
}

BYTE* ReadFileToMemoryCompat(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return nullptr;
    }
    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0) {
        CloseHandle(hFile);
        return nullptr;
    }
    BYTE* buffer = (BYTE*)malloc((size_t)fileSize.QuadPart);
    if (buffer == nullptr) {
        CloseHandle(hFile);
        return nullptr;
    }
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, buffer, (DWORD)fileSize.QuadPart, &bytesRead, nullptr);
    CloseHandle(hFile);
    if (!ok || bytesRead != (DWORD)fileSize.QuadPart) {
        free(buffer);
        return nullptr;
    }
    return buffer;
}

bool ReadFileToVectorCompat(const std::wstring& filePath, std::vector<uint8_t>& data) {
    data.clear();
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > 256 * 1024 * 1024) {
        CloseHandle(hFile);
        return false;
    }
    data.resize(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    const BOOL ok = ReadFile(hFile, &data[0], static_cast<DWORD>(data.size()), &bytesRead, nullptr);
    CloseHandle(hFile);
    if (!ok || bytesRead != data.size()) {
        data.clear();
        return false;
    }
    return true;
}

bool DiskPeRvaToOffset(const std::vector<uint8_t>& image, DWORD rva, DWORD& offset) {
    offset = 0;
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(&image[0]);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > image.size()) {
        return false;
    }
    const uint8_t* ntBase = &image[0] + dos->e_lfanew;
    const DWORD signature = *reinterpret_cast<const DWORD*>(ntBase);
    if (signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const IMAGE_FILE_HEADER* fileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(DWORD));
    const uint8_t* optionalHeader = ntBase + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optionalHeader + fileHeader->SizeOfOptionalHeader > &image[0] + image.size()) {
        return false;
    }

    DWORD sizeOfHeaders = 0;
    const WORD magic = *reinterpret_cast<const WORD*>(optionalHeader);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
        sizeOfHeaders = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalHeader)->SizeOfHeaders;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
               fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
        sizeOfHeaders = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalHeader)->SizeOfHeaders;
    }
    if (rva < sizeOfHeaders && rva < image.size()) {
        offset = rva;
        return true;
    }

    const IMAGE_SECTION_HEADER* section =
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(optionalHeader + fileHeader->SizeOfOptionalHeader);
    if (reinterpret_cast<const uint8_t*>(section + fileHeader->NumberOfSections) > &image[0] + image.size()) {
        return false;
    }
    for (WORD i = 0; i < fileHeader->NumberOfSections; ++i) {
        const DWORD virtualSize = section[i].Misc.VirtualSize != 0 ? section[i].Misc.VirtualSize : section[i].SizeOfRawData;
        if (rva >= section[i].VirtualAddress && rva < section[i].VirtualAddress + virtualSize) {
            const DWORD delta = rva - section[i].VirtualAddress;
            if (delta >= section[i].SizeOfRawData) {
                return false;
            }
            offset = section[i].PointerToRawData + delta;
            return offset < image.size();
        }
    }
    return false;
}

bool DiskPeRead(const std::vector<uint8_t>& image, DWORD rva, void* output, size_t size) {
    DWORD offset = 0;
    if (output == nullptr || !DiskPeRvaToOffset(image, rva, offset) || offset + size > image.size()) {
        return false;
    }
    std::memcpy(output, &image[offset], size);
    return true;
}

bool DiskPeReadAnsiString(const std::vector<uint8_t>& image, DWORD rva, std::string& text, size_t maxChars = 256) {
    text.clear();
    DWORD offset = 0;
    if (!DiskPeRvaToOffset(image, rva, offset) || offset >= image.size()) {
        return false;
    }
    for (size_t i = 0; i < maxChars && offset + i < image.size(); ++i) {
        const char ch = static_cast<char>(image[offset + i]);
        if (ch == '\0') {
            return true;
        }
        text.push_back(ch);
    }
    text.clear();
    return false;
}

bool DiskPeDataDirectory(
    const std::vector<uint8_t>& image,
    DWORD directoryIndex,
    DWORD& virtualAddress,
    DWORD& size) {
    virtualAddress = 0;
    size = 0;
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(&image[0]);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > image.size()) {
        return false;
    }
    const uint8_t* ntBase = &image[0] + dos->e_lfanew;
    const DWORD signature = *reinterpret_cast<const DWORD*>(ntBase);
    if (signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const IMAGE_FILE_HEADER* fileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(DWORD));
    const uint8_t* optionalHeader = ntBase + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optionalHeader + fileHeader->SizeOfOptionalHeader > &image[0] + image.size()) {
        return false;
    }
    const WORD magic = *reinterpret_cast<const WORD*>(optionalHeader);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalHeader);
        if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
            directoryIndex >= opt->NumberOfRvaAndSizes) {
            return false;
        }
        virtualAddress = opt->DataDirectory[directoryIndex].VirtualAddress;
        size = opt->DataDirectory[directoryIndex].Size;
        return true;
    }
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalHeader);
        if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32) ||
            directoryIndex >= opt->NumberOfRvaAndSizes) {
            return false;
        }
        virtualAddress = opt->DataDirectory[directoryIndex].VirtualAddress;
        size = opt->DataDirectory[directoryIndex].Size;
        return true;
    }
    return false;
}

bool DiskPeResolveExportRva(const std::vector<uint8_t>& image, const char* exportName, DWORD& functionRva) {
    functionRva = 0;
    DWORD exportRva = 0;
    DWORD exportSize = 0;
    if (exportName == nullptr ||
        !DiskPeDataDirectory(image, IMAGE_DIRECTORY_ENTRY_EXPORT, exportRva, exportSize) ||
        exportRva == 0) {
        return false;
    }
    IMAGE_EXPORT_DIRECTORY exportDir = IMAGE_EXPORT_DIRECTORY();
    if (!DiskPeRead(image, exportRva, &exportDir, sizeof(exportDir)) ||
        exportDir.NumberOfNames == 0 || exportDir.NumberOfFunctions == 0) {
        return false;
    }
    for (DWORD i = 0; i < exportDir.NumberOfNames && i < 65536; ++i) {
        DWORD nameRva = 0;
        WORD ordinal = 0;
        std::string name;
        if (!DiskPeRead(image, exportDir.AddressOfNames + i * sizeof(DWORD), &nameRva, sizeof(nameRva)) ||
            !DiskPeRead(image, exportDir.AddressOfNameOrdinals + i * sizeof(WORD), &ordinal, sizeof(ordinal)) ||
            ordinal >= exportDir.NumberOfFunctions ||
            !DiskPeReadAnsiString(image, nameRva, name)) {
            continue;
        }
        if (name == exportName) {
            DWORD rva = 0;
            if (!DiskPeRead(image, exportDir.AddressOfFunctions + ordinal * sizeof(DWORD), &rva, sizeof(rva))) {
                return false;
            }
            if (exportSize != 0 && rva >= exportRva && rva < exportRva + exportSize) {
                return false;
            }
            functionRva = rva;
            return true;
        }
    }
    return false;
}

bool InjectVehAgentDllManualMap(HANDLE process, const std::wstring& dllPath, std::wstring* detail) {
    BYTE* dllMemory = ReadFileToMemoryCompat(dllPath);
    if (dllMemory == nullptr) {
        if (detail != nullptr) {
            *detail = L"Cannot read VEH agent DLL to memory: " + dllPath;
        }
        return false;
    }
    LPVOID remoteBase = ManualMapModuleToProcess(process, dllMemory, false);
    if (remoteBase == nullptr) {
        free(dllMemory);
        if (detail != nullptr) {
            *detail = L"ManualMapModuleToProcess failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    const DWORD entryRva = ManualMapGetEntryPointRva(dllMemory);
    free(dllMemory);
    if (entryRva == 0) {
        if (detail != nullptr) {
            *detail = L"VEH agent DLL has no entry point.";
        }
        return false;
    }
    const DWORD_PTR dllMain = (DWORD_PTR)remoteBase + entryRva;

    // Resolve RtlExitUserThread from target ntdll so the stub thread exits
    // cleanly instead of executing a bare ret with no return address.
    DWORD processId = GetProcessId(process);
    const uint64_t ntdllBase = WaitForRemoteModuleBaseWithProcessHandle(process, processId, L"ntdll.dll", 5000);
    uint64_t rtlExitUserThread = 0;
    if (ntdllBase != 0) {
        rtlExitUserThread = ResolveRemoteExportAddress(process, ntdllBase, "RtlExitUserThread");
    }

#if defined(_M_X64)
    // Shellcode stub: set rcx=remoteBase, rdx=1(DLL_PROCESS_ATTACH), r8=0,
    // call _DllMainCRTStartup, then call RtlExitUserThread(status).
    // Layout (57 bytes + 8 byte exit ptr = 65):
    //   sub rsp, 28h
    //   mov rdx, 1
    //   xor r8d, r8d
    //   mov rcx, <remoteBase>
    //   mov rax, <dllMain>
    //   call rax
    //   mov rcx, rax          ; pass DllMain return as exit status
    //   mov rax, <RtlExitUserThread>
    //   jmp rax               ; tail-call exit (never returns)
    static const unsigned char stub[] = {
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 28h
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, // mov rdx, 1
        0x45, 0x33, 0xC0,                   // xor r8d, r8d
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, // mov rcx, <remoteBase>
        0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, // mov rax, <dllMain>
        0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,                         // call rax
        0x48, 0x89, 0xC1,                   // mov rcx, rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, // mov rax, <RtlExitUserThread>
        0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0,                         // jmp rax
    };
    unsigned char stubCode[sizeof(stub)];
    memcpy(stubCode, stub, sizeof(stub));
    // Patch remoteBase into mov rcx placeholder (offset 16: 4+7+3=14, 0x48 0xB9 at 14, imm at 16)
    *reinterpret_cast<DWORD_PTR*>(stubCode + 16) = (DWORD_PTR)remoteBase;
    // Patch dllMain into mov rax placeholder (offset 26: 16+10=26, 0x48 0xB8 at 26, imm at 28)
    *reinterpret_cast<DWORD_PTR*>(stubCode + 26) = dllMain;
    // Patch RtlExitUserThread into second mov rax placeholder
    // Offset: 28+10+3(call rax)+3(mov rcx,rax)=44, 0x48 0xB8 at 44, imm at 46
    DWORD_PTR exitAddr = rtlExitUserThread != 0 ? (DWORD_PTR)rtlExitUserThread : 0;
    *reinterpret_cast<DWORD_PTR*>(stubCode + 41) = exitAddr;

    LPVOID stubRemote = VirtualAllocEx(process, nullptr, sizeof(stubCode),
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (stubRemote == nullptr) {
        if (detail != nullptr) {
            *detail = L"VirtualAllocEx DllMain stub failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, stubRemote, stubCode, sizeof(stubCode), &written) ||
        written != sizeof(stubCode)) {
        if (detail != nullptr) {
            *detail = L"WriteProcessMemory DllMain stub failed. LastError=" + ToWStringCompat(GetLastError());
        }
        VirtualFreeEx(process, stubRemote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = nullptr;
    if (!StartRemoteThreadWithNtCreateThreadEx(process, stubRemote, nullptr, &thread, detail)) {
        VirtualFreeEx(process, stubRemote, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(thread, 10000);
    CloseHandle(thread);
    VirtualFreeEx(process, stubRemote, 0, MEM_RELEASE);
    return true;
#else
    HANDLE thread = nullptr;
    if (!StartRemoteThreadWithNtCreateThreadEx(process, reinterpret_cast<LPVOID>(dllMain), remoteBase, &thread, detail)) {
        return false;
    }
    WaitForSingleObject(thread, 10000);
    CloseHandle(thread);
    return true;
#endif
}


#endif

bool ReadFileToVectorCompat(const std::wstring& filePath, std::vector<uint8_t>& data) {
    data.clear();
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > 256 * 1024 * 1024) {
        CloseHandle(hFile);
        return false;
    }
    data.resize(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    const BOOL ok = ReadFile(hFile, &data[0], static_cast<DWORD>(data.size()), &bytesRead, nullptr);
    CloseHandle(hFile);
    if (!ok || static_cast<size_t>(bytesRead) != data.size()) {
        data.clear();
        return false;
    }
    return true;
}

bool DiskPeRvaToOffset(const std::vector<uint8_t>& image, DWORD rva, DWORD& offset) {
    offset = 0;
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(&image[0]);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > image.size()) {
        return false;
    }
    const uint8_t* ntBase = &image[0] + dos->e_lfanew;
    if (*reinterpret_cast<const DWORD*>(ntBase) != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const IMAGE_FILE_HEADER* fileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(DWORD));
    const uint8_t* optionalHeader = ntBase + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optionalHeader + fileHeader->SizeOfOptionalHeader > &image[0] + image.size()) {
        return false;
    }
    DWORD sizeOfHeaders = 0;
    const WORD magic = *reinterpret_cast<const WORD*>(optionalHeader);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
        sizeOfHeaders = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalHeader)->SizeOfHeaders;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
               fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
        sizeOfHeaders = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalHeader)->SizeOfHeaders;
    }
    if (rva < sizeOfHeaders && rva < image.size()) {
        offset = rva;
        return true;
    }
    const IMAGE_SECTION_HEADER* section =
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(optionalHeader + fileHeader->SizeOfOptionalHeader);
    if (reinterpret_cast<const uint8_t*>(section + fileHeader->NumberOfSections) > &image[0] + image.size()) {
        return false;
    }
    for (WORD i = 0; i < fileHeader->NumberOfSections; ++i) {
        const DWORD virtualSize = section[i].Misc.VirtualSize != 0 ? section[i].Misc.VirtualSize : section[i].SizeOfRawData;
        if (rva >= section[i].VirtualAddress && rva < section[i].VirtualAddress + virtualSize) {
            const DWORD delta = rva - section[i].VirtualAddress;
            if (delta >= section[i].SizeOfRawData) {
                return false;
            }
            offset = section[i].PointerToRawData + delta;
            return offset < image.size();
        }
    }
    return false;
}

bool DiskPeRead(const std::vector<uint8_t>& image, DWORD rva, void* output, size_t size) {
    DWORD offset = 0;
    if (output == nullptr || !DiskPeRvaToOffset(image, rva, offset) || offset + size > image.size()) {
        return false;
    }
    std::memcpy(output, &image[offset], size);
    return true;
}

bool DiskPeReadAnsiString(const std::vector<uint8_t>& image, DWORD rva, std::string& text, size_t maxChars = 256) {
    text.clear();
    DWORD offset = 0;
    if (!DiskPeRvaToOffset(image, rva, offset) || offset >= image.size()) {
        return false;
    }
    for (size_t i = 0; i < maxChars && offset + i < image.size(); ++i) {
        const char ch = static_cast<char>(image[offset + i]);
        if (ch == '\0') {
            return true;
        }
        text.push_back(ch);
    }
    text.clear();
    return false;
}

bool DiskPeDataDirectory(const std::vector<uint8_t>& image, DWORD directoryIndex, DWORD& virtualAddress, DWORD& size) {
    virtualAddress = 0;
    size = 0;
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(&image[0]);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > image.size()) {
        return false;
    }
    const uint8_t* ntBase = &image[0] + dos->e_lfanew;
    if (*reinterpret_cast<const DWORD*>(ntBase) != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const IMAGE_FILE_HEADER* fileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(DWORD));
    const uint8_t* optionalHeader = ntBase + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optionalHeader + fileHeader->SizeOfOptionalHeader > &image[0] + image.size()) {
        return false;
    }
    const WORD magic = *reinterpret_cast<const WORD*>(optionalHeader);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalHeader);
        if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
            directoryIndex >= opt->NumberOfRvaAndSizes) {
            return false;
        }
        virtualAddress = opt->DataDirectory[directoryIndex].VirtualAddress;
        size = opt->DataDirectory[directoryIndex].Size;
        return true;
    }
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalHeader);
        if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32) ||
            directoryIndex >= opt->NumberOfRvaAndSizes) {
            return false;
        }
        virtualAddress = opt->DataDirectory[directoryIndex].VirtualAddress;
        size = opt->DataDirectory[directoryIndex].Size;
        return true;
    }
    return false;
}

bool DiskPeResolveExportRva(const std::vector<uint8_t>& image, const char* exportName, DWORD& functionRva) {
    functionRva = 0;
    DWORD exportRva = 0;
    DWORD exportSize = 0;
    if (exportName == nullptr ||
        !DiskPeDataDirectory(image, IMAGE_DIRECTORY_ENTRY_EXPORT, exportRva, exportSize) ||
        exportRva == 0) {
        return false;
    }
    IMAGE_EXPORT_DIRECTORY exportDir = IMAGE_EXPORT_DIRECTORY();
    if (!DiskPeRead(image, exportRva, &exportDir, sizeof(exportDir)) ||
        exportDir.NumberOfNames == 0 || exportDir.NumberOfFunctions == 0) {
        return false;
    }
    for (DWORD i = 0; i < exportDir.NumberOfNames && i < 65536; ++i) {
        DWORD nameRva = 0;
        WORD ordinal = 0;
        std::string name;
        if (!DiskPeRead(image, exportDir.AddressOfNames + i * sizeof(DWORD), &nameRva, sizeof(nameRva)) ||
            !DiskPeRead(image, exportDir.AddressOfNameOrdinals + i * sizeof(WORD), &ordinal, sizeof(ordinal)) ||
            ordinal >= exportDir.NumberOfFunctions ||
            !DiskPeReadAnsiString(image, nameRva, name)) {
            continue;
        }
        if (name == exportName) {
            DWORD rva = 0;
            if (!DiskPeRead(image, exportDir.AddressOfFunctions + ordinal * sizeof(DWORD), &rva, sizeof(rva))) {
                return false;
            }
            if (exportSize != 0 && rva >= exportRva && rva < exportRva + exportSize) {
                return false;
            }
            functionRva = rva;
            return true;
        }
    }
    return false;
}

void FreePreparedRemoteLdrLoadDllBlock(HANDLE process, const PreparedRemoteLdrLoadDll& prepared);

uint64_t FindRemoteModuleBaseByHandle(HANDLE process, const std::wstring& moduleName);
uint64_t ResolveRemoteExportAddress(HANDLE process, uint64_t moduleBase, const char* exportName);
uint64_t WaitForRemoteModuleBaseWithProcessHandle(
    HANDLE process, 
    DWORD processId, 
    const std::wstring& moduleName,
    DWORD timeoutMilliseconds);
#ifndef _WDBL_CLIENT_ID_DEFINED
#define _WDBL_CLIENT_ID_DEFINED
typedef struct _WDBL_CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} WDBL_CLIENT_ID, *PWDBL_CLIENT_ID;
#endif

// ---------------------------------------------------------------------------
// CrossInject-style DLL injection for x64.
// Writes a loader data block + LoaderDll64 shellcode into the target,
// then creates a remote thread via RtlCreateUserThread. The shellcode calls
// ntdll!LdrLoadDll to properly load the DLL through the loader (so CRT
// globals, DllMain, TLS etc. all work correctly).
// Adapted from D:\codelib\Z0BufferPcTools\CrossInject-master\CrossInject.cpp
// ---------------------------------------------------------------------------

typedef struct _WDBL_CROSS_DLL_LOADER {
    BOOLEAN UnloadDll;
    DWORD64 LdrLoadDll;
    DWORD64 LdrUnloadDll;
    DWORD64 LdrGetDllHandle;
    DWORD64 RtlInitUnicodeString;
    WCHAR DllPath[MAX_PATH];
} WDBL_CROSS_DLL_LOADER;

// Shell64.asm from CrossInject: calls RtlInitUnicodeString + LdrLoadDll,
// optionally LdrUnloadDll. Expects a pointer to WDBL_CROSS_DLL_LOADER in rcx.
static const BYTE WdblLoaderDll64[142] = {
    0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28, 0x53, 0x48, 0x89, 0xCB, 0x48, 0x83, 0xEC, 0x20,
    0x48, 0x8D, 0x4D, 0xE8, 0x48, 0x8D, 0x53, 0x28, 0xFF, 0x53, 0x20, 0x48, 0x83, 0xC4, 0x20, 0x48,
    0xC7, 0x45, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x20, 0x48, 0xC7, 0xC1, 0x00, 0x00,
    0x00, 0x00, 0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x45, 0xE8, 0x4C, 0x8D, 0x4D,
    0xE0, 0xFF, 0x53, 0x18, 0x48, 0x83, 0xC4, 0x20, 0x80, 0x3B, 0x01, 0x75, 0x18, 0x48, 0x83, 0x7D,
    0xE0, 0x00, 0x76, 0x11, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x4D, 0xE0, 0xFF, 0x53, 0x10, 0x48,
    0x83, 0xC4, 0x20, 0xEB, 0x26, 0x80, 0x3B, 0x00, 0x75, 0x21, 0x48, 0x83, 0xEC, 0x20, 0x48, 0xC7,
    0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x45, 0xE8,
    0x4C, 0x8D, 0x4D, 0xE0, 0xFF, 0x53, 0x08, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC9, 0xC3
};

typedef NTSTATUS(NTAPI* WdblRtlCreateUserThreadFn)(
    HANDLE Process,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    SIZE_T MaximumStackSize,
    SIZE_T InitialStackSize,
    PVOID StartAddress,
    PVOID Parameter,
    PHANDLE Thread,
    PVOID ClientId);

bool InjectVehAgentDllCrossInject(HANDLE process, const std::wstring& dllPath, std::wstring* detail) {
    const DWORD processId = GetProcessId(process);

    const uint64_t ntdllBase = WaitForRemoteModuleBaseWithProcessHandle(process, processId, L"ntdll.dll", 5000);
    if (ntdllBase == 0) {
        if (detail != nullptr) {
            *detail = L"Cannot find target ntdll.dll.";
        }
        return false;
    }

    WDBL_CROSS_DLL_LOADER loader = {};
    loader.LdrLoadDll = ResolveRemoteExportAddress(process, ntdllBase, "LdrLoadDll");
    if (loader.LdrLoadDll == 0) {
        if (detail != nullptr) {
            *detail = L"Cannot resolve target ntdll!LdrLoadDll.";
        }
        return false;
    }
    loader.LdrUnloadDll = ResolveRemoteExportAddress(process, ntdllBase, "LdrUnloadDll");
    loader.LdrGetDllHandle = ResolveRemoteExportAddress(process, ntdllBase, "LdrGetDllHandle");
    loader.RtlInitUnicodeString = ResolveRemoteExportAddress(process, ntdllBase, "RtlInitUnicodeString");
    if (loader.LdrUnloadDll == 0 || loader.LdrGetDllHandle == 0 || loader.RtlInitUnicodeString == 0) {
        if (detail != nullptr) {
            *detail = L"Cannot resolve target ntdll loader exports.";
        }
        return false;
    }
    loader.UnloadDll = FALSE;

    if (dllPath.size() >= MAX_PATH) {
        if (detail != nullptr) {
            *detail = L"VEH agent DLL path too long.";
        }
        return false;
    }
    wcscpy_s(loader.DllPath, _countof(loader.DllPath), dllPath.c_str());

    PVOID shellData = VirtualAllocEx(process, nullptr, sizeof(loader),
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (shellData == nullptr) {
        if (detail != nullptr) {
            *detail = L"VirtualAllocEx loader data failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, shellData, &loader, sizeof(loader), &written) ||
        written != sizeof(loader)) {
        if (detail != nullptr) {
            *detail = L"WriteProcessMemory loader data failed. LastError=" + ToWStringCompat(GetLastError());
        }
        VirtualFreeEx(process, shellData, 0, MEM_RELEASE);
        return false;
    }

    const SIZE_T loaderSize = sizeof(WdblLoaderDll64);
    PVOID shellCode = VirtualAllocEx(process, nullptr, loaderSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellCode == nullptr) {
        if (detail != nullptr) {
            *detail = L"VirtualAllocEx shellcode failed. LastError=" + ToWStringCompat(GetLastError());
        }
        VirtualFreeEx(process, shellData, 0, MEM_RELEASE);
        return false;
    }
    if (!WriteProcessMemory(process, shellCode, (PVOID)WdblLoaderDll64, loaderSize, &written) ||
        written != loaderSize) {
        if (detail != nullptr) {
            *detail = L"WriteProcessMemory shellcode failed. LastError=" + ToWStringCompat(GetLastError());
        }
        VirtualFreeEx(process, shellCode, 0, MEM_RELEASE);
        VirtualFreeEx(process, shellData, 0, MEM_RELEASE);
        return false;
    }

    HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
    WdblRtlCreateUserThreadFn rtlCreateUserThread = localNtdll != nullptr
        ? (WdblRtlCreateUserThreadFn)GetProcAddress(localNtdll, "RtlCreateUserThread")
        : nullptr;
    if (rtlCreateUserThread == nullptr) {
        if (detail != nullptr) {
            *detail = L"Cannot resolve local ntdll!RtlCreateUserThread.";
        }
        VirtualFreeEx(process, shellCode, 0, MEM_RELEASE);
        VirtualFreeEx(process, shellData, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = nullptr;
    WDBL_CLIENT_ID clientId = {};
    const NTSTATUS status = rtlCreateUserThread(
        process, nullptr, FALSE, 0, 0, 0, shellCode, shellData, &thread, &clientId);
    if (status < 0) {
        if (detail != nullptr) {
            *detail = L"RtlCreateUserThread failed. status=" + ToHex(static_cast<uint32_t>(status), 8);
        }
        VirtualFreeEx(process, shellCode, 0, MEM_RELEASE);
        VirtualFreeEx(process, shellData, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(thread, 10000);
    CloseHandle(thread);
    VirtualFreeEx(process, shellCode, 0, MEM_RELEASE);
    VirtualFreeEx(process, shellData, 0, MEM_RELEASE);
    return true;
}


std::wstring FindVehAgentDllPath(const std::wstring& explicitPath, HANDLE targetProcess);
uint64_t WaitForRemoteModuleBaseWithProcessHandle(HANDLE process, DWORD processId, const std::wstring& moduleName, DWORD timeoutMilliseconds);

TraceLogger::TraceLogger(const std::wstring& filePath) {
    stream_.open(filePath.c_str(), std::ios::out | std::ios::app);
}

TraceLogger::~TraceLogger() {
    if (stream_.is_open()) {
        stream_.flush();
        stream_.close();
    }
}

void TraceLogger::Log(const std::wstring& message) {
    if (!stream_.is_open()) {
        return;
    }
    stream_ << L"[" << NowTimestamp() << L"] " << message << L"\n";
    stream_.flush();
}

void TraceLogger::LogEvent(const std::wstring& prefix, const DEBUG_EVENT& event) {
    std::wstringstream ss;
    ss << prefix
       << L" event=" << event.dwDebugEventCode
       << L" pid=" << event.dwProcessId
       << L" tid=" << event.dwThreadId;
    Log(ss.str());
}

Debugger::Debugger(const std::wstring& tracePath)
    : logger_(tracePath),
      active_(false),
      attached_(false),
      processId_(0),
      processHandle_(NULL),
      symbolsInitialized_(false),
      symbolInitAttempted_(false),
      scriptCursor_(0),
      scriptLoaded_(false),
      scriptResumePastBreakpoint_(false),
      pendingEvent_(),
      stopState_(),
      stepRequested_(false),
      stepThreadId_(0),
      runFlowActive_(false),
      mainModuleBase_(0),
      entryPointAddress_(0),
      runToEntryOnLaunch_(false),
      runToEntryBreakpointId_(-1),
      runToEntryOwnsBreakpoint_(false),
      stepOverBreakpointId_(-1),
      nextBreakpointId_(1),
      nextPluginId_(1),
      pluginEventDispatchActive_(false),
      activePluginDispatchIndex_(-1),
      eventPumpThreadHandle_(NULL),
      eventPumpResumeEvent_(NULL),
      eventPumpReadyEvent_(NULL),
      stateLockInitialized_(false),
      eventPumpStartMode_(0),
      eventPumpStartSucceeded_(false),
      detachRequested_(false),
      eventPumpAttachProcessId_(0),
      disasmColorEnabled_(true) {
    InitializeCriticalSection(&stateLock_);
    stateLockInitialized_ = true;
    eventPumpResumeEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    eventPumpReadyEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    debuggerApi_.context = this;
    debuggerApi_.launch = &Debugger::DebuggerApiLaunchThunk;
    debuggerApi_.attach = &Debugger::DebuggerApiAttachThunk;
    debuggerApi_.detach = &Debugger::DebuggerApiDetachThunk;
    debuggerApi_.continueExecution = &Debugger::DebuggerApiContinueThunk;
    debuggerApi_.singleStep = &Debugger::DebuggerApiSingleStepThunk;
    debuggerApi_.stepOver = &Debugger::DebuggerApiStepOverThunk;
    debuggerApi_.readMemory = &Debugger::DebuggerApiReadMemoryThunk;
    debuggerApi_.writeMemory = &Debugger::DebuggerApiWriteMemoryThunk;
    debuggerApi_.resolveSymbol = &Debugger::DebuggerApiResolveSymbolThunk;
    debuggerApi_.resolveAddressExpression = &Debugger::DebuggerApiResolveAddressExpressionThunk;
    debuggerApi_.addSoftwareBreakpoint = &Debugger::DebuggerApiAddSoftwareBreakpointThunk;
    debuggerApi_.addHardwareBreakpoint = &Debugger::DebuggerApiAddHardwareBreakpointThunk;
    debuggerApi_.addMemoryBreakpoint = &Debugger::DebuggerApiAddMemoryBreakpointThunk;
    debuggerApi_.enableBreakpoint = &Debugger::DebuggerApiEnableBreakpointThunk;
    debuggerApi_.disableBreakpoint = &Debugger::DebuggerApiDisableBreakpointThunk;
    debuggerApi_.removeBreakpoint = &Debugger::DebuggerApiRemoveBreakpointThunk;
    debuggerApi_.setBreakpointCondition = &Debugger::DebuggerApiSetBreakpointConditionThunk;
    debuggerApi_.clearBreakpointCondition = &Debugger::DebuggerApiClearBreakpointConditionThunk;
    debuggerApi_.loadSymbols = &Debugger::DebuggerApiLoadSymbolsThunk;
    debuggerApi_.downloadSymbols = &Debugger::DebuggerApiDownloadSymbolsThunk;
    debuggerApi_.setSymbolSearchPath = &Debugger::DebuggerApiSetSymbolSearchPathThunk;
    debuggerApi_.getSymbolSearchPath = &Debugger::DebuggerApiGetSymbolSearchPathThunk;
    debuggerApi_.selectThread = &Debugger::DebuggerApiSelectThreadThunk;
    debuggerApi_.setRegisterValue = &Debugger::DebuggerApiSetRegisterValueThunk;
    debuggerApi_.writeMemoryPatch = &Debugger::DebuggerApiWriteMemoryPatchThunk;
    debuggerApi_.undoMemoryPatch = &Debugger::DebuggerApiUndoMemoryPatchThunk;
    debuggerApi_.saveCurrentStopSnapshot = &Debugger::DebuggerApiSaveCurrentStopSnapshotThunk;
    debuggerApi_.saveNamedSnapshot = &Debugger::DebuggerApiSaveNamedSnapshotThunk;
    debuggerApi_.restoreNamedSnapshot = &Debugger::DebuggerApiRestoreNamedSnapshotThunk;
    debuggerApi_.listNamedSnapshots = &Debugger::DebuggerApiListNamedSnapshotsThunk;
    debuggerApi_.stepBackToPreviousSnapshot = &Debugger::DebuggerApiStepBackToPreviousSnapshotThunk;
    debuggerApi_.addSourceRoot = &Debugger::DebuggerApiAddSourceRootThunk;
    debuggerApi_.removeSourceRoot = &Debugger::DebuggerApiRemoveSourceRootThunk;
    debuggerApi_.clearSourceRoots = &Debugger::DebuggerApiClearSourceRootsThunk;
    debuggerApi_.listSourceRoots = &Debugger::DebuggerApiListSourceRootsThunk;
    debuggerApi_.loadScriptFile = &Debugger::DebuggerApiLoadScriptFileThunk;
    debuggerApi_.setScriptBreakpoint = &Debugger::DebuggerApiSetScriptBreakpointThunk;
    debuggerApi_.removeScriptBreakpoint = &Debugger::DebuggerApiRemoveScriptBreakpointThunk;
    debuggerApi_.listScriptBreakpoints = &Debugger::DebuggerApiListScriptBreakpointsThunk;
    debuggerApi_.configureExceptionIgnoreAll = &Debugger::DebuggerApiConfigureExceptionIgnoreAllThunk;
    debuggerApi_.addIgnoredExceptionCode = &Debugger::DebuggerApiAddIgnoredExceptionCodeThunk;
    debuggerApi_.removeIgnoredExceptionCode = &Debugger::DebuggerApiRemoveIgnoredExceptionCodeThunk;
    debuggerApi_.clearIgnoredExceptionCodes = &Debugger::DebuggerApiClearIgnoredExceptionCodesThunk;
    debuggerApi_.listExceptionSettings = &Debugger::DebuggerApiListExceptionSettingsThunk;
    debuggerApi_.addRunStopExpression = &Debugger::DebuggerApiAddRunStopExpressionThunk;
    debuggerApi_.removeRunStopExpression = &Debugger::DebuggerApiRemoveRunStopExpressionThunk;
    debuggerApi_.clearRunStopExpressions = &Debugger::DebuggerApiClearRunStopExpressionsThunk;
    debuggerApi_.listRunStopExpressions = &Debugger::DebuggerApiListRunStopExpressionsThunk;
    debuggerApi_.stepUntilCondition = &Debugger::DebuggerApiStepUntilConditionThunk;
    debuggerApi_.runUntilCondition = &Debugger::DebuggerApiRunUntilConditionThunk;
    debuggerApi_.autoStep = &Debugger::DebuggerApiAutoStepThunk;
    debuggerApi_.autoRun = &Debugger::DebuggerApiAutoRunThunk;
    debuggerApi_.getStopInfo = &Debugger::DebuggerApiGetStopInfoThunk;
    debuggerApi_.getThreadCount = &Debugger::DebuggerApiGetThreadCountThunk;
    debuggerApi_.getThreadInfo = &Debugger::DebuggerApiGetThreadInfoThunk;
    debuggerApi_.getRegisterInfo = &Debugger::DebuggerApiGetRegisterInfoThunk;
    debuggerApi_.getStackFrameInfo = &Debugger::DebuggerApiGetStackFrameInfoThunk;
    debuggerApi_.getModuleCount = &Debugger::DebuggerApiGetModuleCountThunk;
    debuggerApi_.getModuleInfo = &Debugger::DebuggerApiGetModuleInfoThunk;
    debuggerApi_.getBreakpointCount = &Debugger::DebuggerApiGetBreakpointCountThunk;
    debuggerApi_.getBreakpointInfo = &Debugger::DebuggerApiGetBreakpointInfoThunk;
    debuggerApi_.executeCommand = &Debugger::DebuggerApiExecuteCommandThunk;
    symbolCacheDirectory_ = QueryDefaultSymbolCacheDirectory();
    symbolServerUrl_ = L"https://msdl.microsoft.com/download/symbols";
    EnsureConsoleColorEnabled();
    AutoLoadPluginModules();
}

Debugger::~Debugger() {
    Shutdown();
    if (stateLockInitialized_) {
        DeleteCriticalSection(&stateLock_);
        stateLockInitialized_ = false;
    }
    if (eventPumpResumeEvent_ != NULL) {
        CloseHandle(eventPumpResumeEvent_);
        eventPumpResumeEvent_ = NULL;
    }
    if (eventPumpReadyEvent_ != NULL) {
        CloseHandle(eventPumpReadyEvent_);
        eventPumpReadyEvent_ = NULL;
    }
}

bool Debugger::EnsureDebuggee() const {
    if (!active_ || processHandle_ == nullptr) {
        std::wcout << L"No active debuggee.\n";
        return false;
    }
    return true;
}

bool Debugger::EnsurePaused() const {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (!pendingEvent_.valid || !stopState_.valid) {
        std::wcout << L"Debuggee is not paused on a debug event.\n";
        return false;
    }
    return true;
}

bool Debugger::CaptureThreadContext(DWORD threadId, CONTEXT& ctx) const {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!thread) {
        return false;
    }
    ZeroMemory(&ctx, sizeof(ctx));
#if defined(_M_X64)
    ctx.ContextFlags = CONTEXT_ALL;
#else
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
#endif
    const BOOL ok = GetThreadContext(thread, &ctx);
    CloseHandle(thread);
    if (ok != TRUE) {
        return false;
    }

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (CaptureWow64ThreadContextById(threadId, wowCtx)) {
            // Map critical WOW64 execution state into CONTEXT so existing
            // debugger logic can keep using Get/SetInstructionPointer + EFlags.
            ctx.Rip = static_cast<DWORD64>(wowCtx.Eip);
            ctx.Rsp = static_cast<DWORD64>(wowCtx.Esp);
            ctx.Rbp = static_cast<DWORD64>(wowCtx.Ebp);
            ctx.EFlags = wowCtx.EFlags;
            ctx.Dr0 = static_cast<DWORD64>(wowCtx.Dr0);
            ctx.Dr1 = static_cast<DWORD64>(wowCtx.Dr1);
            ctx.Dr2 = static_cast<DWORD64>(wowCtx.Dr2);
            ctx.Dr3 = static_cast<DWORD64>(wowCtx.Dr3);
            ctx.Dr6 = static_cast<DWORD64>(wowCtx.Dr6);
            ctx.Dr7 = static_cast<DWORD64>(wowCtx.Dr7);
        }
    }
#endif
    return true;
}

bool Debugger::ApplyThreadContext(DWORD threadId, CONTEXT& ctx) const {
#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (!CaptureWow64ThreadContextById(threadId, wowCtx)) {
            return false;
        }
        wowCtx.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_DEBUG_REGISTERS;
        wowCtx.Eip = static_cast<DWORD>(ctx.Rip);
        wowCtx.Esp = static_cast<DWORD>(ctx.Rsp);
        wowCtx.Ebp = static_cast<DWORD>(ctx.Rbp);
        wowCtx.EFlags = ctx.EFlags;
        wowCtx.Dr0 = static_cast<DWORD>(ctx.Dr0);
        wowCtx.Dr1 = static_cast<DWORD>(ctx.Dr1);
        wowCtx.Dr2 = static_cast<DWORD>(ctx.Dr2);
        wowCtx.Dr3 = static_cast<DWORD>(ctx.Dr3);
        wowCtx.Dr6 = static_cast<DWORD>(ctx.Dr6);
        wowCtx.Dr7 = static_cast<DWORD>(ctx.Dr7);
        if (ApplyWow64ThreadContextById(threadId, wowCtx)) {
            return true;
        }
        // Fallback for environments where WOW64 context set may be blocked.
    }
#endif

    HANDLE thread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!thread) {
        return false;
    }
    const BOOL ok = SetThreadContext(thread, &ctx);
    CloseHandle(thread);
    return ok == TRUE;
}

uint64_t Debugger::GetInstructionPointer(const CONTEXT& ctx) const {
#if defined(_M_X64)
    return ctx.Rip;
#else
    return ctx.Eip;
#endif
}

uint64_t Debugger::GetStackPointer(const CONTEXT& ctx) const {
#if defined(_M_X64)
    return ctx.Rsp;
#else
    return ctx.Esp;
#endif
}

void Debugger::SetInstructionPointer(CONTEXT& ctx, uint64_t ip) const {
#if defined(_M_X64)
    ctx.Rip = ip;
#else
    ctx.Eip = static_cast<DWORD>(ip);
#endif
}

void Debugger::SetTrapFlag(CONTEXT& ctx, bool enabled) const {
    if (enabled) {
        ctx.EFlags |= 0x100;
    } else {
        ctx.EFlags &= ~0x100u;
    }
}

bool Debugger::InitializeSymbolEngine() {
    if (symbolsInitialized_) {
        return true;
    }
    if (processHandle_ == nullptr || symbolInitAttempted_) {
        return symbolsInitialized_;
    }

    symbolInitAttempted_ = true;

    ConfigureDefaultSymbolPath(false);
    DWORD options = SymGetOptions();
    options |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES;
    SymSetOptions(options);

    std::string configuredPathAnsi;
    PCSTR configuredPath = nullptr;
    if (!symbolSearchPath_.empty()) {
        configuredPathAnsi = WideToAnsi(symbolSearchPath_);
        configuredPath = configuredPathAnsi.empty() ? nullptr : configuredPathAnsi.c_str();
    }

    if (!SymInitialize(processHandle_, configuredPath, FALSE)) {
        logger_.Log(L"SymInitialize failed error=" + ToWStringCompat(GetLastError()));
        symbolInitAttempted_ = false;
        return false;
    }

    symbolsInitialized_ = true;
    logger_.Log(L"Symbol engine initialized path=" + GetSymbolSearchPath());
    return true;
}

bool Debugger::ConfigureDefaultSymbolPath(bool forceReset) {
    if (!forceReset && !symbolSearchPath_.empty()) {
        return true;
    }

    if (symbolCacheDirectory_.empty()) {
        symbolCacheDirectory_ = QueryDefaultSymbolCacheDirectory();
    }
    if (symbolServerUrl_.empty()) {
        symbolServerUrl_ = L"https://msdl.microsoft.com/download/symbols";
    }

    EnsureDirectoryRecursive(symbolCacheDirectory_, nullptr);

    const std::wstring path = L"srv*" + symbolCacheDirectory_ + L"*" + symbolServerUrl_;
    return SetSymbolSearchPath(path);
}

bool Debugger::SetSymbolSearchPath(const std::wstring& symbolPath) {
    const std::wstring trimmed = TrimWhitespace(symbolPath);
    if (trimmed.empty()) {
        std::wcout << L"Symbol path cannot be empty.\n";
        return false;
    }

    if (symbolsInitialized_ && processHandle_ != nullptr) {
        if (!SymSetSearchPathW(processHandle_, trimmed.c_str())) {
            const DWORD err = GetLastError();
            std::wcout << L"SymSetSearchPathW failed: " << err << L"\n";
            logger_.Log(L"SymSetSearchPathW failed error=" + ToWStringCompat(err));
            return false;
        }
    }

    symbolSearchPath_ = trimmed;
    logger_.Log(L"Symbol path set: " + symbolSearchPath_);
    return true;
}

std::wstring Debugger::GetSymbolSearchPath() const {
    if (symbolsInitialized_ && processHandle_ != nullptr) {
        wchar_t buffer[4096] = {0};
        if (SymGetSearchPathW(processHandle_, buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])))) {
            return std::wstring(buffer);
        }
    }
    return symbolSearchPath_;
}

bool Debugger::CollectModuleRecords(std::vector<ModuleRecord>& modules) const {
    modules.clear();
    if (!EnsureDebuggee()) {
        return false;
    }

    std::vector<WDBL_MODULE_ENUM_ENTRY> driverModules;
    if (wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverModuleList(processId_, &driverModules) &&
        !driverModules.empty()) {
        modules.reserve(driverModules.size());
        for (size_t i = 0; i < driverModules.size(); ++i) {
            const WDBL_MODULE_ENUM_ENTRY& dm = driverModules[i];
            ModuleRecord record = ModuleRecord();
            record.baseAddress = dm.BaseAddress;
            record.size = dm.SizeOfImage;
            record.imagePath = dm.ImagePath;
            record.moduleName = dm.ModuleName;
            if (record.moduleName.empty()) {
                record.moduleName = GetModuleNameFromPath(record.imagePath);
            }
            modules.push_back(std::move(record));
        }
        std::sort(modules.begin(), modules.end(),
                  [](const ModuleRecord& a, const ModuleRecord& b) { return a.baseAddress < b.baseAddress; });
        return true;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId_);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W me = MODULEENTRY32W();
    me.dwSize = sizeof(me);
    if (Module32FirstW(snapshot, &me)) {
        do {
            ModuleRecord record = ModuleRecord();
            record.baseAddress = reinterpret_cast<uint64_t>(me.modBaseAddr);
            record.size = me.modBaseSize;
            record.imagePath = me.szExePath;
            record.moduleName = me.szModule;
            if (record.moduleName.empty()) {
                record.moduleName = GetModuleNameFromPath(record.imagePath);
            }
            modules.push_back(std::move(record));
        } while (Module32NextW(snapshot, &me));
    }
    CloseHandle(snapshot);

    std::sort(modules.begin(), modules.end(),
              [](const ModuleRecord& a, const ModuleRecord& b) { return a.baseAddress < b.baseAddress; });
    return true;
}

bool Debugger::ResolveEntryPointFromModuleBase(uint64_t moduleBase, uint64_t& entryPointAddress) const {
    entryPointAddress = 0;
    if (!EnsureDebuggee() || moduleBase == 0) {
        return false;
    }

    IMAGE_DOS_HEADER dos = IMAGE_DOS_HEADER();
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(
            processHandle_,
            reinterpret_cast<LPCVOID>(moduleBase),
            &dos,
            sizeof(dos),
            &bytesRead) ||
        bytesRead != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0) {
        return false;
    }

    const uint64_t ntAddress = moduleBase + static_cast<uint64_t>(dos.e_lfanew);
    IMAGE_NT_HEADERS64 nt64 = IMAGE_NT_HEADERS64();
    if (!ReadProcessMemory(
            processHandle_,
            reinterpret_cast<LPCVOID>(ntAddress),
            &nt64,
            sizeof(nt64),
            &bytesRead) ||
        bytesRead < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) ||
        nt64.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    DWORD entryRva = 0;
    if (nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        entryRva = nt64.OptionalHeader.AddressOfEntryPoint;
    } else {
        IMAGE_NT_HEADERS32 nt32 = IMAGE_NT_HEADERS32();
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(ntAddress),
                &nt32,
                sizeof(nt32),
                &bytesRead) ||
            bytesRead < sizeof(nt32) ||
            nt32.Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }
        entryRva = nt32.OptionalHeader.AddressOfEntryPoint;
    }

    if (entryRva == 0) {
        return false;
    }

    entryPointAddress = moduleBase + static_cast<uint64_t>(entryRva);
    return true;
}

bool Debugger::ResolveMainModuleEntryPoint(uint64_t& moduleBase, uint64_t& entryPointAddress) const {
    moduleBase = 0;
    entryPointAddress = 0;
    if (!EnsureDebuggee()) {
        return false;
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules) || modules.empty()) {
        return false;
    }

    std::wstring processImagePath;
    wchar_t processPathBuffer[MAX_PATH] = {};
    DWORD processPathLength = MAX_PATH;
    if (QueryFullProcessImageNameW(processHandle_, 0, processPathBuffer, &processPathLength)) {
        processImagePath = NormalizePathForCompare(std::wstring(processPathBuffer, processPathLength));
    }

    const ModuleRecord* best = nullptr;
    if (!processImagePath.empty()) {
 for (auto __rangeIt1 = (modules).begin(); __rangeIt1 != (modules).end(); ++__rangeIt1) {
            const auto& module = *__rangeIt1;
            if (NormalizePathForCompare(module.imagePath) == processImagePath) {
                best = &module;
                break;
            }
        }
    }

    if (best == nullptr) {
        best = &modules.front();
    }

    uint64_t entry = 0;
    if (!ResolveEntryPointFromModuleBase(best->baseAddress, entry)) {
        return false;
    }

    moduleBase = best->baseAddress;
    entryPointAddress = entry;
    return true;
}

bool Debugger::ReloadSymbols(bool forceDownload, const std::optional<std::wstring>& moduleFilter) {
    return ReloadSymbolsDetailed(forceDownload, moduleFilter, nullptr);
}

bool Debugger::ReloadSymbolsDetailed(bool forceDownload, const std::optional<std::wstring>& moduleFilter, std::wstring* outPdbPath) {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (!InitializeSymbolEngine()) {
        std::wcout << L"Symbol engine is not initialized.\n";
        return false;
    }

    SymRefreshModuleList(processHandle_);
    if (outPdbPath != nullptr) {
        outPdbPath->clear();
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules)) {
        std::wcout << L"Unable to enumerate modules for symbol reload.\n";
        return false;
    }
    if (modules.empty()) {
        std::wcout << L"No modules found.\n";
        return false;
    }

    std::wstring filterText;
    bool useFilter = false;
    bool filterByAddress = false;
    uint64_t filterAddress = 0;
    if (moduleFilter.has_value()) {
        filterText = TrimWhitespace(*moduleFilter);
        if (!filterText.empty() && ToLower(filterText) != L"*") {
            useFilter = true;
            filterByAddress = ParseUInt64(filterText, filterAddress);
            filterText = ToLower(filterText);
        }
    }

    DWORD oldOptions = SymGetOptions();
    if (forceDownload) {
        SymSetOptions(oldOptions & ~SYMOPT_DEFERRED_LOADS);
    }

    size_t matchedModules = 0;
    size_t loadedModules = 0;
    size_t failedModules = 0;

 for (auto __rangeIt2 = (modules).begin(); __rangeIt2 != (modules).end(); ++__rangeIt2) {
        const auto& module = *__rangeIt2;
        if (useFilter) {
            const std::wstring lowerName = ToLower(module.moduleName);
            const std::wstring lowerPath = ToLower(module.imagePath);
            bool matched = (lowerName == filterText) || (lowerPath.find(filterText) != std::wstring::npos);
            if (!matched && filterByAddress) {
                const uint64_t moduleEnd = module.baseAddress + static_cast<uint64_t>(module.size);
                matched = filterAddress >= module.baseAddress && filterAddress < moduleEnd;
            }
            if (!matched) {
                continue;
            }
        }

        ++matchedModules;
        const std::wstring moduleName = !module.moduleName.empty()
            ? module.moduleName
            : GetModuleNameFromPath(module.imagePath);
        SetLastError(ERROR_SUCCESS);
        const DWORD64 loadedBase = SymLoadModuleExW(
            processHandle_,
            nullptr,
            module.imagePath.empty() ? nullptr : module.imagePath.c_str(),
            moduleName.empty() ? nullptr : moduleName.c_str(),
            module.baseAddress,
            module.size,
            nullptr,
            0);
        const DWORD loadError = GetLastError();

        if (loadedBase == 0 && loadError != ERROR_SUCCESS) {
            ++failedModules;
            std::wcout << L"[sym] failed " << module.moduleName
                       << L" base=" << ToHex(module.baseAddress)
                       << L" error=" << loadError << L"\n";
            continue;
        }

        IMAGEHLP_MODULEW64 moduleInfo = IMAGEHLP_MODULEW64();
        moduleInfo.SizeOfStruct = sizeof(moduleInfo);
        if (SymGetModuleInfoW64(processHandle_, module.baseAddress, &moduleInfo)) {
            ++loadedModules;
            const std::wstring pdbName = moduleInfo.LoadedPdbName[0] != L'\0'
                ? std::wstring(moduleInfo.LoadedPdbName)
                : L"(no pdb)";
            if (outPdbPath != nullptr && outPdbPath->empty() && moduleInfo.LoadedPdbName[0] != L'\0') {
                *outPdbPath = moduleInfo.LoadedPdbName;
            }
            std::wcout << L"[sym] loaded " << module.moduleName
                       << L" -> " << pdbName << L"\n";
        } else {
            ++failedModules;
            std::wcout << L"[sym] loaded module but failed to query pdb for "
                       << module.moduleName << L"\n";
        }
    }

    if (forceDownload) {
        SymSetOptions(oldOptions);
    }

    if (matchedModules == 0) {
        std::wcout << L"No module matched filter.\n";
        return false;
    }

    std::wcout << L"Symbol reload complete. matched=" << matchedModules
               << L" loaded=" << loadedModules
               << L" failed=" << failedModules << L"\n";
    return failedModules == 0;
}

bool Debugger::AddSourceRoot(const std::wstring& path) {
    const std::wstring trimmed = TrimWhitespace(path);
    if (trimmed.empty()) {
        std::wcout << L"Source root path cannot be empty.\n";
        return false;
    }

    const std::wstring normalized = CanonicalizePathBestEffort(trimmed);
    const std::wstring normalizedLower = ToLower(normalized);

 for (auto __rangeIt3 = (sourceRoots_).begin(); __rangeIt3 != (sourceRoots_).end(); ++__rangeIt3) {
        const auto& root = *__rangeIt3;
        if (ToLower(root) == normalizedLower) {
            std::wcout << L"Source root already exists: " << normalized << L"\n";
            return true;
        }
    }

    sourceRoots_.push_back(normalized);
    std::wcout << L"Added source root: " << normalized << L"\n";
    return true;
}

bool Debugger::RemoveSourceRoot(const std::wstring& path) {
    const std::wstring trimmed = TrimWhitespace(path);
    if (trimmed.empty()) {
        std::wcout << L"Source root path cannot be empty.\n";
        return false;
    }

    const std::wstring target = ToLower(trimmed);
    const auto oldSize = sourceRoots_.size();
    sourceRoots_.erase(
        std::remove_if(sourceRoots_.begin(), sourceRoots_.end(),
                       [&](const std::wstring& root) -> bool {
                           const std::wstring rootLower = ToLower(root);
                           return rootLower == target || rootLower.find(target) != std::wstring::npos;
                       }),
        sourceRoots_.end());

    if (sourceRoots_.size() == oldSize) {
        std::wcout << L"No matching source root found.\n";
        return false;
    }
    std::wcout << L"Source root removed.\n";
    return true;
}

void Debugger::ClearSourceRoots() {
    sourceRoots_.clear();
    std::wcout << L"All source roots cleared.\n";
}

void Debugger::ListSourceRoots() const {
    std::wcout << L"--- Source Roots ---\n";
    if (sourceRoots_.empty()) {
        std::wcout << L"(none)\n";
        return;
    }
    for (size_t i = 0; i < sourceRoots_.size(); ++i) {
        std::wcout << L"[" << i << L"] " << sourceRoots_[i] << L"\n";
    }
}

std::wstring Debugger::LocalizeSourcePath(const std::wstring& sourcePath) const {
    if (sourcePath.empty()) {
        return L"";
    }

    if (PathExists(sourcePath)) {
        return sourcePath;
    }

    const std::wstring fileName = FileNameFromPath(sourcePath);
    const std::vector<std::wstring> segments = SplitPathSegments(sourcePath);

 for (auto __rangeIt4 = (sourceRoots_).begin(); __rangeIt4 != (sourceRoots_).end(); ++__rangeIt4) {
        const auto& root = *__rangeIt4;
        const std::wstring rootPath = CanonicalizePathBestEffort(root);

        if (!fileName.empty()) {
            const std::wstring fileCandidate = JoinPath(rootPath, fileName);
            if (PathExists(fileCandidate)) {
                return fileCandidate;
            }
        }

        for (size_t i = 0; i < segments.size(); ++i) {
            if (segments[i].find(L':') != std::wstring::npos) {
                continue;
            }
            std::wstring tail;
            for (size_t j = i; j < segments.size(); ++j) {
                if (segments[j].find(L':') != std::wstring::npos) {
                    continue;
                }
                tail = tail.empty() ? segments[j] : JoinPath(tail, segments[j]);
            }
            const std::wstring candidate = JoinPath(rootPath, tail);
            if (!tail.empty() && PathExists(candidate)) {
                return candidate;
            }
        }
    }

    return sourcePath;
}

bool Debugger::ResolveSourceLocation(uint64_t address, std::wstring& filePath, uint32_t& line, uint32_t& displacement) const {
    line = 0;
    filePath.clear();
    displacement = 0;
    if (!symbolsInitialized_ || processHandle_ == nullptr) {
        return false;
    }

    IMAGEHLP_LINEW64 lineInfo = IMAGEHLP_LINEW64();
    lineInfo.SizeOfStruct = sizeof(lineInfo);
    DWORD disp = 0;
    if (!SymGetLineFromAddrW64(processHandle_, address, &disp, &lineInfo)) {
        return false;
    }

    line = lineInfo.LineNumber;
    displacement = disp;
    if (lineInfo.FileName != nullptr) {
        filePath = LocalizeSourcePath(lineInfo.FileName);
    }
    return true;
}

void Debugger::PrintSourceAtAddress(uint64_t address, size_t contextLines) const {
    uint32_t line = 0;
    uint32_t displacement = 0;
    std::wstring filePath;
    if (!ResolveSourceLocation(address, filePath, line, displacement)) {
        std::wcout << L"No source information for " << ToHex(address) << L".\n";
        return;
    }

    std::wcout << L"Source: " << filePath << L":" << line;
    if (displacement != 0) {
        std::wcout << L" (+" << displacement << L")";
    }
    std::wcout << L"\n";

    std::wstring text;
    if (!ReadTextFileToWide(filePath, text)) {
        std::wcout << L"Unable to open source file locally.\n";
        return;
    }

    std::vector<std::wstring> lines;
    std::wistringstream input(text);
    std::wstring row;
    while (std::getline(input, row)) {
        if (!row.empty() && row.back() == L'\r') {
            row.pop_back();
        }
        lines.push_back(row);
    }
    if (lines.empty() || line == 0 || line > lines.size()) {
        return;
    }

    const size_t lineIndex = static_cast<size_t>(line - 1);
    const size_t start = (lineIndex > contextLines) ? (lineIndex - contextLines) : 0;
    const size_t end = std::min(lines.size() - 1, lineIndex + contextLines);
    for (size_t i = start; i <= end; ++i) {
        std::wcout << (i == lineIndex ? L">" : L" ") << std::setw(6) << (i + 1) << L" | " << lines[i] << L"\n";
    }
}

bool Debugger::ResolveSourceAddress(const std::wstring& sourceFile, uint32_t line, uint64_t& address, std::wstring& matchedFile) {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (!InitializeSymbolEngine()) {
        std::wcout << L"Symbol engine is not initialized.\n";
        return false;
    }
    if (line == 0) {
        std::wcout << L"Line number must be greater than 0.\n";
        return false;
    }

    SourceBreakpointSearchContext ctx = SourceBreakpointSearchContext();
    ctx.queryLower = ToLower(TrimWhitespace(sourceFile));
    ctx.queryFileLower = ToLower(GetModuleNameFromPath(ctx.queryLower));
    ctx.line = line;

    SetLastError(ERROR_SUCCESS);
    SymEnumLinesW(processHandle_, 0, nullptr, nullptr, FindSourceLineCallback, &ctx);
    if (ctx.address == 0) {
        std::vector<ModuleRecord> modules;
        if (CollectModuleRecords(modules)) {
 for (auto __rangeIt5 = (modules).begin(); __rangeIt5 != (modules).end(); ++__rangeIt5) {
                const auto& module = *__rangeIt5;
                SymEnumLinesW(
                    processHandle_,
                    module.baseAddress,
                    nullptr,
                    nullptr,
                    FindSourceLineCallback,
                    &ctx);
                if (ctx.address != 0) {
                    break;
                }
            }
        }
    }
    if (ctx.address == 0) {
        std::wcout << L"No matching source line found for " << sourceFile << L":" << line << L".\n";
        return false;
    }
    address = static_cast<uint64_t>(ctx.address);
    matchedFile = ctx.file;
    return true;
}

bool Debugger::SetSourceBreakpoint(const std::wstring& sourceFile, uint32_t line) {
    uint64_t address = 0;
    std::wstring matchedFile;
    if (!ResolveSourceAddress(sourceFile, line, address, matchedFile)) {
        return false;
    }

    const int bpId = AddSoftwareBreakpoint(address);
    if (bpId < 0) {
        return false;
    }
    std::wcout << L"Source breakpoint #" << bpId << L" set at "
               << matchedFile << L":" << line << L" addr=" << ToHex(address) << L"\n";
    return true;
}

bool Debugger::LoadScriptFile(const std::wstring& path) {
    std::wstring scriptText;
    if (!ReadTextFileToWide(path, scriptText)) {
        std::wcout << L"Failed to open script file: " << path << L"\n";
        return false;
    }

    scriptPath_ = path;
    scriptLines_.clear();
    scriptLabels_.clear();
    scriptBreakpoints_.clear();
    scriptVariables_.clear();
    scriptCursor_ = 0;
    scriptResumePastBreakpoint_ = false;

    std::wistringstream input(scriptText);
    std::wstring line;
    size_t sourceLine = 1;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }
        const std::wstring trimmed = TrimWhitespace(line);
        if (trimmed.empty() || IsScriptComment(trimmed)) {
            ++sourceLine;
            continue;
        }
        ScriptLine scriptLine;
        scriptLine.sourceLine = sourceLine;
        scriptLine.text = line;
        scriptLines_.push_back(scriptLine);
        ++sourceLine;
    }

    for (size_t i = 0; i < scriptLines_.size(); ++i) {
        const auto tokens = Tokenize(TrimWhitespace(scriptLines_[i].text));
        if (tokens.empty()) {
            continue;
        }
        const std::wstring cmd = ToLower(tokens[0]);
        if (cmd != L"label") {
            continue;
        }
        if (tokens.size() != 2) {
            std::wcout << L"Invalid label directive on script line " << scriptLines_[i].sourceLine << L".\n";
            return false;
        }
        const std::wstring name = ToLower(tokens[1]);
        if (scriptLabels_.find(name) != scriptLabels_.end()) {
            std::wcout << L"Duplicate label: " << tokens[1] << L"\n";
            return false;
        }
        scriptLabels_[name] = i + 1;
    }

    scriptLoaded_ = true;
    std::wcout << L"Script loaded: " << path
               << L" (" << scriptLines_.size() << L" executable lines, "
               << scriptLabels_.size() << L" labels)\n";
    logger_.Log(L"Script loaded path=" + path + L" lines=" + ToWStringCompat(scriptLines_.size()));
    return true;
}

void Debugger::ClearScriptState() {
    scriptPath_.clear();
    scriptLines_.clear();
    scriptLabels_.clear();
    scriptVariables_.clear();
    scriptBreakpoints_.clear();
    scriptCursor_ = 0;
    scriptLoaded_ = false;
    scriptResumePastBreakpoint_ = false;
}

void Debugger::ShowScript() const {
    if (!scriptLoaded_) {
        std::wcout << L"No script loaded.\n";
        return;
    }

    std::wcout << L"--- Script ---\n";
    std::wcout << L"Path: " << scriptPath_ << L"\n";
    std::wcout << L"Lines: " << scriptLines_.size() << L"\n";

    for (size_t i = 0; i < scriptLines_.size(); ++i) {
        const auto& line = scriptLines_[i];
        const wchar_t currentMarker = (i == scriptCursor_) ? L'>' : L' ';
        const wchar_t bpMarker = (scriptBreakpoints_.find(line.sourceLine) != scriptBreakpoints_.end()) ? L'*' : L' ';
        std::wcout << currentMarker << bpMarker << L" "
                   << std::setw(4) << line.sourceLine << L" | "
                   << line.text << L"\n";
    }
}

void Debugger::ShowScriptVariables() const {
    std::wcout << L"--- Script Variables ---\n";
    std::wcout << L"${pid}=" << processId_ << L"\n";
    std::wcout << L"${active}=" << (active_ ? L"1" : L"0") << L"\n";
    std::wcout << L"${stopped}=" << (stopState_.valid ? L"1" : L"0") << L"\n";
    std::wcout << L"${tid}=" << (stopState_.valid ? ToWStringCompat(stopState_.threadId) : L"0") << L"\n";
    std::wcout << L"${ip}=" << (stopState_.valid ? ToHex(GetInstructionPointer(stopState_.context)) : L"0x0") << L"\n";
    std::wcout << L"${exception}=" << (stopState_.valid ? ExceptionCodeToString(stopState_.exceptionCode) : L"none") << L"\n";

    if (scriptVariables_.empty()) {
        std::wcout << L"(no user variables)\n";
        return;
    }

    for (auto it = scriptVariables_.begin(); it != scriptVariables_.end(); ++it) {
        const std::wstring& name = it->first;
        const std::wstring& value = it->second;
        std::wcout << L"${" << name << L"}=" << value << L"\n";
    }
}

bool Debugger::SetScriptBreakpoint(size_t sourceLine) {
    if (!scriptLoaded_) {
        std::wcout << L"No script loaded.\n";
        return false;
    }

    bool exists = false;
 for (auto __rangeIt6 = (scriptLines_).begin(); __rangeIt6 != (scriptLines_).end(); ++__rangeIt6) {
        const auto& line = *__rangeIt6;
        if (line.sourceLine == sourceLine) {
            exists = true;
            break;
        }
    }
    if (!exists) {
        std::wcout << L"Script line " << sourceLine << L" is not executable.\n";
        return false;
    }

    scriptBreakpoints_.insert(sourceLine);
    std::wcout << L"Script breakpoint set on line " << sourceLine << L".\n";
    return true;
}

bool Debugger::RemoveScriptBreakpoint(size_t sourceLine) {
    if (scriptBreakpoints_.erase(sourceLine) == 0) {
        std::wcout << L"No script breakpoint found on line " << sourceLine << L".\n";
        return false;
    }
    std::wcout << L"Script breakpoint removed from line " << sourceLine << L".\n";
    return true;
}

void Debugger::ListScriptBreakpoints() const {
    std::wcout << L"--- Script Breakpoints ---\n";
    if (scriptBreakpoints_.empty()) {
        std::wcout << L"(none)\n";
        return;
    }

    std::vector<size_t> sorted(scriptBreakpoints_.begin(), scriptBreakpoints_.end());
    std::sort(sorted.begin(), sorted.end());
 for (auto __rangeIt7 = (sorted).begin(); __rangeIt7 != (sorted).end(); ++__rangeIt7) {
        size_t line = *__rangeIt7;
        std::wcout << L"line " << line << L"\n";
    }
}

bool Debugger::SaveEnvironmentSnapshot(const std::wstring& filePath) const {
    const std::wstring trimmedPath = TrimWhitespace(filePath);
    if (trimmedPath.empty()) {
        std::wcout << L"Environment snapshot path cannot be empty.\n";
        return false;
    }

    const auto boolText = [](bool value) -> const wchar_t* { return value ? L"yes" : L"no"; };
    const auto hardwareAccessText = [](HardwareAccessType access) -> const wchar_t* {
        switch (access.value) {
        case HardwareAccessType::Execute:
            return L"exec";
        case HardwareAccessType::Write:
            return L"write";
        case HardwareAccessType::Access:
        default:
            return L"access";
        }
    };
    const auto exceptionSetText = [](const std::unordered_set<DWORD>& codes) -> std::wstring {
        std::vector<DWORD> ordered(codes.begin(), codes.end());
        std::sort(ordered.begin(), ordered.end());
        if (ordered.empty()) {
            return std::wstring(L"(none)");
        }
        std::wstringstream ss;
        for (size_t i = 0; i < ordered.size(); ++i) {
            if (i > 0) {
                ss << L", ";
            }
            ss << Debugger::ExceptionCodeToString(ordered[i]);
        }
        return ss.str();
    };

    std::wstringstream report;
    report << L"WinDbgLite Environment Snapshot\n";
    report << L"Generated: " << NowTimestamp() << L"\n\n";

    report << L"[Session]\n";
    report << L"active=" << boolText(active_) << L"\n";
    report << L"attached=" << boolText(attached_) << L"\n";
    report << L"process_id=" << processId_ << L"\n";
    report << L"paused=" << boolText(pendingEvent_.valid && stopState_.valid) << L"\n";
    report << L"symbols_initialized=" << boolText(symbolsInitialized_) << L"\n";
    report << L"symbol_path=" << (symbolSearchPath_.empty() ? L"(empty)" : symbolSearchPath_) << L"\n";
    report << L"symbol_cache_dir=" << (symbolCacheDirectory_.empty() ? L"(empty)" : symbolCacheDirectory_) << L"\n";
    report << L"symbol_server_url=" << (symbolServerUrl_.empty() ? L"(empty)" : symbolServerUrl_) << L"\n";
    report << L"main_module_base=" << (mainModuleBase_ == 0 ? L"(unresolved)" : ToHex(mainModuleBase_)) << L"\n";
    report << L"entry_point=" << (entryPointAddress_ == 0 ? L"(unresolved)" : ToHex(entryPointAddress_)) << L"\n";
    if (stopState_.valid) {
        report << L"stop_reason=" << stopState_.reason << L"\n";
        report << L"stop_tid=" << stopState_.threadId << L"\n";
        report << L"stop_address=" << ToHex(stopState_.address) << L"\n";
        report << L"stop_ip=" << ToHex(GetInstructionPointer(stopState_.context)) << L"\n";
        report << L"stop_exception=" << ExceptionCodeToString(stopState_.exceptionCode) << L"\n";
    } else {
        report << L"stop_state=(none)\n";
    }
    report << L"\n";

    report << L"[SourceRoots]\n";
    if (sourceRoots_.empty()) {
        report << L"(none)\n";
    } else {
        for (size_t i = 0; i < sourceRoots_.size(); ++i) {
            report << L"[" << i << L"] " << sourceRoots_[i] << L"\n";
        }
    }
    report << L"\n";

    report << L"[ExceptionSettings]\n";
    report << L"debug.ignore_all=" << boolText(debuggingExceptionRules_.ignoreAll) << L"\n";
    report << L"debug.ignored_codes=" << exceptionSetText(debuggingExceptionRules_.ignoredCodes) << L"\n";
    report << L"run.ignore_all=" << boolText(runtimeExceptionRules_.ignoreAll) << L"\n";
    report << L"run.ignored_codes=" << exceptionSetText(runtimeExceptionRules_.ignoredCodes) << L"\n";
    report << L"step.ignore_all=" << boolText(steppingExceptionRules_.ignoreAll) << L"\n";
    report << L"step.ignored_codes=" << exceptionSetText(steppingExceptionRules_.ignoredCodes) << L"\n";
    if (runStopExpressions_.empty()) {
        report << L"run_stop_expressions=(none)\n";
    } else {
        for (size_t i = 0; i < runStopExpressions_.size(); ++i) {
            report << L"run_stop_expression[" << i << L"]=" << runStopExpressions_[i] << L"\n";
        }
    }
    report << L"\n";

    report << L"[Breakpoints.Software]\n";
    if (softwareBreakpoints_.empty()) {
        report << L"(none)\n";
    } else {
        for (auto it = softwareBreakpoints_.begin(); it != softwareBreakpoints_.end(); ++it) {
            const int id = it->first;
            const SoftwareBreakpoint& bp = it->second;
            report << L"id=" << id
                   << L" address=" << ToHex(bp.address)
                   << L" enabled=" << boolText(bp.enabled)
                   << L" hits=" << bp.hitCount;
            if (!bp.condition.empty()) {
                report << L" condition=" << bp.condition;
            }
            report << L"\n";
        }
    }
    report << L"\n";

    report << L"[Breakpoints.Hardware]\n";
    if (hardwareBreakpoints_.empty()) {
        report << L"(none)\n";
    } else {
        for (auto it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
            const int id = it->first;
            const HardwareBreakpoint& bp = it->second;
            report << L"id=" << id
                   << L" slot=" << bp.slot
                   << L" address=" << ToHex(bp.address)
                   << L" access=" << hardwareAccessText(bp.access)
                   << L" length=" << bp.length
                   << L" thread_id=" << (bp.threadId == 0 ? L"all" : ToWStringCompat(bp.threadId))
                   << L" enabled=" << boolText(bp.enabled)
                   << L" hits=" << bp.hitCount;
            if (!bp.condition.empty()) {
                report << L" condition=" << bp.condition;
            }
            report << L"\n";
        }
    }
    report << L"\n";

    report << L"[Breakpoints.Memory]\n";
    if (memoryBreakpoints_.empty()) {
        report << L"(none)\n";
    } else {
        for (auto it = memoryBreakpoints_.begin(); it != memoryBreakpoints_.end(); ++it) {
            const int id = it->first;
            const MemoryBreakpoint& bp = it->second;
            report << L"id=" << id
                   << L" address=" << ToHex(bp.address)
                   << L" size=" << bp.size
                   << L" access=" << MemoryAccessToString(bp.access)
                   << L" enabled=" << boolText(bp.enabled)
                   << L" hits=" << bp.hitCount;
            if (!bp.condition.empty()) {
                report << L" condition=" << bp.condition;
            }
            report << L"\n";
        }
    }
    report << L"\n";

    report << L"[Plugins]\n";
    if (pluginModules_.empty()) {
        report << L"(none)\n";
    } else {
 for (auto __rangeIt8 = (pluginModules_).begin(); __rangeIt8 != (pluginModules_).end(); ++__rangeIt8) {
            const auto& plugin = *__rangeIt8;
            report << L"id=" << plugin.id
                   << L" name=" << plugin.name
                   << L" enabled=" << boolText(plugin.enabled)
                   << L" subscribed_events=" << boolText(plugin.subscribedEvents)
                   << L" path=" << plugin.path;
            if (!plugin.version.empty()) {
                report << L" version=" << plugin.version;
            }
            if (!plugin.description.empty()) {
                report << L" description=" << plugin.description;
            }
            report << L"\n";
        }
    }
    report << L"\n";

    report << L"[ScriptEngine]\n";
    report << L"script_loaded=" << boolText(scriptLoaded_) << L"\n";
    report << L"script_path=" << (scriptPath_.empty() ? L"(none)" : scriptPath_) << L"\n";
    report << L"script_cursor=" << scriptCursor_ << L"\n";
    report << L"script_line_count=" << scriptLines_.size() << L"\n";
    if (scriptBreakpoints_.empty()) {
        report << L"script_breakpoints=(none)\n";
    } else {
        std::vector<size_t> scriptBreakpoints(scriptBreakpoints_.begin(), scriptBreakpoints_.end());
        std::sort(scriptBreakpoints.begin(), scriptBreakpoints.end());
        report << L"script_breakpoints=";
        for (size_t i = 0; i < scriptBreakpoints.size(); ++i) {
            if (i > 0) {
                report << L",";
            }
            report << scriptBreakpoints[i];
        }
        report << L"\n";
    }
    if (scriptVariables_.empty()) {
        report << L"script_variables=(none)\n";
    } else {
        for (auto it = scriptVariables_.begin(); it != scriptVariables_.end(); ++it) {
            const std::wstring& name = it->first;
            const std::wstring& value = it->second;
            report << L"var." << name << L"=" << value << L"\n";
        }
    }
    report << L"\n";

    report << L"[Trace]\n";
    report << L"snapshot_history_count=" << stopHistory_.size() << L"\n";
    report << L"named_snapshot_count=" << namedSnapshots_.size() << L"\n";
    report << L"pending_software_reinsert_count=" << pendingSoftwareReinsert_.size() << L"\n";
    report << L"pending_memory_rearm_count=" << pendingMemoryRearm_.size() << L"\n";
    report << L"\n";

    report << L"[InstructionComments]\n";
    if (instructionComments_.empty()) {
        report << L"(none)\n";
    } else {
        for (auto it = instructionComments_.begin(); it != instructionComments_.end(); ++it) {
            const uint64_t address = it->first;
            const std::wstring& comment = it->second;
            report << L"comment[" << ToHex(address) << L"]=" << comment << L"\n";
        }
    }

    std::wstring error;
    if (!WriteWideTextUtf8File(trimmedPath, report.str(), error)) {
        std::wcout << L"Failed to save environment snapshot: " << error << L"\n";
        return false;
    }

    std::wcout << L"Environment snapshot saved to: " << trimmedPath << L"\n";
    return true;
}

bool Debugger::LoadEnvironmentSnapshot(const std::wstring& filePath) {
    const std::wstring trimmedPath = TrimWhitespace(filePath);
    if (trimmedPath.empty()) {
        std::wcout << L"Environment snapshot path cannot be empty.\n";
        return false;
    }

    std::wstring text;
    if (!ReadTextFileToWide(trimmedPath, text)) {
        std::wcout << L"Failed to read environment snapshot file: " << trimmedPath << L"\n";
        return false;
    }

    struct SavedSoftwareBp {
        uint64_t address;
        bool enabled;
        std::wstring condition;

        SavedSoftwareBp()
            : address(0),
              enabled(true) {
        }
    };
    struct SavedHardwareBp {
        int slot;
        uint64_t address;
        HardwareAccessType access;
        int length;
        DWORD threadId;
        bool enabled;
        std::wstring condition;

        SavedHardwareBp()
            : slot(0),
              address(0),
              access(HardwareAccessType::Execute),
              length(1),
              threadId(0),
              enabled(true) {
        }
    };
    struct SavedMemoryBp {
        uint64_t address;
        size_t size;
        MemoryAccessType access;
        bool enabled;
        std::wstring condition;

        SavedMemoryBp()
            : address(0),
              size(1),
              access(MemoryAccessType::Read),
              enabled(true) {
        }
    };
    struct SavedPlugin {
        std::wstring path;
        std::wstring name;
        bool enabled;

        SavedPlugin()
            : enabled(true) {
        }
    };

    auto parseBool = [](const std::wstring& value, bool& out) -> bool {
        const std::wstring v = Debugger::ToLower(TrimWhitespace(value));
        if (v == L"1" || v == L"yes" || v == L"true" || v == L"on") {
            out = true;
            return true;
        }
        if (v == L"0" || v == L"no" || v == L"false" || v == L"off") {
            out = false;
            return true;
        }
        return false;
    };
    auto parseKeyValueToken = [](const std::wstring& token, std::wstring& key, std::wstring& value) -> bool {
        const size_t eq = token.find(L'=');
        if (eq == std::wstring::npos) {
            return false;
        }
        key = token.substr(0, eq);
        value = token.substr(eq + 1);
        return !key.empty();
    };
    auto parseCodeList = [&](const std::wstring& raw, std::unordered_set<DWORD>& outCodes) {
        outCodes.clear();
        const std::wstring trimmed = TrimWhitespace(raw);
        if (trimmed.empty() || trimmed == L"(none)") {
            return;
        }
        size_t start = 0;
        while (start < trimmed.size()) {
            size_t comma = trimmed.find(L',', start);
            std::wstring token = TrimWhitespace(
                comma == std::wstring::npos
                    ? trimmed.substr(start)
                    : trimmed.substr(start, comma - start));
            if (!token.empty()) {
                DWORD code = 0;
                if (ParseExceptionCodeToken(token, code)) {
                    outCodes.insert(code);
                }
            }
            if (comma == std::wstring::npos) {
                break;
            }
            start = comma + 1;
        }
    };

    bool sawSession = false;
    bool sawSourceRoots = false;
    bool sawExceptionSettings = false;
    bool sawSoftwareBreakpoints = false;
    bool sawHardwareBreakpoints = false;
    bool sawMemoryBreakpoints = false;
    bool sawPlugins = false;
    bool sawScriptEngine = false;
    bool sawInstructionComments = false;

    std::optional<std::wstring> loadedSymbolPath;
    std::optional<std::wstring> loadedSymbolCacheDir;
    std::optional<std::wstring> loadedSymbolServerUrl;
    std::vector<std::wstring> loadedSourceRoots;
    ExceptionRuleSet loadedDebugRules = debuggingExceptionRules_;
    ExceptionRuleSet loadedRuntimeRules = runtimeExceptionRules_;
    ExceptionRuleSet loadedSteppingRules = steppingExceptionRules_;
    std::vector<std::wstring> loadedRunStopExpressions;
    std::vector<SavedSoftwareBp> loadedSoftwareBps;
    std::vector<SavedHardwareBp> loadedHardwareBps;
    std::vector<SavedMemoryBp> loadedMemoryBps;
    std::vector<SavedPlugin> loadedPlugins;
    bool loadedScriptEnabled = false;
    std::wstring loadedScriptPath;
    size_t loadedScriptCursor = 0;
    std::vector<size_t> loadedScriptBreakpoints;
    std::unordered_map<std::wstring, std::wstring> loadedScriptVariables;
    std::map<uint64_t, std::wstring> loadedInstructionComments;

    std::wstring section;
    std::wistringstream input(text);
    std::wstring line;
    while (std::getline(input, line)) {
        line = TrimWhitespace(line);
        if (line.empty()) {
            continue;
        }
        if (line.rfind(L"\uFEFF", 0) == 0) {
            line = TrimWhitespace(line.substr(1));
            if (line.empty()) {
                continue;
            }
        }
        if (line.front() == L'[' && line.back() == L']') {
            section = line.substr(1, line.size() - 2);
            continue;
        }

        if (section == L"Session") {
            sawSession = true;
            std::wstring key;
            std::wstring value;
            if (!parseKeyValueToken(line, key, value)) {
                continue;
            }
            if (key == L"symbol_path") {
                loadedSymbolPath = value;
            } else if (key == L"symbol_cache_dir") {
                loadedSymbolCacheDir = value;
            } else if (key == L"symbol_server_url") {
                loadedSymbolServerUrl = value;
            }
            continue;
        }

        if (section == L"SourceRoots") {
            sawSourceRoots = true;
            if (line == L"(none)") {
                continue;
            }
            const size_t close = line.find(L']');
            if (line.rfind(L"[", 0) == 0 && close != std::wstring::npos && close + 1 < line.size()) {
                const std::wstring root = TrimWhitespace(line.substr(close + 1));
                if (!root.empty()) {
                    loadedSourceRoots.push_back(root);
                }
            }
            continue;
        }

        if (section == L"ExceptionSettings") {
            sawExceptionSettings = true;
            std::wstring key;
            std::wstring value;
            if (!parseKeyValueToken(line, key, value)) {
                continue;
            }
            bool toggle = false;
            if (key == L"debug.ignore_all" && parseBool(value, toggle)) {
                loadedDebugRules.ignoreAll = toggle;
            } else if (key == L"run.ignore_all" && parseBool(value, toggle)) {
                loadedRuntimeRules.ignoreAll = toggle;
            } else if (key == L"step.ignore_all" && parseBool(value, toggle)) {
                loadedSteppingRules.ignoreAll = toggle;
            } else if (key == L"debug.ignored_codes") {
                parseCodeList(value, loadedDebugRules.ignoredCodes);
            } else if (key == L"run.ignored_codes") {
                parseCodeList(value, loadedRuntimeRules.ignoredCodes);
            } else if (key == L"step.ignored_codes") {
                parseCodeList(value, loadedSteppingRules.ignoredCodes);
            } else if (key.rfind(L"run_stop_expression[", 0) == 0) {
                loadedRunStopExpressions.push_back(value);
            } else if (key == L"run_stop_expressions" && value == L"(none)") {
                loadedRunStopExpressions.clear();
            }
            continue;
        }

        if (section == L"Breakpoints.Software") {
            sawSoftwareBreakpoints = true;
            if (line == L"(none)") {
                continue;
            }
            SavedSoftwareBp item = SavedSoftwareBp();
            size_t conditionPos = line.find(L" condition=");
            std::wstring base = conditionPos == std::wstring::npos ? line : line.substr(0, conditionPos);
            if (conditionPos != std::wstring::npos) {
                item.condition = line.substr(conditionPos + 11);
            }
            const auto tokens = Tokenize(base);
 for (auto __rangeIt9 = (tokens).begin(); __rangeIt9 != (tokens).end(); ++__rangeIt9) {
                const auto& token = *__rangeIt9;
                std::wstring key;
                std::wstring value;
                if (!parseKeyValueToken(token, key, value)) {
                    continue;
                }
                if (key == L"address") {
                    ParseUInt64(value, item.address);
                } else if (key == L"enabled") {
                    parseBool(value, item.enabled);
                }
            }
            if (item.address != 0) {
                loadedSoftwareBps.push_back(item);
            }
            continue;
        }

        if (section == L"Breakpoints.Hardware") {
            sawHardwareBreakpoints = true;
            if (line == L"(none)") {
                continue;
            }
            SavedHardwareBp item = SavedHardwareBp();
            size_t conditionPos = line.find(L" condition=");
            std::wstring base = conditionPos == std::wstring::npos ? line : line.substr(0, conditionPos);
            if (conditionPos != std::wstring::npos) {
                item.condition = line.substr(conditionPos + 11);
            }
            const auto tokens = Tokenize(base);
 for (auto __rangeIt10 = (tokens).begin(); __rangeIt10 != (tokens).end(); ++__rangeIt10) {
                const auto& token = *__rangeIt10;
                std::wstring key;
                std::wstring value;
                if (!parseKeyValueToken(token, key, value)) {
                    continue;
                }
                if (key == L"slot") {
                    uint64_t parsed = 0;
                    if (ParseUInt64(value, parsed)) {
                        item.slot = static_cast<int>(parsed);
                    }
                } else if (key == L"address") {
                    ParseUInt64(value, item.address);
                } else if (key == L"access") {
                    auto parsedAccess = ParseHardwareAccess(value);
                    if (parsedAccess.has_value()) {
                        item.access = *parsedAccess;
                    }
                } else if (key == L"length") {
                    uint64_t parsed = 0;
                    if (ParseUInt64(value, parsed)) {
                        item.length = static_cast<int>(parsed);
                    }
                } else if (key == L"thread_id") {
                    if (ToLower(value) == L"all") {
                        item.threadId = 0;
                    } else {
                        uint32_t tid = 0;
                        if (ParseUInt32(value, tid)) {
                            item.threadId = tid;
                        }
                    }
                } else if (key == L"enabled") {
                    parseBool(value, item.enabled);
                }
            }
            if (item.address != 0) {
                loadedHardwareBps.push_back(item);
            }
            continue;
        }

        if (section == L"Breakpoints.Memory") {
            sawMemoryBreakpoints = true;
            if (line == L"(none)") {
                continue;
            }
            SavedMemoryBp item = SavedMemoryBp();
            size_t conditionPos = line.find(L" condition=");
            std::wstring base = conditionPos == std::wstring::npos ? line : line.substr(0, conditionPos);
            if (conditionPos != std::wstring::npos) {
                item.condition = line.substr(conditionPos + 11);
            }
            const auto tokens = Tokenize(base);
 for (auto __rangeIt11 = (tokens).begin(); __rangeIt11 != (tokens).end(); ++__rangeIt11) {
                const auto& token = *__rangeIt11;
                std::wstring key;
                std::wstring value;
                if (!parseKeyValueToken(token, key, value)) {
                    continue;
                }
                if (key == L"address") {
                    ParseUInt64(value, item.address);
                } else if (key == L"size") {
                    uint64_t parsed = 0;
                    if (ParseUInt64(value, parsed) && parsed > 0) {
                        item.size = static_cast<size_t>(parsed);
                    }
                } else if (key == L"access") {
                    auto parsedAccess = ParseMemoryAccess(value);
                    if (parsedAccess.has_value()) {
                        item.access = *parsedAccess;
                    }
                } else if (key == L"enabled") {
                    parseBool(value, item.enabled);
                }
            }
            if (item.address != 0 && item.size != 0) {
                loadedMemoryBps.push_back(item);
            }
            continue;
        }

        if (section == L"Plugins") {
            sawPlugins = true;
            if (line == L"(none)") {
                continue;
            }
            SavedPlugin item = SavedPlugin();
            const auto tokens = Tokenize(line);
 for (auto __rangeIt12 = (tokens).begin(); __rangeIt12 != (tokens).end(); ++__rangeIt12) {
                const auto& token = *__rangeIt12;
                std::wstring key;
                std::wstring value;
                if (!parseKeyValueToken(token, key, value)) {
                    continue;
                }
                if (key == L"path") {
                    item.path = value;
                } else if (key == L"name") {
                    item.name = value;
                } else if (key == L"enabled") {
                    parseBool(value, item.enabled);
                }
            }
            if (!item.path.empty()) {
                loadedPlugins.push_back(item);
            }
            continue;
        }

        if (section == L"ScriptEngine") {
            sawScriptEngine = true;
            std::wstring key;
            std::wstring value;
            if (!parseKeyValueToken(line, key, value)) {
                continue;
            }
            if (key == L"script_loaded") {
                parseBool(value, loadedScriptEnabled);
            } else if (key == L"script_path") {
                loadedScriptPath = value;
            } else if (key == L"script_cursor") {
                uint64_t parsed = 0;
                if (ParseUInt64(value, parsed)) {
                    loadedScriptCursor = static_cast<size_t>(parsed);
                }
            } else if (key == L"script_breakpoints") {
                loadedScriptBreakpoints.clear();
                if (value != L"(none)") {
                    size_t start = 0;
                    while (start < value.size()) {
                        const size_t comma = value.find(L',', start);
                        const std::wstring token = TrimWhitespace(
                            comma == std::wstring::npos ? value.substr(start) : value.substr(start, comma - start));
                        uint64_t parsed = 0;
                        if (ParseUInt64(token, parsed) && parsed > 0) {
                            loadedScriptBreakpoints.push_back(static_cast<size_t>(parsed));
                        }
                        if (comma == std::wstring::npos) {
                            break;
                        }
                        start = comma + 1;
                    }
                }
            } else if (key.rfind(L"var.", 0) == 0) {
                loadedScriptVariables[key.substr(4)] = value;
            }
            continue;
        }

        if (section == L"InstructionComments") {
            sawInstructionComments = true;
            if (line == L"(none)") {
                continue;
            }
            std::wstring key;
            std::wstring value;
            if (!parseKeyValueToken(line, key, value)) {
                continue;
            }
            if (key.rfind(L"comment[", 0) == 0 && key.size() > 9 && key.back() == L']') {
                const std::wstring addressToken = key.substr(8, key.size() - 9);
                uint64_t address = 0;
                if (ParseUInt64(addressToken, address) && address != 0) {
                    loadedInstructionComments[address] = value;
                }
            }
            continue;
        }
    }

    if (sawSession) {
        if (loadedSymbolCacheDir.has_value() && *loadedSymbolCacheDir != L"(empty)") {
            symbolCacheDirectory_ = *loadedSymbolCacheDir;
        }
        if (loadedSymbolServerUrl.has_value() && *loadedSymbolServerUrl != L"(empty)") {
            symbolServerUrl_ = *loadedSymbolServerUrl;
        }
        if (loadedSymbolPath.has_value() && *loadedSymbolPath != L"(empty)" && !loadedSymbolPath->empty()) {
            SetSymbolSearchPath(*loadedSymbolPath);
        }
    }

    if (sawSourceRoots) {
        sourceRoots_.clear();
 for (auto __rangeIt13 = (loadedSourceRoots).begin(); __rangeIt13 != (loadedSourceRoots).end(); ++__rangeIt13) {
            const auto& root = *__rangeIt13;
            AddSourceRoot(root);
        }
    }

    if (sawExceptionSettings) {
        debuggingExceptionRules_ = std::move(loadedDebugRules);
        runtimeExceptionRules_ = std::move(loadedRuntimeRules);
        steppingExceptionRules_ = std::move(loadedSteppingRules);
        runStopExpressions_ = std::move(loadedRunStopExpressions);
    }

    const bool wantsBreakpoints = sawSoftwareBreakpoints || sawHardwareBreakpoints || sawMemoryBreakpoints;
    const bool hasBreakpointEntries =
        !loadedSoftwareBps.empty() || !loadedHardwareBps.empty() || !loadedMemoryBps.empty();
    if (wantsBreakpoints) {
        if (!active_) {
            if (hasBreakpointEntries) {
                std::wcout << L"Environment loaded, but breakpoint entries were skipped because no debuggee is active.\n";
            }
        } else {
            RemoveAllBreakpoints();
 for (auto __rangeIt14 = (loadedSoftwareBps).begin(); __rangeIt14 != (loadedSoftwareBps).end(); ++__rangeIt14) {
                const auto& bp = *__rangeIt14;
                const int id = AddSoftwareBreakpoint(bp.address);
                if (id > 0) {
                    if (!bp.enabled) {
                        DisableBreakpoint(id);
                    }
                    if (!bp.condition.empty()) {
                        SetBreakpointCondition(id, bp.condition);
                    }
                }
            }
 for (auto __rangeIt15 = (loadedHardwareBps).begin(); __rangeIt15 != (loadedHardwareBps).end(); ++__rangeIt15) {
                const auto& bp = *__rangeIt15;
                const int id = AddHardwareBreakpoint(bp.slot, bp.address, bp.access, bp.length, bp.threadId);
                if (id > 0) {
                    if (!bp.enabled) {
                        DisableBreakpoint(id);
                    }
                    if (!bp.condition.empty()) {
                        SetBreakpointCondition(id, bp.condition);
                    }
                }
            }
 for (auto __rangeIt16 = (loadedMemoryBps).begin(); __rangeIt16 != (loadedMemoryBps).end(); ++__rangeIt16) {
                const auto& bp = *__rangeIt16;
                const int id = AddMemoryBreakpoint(bp.address, bp.size, bp.access);
                if (id > 0) {
                    if (!bp.enabled) {
                        DisableBreakpoint(id);
                    }
                    if (!bp.condition.empty()) {
                        SetBreakpointCondition(id, bp.condition);
                    }
                }
            }
        }
    }

    if (sawPlugins) {
        UnloadAllPluginModules();
 for (auto __rangeIt17 = (loadedPlugins).begin(); __rangeIt17 != (loadedPlugins).end(); ++__rangeIt17) {
            const auto& plugin = *__rangeIt17;
            if (LoadPluginModule(plugin.path) && !plugin.enabled) {
                const std::wstring token = plugin.name.empty() ? plugin.path : plugin.name;
                SetPluginModuleEnabled(token, false);
            }
        }
    }

    if (sawScriptEngine) {
        if (!loadedScriptEnabled) {
            ClearScriptState();
            scriptVariables_.clear();
        } else if (!loadedScriptPath.empty() && loadedScriptPath != L"(none)") {
            if (LoadScriptFile(loadedScriptPath)) {
                scriptVariables_ = std::move(loadedScriptVariables);
                scriptBreakpoints_.clear();
 for (auto __rangeIt18 = (loadedScriptBreakpoints).begin(); __rangeIt18 != (loadedScriptBreakpoints).end(); ++__rangeIt18) {
                    size_t lineNumber = *__rangeIt18;
                    scriptBreakpoints_.insert(lineNumber);
                }
                scriptCursor_ = std::min(loadedScriptCursor, scriptLines_.size());
            }
        }
    }

    if (sawInstructionComments) {
        instructionComments_ = std::move(loadedInstructionComments);
    }

    std::wcout << L"Environment snapshot loaded from: " << trimmedPath << L"\n";
    return true;
}

std::wstring Debugger::ExpandScriptVariables(const std::wstring& text) const {
    if (text.empty()) {
        return text;
    }

    std::wstring out;
    out.reserve(text.size());

    size_t cursor = 0;
    while (cursor < text.size()) {
        const size_t varStart = text.find(L"${", cursor);
        if (varStart == std::wstring::npos) {
            out.append(text.substr(cursor));
            break;
        }
        out.append(text.substr(cursor, varStart - cursor));
        const size_t varEnd = text.find(L'}', varStart + 2);
        if (varEnd == std::wstring::npos) {
            out.append(text.substr(varStart));
            break;
        }

        std::wstring key = ToLower(TrimWhitespace(text.substr(varStart + 2, varEnd - (varStart + 2))));
        std::wstring value;
        if (key == L"pid") {
            value = ToWStringCompat(processId_);
        } else if (key == L"active") {
            value = active_ ? L"1" : L"0";
        } else if (key == L"stopped") {
            value = stopState_.valid ? L"1" : L"0";
        } else if (key == L"tid") {
            value = stopState_.valid ? ToWStringCompat(stopState_.threadId) : L"0";
        } else if (key == L"ip") {
            value = stopState_.valid ? ToHex(GetInstructionPointer(stopState_.context)) : L"0x0";
        } else if (key == L"exception") {
            value = stopState_.valid ? ExceptionCodeToString(stopState_.exceptionCode) : L"none";
        } else if (key == L"reason") {
            value = stopState_.valid ? stopState_.reason : L"none";
        } else if (key == L"scriptline") {
            value = (scriptCursor_ < scriptLines_.size())
                ? ToWStringCompat(scriptLines_[scriptCursor_].sourceLine)
                : L"0";
        } else {
            const auto it = scriptVariables_.find(key);
            if (it != scriptVariables_.end()) {
                value = it->second;
            }
        }

        out.append(value);
        cursor = varEnd + 1;
    }
    return out;
}

bool Debugger::ExecuteScriptLine(const ScriptLine& line, size_t& nextIndex) {
    const std::wstring trimmed = TrimWhitespace(line.text);
    if (trimmed.empty() || IsScriptComment(trimmed)) {
        return true;
    }

    const std::wstring expanded = ExpandScriptVariables(trimmed);
    const auto tokens = Tokenize(expanded);
    if (tokens.empty()) {
        return true;
    }

    const std::wstring cmd = ToLower(tokens[0]);
    if (cmd == L"label") {
        return true;
    }
    if (cmd == L"echo") {
        std::wcout << L"[script] " << JoinTokens(tokens, 1) << L"\n";
        return true;
    }
    if (cmd == L"sleep") {
        if (tokens.size() != 2) {
            std::wcout << L"Script line " << line.sourceLine << L": usage sleep <milliseconds>\n";
            return false;
        }
        uint64_t ms = 0;
        if (!ParseUInt64(tokens[1], ms)) {
            std::wcout << L"Script line " << line.sourceLine << L": invalid sleep value.\n";
            return false;
        }
        Sleep(static_cast<DWORD>(std::min<uint64_t>(ms, 60000)));
        return true;
    }
    if (cmd == L"set") {
        if (tokens.size() < 3) {
            std::wcout << L"Script line " << line.sourceLine << L": usage set <name> <value>\n";
            return false;
        }
        scriptVariables_[ToLower(tokens[1])] = JoinTokens(tokens, 2);
        return true;
    }
    if (cmd == L"unset") {
        if (tokens.size() != 2) {
            std::wcout << L"Script line " << line.sourceLine << L": usage unset <name>\n";
            return false;
        }
        scriptVariables_.erase(ToLower(tokens[1]));
        return true;
    }
    if (cmd == L"goto") {
        if (tokens.size() != 2) {
            std::wcout << L"Script line " << line.sourceLine << L": usage goto <label>\n";
            return false;
        }
        const auto it = scriptLabels_.find(ToLower(tokens[1]));
        if (it == scriptLabels_.end()) {
            std::wcout << L"Script line " << line.sourceLine << L": unknown label " << tokens[1] << L"\n";
            return false;
        }
        nextIndex = it->second;
        return true;
    }
    if (cmd == L"ifstopped" || cmd == L"ifrunning") {
        if (tokens.size() != 3 || ToLower(tokens[1]) != L"goto") {
            std::wcout << L"Script line " << line.sourceLine << L": usage "
                       << cmd << L" goto <label>\n";
            return false;
        }
        const bool shouldJump = (cmd == L"ifstopped") ? stopState_.valid : !stopState_.valid;
        if (!shouldJump) {
            return true;
        }
        const auto it = scriptLabels_.find(ToLower(tokens[2]));
        if (it == scriptLabels_.end()) {
            std::wcout << L"Script line " << line.sourceLine << L": unknown label " << tokens[2] << L"\n";
            return false;
        }
        nextIndex = it->second;
        return true;
    }
    if (cmd.rfind(L"script", 0) == 0) {
        std::wcout << L"Script line " << line.sourceLine << L": nested script control commands are not allowed.\n";
        return false;
    }
    return ExecuteCommand(tokens, true);
}

bool Debugger::RunScript(bool singleStep) {
    if (!scriptLoaded_) {
        std::wcout << L"No script loaded. Use scriptload <file> first.\n";
        return false;
    }
    if (scriptCursor_ >= scriptLines_.size()) {
        std::wcout << L"Script is at end. Use scriptreset to run again.\n";
        return true;
    }

    size_t executed = 0;
    size_t guard = 0;
    const size_t kMaxScriptOpsPerRun = 100000;
    while (scriptCursor_ < scriptLines_.size()) {
        if (!singleStep && ++guard > kMaxScriptOpsPerRun) {
            std::wcout << L"Script execution aborted after " << kMaxScriptOpsPerRun
                       << L" operations (possible infinite loop).\n";
            return false;
        }

        const auto& line = scriptLines_[scriptCursor_];
        if (!singleStep && scriptBreakpoints_.find(line.sourceLine) != scriptBreakpoints_.end()) {
            if (!scriptResumePastBreakpoint_) {
                scriptResumePastBreakpoint_ = true;
                std::wcout << L"Script paused at breakpoint line " << line.sourceLine
                           << L" (run again or use scriptstep to continue).\n";
                return true;
            }
        }

        size_t nextIndex = scriptCursor_ + 1;
        if (singleStep) {
            std::wcout << L"[script] step line " << line.sourceLine << L": " << line.text << L"\n";
        }
        if (!ExecuteScriptLine(line, nextIndex)) {
            std::wcout << L"Script execution failed at line " << line.sourceLine << L".\n";
            scriptResumePastBreakpoint_ = false;
            return false;
        }
        scriptCursor_ = nextIndex;
        ++executed;
        scriptResumePastBreakpoint_ = false;

        if (singleStep) {
            return true;
        }
    }

    std::wcout << L"Script completed (" << executed << L" command(s) executed).\n";
    return true;
}

bool Debugger::RunScriptUntilLabel(const std::wstring& label) {
    if (!scriptLoaded_) {
        std::wcout << L"No script loaded. Use scriptload <file> first.\n";
        return false;
    }

    const std::wstring labelKey = ToLower(TrimWhitespace(label));
    if (labelKey.empty()) {
        std::wcout << L"Usage: scriptuntil <label>\n";
        return false;
    }

    const auto labelIt = scriptLabels_.find(labelKey);
    if (labelIt == scriptLabels_.end()) {
        std::wcout << L"Unknown script label: " << label << L"\n";
        return false;
    }

    const size_t targetIndex = labelIt->second;
    if (scriptCursor_ >= targetIndex) {
        std::wcout << L"Script cursor is already at/after label '" << label << L"'.\n";
        return true;
    }

    size_t executed = 0;
    size_t guard = 0;
    const size_t kMaxScriptOpsPerRun = 100000;

    while (scriptCursor_ < scriptLines_.size() && scriptCursor_ < targetIndex) {
        if (++guard > kMaxScriptOpsPerRun) {
            std::wcout << L"scriptuntil aborted after " << kMaxScriptOpsPerRun
                       << L" operations (possible infinite loop).\n";
            return false;
        }

        const auto& line = scriptLines_[scriptCursor_];
        if (scriptBreakpoints_.find(line.sourceLine) != scriptBreakpoints_.end()) {
            if (!scriptResumePastBreakpoint_) {
                scriptResumePastBreakpoint_ = true;
                std::wcout << L"Script paused at breakpoint line " << line.sourceLine
                           << L" before label '" << label << L"'.\n";
                return true;
            }
        }

        size_t nextIndex = scriptCursor_ + 1;
        if (!ExecuteScriptLine(line, nextIndex)) {
            std::wcout << L"Script execution failed at line " << line.sourceLine << L".\n";
            scriptResumePastBreakpoint_ = false;
            return false;
        }
        scriptCursor_ = nextIndex;
        ++executed;
        scriptResumePastBreakpoint_ = false;
    }

    if (scriptCursor_ >= targetIndex) {
        std::wcout << L"Reached label '" << label << L"' after " << executed << L" command(s).\n";
        return true;
    }
    std::wcout << L"Script finished before reaching label '" << label << L"'.\n";
    return false;
}

void Debugger::CleanupDebuggee() {
    if (g_wdblVehPipe != INVALID_HANDLE_VALUE &&
        (g_wdblVehProcessId == 0 || processId_ == 0 || g_wdblVehProcessId == processId_)) {
        CloseVehSession();
    }
    if (symbolsInitialized_ && processHandle_ != nullptr) {
        SymCleanup(processHandle_);
        symbolsInitialized_ = false;
    }
    if (processHandle_ != nullptr) {
        CloseHandle(processHandle_);
        processHandle_ = nullptr;
    }
    symbolInitAttempted_ = false;
    active_ = false;
    attached_ = false;
    detachRequested_ = false;
    processId_ = 0;
    pendingEvent_ = PendingDebugEvent();
    stopState_ = StopState();
    stepRequested_ = false;
    stepThreadId_ = 0;
    pendingSoftwareReinsert_.clear();
    pendingMemoryRearm_.clear();
    softwareBreakpoints_.clear();
    softwareBreakpointByAddress_.clear();
    hardwareBreakpoints_.clear();
    memoryBreakpoints_.clear();
    patchHistory_.clear();
    namedSnapshots_.clear();
    instructionComments_.clear();
    stopHistory_.clear();
    mainModuleBase_ = 0;
    entryPointAddress_ = 0;
    runToEntryOnLaunch_ = false;
    runToEntryBreakpointId_ = -1;
    runToEntryOwnsBreakpoint_ = false;
    nextBreakpointId_ = 1;
}

void Debugger::Shutdown() {
    if (active_) {
        if (eventPumpThreadHandle_ != NULL) {
            if (pendingEvent_.valid) {
                SignalResumeForBackgroundPump();
            }
            WaitForSingleObject(eventPumpThreadHandle_, 500);
            CloseHandle(eventPumpThreadHandle_);
            eventPumpThreadHandle_ = NULL;
        }

        if (attached_ && processId_ != 0) {
            DebugActiveProcessStop(processId_);
        }

        CleanupDebuggee();
    }
    UnloadAllPluginModules();
}

bool Debugger::Launch(const std::wstring& commandLine) {
    if (active_ || IsBackgroundEventPumpRunning()) {
        std::wcout << L"A debug session is already active.\n";
        return false;
    }

    eventPumpStartMode_ = 1;
    eventPumpStartSucceeded_ = false;
    detachRequested_ = false;
    runToEntryOnLaunch_ = true;
    eventPumpLaunchCommandLine_ = commandLine;
    eventPumpAttachProcessId_ = 0;
    ResetEvent(eventPumpReadyEvent_);
    if (!StartBackgroundEventPump()) {
        return false;
    }
    WaitForSingleObject(eventPumpReadyEvent_, INFINITE);
    return eventPumpStartSucceeded_;
}

bool Debugger::LaunchVeh(const std::wstring& commandLine, const std::wstring& dllPath) {
    if (active_ || IsBackgroundEventPumpRunning()) {
        std::wcout << L"A debug session is already active.\n";
        return false;
    }
    if (g_wdblVehPipe != INVALID_HANDLE_VALUE) {
        std::wcout << L"A VEH session is already active.\n";
        return false;
    }

    STARTUPINFOW si = STARTUPINFOW();
    PROCESS_INFORMATION pi = PROCESS_INFORMATION();
    si.cb = sizeof(si);

    std::vector<wchar_t> mutableCmd(commandLine.begin(), commandLine.end());
    mutableCmd.push_back(L'\0');

    const BOOL ok = CreateProcessW(
        nullptr,
        mutableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        nullptr,
        nullptr,
        &si,
        &pi);
    if (!ok) {
        std::wcout << L"CreateProcessW failed: " << GetLastError() << L"\n";
        return false;
    }

    std::wstring detail;
    const std::wstring resolvedDll = FindVehAgentDllPath(dllPath, pi.hProcess);
    if (!PathExists(resolvedDll)) {
        std::wcout << L"VEH launch failed: Cannot find Z0BDbgVehAgent.dll"
                   << L": " << resolvedDll << L"\n";
        TerminateProcess(pi.hProcess, 1);
        if (pi.hThread != nullptr) {
            CloseHandle(pi.hThread);
        }
        if (pi.hProcess != nullptr) {
            CloseHandle(pi.hProcess);
        }
        return false;
    }

    const DWORD resumeResult = ResumeThread(pi.hThread);
    if (resumeResult == static_cast<DWORD>(-1)) {
        std::wcout << L"ResumeThread failed: " + GetLastError() << L"\n";
        TerminateProcess(pi.hProcess, 1);
        if (pi.hThread != nullptr) {
            CloseHandle(pi.hThread);
        }
        if (pi.hProcess != nullptr) {
            CloseHandle(pi.hProcess);
        }
        return false;
    }
    WaitForInputIdle(pi.hProcess, 2000);
    Sleep(100);

    if (!StartVehSessionWithProcessHandle(pi.dwProcessId, pi.hProcess, nullptr, resolvedDll, &detail)) {
        std::wcout << L"VEH launch failed: " + detail << L"\n";
        TerminateProcess(pi.hProcess, 1);
        if (pi.hThread != nullptr) {
            CloseHandle(pi.hThread);
        }
        if (pi.hProcess != nullptr) {
            CloseHandle(pi.hProcess);
        }
        return false;
    }

    active_ = true;
    attached_ = false;
    processId_ = pi.dwProcessId;
    processHandle_ = pi.hProcess;
    detachRequested_ = false;
    g_wdblVehPreferred = true;
    logger_.Log(L"VEH launch: " + commandLine);
    std::wcout << detail << L"\n";
    std::wcout << L"VEH process launched. pid=" << processId_ << L"\n";
    if (pi.hThread != nullptr) {
        CloseHandle(pi.hThread);
    }
    return true;
}

bool Debugger::Attach(DWORD processId) {
    if (active_ || IsBackgroundEventPumpRunning()) {
        std::wcout << L"A debug session is already active.\n";
        return false;
    }

    eventPumpStartMode_ = 2;
    eventPumpStartSucceeded_ = false;
    detachRequested_ = false;
    eventPumpLaunchCommandLine_.clear();
    eventPumpAttachProcessId_ = processId;
    ResetEvent(eventPumpReadyEvent_);
    if (!StartBackgroundEventPump()) {
        return false;
    }
    WaitForSingleObject(eventPumpReadyEvent_, INFINITE);
    return eventPumpStartSucceeded_;
}

bool Debugger::Detach() {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (!attached_) {
        std::wcout << L"Detach is only available for attached debug sessions.\n";
        return false;
    }

    RemoveAllBreakpoints();
    const DWORD pid = processId_;
    detachRequested_ = true;
    active_ = false;

    PendingDebugEvent pending;
    EnterCriticalSection(&stateLock_);
    pending = pendingEvent_;
    LeaveCriticalSection(&stateLock_);

    if (pending.valid) {
        SignalResumeForBackgroundPump();
    }

    if (eventPumpThreadHandle_ != NULL) {
        const DWORD waitResult = WaitForSingleObject(eventPumpThreadHandle_, 5000);
        if (waitResult == WAIT_OBJECT_0) {
            CloseHandle(eventPumpThreadHandle_);
            eventPumpThreadHandle_ = NULL;
        } else {
            std::wcout << L"Detach requested; event pump did not exit within timeout.\n";
            return false;
        }
    }

    if (processId_ == pid) {
        CleanupDebuggee();
    }
    std::wcout << L"Detached from process " << pid << L".\n";
    return true;
}

bool Debugger::PollDebugEvents() {
    return true;
}

bool Debugger::IsBackgroundEventPumpRunning() const {
    if (eventPumpThreadHandle_ == NULL) {
        return false;
    }
    const DWORD waitResult = WaitForSingleObject(eventPumpThreadHandle_, 0);
    return waitResult == WAIT_TIMEOUT;
}

bool Debugger::SignalResumeForBackgroundPump() {
    if (eventPumpResumeEvent_ == NULL) {
        return false;
    }
    return SetEvent(eventPumpResumeEvent_) == TRUE;
}

bool Debugger::StartBackgroundEventPump() {
    if (!active_ && eventPumpStartMode_ == 0) {
        return false;
    }

    if (IsBackgroundEventPumpRunning()) {
        return true;
    }

    if (eventPumpThreadHandle_ != NULL) {
        CloseHandle(eventPumpThreadHandle_);
        eventPumpThreadHandle_ = NULL;
    }

    if (eventPumpResumeEvent_ != NULL) {
        ResetEvent(eventPumpResumeEvent_);
    }

    const HANDLE thread = CreateThread(
        nullptr,
        0,
        &Debugger::BackgroundEventPumpThreadProc,
        this,
        0,
        nullptr);
    if (!thread) {
        std::wcout << L"Failed to start background event pump: " << GetLastError() << L"\n";
        return false;
    }

    eventPumpThreadHandle_ = thread;
    return true;
}

DWORD WINAPI Debugger::BackgroundEventPumpThreadProc(LPVOID param) {
    Debugger* self = reinterpret_cast<Debugger*>(param);
    if (self == nullptr) {
        return 0;
    }

    if (self->eventPumpStartMode_ == 1) {
        STARTUPINFOW si = STARTUPINFOW();
        PROCESS_INFORMATION pi = PROCESS_INFORMATION();
        si.cb = sizeof(si);

        std::vector<wchar_t> mutableCmd(self->eventPumpLaunchCommandLine_.begin(), self->eventPumpLaunchCommandLine_.end());
        mutableCmd.push_back(L'\0');

        const BOOL ok = CreateProcessW(
            nullptr,
            mutableCmd.data(),
            nullptr,
            nullptr,
            FALSE,
            DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
            nullptr,
            nullptr,
            &si,
            &pi);

        if (!ok) {
            std::wcout << L"CreateProcessW failed: " << GetLastError() << L"\n";
            self->eventPumpStartSucceeded_ = false;
            SetEvent(self->eventPumpReadyEvent_);
            return 0;
        }

        self->active_ = true;
        self->attached_ = false;
        self->processId_ = pi.dwProcessId;
        self->processHandle_ = pi.hProcess;
        self->logger_.Log(L"Launch: " + self->eventPumpLaunchCommandLine_);

        if (pi.hThread) {
            CloseHandle(pi.hThread);
        }
    } else if (self->eventPumpStartMode_ == 2) {
        const DWORD pid = self->eventPumpAttachProcessId_;
        if (!DebugActiveProcess(pid)) {
            std::wcout << L"DebugActiveProcess failed: " << GetLastError() << L"\n";
            self->eventPumpStartSucceeded_ = false;
            SetEvent(self->eventPumpReadyEvent_);
            return 0;
        }

        DebugSetProcessKillOnExit(FALSE);

        self->processHandle_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        if (!self->processHandle_) {
            std::wcout << L"OpenProcess failed: " << GetLastError() << L"\n";
            DebugActiveProcessStop(pid);
            self->eventPumpStartSucceeded_ = false;
            SetEvent(self->eventPumpReadyEvent_);
            return 0;
        }

        self->active_ = true;
        self->attached_ = true;
        self->processId_ = pid;
        self->logger_.Log(L"Attach pid=" + ToWStringCompat(pid));

        uint64_t resolvedBase = 0;
        uint64_t resolvedEntry = 0;
        if (self->ResolveMainModuleEntryPoint(resolvedBase, resolvedEntry)) {
            self->mainModuleBase_ = resolvedBase;
            self->entryPointAddress_ = resolvedEntry;
            self->logger_.Log(
                L"Attach entrypoint resolved base=" + ToHex(self->mainModuleBase_) +
                L" entry=" + ToHex(self->entryPointAddress_));
        } else {
            self->mainModuleBase_ = 0;
            self->entryPointAddress_ = 0;
        }
    }

    if (self->eventPumpStartMode_ != 0) {
        const bool started = self->PumpEventsUntilPause();
        self->eventPumpStartSucceeded_ = started && self->active_;
        SetEvent(self->eventPumpReadyEvent_);
        self->eventPumpStartMode_ = 0;
        if (!started) {
            return 0;
        }
    }

    while (self->active_) {
        PendingDebugEvent pending;
        EnterCriticalSection(&self->stateLock_);
        pending = self->pendingEvent_;
        LeaveCriticalSection(&self->stateLock_);

        if (pending.valid) {
            if (self->eventPumpResumeEvent_ == NULL) {
                break;
            }
            const DWORD waitResult = WaitForSingleObject(self->eventPumpResumeEvent_, INFINITE);
            if (waitResult != WAIT_OBJECT_0) {
                break;
            }
            ResetEvent(self->eventPumpResumeEvent_);
            if (!ContinueDebugEvent(pending.processId, pending.threadId, pending.continueStatus)) {
                std::wcout << L"ContinueDebugEvent failed: " << GetLastError() << L"\n";
                break;
            }

            EnterCriticalSection(&self->stateLock_);
            self->pendingEvent_ = PendingDebugEvent();
            self->stopState_ = StopState();
            LeaveCriticalSection(&self->stateLock_);
            continue;
        }

        if (!self->active_ && self->detachRequested_) {
            break;
        }

        DEBUG_EVENT event = DEBUG_EVENT();
        if (!WaitForDebugEvent(&event, 100)) {
            const DWORD waitError = GetLastError();
            if (waitError == ERROR_SEM_TIMEOUT) {
                continue;
            }
            if (self->active_) {
                std::wcout << L"WaitForDebugEvent failed: " << waitError << L"\n";
            }
            break;
        }

        DWORD continueStatus = DBG_CONTINUE;
        bool shouldPause = false;
        if (!self->HandleDebugEvent(event, continueStatus, shouldPause)) {
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        }

        if (shouldPause) {
            EnterCriticalSection(&self->stateLock_);
            self->pendingEvent_.valid = true;
            self->pendingEvent_.processId = event.dwProcessId;
            self->pendingEvent_.threadId = event.dwThreadId;
            self->pendingEvent_.continueStatus = continueStatus;
            self->pendingEvent_.event = event;
            LeaveCriticalSection(&self->stateLock_);

            if (self->runFlowActive_ && self->runToEntryBreakpointId_ < 0 && !self->runStopExpressions_.empty()) {
                bool matched = false;
                std::wstring detail;
                if (!self->EvaluateRunStopExpressions(matched, detail)) {
                    std::wcout << L"[RunStop] " << detail << L"\n";
                } else if (!matched) {
                    self->logger_.Log(L"Run-stop expressions not matched; auto-continue.");
                    EnterCriticalSection(&self->stateLock_);
                    self->ClearStopState();
                    self->pendingEvent_ = PendingDebugEvent();
                    LeaveCriticalSection(&self->stateLock_);
                    if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus)) {
                        std::wcout << L"ContinueDebugEvent failed: " << GetLastError() << L"\n";
                        break;
                    }
                    continue;
                } else {
                    std::wcout << L"[RunStop] matched expression: " << detail << L"\n";
                }
            }

            EnterCriticalSection(&self->stateLock_);
            const bool hasStopState = self->stopState_.valid;
            LeaveCriticalSection(&self->stateLock_);
            if (hasStopState) {
                WdblPluginEvent pluginEvent = WdblPluginEvent();
                pluginEvent.size = sizeof(WdblPluginEvent);
                pluginEvent.type = WDBL_PLUGIN_EVENT_PAUSED;
                EnterCriticalSection(&self->stateLock_);
                pluginEvent.processId = self->stopState_.processId;
                pluginEvent.threadId = self->stopState_.threadId;
                pluginEvent.address = self->stopState_.address;
                CopyWideText(pluginEvent.message, self->stopState_.reason);
                LeaveCriticalSection(&self->stateLock_);
                pluginEvent.debugEventCode = event.dwDebugEventCode;
                pluginEvent.stopInfo.size = sizeof(WdblStopInfo);
                self->PluginHostGetStopInfo(&pluginEvent.stopInfo);
                self->DispatchPluginEvent(pluginEvent);
            }
            std::wcout << std::flush;
            continue;
        }

        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus)) {
            std::wcout << L"ContinueDebugEvent failed: " << GetLastError() << L"\n";
            break;
        }
        if (!self->active_) {
            break;
        }
    }
    if (self->attached_ && self->processId_ != 0) {
        DebugActiveProcessStop(self->processId_);
    }
    return 0;
}

bool Debugger::ContinuePendingEvent() {
    PendingDebugEvent pending;
    EnterCriticalSection(&stateLock_);
    pending = pendingEvent_;
    LeaveCriticalSection(&stateLock_);

    if (!pending.valid) {
        return true;
    }
    if (!IsBackgroundEventPumpRunning()) {
        std::wcout << L"Debug event pump is not running; cannot continue pending event.\n";
        return false;
    }

    if (!SignalResumeForBackgroundPump()) {
        std::wcout << L"Failed to signal background resume.\n";
        return false;
    }
    return true;
}

bool Debugger::ContinueExecution() {
    if (!EnsureDebuggee()) {
        return false;
    }

    PendingDebugEvent pending;
    StopState stop;
    EnterCriticalSection(&stateLock_);
    pending = pendingEvent_;
    stop = stopState_;
    LeaveCriticalSection(&stateLock_);

    if (!pending.valid || !stop.valid) {
        if (!IsBackgroundEventPumpRunning()) {
            StartBackgroundEventPump();
        }
        std::wcout << L"Already running.\n";
        return true;
    }

    SaveCurrentStopSnapshot();
    WdblPluginEvent pluginEvent = WdblPluginEvent();
    pluginEvent.size = sizeof(WdblPluginEvent);
    pluginEvent.type = WDBL_PLUGIN_EVENT_CONTINUE_REQUESTED;
    pluginEvent.processId = stop.processId;
    pluginEvent.threadId = stop.threadId;
    pluginEvent.address = GetInstructionPointer(stop.context);
    CopyWideText(pluginEvent.message, L"Continue requested");
    DispatchPluginEvent(pluginEvent);

    stepRequested_ = false;
    stepThreadId_ = 0;
    runFlowActive_ = true;
    if (!IsBackgroundEventPumpRunning()) {
        StartBackgroundEventPump();
    }
    if (!ContinuePendingEvent()) {
        runFlowActive_ = false;
        return false;
    }
    runFlowActive_ = false;

    const bool hasPersistentBreakpoints =
        !softwareBreakpoints_.empty() ||
        !hardwareBreakpoints_.empty() ||
        !memoryBreakpoints_.empty() ||
        runToEntryBreakpointId_ >= 0 ||
        stepOverBreakpointId_ >= 0 ||
        !pendingSoftwareReinsert_.empty() ||
        !pendingMemoryRearm_.empty();

    if (!hasPersistentBreakpoints && stop.valid) {
        CONTEXT ctx = stop.context;
        SetTrapFlag(ctx, false);
        ApplyThreadContext(stop.threadId, ctx);
    }

    std::wcout << L"Running.\n";
    return true;
}

bool Debugger::SingleStep() {
    if (!EnsurePaused()) {
        return false;
    }
    CancelPendingStepOver();
    SaveCurrentStopSnapshot();
    WdblPluginEvent pluginEvent = WdblPluginEvent();
    pluginEvent.size = sizeof(WdblPluginEvent);
    pluginEvent.type = WDBL_PLUGIN_EVENT_SINGLE_STEP_REQUESTED;
    pluginEvent.processId = stopState_.processId;
    pluginEvent.threadId = stopState_.threadId;
    pluginEvent.address = GetInstructionPointer(stopState_.context);
    CopyWideText(pluginEvent.message, L"Single-step requested");
    DispatchPluginEvent(pluginEvent);

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        std::wcout << L"Failed to capture thread context.\n";
        return false;
    }
    SetTrapFlag(ctx, true);
    if (!ApplyThreadContext(stopState_.threadId, ctx)) {
        std::wcout << L"Failed to apply trap flag.\n";
        return false;
    }

    stepRequested_ = true;
    stepThreadId_ = stopState_.threadId;
    runFlowActive_ = false;
    logger_.Log(L"SingleStep tid=" + ToWStringCompat(stepThreadId_));

    if (!IsBackgroundEventPumpRunning()) {
        StartBackgroundEventPump();
    }
    if (!ContinuePendingEvent()) {
        return false;
    }
    std::wcout << L"Stepping.\n";
    return true;
}

void Debugger::CancelPendingStepOver() {
    if (stepOverBreakpointId_ >= 0) {
        const int id = stepOverBreakpointId_;
        stepOverBreakpointId_ = -1;
        RemoveBreakpoint(id);
    }
}

bool Debugger::StepOver() {
    if (!EnsurePaused()) {
        return false;
    }
    CancelPendingStepOver();
    SaveCurrentStopSnapshot();
    WdblPluginEvent pluginEvent = WdblPluginEvent();
    pluginEvent.size = sizeof(WdblPluginEvent);
    pluginEvent.type = WDBL_PLUGIN_EVENT_SINGLE_STEP_REQUESTED;
    pluginEvent.processId = stopState_.processId;
    pluginEvent.threadId = stopState_.threadId;
    pluginEvent.address = GetInstructionPointer(stopState_.context);
    CopyWideText(pluginEvent.message, L"Step over requested");
    DispatchPluginEvent(pluginEvent);

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        std::wcout << L"Failed to capture thread context.\n";
        return false;
    }
    const uint64_t ip = GetInstructionPointer(ctx);
    const uint8_t modeBits = DetermineDisassemblyModeBits(processHandle_);

    uint8_t codeBuf[16] = {0};
    SIZE_T readBytes = 0;
    if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(ip),
                          codeBuf, sizeof(codeBuf), &readBytes) || readBytes == 0) {
        std::wcout << L"Failed to read instruction bytes for step-over.\n";
        return false;
    }

    const DecodedInstruction decoded = DecodeInstruction(ip, codeBuf, readBytes, modeBits);
    const std::wstring mnemonic = ToLower(decoded.text);
    const size_t insnLen = decoded.length > 0 ? static_cast<size_t>(decoded.length) : 1;
    const uint64_t nextAddr = ip + insnLen;

    const bool isCall = (mnemonic.find(L"call") == 0);
    const bool isRepOrLoop = (mnemonic.find(L"rep") == 0 || mnemonic.find(L"loop") == 0);
    const bool isInt = (mnemonic.find(L"int") == 0);
    const bool overable = (isCall || isRepOrLoop || isInt) && nextAddr != 0;

    if (!overable) {
        // Not a subroutine / repeated / ISR instruction: single-step instead.
        SetTrapFlag(ctx, true);
        if (!ApplyThreadContext(stopState_.threadId, ctx)) {
            std::wcout << L"Failed to apply trap flag.\n";
            return false;
        }
        stepRequested_ = true;
        stepThreadId_ = stopState_.threadId;
        runFlowActive_ = false;
        stepOverBreakpointId_ = -1;
        logger_.Log(L"StepOver (single-step fallback) tid=" + ToWStringCompat(stepThreadId_));
        if (!IsBackgroundEventPumpRunning()) {
            StartBackgroundEventPump();
        }
        if (!ContinuePendingEvent()) {
            return false;
        }
        std::wcout << L"Stepping.\n";
        return true;
    }

    // Step over: set a temporary breakpoint at the instruction after the current
    // one, continue, and pause when it is hit (removing the temp breakpoint).
    const int tempId = AddSoftwareBreakpoint(nextAddr);
    if (tempId < 0) {
        std::wcout << L"Step-over: failed to set temporary breakpoint at "
                   << ToHex(nextAddr) << L".\n";
        return false;
    }
    stepOverBreakpointId_ = tempId;
    stepRequested_ = false;
    stepThreadId_ = 0;
    runFlowActive_ = true;
    logger_.Log(L"StepOver (temp bp) tid=" + ToWStringCompat(stopState_.threadId)
                + L" next=" + ToHex(nextAddr));
    if (!IsBackgroundEventPumpRunning()) {
        StartBackgroundEventPump();
    }
    if (!ContinuePendingEvent()) {
        runFlowActive_ = false;
        return false;
    }
    std::wcout << L"Running.\n";
    return true;
}
bool Debugger::PumpEventsUntilPause(DWORD waitMilliseconds) {
    while (active_) {
        DEBUG_EVENT event = DEBUG_EVENT();
        if (!WaitForDebugEvent(&event, waitMilliseconds)) {
            const DWORD waitError = GetLastError();
            if (waitError == ERROR_SEM_TIMEOUT) {
                return true;
            }
            std::wcout << L"WaitForDebugEvent failed: " << GetLastError() << L"\n";
            return false;
        }

        DWORD continueStatus = DBG_CONTINUE;
        bool shouldPause = false;
        if (!HandleDebugEvent(event, continueStatus, shouldPause)) {
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        }

        if (shouldPause) {
            EnterCriticalSection(&stateLock_);
            pendingEvent_.valid = true;
            pendingEvent_.processId = event.dwProcessId;
            pendingEvent_.threadId = event.dwThreadId;
            pendingEvent_.continueStatus = continueStatus;
            pendingEvent_.event = event;
            LeaveCriticalSection(&stateLock_);

            if (runFlowActive_ && runToEntryBreakpointId_ < 0 && !runStopExpressions_.empty()) {
                bool matched = false;
                std::wstring detail;
                if (!EvaluateRunStopExpressions(matched, detail)) {
                    std::wcout << L"[RunStop] " << detail << L"\n";
                } else if (!matched) {
                    logger_.Log(L"Run-stop expressions not matched; auto-continue.");
                    ClearStopState();
                    pendingEvent_ = PendingDebugEvent();
                    if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus)) {
                        std::wcout << L"ContinueDebugEvent failed: " << GetLastError() << L"\n";
                        return false;
                    }
                    continue;
                } else {
                    std::wcout << L"[RunStop] matched expression: " << detail << L"\n";
                }
            }

            if (stopState_.valid) {
                WdblPluginEvent pluginEvent = WdblPluginEvent();
                pluginEvent.size = sizeof(WdblPluginEvent);
                pluginEvent.type = WDBL_PLUGIN_EVENT_PAUSED;
                pluginEvent.processId = stopState_.processId;
                pluginEvent.threadId = stopState_.threadId;
                pluginEvent.debugEventCode = event.dwDebugEventCode;
                pluginEvent.address = stopState_.address;
                pluginEvent.stopInfo.size = sizeof(WdblStopInfo);
                PluginHostGetStopInfo(&pluginEvent.stopInfo);
                CopyWideText(pluginEvent.message, stopState_.reason);
                DispatchPluginEvent(pluginEvent);
            }
            return true;
        }

        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus)) {
            std::wcout << L"ContinueDebugEvent failed: " << GetLastError() << L"\n";
            return false;
        }

        if (!active_) {
            break;
        }
    }
    return true;
}

bool Debugger::HandleDebugEvent(const DEBUG_EVENT& event, DWORD& continueStatus, bool& shouldPause) {
    logger_.LogEvent(L"debug", event);
    continueStatus = DBG_CONTINUE;
    shouldPause = false;

    switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            std::wstring imagePath = TryGetPathFromHandle(event.u.CreateProcessInfo.hFile);
            if (processHandle_ == nullptr) {
                processHandle_ = event.u.CreateProcessInfo.hProcess;
            } else if (event.u.CreateProcessInfo.hProcess != nullptr) {
                CloseHandle(event.u.CreateProcessInfo.hProcess);
            }
            processId_ = event.dwProcessId;
            active_ = true;
            mainModuleBase_ = reinterpret_cast<uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage);
            entryPointAddress_ = 0;
            ResolveEntryPointFromModuleBase(mainModuleBase_, entryPointAddress_);

            InitializeSymbolEngine();
            if (symbolsInitialized_) {
                SymLoadModuleExW(
                    processHandle_,
                    event.u.CreateProcessInfo.hFile,
                    imagePath.empty() ? nullptr : imagePath.c_str(),
                    nullptr,
                    reinterpret_cast<DWORD64>(event.u.CreateProcessInfo.lpBaseOfImage),
                    0,
                    nullptr,
                    0);
            }

            if (event.u.CreateProcessInfo.hThread) {
                CloseHandle(event.u.CreateProcessInfo.hThread);
            }
            if (event.u.CreateProcessInfo.hFile) {
                CloseHandle(event.u.CreateProcessInfo.hFile);
            }

            WdblPluginEvent pluginEvent = WdblPluginEvent();
            pluginEvent.size = sizeof(WdblPluginEvent);
            pluginEvent.type = WDBL_PLUGIN_EVENT_MODULE_LOADED;
            pluginEvent.processId = event.dwProcessId;
            pluginEvent.threadId = event.dwThreadId;
            pluginEvent.debugEventCode = event.dwDebugEventCode;
            pluginEvent.address = reinterpret_cast<uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage);
            CopyWideText(pluginEvent.modulePath, imagePath.empty() ? L"<main image>" : imagePath);
            CopyWideText(pluginEvent.message, L"Main module loaded");
            DispatchPluginEvent(pluginEvent);
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT: {
            const DWORD exitCode = event.u.ExitProcess.dwExitCode;
            logger_.Log(L"Process exited code=" + ToWStringCompat(exitCode));
            std::wcout << L"Process exited with code: " << exitCode << L"\n";
            active_ = false;
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT: {
            if (event.u.CreateThread.hThread) {
                CloseHandle(event.u.CreateThread.hThread);
            }
            if (!hardwareBreakpoints_.empty()) {
                ApplyHardwareBreakpointsForThread(event.dwThreadId);
            }
            break;
        }
        case EXIT_THREAD_DEBUG_EVENT: {
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            const std::wstring dllPath = TryGetPathFromHandle(event.u.LoadDll.hFile);
            if (symbolsInitialized_) {
                SymLoadModuleExW(
                    processHandle_,
                    event.u.LoadDll.hFile,
                    dllPath.empty() ? nullptr : dllPath.c_str(),
                    nullptr,
                    reinterpret_cast<DWORD64>(event.u.LoadDll.lpBaseOfDll),
                    0,
                    nullptr,
                    0);
            }
            ResolvePendingSoftwareBreakpoints();
            if (event.u.LoadDll.hFile) {
                CloseHandle(event.u.LoadDll.hFile);
            }

            WdblPluginEvent pluginEvent = WdblPluginEvent();
            pluginEvent.size = sizeof(WdblPluginEvent);
            pluginEvent.type = WDBL_PLUGIN_EVENT_MODULE_LOADED;
            pluginEvent.processId = event.dwProcessId;
            pluginEvent.threadId = event.dwThreadId;
            pluginEvent.debugEventCode = event.dwDebugEventCode;
            pluginEvent.address = reinterpret_cast<uint64_t>(event.u.LoadDll.lpBaseOfDll);
            std::wstring modulePath = dllPath;
            if (modulePath.empty()) {
                modulePath = ModulePathFromBase(pluginEvent.address, event.dwProcessId);
            }
            CopyWideText(pluginEvent.modulePath, modulePath.empty() ? L"<unknown module>" : modulePath);
            CopyWideText(pluginEvent.message, L"Module loaded");
            DispatchPluginEvent(pluginEvent);
            break;
        }
        case UNLOAD_DLL_DEBUG_EVENT: {
            if (symbolsInitialized_) {
                SymUnloadModule64(processHandle_, reinterpret_cast<DWORD64>(event.u.UnloadDll.lpBaseOfDll));
            }
            break;
        }
        case OUTPUT_DEBUG_STRING_EVENT: {
            std::wstring out = L"<debug string unavailable>";
            const auto& info = event.u.DebugString;
            if (processHandle_ != nullptr && info.lpDebugStringData != nullptr && info.nDebugStringLength > 1) {
                if (info.fUnicode) {
                    std::vector<wchar_t> buffer(info.nDebugStringLength + 1, L'\0');
                    SIZE_T read = 0;
                    if (ReadProcessMemory(processHandle_, info.lpDebugStringData, buffer.data(),
                                          info.nDebugStringLength * sizeof(wchar_t), &read)) {
                        out.assign(buffer.data());
                    }
                } else {
                    std::vector<char> buffer(info.nDebugStringLength + 1, '\0');
                    SIZE_T read = 0;
                    if (ReadProcessMemory(processHandle_, info.lpDebugStringData, buffer.data(),
                                          info.nDebugStringLength, &read)) {
                        out.assign(buffer.begin(), buffer.end());
                    }
                }
            }
            logger_.Log(L"OutputDebugString: " + out);
            break;
        }
        case RIP_EVENT: {
            logger_.Log(L"RIP_EVENT type=" + ToWStringCompat(event.u.RipInfo.dwType) +
                        L" error=" + ToWStringCompat(event.u.RipInfo.dwError));
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            return HandleExceptionEvent(event, continueStatus, shouldPause);
        }
        default:
            break;
    }

    return true;
}

bool Debugger::IsKnownSoftwareBreakpointHit(const DEBUG_EVENT& event, CONTEXT& ctx, int& breakpointId, uint64_t& breakpointAddress) {
    breakpointId = -1;
    breakpointAddress = 0;

    const uint64_t exceptionAddress = reinterpret_cast<uint64_t>(event.u.Exception.ExceptionRecord.ExceptionAddress);
    const uint64_t ip = GetInstructionPointer(ctx);

    auto byException = softwareBreakpointByAddress_.find(exceptionAddress);
    if (byException != softwareBreakpointByAddress_.end()) {
        breakpointId = byException->second;
        breakpointAddress = exceptionAddress;
        return true;
    }

    if (ip > 0) {
        auto byRipMinusOne = softwareBreakpointByAddress_.find(ip - 1);
        if (byRipMinusOne != softwareBreakpointByAddress_.end()) {
            breakpointId = byRipMinusOne->second;
            breakpointAddress = ip - 1;
            return true;
        }
    }

    return false;
}

bool Debugger::RearmSoftwareBreakpoint(DWORD threadId) {
    const auto it = pendingSoftwareReinsert_.find(threadId);
    if (it == pendingSoftwareReinsert_.end()) {
        return false;
    }
    const uint64_t address = it->second;
    auto addrIt = softwareBreakpointByAddress_.find(address);
    if (addrIt != softwareBreakpointByAddress_.end()) {
        auto bpIt = softwareBreakpoints_.find(addrIt->second);
        if (bpIt != softwareBreakpoints_.end() && bpIt->second.enabled) {
            uint8_t int3 = 0xCC;
            SIZE_T written = 0;
            WriteProcessMemory(processHandle_, reinterpret_cast<LPVOID>(address), &int3, sizeof(int3), &written);
            FlushInstructionCache(processHandle_, reinterpret_cast<LPCVOID>(address), sizeof(int3));
        }
    }
    pendingSoftwareReinsert_.erase(it);

    CONTEXT ctx = CONTEXT();
    if (CaptureThreadContext(threadId, ctx)) {
        SetTrapFlag(ctx, false);
        ApplyThreadContext(threadId, ctx);
    }
    return true;
}

void Debugger::RearmMemoryBreakpoint(MemoryBreakpoint& bp) const {
 for (auto __rangeIt19 = (bp.guardedPages).begin(); __rangeIt19 != (bp.guardedPages).end(); ++__rangeIt19) {
        const auto& page = *__rangeIt19;
        DWORD oldProtect = 0;
        VirtualProtectEx(processHandle_, reinterpret_cast<LPVOID>(page.base), page.size,
                         page.originalProtection | PAGE_GUARD, &oldProtect);
    }
}

bool Debugger::RearmMemoryBreakpoints(DWORD threadId) {
    const auto it = pendingMemoryRearm_.find(threadId);
    if (it == pendingMemoryRearm_.end()) {
        return false;
    }
 for (auto __rangeIt20 = (it->second).begin(); __rangeIt20 != (it->second).end(); ++__rangeIt20) {
        const int id = *__rangeIt20;
        auto mbpIt = memoryBreakpoints_.find(id);
        if (mbpIt != memoryBreakpoints_.end() && mbpIt->second.enabled) {
            RearmMemoryBreakpoint(mbpIt->second);
        }
    }
    pendingMemoryRearm_.erase(it);

    CONTEXT ctx = CONTEXT();
    if (CaptureThreadContext(threadId, ctx)) {
        SetTrapFlag(ctx, false);
        ApplyThreadContext(threadId, ctx);
    }
    return true;
}

bool Debugger::ResolvePendingSoftwareBreakpoints() {
    bool allOk = true;
    for (size_t i = 0; i < pendingSoftwareBreakpoints_.size(); ) {
        uint64_t address = 0;
        std::wstring resolvedText;
        if (!ResolveAddressExpression(pendingSoftwareBreakpoints_[i], address, resolvedText)) {
            allOk = false;
            ++i;
            continue;
        }
        const int id = AddSoftwareBreakpoint(address);
        if (id < 0) {
            allOk = false;
            ++i;
            continue;
        }
        std::wcout << L"Deferred breakpoint resolved: " << pendingSoftwareBreakpoints_[i]
                   << L" -> " << ToHex(address) << L"\n";
        pendingSoftwareBreakpoints_.erase(pendingSoftwareBreakpoints_.begin() + static_cast<std::ptrdiff_t>(i));
    }
    return allOk;
}

bool Debugger::WasHardwareBreakpointTriggered(const CONTEXT& ctx, int& breakpointId) const {
    breakpointId = -1;
    const DWORD64 dr6 = ctx.Dr6;
    for (auto it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
        const int id = it->first;
        const HardwareBreakpoint& bp = it->second;
        if (!bp.enabled) {
            continue;
        }
        if ((dr6 & (1ull << bp.slot)) != 0) {
            breakpointId = id;
            return true;
        }
    }
    return false;
}

bool Debugger::HandleExceptionEvent(const DEBUG_EVENT& event, DWORD& continueStatus, bool& shouldPause) {
    const auto& ex = event.u.Exception;
    const DWORD code = ex.ExceptionRecord.ExceptionCode;
    const bool firstChance = ex.dwFirstChance != 0;

    CONTEXT ctx = CONTEXT();
    CaptureThreadContext(event.dwThreadId, ctx);

    if (code == EXCEPTION_BREAKPOINT) {
        int breakpointId = -1;
        uint64_t breakpointAddress = 0;

        if (IsKnownSoftwareBreakpointHit(event, ctx, breakpointId, breakpointAddress)) {
            auto bpIt = softwareBreakpoints_.find(breakpointId);
            if (bpIt != softwareBreakpoints_.end() && bpIt->second.enabled) {
                SIZE_T written = 0;
                WriteProcessMemory(processHandle_, reinterpret_cast<LPVOID>(breakpointAddress),
                                   &bpIt->second.originalByte, sizeof(bpIt->second.originalByte), &written);
                FlushInstructionCache(processHandle_, reinterpret_cast<LPCVOID>(breakpointAddress), 1);

                SetInstructionPointer(ctx, breakpointAddress);
                SetTrapFlag(ctx, true);
                ApplyThreadContext(event.dwThreadId, ctx);
                pendingSoftwareReinsert_[event.dwThreadId] = breakpointAddress;

                const uint64_t hitCount = bpIt->second.hitCount + 1;
                bpIt->second.hitCount = hitCount;
                bool conditionMatched = true;
                const bool isRunToEntryBreakpoint = (runToEntryBreakpointId_ >= 0 && breakpointId == runToEntryBreakpointId_);
                const bool isStepOverBreakpoint = (stepOverBreakpointId_ >= 0 && breakpointId == stepOverBreakpointId_);
                if (!bpIt->second.condition.empty()) {
                    std::wstring conditionError;
                    if (!EvaluateBreakpointCondition(
                            bpIt->second.condition,
                            hitCount,
                            event.dwThreadId,
                            breakpointAddress,
                            breakpointAddress,
                            conditionMatched,
                            conditionError)) {
                        std::wcout << L"Breakpoint #" << breakpointId
                                   << L" condition parse error: " << conditionError << L"\n";
                        conditionMatched = true;
                    }
                }

                continueStatus = DBG_CONTINUE;
                shouldPause = conditionMatched || isStepOverBreakpoint;
                if (shouldPause) {
                    std::wstring reason;
                    if (isStepOverBreakpoint) {
                        reason = L"Step over completed at " + ToHex(breakpointAddress);
                    } else if (isRunToEntryBreakpoint) {
                        reason = L"Entry point reached at " + ToHex(breakpointAddress);
                    } else {
                        reason = L"Software breakpoint #" + ToWStringCompat(breakpointId) + L" hit";
                        if (!bpIt->second.condition.empty()) {
                            reason += L" [cond]";
                        }
                    }
                    SetStoppedState(event, reason, code, firstChance);
                    if (isStepOverBreakpoint) {
                        RemoveBreakpoint(stepOverBreakpointId_);
                        stepOverBreakpointId_ = -1;
                        runFlowActive_ = false;
                    }
                    if (isRunToEntryBreakpoint) {
                        if (runToEntryOwnsBreakpoint_) {
                            RemoveBreakpoint(runToEntryBreakpointId_);
                        }
                        runToEntryBreakpointId_ = -1;
                        runToEntryOwnsBreakpoint_ = false;
                        runFlowActive_ = false;
                    }
                }
                return true;
            }
        }

        if (runToEntryOnLaunch_ && !attached_ && entryPointAddress_ != 0) {
            const uint64_t ip = GetInstructionPointer(ctx);
            const uint64_t exceptionAddress = reinterpret_cast<uint64_t>(ex.ExceptionRecord.ExceptionAddress);
            if (ip != entryPointAddress_ && exceptionAddress != entryPointAddress_) {
                auto existing = softwareBreakpointByAddress_.find(entryPointAddress_);
                if (existing != softwareBreakpointByAddress_.end()) {
                    runToEntryBreakpointId_ = existing->second;
                    runToEntryOwnsBreakpoint_ = false;
                } else {
                    const int id = AddSoftwareBreakpoint(entryPointAddress_);
                    if (id >= 0) {
                        runToEntryBreakpointId_ = id;
                        runToEntryOwnsBreakpoint_ = true;
                    }
                }

                if (runToEntryBreakpointId_ >= 0) {
                    runFlowActive_ = true;
                    continueStatus = DBG_CONTINUE;
                    shouldPause = false;
                    runToEntryOnLaunch_ = false;
                    std::wcout << L"Running to entry point at " << ToHex(entryPointAddress_) << L"...\n";
                    return true;
                }
            }
        }

        runToEntryOnLaunch_ = false;
        continueStatus = DBG_CONTINUE;
        shouldPause = true;
        SetStoppedState(event, L"Breakpoint hit", code, firstChance);
        return true;
    }

    if (code == EXCEPTION_SINGLE_STEP) {
        const bool rearmedSoftware = RearmSoftwareBreakpoint(event.dwThreadId);
        const bool rearmedMemory = RearmMemoryBreakpoints(event.dwThreadId);

        int hardwareId = -1;
        const bool hardwareTriggered = WasHardwareBreakpointTriggered(ctx, hardwareId);

        if (stepRequested_ && event.dwThreadId == stepThreadId_) {
            stepRequested_ = false;
            stepThreadId_ = 0;
            continueStatus = DBG_CONTINUE;
            shouldPause = true;
            SetStoppedState(event, L"Single step completed", code, firstChance);
            return true;
        }

        if (hardwareTriggered) {
            auto hwIt = hardwareBreakpoints_.find(hardwareId);
            uint64_t ip = GetInstructionPointer(ctx);
            bool conditionMatched = true;
            if (hwIt != hardwareBreakpoints_.end()) {
                const uint64_t hitCount = hwIt->second.hitCount + 1;
                hwIt->second.hitCount = hitCount;
                if (!hwIt->second.condition.empty()) {
                    std::wstring conditionError;
                    if (!EvaluateBreakpointCondition(
                            hwIt->second.condition,
                            hitCount,
                            event.dwThreadId,
                            ip,
                            hwIt->second.address,
                            conditionMatched,
                            conditionError)) {
                        std::wcout << L"Breakpoint #" << hardwareId
                                   << L" condition parse error: " << conditionError << L"\n";
                        conditionMatched = true;
                    }
                }
            }
            continueStatus = DBG_CONTINUE;
            shouldPause = conditionMatched;
            if (shouldPause) {
                std::wstring reason = L"Hardware breakpoint #" + ToWStringCompat(hardwareId) + L" hit";
                if (hwIt != hardwareBreakpoints_.end() && !hwIt->second.condition.empty()) {
                    reason += L" [cond]";
                }
                SetStoppedState(event, reason, code, firstChance);
            }
            return true;
        }

        continueStatus = DBG_CONTINUE;
        shouldPause = !(rearmedSoftware || rearmedMemory);
        if (shouldPause) {
            SetTrapFlag(ctx, false);
            ApplyThreadContext(event.dwThreadId, ctx);
            SetStoppedState(event, L"Single-step exception", code, firstChance);
        }
        return true;
    }

    if (code == STATUS_GUARD_PAGE_VIOLATION_VALUE) {
        const ULONG_PTR accessKind = ex.ExceptionRecord.NumberParameters > 0 ? ex.ExceptionRecord.ExceptionInformation[0] : 0;
        const uint64_t faultAddress = ex.ExceptionRecord.NumberParameters > 1 ? ex.ExceptionRecord.ExceptionInformation[1] : 0;

        MemoryAccessType actualAccess = MemoryAccessType::Read;
        if (accessKind == 1) {
            actualAccess = MemoryAccessType::Write;
        } else if (accessKind == 8) {
            actualAccess = MemoryAccessType::Execute;
        }

        std::vector<int> touched;
        std::vector<int> matched;
        for (auto it = memoryBreakpoints_.begin(); it != memoryBreakpoints_.end(); ++it) {
            const int id = it->first;
            const MemoryBreakpoint& mbp = it->second;
            if (!mbp.enabled) {
                continue;
            }
            if (faultAddress >= mbp.address && faultAddress < mbp.address + mbp.size) {
                touched.push_back(id);
                if (HasMemoryAccess(mbp.access, actualAccess)) {
                    matched.push_back(id);
                }
            }
        }

        if (!touched.empty()) {
            pendingMemoryRearm_[event.dwThreadId] = touched;
            SetTrapFlag(ctx, true);
            ApplyThreadContext(event.dwThreadId, ctx);
            continueStatus = DBG_CONTINUE;

            if (!matched.empty()) {
                shouldPause = false;
                int matchedId = -1;
                bool conditioned = false;
                const uint64_t ip = GetInstructionPointer(ctx);
 for (auto __rangeIt21 = (matched).begin(); __rangeIt21 != (matched).end(); ++__rangeIt21) {
                    int candidateId = *__rangeIt21;
                    auto mbpIt = memoryBreakpoints_.find(candidateId);
                    if (mbpIt == memoryBreakpoints_.end()) {
                        continue;
                    }
                    const uint64_t hitCount = mbpIt->second.hitCount + 1;
                    mbpIt->second.hitCount = hitCount;
                    bool conditionMatched = true;
                    if (!mbpIt->second.condition.empty()) {
                        std::wstring conditionError;
                        if (!EvaluateBreakpointCondition(
                                mbpIt->second.condition,
                                hitCount,
                                event.dwThreadId,
                                ip,
                                faultAddress,
                                conditionMatched,
                                conditionError)) {
                            std::wcout << L"Breakpoint #" << candidateId
                                       << L" condition parse error: " << conditionError << L"\n";
                            conditionMatched = true;
                        }
                    }
                    if (conditionMatched) {
                        shouldPause = true;
                        matchedId = candidateId;
                        conditioned = !mbpIt->second.condition.empty();
                        break;
                    }
                }
                if (shouldPause && matchedId >= 0) {
                    std::wstringstream reason;
                    reason << L"Memory breakpoint #" << matchedId << L" hit addr=" << ToHex(faultAddress);
                    if (conditioned) {
                        reason << L" [cond]";
                    }
                    SetStoppedState(event, reason.str(), code, firstChance);
                }
            } else {
                shouldPause = false;
            }
            return true;
        }
    }

    if (ShouldIgnoreException(code)) {
        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        shouldPause = false;
        logger_.Log(L"Ignored exception " + ExceptionCodeToString(code));
        return true;
    }

    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    shouldPause = true;
    SetStoppedState(event, L"Exception: " + ExceptionCodeToString(code), code, firstChance);
    return true;
}

void Debugger::SetStoppedState(const DEBUG_EVENT& event, const std::wstring& reason, DWORD exceptionCode, bool firstChance) {
    stopState_ = StopState();
    stopState_.valid = true;
    stopState_.processId = event.dwProcessId;
    stopState_.threadId = event.dwThreadId;
    stopState_.exceptionCode = exceptionCode;
    stopState_.firstChance = firstChance;
    stopState_.address = reinterpret_cast<uint64_t>(event.u.Exception.ExceptionRecord.ExceptionAddress);
    stopState_.reason = reason;
    CaptureThreadContext(event.dwThreadId, stopState_.context);
    PrintStopSummary();
}

void Debugger::ClearStopState() {
    stopState_ = StopState();
}

bool Debugger::EnableSoftwareBreakpoint(SoftwareBreakpoint& bp) {
    if (bp.enabled) {
        return true;
    }
    uint8_t original = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(bp.address), &original, sizeof(original), &read) || read != 1) {
        return false;
    }
    bp.originalByte = original;
    uint8_t int3 = 0xCC;
    SIZE_T written = 0;
    if (!WriteProcessMemory(processHandle_, reinterpret_cast<LPVOID>(bp.address), &int3, sizeof(int3), &written) || written != 1) {
        return false;
    }
    FlushInstructionCache(processHandle_, reinterpret_cast<LPCVOID>(bp.address), sizeof(int3));
    bp.enabled = true;
    softwareBreakpointByAddress_[bp.address] = bp.id;
    return true;
}

bool Debugger::DisableSoftwareBreakpoint(SoftwareBreakpoint& bp) {
    if (!bp.enabled) {
        return true;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(processHandle_, reinterpret_cast<LPVOID>(bp.address), &bp.originalByte, sizeof(bp.originalByte), &written) || written != 1) {
        return false;
    }
    FlushInstructionCache(processHandle_, reinterpret_cast<LPCVOID>(bp.address), sizeof(bp.originalByte));
    bp.enabled = false;
    softwareBreakpointByAddress_.erase(bp.address);
    return true;
}

bool Debugger::ApplyHardwareBreakpointsForThread(DWORD threadId) {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!thread) {
        return false;
    }

    CONTEXT ctx = CONTEXT();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) {
        CloseHandle(thread);
        return false;
    }

    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    ctx.Dr7 = 0;

    std::set<int> usedSlots;
    for (auto it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
        const HardwareBreakpoint& bp = it->second;
        if (!bp.enabled) {
            continue;
        }
        if (bp.threadId != 0 && bp.threadId != threadId) {
            continue;
        }
        if (bp.slot < 0 || bp.slot > 3 || usedSlots.find(bp.slot) != usedSlots.end()) {
            continue;
        }
        usedSlots.insert(bp.slot);
#ifdef _WIN64
        DWORD64* drReg = nullptr;
#else
		DWORD* drReg = nullptr;
#endif
        if (bp.slot == 0) drReg = &ctx.Dr0;
        if (bp.slot == 1) drReg = &ctx.Dr1;
        if (bp.slot == 2) drReg = &ctx.Dr2;
        if (bp.slot == 3) drReg = &ctx.Dr3;
        if (!drReg) {
            continue;
        }
        *drReg = bp.address;

        const int localEnableBit = bp.slot * 2;
        ctx.Dr7 |= (1ull << localEnableBit);

        DWORD64 rw = 0;
        if (bp.access == HardwareAccessType::Write) rw = 1;
        if (bp.access == HardwareAccessType::Access) rw = 3;

        DWORD64 len = 0;
        switch (bp.length) {
            case 1: len = 0; break;
            case 2: len = 1; break;
            case 4: len = 3; break;
            case 8: len = 2; break;
            default: len = 0; break;
        }

        const int ctrlShift = 16 + (bp.slot * 4);
        ctx.Dr7 &= ~(0xFull << ctrlShift);
        ctx.Dr7 |= ((rw | (len << 2)) << ctrlShift);
    }

    const BOOL ok = SetThreadContext(thread, &ctx);
    CloseHandle(thread);
    return ok == TRUE;
}

bool Debugger::ApplyHardwareBreakpointsForAllThreads() {
    bool allOk = true;
    const std::vector<DWORD> threadIds = EnumerateThreadIds();
    for (auto it = threadIds.begin(); it != threadIds.end(); ++it) {
        DWORD tid = *it;
        allOk = ApplyHardwareBreakpointsForThread(tid) && allOk;
    }
    return allOk;
}

bool Debugger::EnableHardwareBreakpoint(HardwareBreakpoint& bp) {
    bp.enabled = true;
    return ApplyHardwareBreakpointsForAllThreads();
}

bool Debugger::DisableHardwareBreakpoint(HardwareBreakpoint& bp) {
    bp.enabled = false;
    return ApplyHardwareBreakpointsForAllThreads();
}

bool Debugger::EnableMemoryBreakpoint(MemoryBreakpoint& bp) {
    if (bp.enabled) {
        return true;
    }

    SYSTEM_INFO si = SYSTEM_INFO();
    GetSystemInfo(&si);
    const uint64_t pageSize = si.dwPageSize;

    const uint64_t start = bp.address & ~(pageSize - 1);
    const uint64_t end = (bp.address + bp.size + pageSize - 1) & ~(pageSize - 1);

    bp.guardedPages.clear();
    for (uint64_t page = start; page < end; page += pageSize) {
        MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
        if (!VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(page), &mbi, sizeof(mbi))) {
            continue;
        }
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS)) {
            continue;
        }
        DWORD oldProtect = 0;
        if (VirtualProtectEx(processHandle_, reinterpret_cast<LPVOID>(page), pageSize, mbi.Protect | PAGE_GUARD, &oldProtect)) {
            GuardPageInfo pageInfo;
            pageInfo.base = page;
            pageInfo.size = pageSize;
            pageInfo.originalProtection = mbi.Protect;
            bp.guardedPages.push_back(pageInfo);
        }
    }
    bp.enabled = !bp.guardedPages.empty();
    return bp.enabled;
}

bool Debugger::DisableMemoryBreakpoint(MemoryBreakpoint& bp) {
    if (!bp.enabled) {
        return true;
    }
 for (auto __rangeIt22 = (bp.guardedPages).begin(); __rangeIt22 != (bp.guardedPages).end(); ++__rangeIt22) {
        const auto& page = *__rangeIt22;
        DWORD oldProtect = 0;
        VirtualProtectEx(processHandle_, reinterpret_cast<LPVOID>(page.base), page.size, page.originalProtection, &oldProtect);
    }
    bp.guardedPages.clear();
    bp.enabled = false;
    return true;
}

int Debugger::AddSoftwareBreakpoint(uint64_t address) {
    if (!EnsureDebuggee()) {
        return -1;
    }
    if (softwareBreakpointByAddress_.find(address) != softwareBreakpointByAddress_.end()) {
        return softwareBreakpointByAddress_[address];
    }
    SoftwareBreakpoint bp = SoftwareBreakpoint();
    bp.id = nextBreakpointId_++;
    bp.address = address;
    if (!EnableSoftwareBreakpoint(bp)) {
        std::wcout << L"Failed to set software breakpoint at " << ToHex(address) << L".\n";
        return -1;
    }
    softwareBreakpoints_[bp.id] = bp;
    logger_.Log(L"Software breakpoint set id=" + ToWStringCompat(bp.id) + L" addr=" + ToHex(address));
    return bp.id;
}

int Debugger::AddHardwareBreakpoint(int slot, uint64_t address, HardwareAccessType access, int length, DWORD threadId) {
    if (!EnsureDebuggee()) {
        return -1;
    }
    if (slot < 0 || slot > 3) {
        std::wcout << L"Hardware slot must be 0..3.\n";
        return -1;
    }
    HardwareBreakpoint bp = HardwareBreakpoint();
    bp.id = nextBreakpointId_++;
    bp.slot = slot;
    bp.address = address;
    bp.access = access;
    bp.length = length;
    bp.threadId = threadId;
    bp.enabled = true;

    hardwareBreakpoints_[bp.id] = bp;
    if (!ApplyHardwareBreakpointsForAllThreads()) {
        std::wcout << L"Failed to apply hardware breakpoint.\n";
        hardwareBreakpoints_.erase(bp.id);
        return -1;
    }
    logger_.Log(L"Hardware breakpoint set id=" + ToWStringCompat(bp.id) + L" slot=" + ToWStringCompat(slot) + L" addr=" + ToHex(address));
    return bp.id;
}

int Debugger::FindFreeHardwareBreakpointSlot(DWORD threadId) const {
    bool used[4] = {false, false, false, false};
    for (auto it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
        const HardwareBreakpoint& bp = it->second;
        if (!bp.enabled || bp.slot < 0 || bp.slot > 3) {
            continue;
        }
        if (threadId == 0 || bp.threadId == 0 || bp.threadId == threadId) {
            used[bp.slot] = true;
        }
    }
    for (int slot = 0; slot < 4; ++slot) {
        if (!used[slot]) {
            return slot;
        }
    }
    return -1;
}

int Debugger::AddMemoryBreakpoint(uint64_t address, size_t size, MemoryAccessType access) {
    if (!EnsureDebuggee()) {
        return -1;
    }
    if (size == 0) {
        std::wcout << L"Memory breakpoint size must be > 0.\n";
        return -1;
    }
    MemoryBreakpoint bp = MemoryBreakpoint();
    bp.id = nextBreakpointId_++;
    bp.address = address;
    bp.size = size;
    bp.access = access;

    if (!EnableMemoryBreakpoint(bp)) {
        std::wcout << L"Failed to set memory breakpoint.\n";
        return -1;
    }
    memoryBreakpoints_[bp.id] = bp;
    logger_.Log(L"Memory breakpoint set id=" + ToWStringCompat(bp.id) + L" addr=" + ToHex(address) + L" size=" + ToWStringCompat(size));
    return bp.id;
}

bool Debugger::EnableBreakpoint(int breakpointId) {
    std::map<int, SoftwareBreakpoint>::iterator sw = softwareBreakpoints_.find(breakpointId);
    if (sw != softwareBreakpoints_.end()) {
        return EnableSoftwareBreakpoint(sw->second);
    }
    std::map<int, HardwareBreakpoint>::iterator hw = hardwareBreakpoints_.find(breakpointId);
    if (hw != hardwareBreakpoints_.end()) {
        return EnableHardwareBreakpoint(hw->second);
    }
    std::map<int, MemoryBreakpoint>::iterator mb = memoryBreakpoints_.find(breakpointId);
    if (mb != memoryBreakpoints_.end()) {
        return EnableMemoryBreakpoint(mb->second);
    }
    return false;
}

bool Debugger::DisableBreakpoint(int breakpointId) {
    std::map<int, SoftwareBreakpoint>::iterator sw = softwareBreakpoints_.find(breakpointId);
    if (sw != softwareBreakpoints_.end()) {
        return DisableSoftwareBreakpoint(sw->second);
    }
    std::map<int, HardwareBreakpoint>::iterator hw = hardwareBreakpoints_.find(breakpointId);
    if (hw != hardwareBreakpoints_.end()) {
        return DisableHardwareBreakpoint(hw->second);
    }
    std::map<int, MemoryBreakpoint>::iterator mb = memoryBreakpoints_.find(breakpointId);
    if (mb != memoryBreakpoints_.end()) {
        return DisableMemoryBreakpoint(mb->second);
    }
    return false;
}

void Debugger::ClearDanglingTrapFlagForAddress(uint64_t address) {
    std::vector<DWORD> threadsToFix;
    for (std::unordered_map<DWORD, uint64_t>::const_iterator it = pendingSoftwareReinsert_.begin();
         it != pendingSoftwareReinsert_.end(); ++it) {
        if (it->second == address) {
            threadsToFix.push_back(it->first);
        }
    }
    for (size_t i = 0; i < threadsToFix.size(); ++i) {
        const DWORD tid = threadsToFix[i];
        pendingSoftwareReinsert_.erase(tid);
        CONTEXT ctx = CONTEXT();
        if (CaptureThreadContext(tid, ctx)) {
            SetTrapFlag(ctx, false);
            ApplyThreadContext(tid, ctx);
        }
    }
}

bool Debugger::RemoveBreakpoint(int breakpointId) {
    std::map<int, SoftwareBreakpoint>::iterator sw = softwareBreakpoints_.find(breakpointId);
    if (sw != softwareBreakpoints_.end()) {
        ClearDanglingTrapFlagForAddress(sw->second.address);
        DisableSoftwareBreakpoint(sw->second);
        softwareBreakpointByAddress_.erase(sw->second.address);
        softwareBreakpoints_.erase(sw);
        return true;
    }
    std::map<int, HardwareBreakpoint>::iterator hw = hardwareBreakpoints_.find(breakpointId);
    if (hw != hardwareBreakpoints_.end()) {
        hw->second.enabled = false;
        ApplyHardwareBreakpointsForAllThreads();
        hardwareBreakpoints_.erase(hw);
        return true;
    }
    std::map<int, MemoryBreakpoint>::iterator mb = memoryBreakpoints_.find(breakpointId);
    if (mb != memoryBreakpoints_.end()) {
        DisableMemoryBreakpoint(mb->second);
        memoryBreakpoints_.erase(mb);
        return true;
    }
    return false;
}

size_t Debugger::RemoveAllBreakpoints() {
    std::vector<int> ids;
    ids.reserve(softwareBreakpoints_.size() + hardwareBreakpoints_.size() + memoryBreakpoints_.size());
    for (auto it = softwareBreakpoints_.begin(); it != softwareBreakpoints_.end(); ++it) {
        const int id = it->first;
        ids.push_back(id);
    }
    for (auto it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
        const int id = it->first;
        ids.push_back(id);
    }
    for (auto it = memoryBreakpoints_.begin(); it != memoryBreakpoints_.end(); ++it) {
        const int id = it->first;
        ids.push_back(id);
    }

    size_t removed = 0;
 for (auto __rangeIt23 = (ids).begin(); __rangeIt23 != (ids).end(); ++__rangeIt23) {
        const int id = *__rangeIt23;
        if (RemoveBreakpoint(id)) {
            ++removed;
        }
    }

    for (std::unordered_map<DWORD, uint64_t>::const_iterator it = pendingSoftwareReinsert_.begin();
         it != pendingSoftwareReinsert_.end(); ++it) {
        CONTEXT ctx = CONTEXT();
        if (CaptureThreadContext(it->first, ctx)) {
            SetTrapFlag(ctx, false);
            ApplyThreadContext(it->first, ctx);
        }
    }
    stepOverBreakpointId_ = -1;
    if (runToEntryBreakpointId_ >= 0) {
        runToEntryBreakpointId_ = -1;
        runToEntryOwnsBreakpoint_ = false;
    }
    pendingSoftwareReinsert_.clear();
    pendingMemoryRearm_.clear();
    return removed;
}

bool Debugger::SetBreakpointCondition(int breakpointId, const std::wstring& expression) {
    const std::wstring trimmed = TrimWhitespace(expression);
    if (trimmed.empty()) {
        std::wcout << L"Condition text cannot be empty.\n";
        return false;
    }

    bool testMatched = false;
    std::wstring parseError;
    if (!EvaluateBreakpointCondition(trimmed, 1, 1, 0, 0, testMatched, parseError)) {
        std::wcout << L"Invalid condition expression: " << parseError << L"\n";
        std::wcout << L"Examples: hit>=3, tid==1234&&hit>=2, addr==0x401000\n";
        return false;
    }

    std::map<int, SoftwareBreakpoint>::iterator sw = softwareBreakpoints_.find(breakpointId);
    if (sw != softwareBreakpoints_.end()) {
        sw->second.condition = trimmed;
        return true;
    }
    std::map<int, HardwareBreakpoint>::iterator hw = hardwareBreakpoints_.find(breakpointId);
    if (hw != hardwareBreakpoints_.end()) {
        hw->second.condition = trimmed;
        return true;
    }
    std::map<int, MemoryBreakpoint>::iterator mb = memoryBreakpoints_.find(breakpointId);
    if (mb != memoryBreakpoints_.end()) {
        mb->second.condition = trimmed;
        return true;
    }

    std::wcout << L"Breakpoint #" << breakpointId << L" not found.\n";
    return false;
}

bool Debugger::ClearBreakpointCondition(int breakpointId) {
    std::map<int, SoftwareBreakpoint>::iterator sw = softwareBreakpoints_.find(breakpointId);
    if (sw != softwareBreakpoints_.end()) {
        sw->second.condition.clear();
        return true;
    }
    std::map<int, HardwareBreakpoint>::iterator hw = hardwareBreakpoints_.find(breakpointId);
    if (hw != hardwareBreakpoints_.end()) {
        hw->second.condition.clear();
        return true;
    }
    std::map<int, MemoryBreakpoint>::iterator mb = memoryBreakpoints_.find(breakpointId);
    if (mb != memoryBreakpoints_.end()) {
        mb->second.condition.clear();
        return true;
    }
    std::wcout << L"Breakpoint #" << breakpointId << L" not found.\n";
    return false;
}

bool Debugger::EvaluateBreakpointCondition(
    const std::wstring& expression,
    uint64_t hitCount,
    DWORD threadId,
    uint64_t instructionPointer,
    uint64_t address,
    bool& matched,
    std::wstring& error) {
    matched = true;
    error.clear();

    const std::wstring trimmed = TrimWhitespace(expression);
    if (trimmed.empty() || ToLower(trimmed) == L"always" || ToLower(trimmed) == L"true") {
        return true;
    }

    const auto resolveValue = [&](const std::wstring& key, uint64_t& value) -> bool {
        const std::wstring lowered = ToLower(key);
        if (lowered == L"hit" || lowered == L"hits" || lowered == L"count") {
            value = hitCount;
            return true;
        }
        if (lowered == L"tid" || lowered == L"thread") {
            value = static_cast<uint64_t>(threadId);
            return true;
        }
        if (lowered == L"ip" || lowered == L"rip" || lowered == L"eip") {
            value = instructionPointer;
            return true;
        }
        if (lowered == L"addr" || lowered == L"address" || lowered == L"bpaddr") {
            value = address;
            return true;
        }
        return false;
    };

    const std::vector<std::wstring> clauses = SplitByAnd(trimmed);
    for (auto clauseIt = clauses.begin(); clauseIt != clauses.end(); ++clauseIt) {
        const std::wstring& rawClause = *clauseIt;
        std::wstring clause = RemoveWhitespace(rawClause);
        if (clause.empty()) {
            continue;
        }
        std::wstring op;
        size_t opPos = std::wstring::npos;
        const wchar_t* candidates[] = {L"==", L"!=", L">=", L"<=", L">", L"<"};
        for (size_t candidateIndex = 0; candidateIndex < sizeof(candidates) / sizeof(candidates[0]); ++candidateIndex) {
            const wchar_t* candidate = candidates[candidateIndex];
            const size_t pos = clause.find(candidate);
            if (pos != std::wstring::npos) {
                op = candidate;
                opPos = pos;
                break;
            }
        }
        if (opPos == std::wstring::npos) {
            error = L"Missing comparison operator in clause '" + rawClause + L"'";
            return false;
        }

        const std::wstring left = clause.substr(0, opPos);
        const std::wstring right = clause.substr(opPos + op.size());
        if (left.empty() || right.empty()) {
            error = L"Invalid clause '" + rawClause + L"'";
            return false;
        }

        uint64_t leftValue = 0;
        if (!resolveValue(left, leftValue)) {
            error = L"Unknown variable '" + left + L"'";
            return false;
        }

        uint64_t rightValue = 0;
        if (!ParseUnsignedInteger(right, rightValue)) {
            error = L"Invalid numeric value '" + right + L"'";
            return false;
        }

        bool clauseResult = false;
        if (op == L"==") clauseResult = leftValue == rightValue;
        else if (op == L"!=") clauseResult = leftValue != rightValue;
        else if (op == L">=") clauseResult = leftValue >= rightValue;
        else if (op == L"<=") clauseResult = leftValue <= rightValue;
        else if (op == L">") clauseResult = leftValue > rightValue;
        else if (op == L"<") clauseResult = leftValue < rightValue;

        if (!clauseResult) {
            matched = false;
            return true;
        }
    }

    matched = true;
    return true;
}

bool Debugger::WriteMemoryPatch(uint64_t address, const std::vector<uint8_t>& bytes, bool recordHistory) {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (bytes.empty()) {
        std::wcout << L"No patch bytes provided.\n";
        return false;
    }

    std::vector<uint8_t> original(bytes.size(), 0);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(
            processHandle_,
            reinterpret_cast<LPCVOID>(address),
            original.data(),
            original.size(),
            &bytesRead) ||
        bytesRead != original.size()) {
        std::wcout << L"ReadProcessMemory failed while backing up patch region.\n";
        return false;
    }

    if (original == bytes) {
        std::wcout << L"Patch skipped: target bytes already match requested payload at " << ToHex(address) << L".\n";
        return true;
    }

    const auto writeBytes = [&](const std::vector<uint8_t>& payload) -> bool {
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(
                processHandle_,
                reinterpret_cast<LPVOID>(address),
                payload.size(),
                PAGE_EXECUTE_READWRITE,
                &oldProtect)) {
            return false;
        }

        SIZE_T written = 0;
        const BOOL writeOk = WriteProcessMemory(
            processHandle_,
            reinterpret_cast<LPVOID>(address),
            payload.data(),
            payload.size(),
            &written);
        DWORD restoreProtect = 0;
        VirtualProtectEx(
            processHandle_,
            reinterpret_cast<LPVOID>(address),
            payload.size(),
            oldProtect,
            &restoreProtect);
        if (!writeOk || written != payload.size()) {
            return false;
        }

        FlushInstructionCache(processHandle_, reinterpret_cast<LPCVOID>(address), payload.size());
        return true;
    };

    if (!writeBytes(bytes)) {
        std::wcout << L"WriteProcessMemory failed while patching process memory.\n";
        return false;
    }

    std::vector<uint8_t> verify(bytes.size(), 0);
    bytesRead = 0;
    if (!ReadProcessMemory(
            processHandle_,
            reinterpret_cast<LPCVOID>(address),
            verify.data(),
            verify.size(),
            &bytesRead) ||
        bytesRead != verify.size()) {
        std::wcout << L"Patch verification failed: unable to re-read patched bytes.\n";
        writeBytes(original);
        return false;
    }
    if (verify != bytes) {
        std::wcout << L"Patch verification failed: byte mismatch after write. Restoring original bytes.\n";
        writeBytes(original);
        return false;
    }

    if (recordHistory) {
        MemoryPatchRecord record = MemoryPatchRecord();
        record.address = address;
        record.originalBytes = original;
        record.patchedBytes = bytes;
        patchHistory_.push_back(std::move(record));
        const size_t kMaxPatchHistory = 512;
        if (patchHistory_.size() > kMaxPatchHistory) {
            patchHistory_.erase(
                patchHistory_.begin(),
                patchHistory_.begin() + static_cast<std::ptrdiff_t>(patchHistory_.size() - kMaxPatchHistory));
        }
    }

    std::wcout << L"Patched " << bytes.size() << L" byte(s) at " << ToHex(address)
               << L" | before: " << BytesToHexPreview(original)
               << L" | after: " << BytesToHexPreview(bytes) << L"\n";
    logger_.Log(
        L"Patch addr=" + ToHex(address) +
        L" size=" + ToWStringCompat(bytes.size()) +
        L" before=" + BytesToHexPreview(original) +
        L" after=" + BytesToHexPreview(bytes));
    return true;
}

bool Debugger::UndoMemoryPatch(size_t count) {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (count == 0) {
        std::wcout << L"Undo count must be greater than zero.\n";
        return false;
    }
    if (patchHistory_.empty()) {
        std::wcout << L"No memory patch history is available for undo.\n";
        return false;
    }

    const size_t undoCount = std::min(count, patchHistory_.size());
    size_t reverted = 0;
    for (size_t i = 0; i < undoCount; ++i) {
        const MemoryPatchRecord record = patchHistory_.back();
        if (!WriteMemoryPatch(record.address, record.originalBytes, false)) {
            std::wcout << L"Undo stopped after " << reverted
                       << L" patch(es); failed to restore " << ToHex(record.address) << L".\n";
            return false;
        }
        patchHistory_.pop_back();
        ++reverted;
    }

    std::wcout << L"Undo complete: reverted " << reverted << L" patch operation(s).\n";
    logger_.Log(L"Patch undo count=" + ToWStringCompat(reverted));
    return true;
}

void Debugger::ListMemoryPatchHistory(size_t maxItems) const {
    if (patchHistory_.empty()) {
        std::wcout << L"No memory patch history.\n";
        return;
    }
    if (maxItems == 0) {
        maxItems = 1;
    }

    const size_t total = patchHistory_.size();
    const size_t shown = std::min(maxItems, total);
    std::wcout << L"--- Memory Patch History (" << total << L") ---\n";
    for (size_t i = 0; i < shown; ++i) {
        const size_t index = total - 1 - i;
        const auto& record = patchHistory_[index];
        std::wcout << L"#" << index
                   << L" addr=" << ToHex(record.address)
                   << L" size=" << record.patchedBytes.size()
                   << L" before=[" << BytesToHexPreview(record.originalBytes) << L"]"
                   << L" after=[" << BytesToHexPreview(record.patchedBytes) << L"]\n";
    }
    if (shown < total) {
        std::wcout << L"... truncated, use 'patch list <max_items>' to show more.\n";
    }
}

bool Debugger::EvaluateCurrentStopCondition(
    const std::wstring& expression,
    uint64_t iteration,
    bool& matched,
    std::wstring& error) const {
    matched = false;
    error.clear();
    if (!pendingEvent_.valid || !stopState_.valid) {
        error = L"No paused state available.";
        return false;
    }
    return EvaluateBreakpointCondition(
        expression,
        iteration,
        stopState_.threadId,
        GetInstructionPointer(stopState_.context),
        stopState_.address,
        matched,
        error);
}

bool Debugger::StepUntilCondition(const std::wstring& condition, uint64_t maxSteps) {
    if (!EnsurePaused()) {
        return false;
    }
    if (TrimWhitespace(condition).empty()) {
        std::wcout << L"Condition cannot be empty.\n";
        return false;
    }
    if (maxSteps == 0) {
        std::wcout << L"Maximum step count must be greater than zero.\n";
        return false;
    }

    bool matched = false;
    std::wstring error;
    if (!EvaluateCurrentStopCondition(condition, 0, matched, error)) {
        std::wcout << L"Invalid step-until condition: " << error << L"\n";
        return false;
    }
    if (matched) {
        std::wcout << L"Condition already satisfied at current pause.\n";
        return true;
    }

    for (uint64_t i = 1; i <= maxSteps; ++i) {
        if (!SingleStep()) {
            return false;
        }
        if (!active_) {
            std::wcout << L"Debuggee exited before condition was met.\n";
            return false;
        }
        if (!EvaluateCurrentStopCondition(condition, i, matched, error)) {
            std::wcout << L"Condition evaluation failed: " << error << L"\n";
            return false;
        }
        if (matched) {
            std::wcout << L"Condition met after " << i << L" step(s).\n";
            return true;
        }
    }

    std::wcout << L"Condition not met within " << maxSteps << L" step(s).\n";
    return false;
}

bool Debugger::RunUntilCondition(const std::wstring& condition, uint64_t maxPauses) {
    if (!EnsurePaused()) {
        return false;
    }
    if (TrimWhitespace(condition).empty()) {
        std::wcout << L"Condition cannot be empty.\n";
        return false;
    }
    if (maxPauses == 0) {
        std::wcout << L"Maximum pause count must be greater than zero.\n";
        return false;
    }

    bool matched = false;
    std::wstring error;
    if (!EvaluateCurrentStopCondition(condition, 0, matched, error)) {
        std::wcout << L"Invalid run-until condition: " << error << L"\n";
        return false;
    }
    if (matched) {
        std::wcout << L"Condition already satisfied at current pause.\n";
        return true;
    }

    for (uint64_t i = 1; i <= maxPauses; ++i) {
        if (!ContinueExecution()) {
            return false;
        }
        if (!active_) {
            std::wcout << L"Debuggee exited before condition was met.\n";
            return false;
        }
        if (!EvaluateCurrentStopCondition(condition, i, matched, error)) {
            std::wcout << L"Condition evaluation failed: " << error << L"\n";
            return false;
        }
        if (matched) {
            std::wcout << L"Condition met after " << i << L" pause event(s).\n";
            return true;
        }
    }

    std::wcout << L"Condition not met within " << maxPauses << L" pause event(s).\n";
    return false;
}

bool Debugger::AutoStep(uint64_t steps, uint32_t delayMs) {
    if (!EnsurePaused()) {
        return false;
    }
    if (steps == 0) {
        std::wcout << L"Step count must be greater than zero.\n";
        return false;
    }
    for (uint64_t i = 0; i < steps; ++i) {
        if (!SingleStep()) {
            return false;
        }
        if (!active_) {
            return false;
        }
        if (delayMs > 0) {
            Sleep(delayMs);
        }
    }
    std::wcout << L"Auto-step completed: " << steps << L" step(s).\n";
    return true;
}

bool Debugger::AutoRun(uint64_t pauses, uint32_t delayMs) {
    if (!EnsurePaused()) {
        return false;
    }
    if (pauses == 0) {
        std::wcout << L"Pause cycle count must be greater than zero.\n";
        return false;
    }
    for (uint64_t i = 0; i < pauses; ++i) {
        if (!ContinueExecution()) {
            return false;
        }
        if (!active_) {
            return false;
        }
        if (delayMs > 0) {
            Sleep(delayMs);
        }
    }
    std::wcout << L"Auto-run completed: " << pauses << L" continue cycle(s).\n";
    return true;
}

bool Debugger::CaptureSnapshotMemory(std::vector<MemorySnapshotRegion>& regions) const {
    regions.clear();
    if (!pendingEvent_.valid || !stopState_.valid || processHandle_ == nullptr) {
        return false;
    }

    auto isCovered = [&](uint64_t address, size_t size) -> bool {
        if (size == 0) {
            return true;
        }
        const uint64_t end = address + static_cast<uint64_t>(size);
 for (auto __rangeIt24 = (regions).begin(); __rangeIt24 != (regions).end(); ++__rangeIt24) {
            const auto& region = *__rangeIt24;
            const uint64_t regionStart = region.address;
            const uint64_t regionEnd = region.address + static_cast<uint64_t>(region.bytes.size());
            if (address >= regionStart && end <= regionEnd) {
                return true;
            }
        }
        return false;
    };

    auto captureRegion = [&](uint64_t address, size_t size) -> bool {
        if (address == 0 || size == 0 || isCovered(address, size)) {
            return false;
        }
        std::vector<uint8_t> bytes(size);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(address),
                bytes.data(),
                bytes.size(),
                &bytesRead) ||
            bytesRead == 0) {
            return false;
        }
        bytes.resize(bytesRead);
        MemorySnapshotRegion region;
        region.address = address;
        region.bytes.swap(bytes);
        regions.push_back(region);
        return true;
    };

    const uint64_t ip = GetInstructionPointer(stopState_.context);
    const uint64_t codeStart = ip > 48 ? (ip - 48) : 0;
    captureRegion(codeStart, 128);

    const uint64_t sp = GetStackPointer(stopState_.context);
    if (sp != 0) {
        MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
        if (VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(sp), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            const DWORD blocked = PAGE_NOACCESS | PAGE_GUARD;
            const bool readable = (mbi.Protect & blocked) == 0 && mbi.State == MEM_COMMIT;
            if (readable) {
                const uint64_t regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                const uint64_t regionEnd = regionBase + static_cast<uint64_t>(mbi.RegionSize);
                uint64_t stackStart = sp > 512 ? (sp - 512) : regionBase;
                if (stackStart < regionBase) {
                    stackStart = regionBase;
                }
                uint64_t stackEnd = sp + 1536;
                if (stackEnd > regionEnd) {
                    stackEnd = regionEnd;
                }
                if (stackEnd > stackStart) {
                    captureRegion(stackStart, static_cast<size_t>(stackEnd - stackStart));
                }
            }
        }
    }

    for (auto it = softwareBreakpoints_.begin(); it != softwareBreakpoints_.end(); ++it) {
        const SoftwareBreakpoint& bp = it->second;
        if (!bp.enabled) {
            continue;
        }
        captureRegion(bp.address, 1);
    }

    return !regions.empty();
}

bool Debugger::RestoreSnapshotMemory(const std::vector<MemorySnapshotRegion>& regions) const {
    if (processHandle_ == nullptr) {
        return false;
    }
    bool allRestored = true;
    size_t restoredRegions = 0;
 for (auto __rangeIt25 = (regions).begin(); __rangeIt25 != (regions).end(); ++__rangeIt25) {
        const auto& region = *__rangeIt25;
        if (region.address == 0 || region.bytes.empty()) {
            continue;
        }

        DWORD oldProtect = 0;
        const bool protectChanged = VirtualProtectEx(
            processHandle_,
            reinterpret_cast<LPVOID>(region.address),
            region.bytes.size(),
            PAGE_EXECUTE_READWRITE,
            &oldProtect) != FALSE;

        SIZE_T written = 0;
        const BOOL writeOk = WriteProcessMemory(
            processHandle_,
            reinterpret_cast<LPVOID>(region.address),
            region.bytes.data(),
            region.bytes.size(),
            &written);

        if (protectChanged) {
            DWORD ignored = 0;
            VirtualProtectEx(
                processHandle_,
                reinterpret_cast<LPVOID>(region.address),
                region.bytes.size(),
                oldProtect,
                &ignored);
        }

        if (!writeOk || written != region.bytes.size()) {
            allRestored = false;
            continue;
        }

        FlushInstructionCache(processHandle_, reinterpret_cast<LPCVOID>(region.address), region.bytes.size());
        ++restoredRegions;
    }

    if (restoredRegions == 0) {
        return false;
    }
    return allRestored;
}

void Debugger::SaveCurrentStopSnapshot() {
    if (!pendingEvent_.valid || !stopState_.valid) {
        return;
    }
    StopSnapshot snapshot = StopSnapshot();
    snapshot.stop = stopState_;
    snapshot.pendingSoftwareReinsert = pendingSoftwareReinsert_;
    snapshot.pendingMemoryRearm = pendingMemoryRearm_;
    CaptureSnapshotMemory(snapshot.memoryRegions);
    stopHistory_.push_back(std::move(snapshot));
    const size_t kMaxHistory = 256;
    if (stopHistory_.size() > kMaxHistory) {
        stopHistory_.erase(stopHistory_.begin(), stopHistory_.begin() + static_cast<std::ptrdiff_t>(stopHistory_.size() - kMaxHistory));
    }
}

bool Debugger::SaveNamedSnapshot(const std::wstring& name) {
    if (!EnsurePaused()) {
        return false;
    }
    StopSnapshot snapshot = StopSnapshot();
    snapshot.stop = stopState_;
    snapshot.pendingSoftwareReinsert = pendingSoftwareReinsert_;
    snapshot.pendingMemoryRearm = pendingMemoryRearm_;
    CaptureSnapshotMemory(snapshot.memoryRegions);

    const std::wstring key = NormalizeSnapshotKey(name);
    namedSnapshots_[key] = std::move(snapshot);
    std::wcout << L"Saved snapshot '" << key << L"' at " << ToHex(GetInstructionPointer(stopState_.context)) << L".\n";
    return true;
}

void Debugger::ListNamedSnapshots() const {
    std::wcout << L"--- Named Snapshots ---\n";
    if (namedSnapshots_.empty()) {
        std::wcout << L"(none)\n";
        return;
    }
    for (auto it = namedSnapshots_.begin(); it != namedSnapshots_.end(); ++it) {
        const std::wstring& name = it->first;
        const StopSnapshot& snapshot = it->second;
        const uint64_t ip = GetInstructionPointer(snapshot.stop.context);
        std::wcout << name
                   << L"  ip=" << ToHex(ip)
                   << L"  tid=" << snapshot.stop.threadId
                   << L"  reason=" << snapshot.stop.reason << L"\n";
    }
}

bool Debugger::RestoreStopSnapshot(const StopSnapshot& snapshot, const std::wstring& reasonTag, bool includeOriginalReason) {
    if (!EnsurePaused()) {
        return false;
    }
    const bool memoryRestored = RestoreSnapshotMemory(snapshot.memoryRegions);
    CONTEXT restore = snapshot.stop.context;
    if (!ApplyThreadContext(snapshot.stop.threadId, restore)) {
        std::wcout << L"Failed to restore thread context from snapshot.\n";
        return false;
    }

    pendingSoftwareReinsert_ = snapshot.pendingSoftwareReinsert;
    pendingMemoryRearm_ = snapshot.pendingMemoryRearm;
    stopState_ = snapshot.stop;
    stopState_.address = GetInstructionPointer(stopState_.context);

    std::wstring reason = reasonTag;
    if (includeOriginalReason && !snapshot.stop.reason.empty()) {
        reason += L" [" + snapshot.stop.reason + L"]";
    }
    reason += memoryRestored ? L" (context + memory)" : L" (context only)";
    stopState_.reason = reason;

    if (!snapshot.memoryRegions.empty() && !memoryRestored) {
        std::wcout << L"Snapshot restore warning: one or more memory regions could not be fully restored.\n";
    }
    PrintStopSummary();
    return true;
}

bool Debugger::RestoreNamedSnapshot(const std::wstring& name, bool rerunAfterRestore) {
    const std::wstring key = NormalizeSnapshotKey(name);
    const auto it = namedSnapshots_.find(key);
    if (it == namedSnapshots_.end()) {
        std::wcout << L"Snapshot '" << key << L"' was not found.\n";
        return false;
    }
    if (!RestoreStopSnapshot(it->second, L"Snapshot restore '" + key + L"'", true)) {
        return false;
    }
    if (!rerunAfterRestore) {
        return true;
    }
    std::wcout << L"Rerunning from snapshot '" << key << L"'...\n";
    return ContinueExecution();
}

bool Debugger::StepBackToPreviousSnapshot() {
    if (!EnsurePaused()) {
        return false;
    }
    if (stopHistory_.empty()) {
        std::wcout << L"No previous debug snapshot is available.\n";
        return false;
    }

    StopSnapshot previous = std::move(stopHistory_.back());
    stopHistory_.pop_back();
    return RestoreStopSnapshot(previous, L"Step-back", true);
}

bool Debugger::RunToEntryPoint() {
    if (!EnsurePaused()) {
        return false;
    }
    if (entryPointAddress_ == 0) {
        uint64_t resolvedBase = 0;
        uint64_t resolvedEntry = 0;
        if (ResolveMainModuleEntryPoint(resolvedBase, resolvedEntry)) {
            mainModuleBase_ = resolvedBase;
            entryPointAddress_ = resolvedEntry;
            std::wcout << L"Resolved main module entry point at " << ToHex(entryPointAddress_) << L".\n";
        } else {
            std::wcout << L"Entry point address is not available.\n";
            return false;
        }
    }

    const uint64_t ip = GetInstructionPointer(stopState_.context);
    if (ip == entryPointAddress_) {
        std::wcout << L"Already paused at the entry point: " << ToHex(entryPointAddress_) << L"\n";
        return true;
    }

    if (runToEntryBreakpointId_ >= 0 && runToEntryOwnsBreakpoint_) {
        RemoveBreakpoint(runToEntryBreakpointId_);
    }
    runToEntryBreakpointId_ = -1;
    runToEntryOwnsBreakpoint_ = false;

    auto existing = softwareBreakpointByAddress_.find(entryPointAddress_);
    if (existing != softwareBreakpointByAddress_.end()) {
        runToEntryBreakpointId_ = existing->second;
        runToEntryOwnsBreakpoint_ = false;
    } else {
        const int id = AddSoftwareBreakpoint(entryPointAddress_);
        if (id < 0) {
            return false;
        }
        runToEntryBreakpointId_ = id;
        runToEntryOwnsBreakpoint_ = true;
    }

    std::wcout << L"Running to entry point at " << ToHex(entryPointAddress_) << L"...\n";
    return ContinueExecution();
}

void Debugger::PrintFlowGraph(uint64_t address, size_t maxBlocks) const {
    if (!EnsureDebuggee()) {
        return;
    }
    const uint8_t disassemblyModeBits = DetermineDisassemblyModeBits(processHandle_);
    if (maxBlocks == 0) {
        maxBlocks = 1;
    }
    if (maxBlocks > 128) {
        maxBlocks = 128;
    }

    struct Block {
        uint64_t start;
        std::vector<std::wstring> lines;
        std::vector<uint64_t> successors;

        Block()
            : start(0) {
        }
    };

    std::deque<uint64_t> queue;
    std::set<uint64_t> seen;
    std::vector<Block> blocks;
    queue.push_back(address);

    auto parseTargetAddress = [&](const std::wstring& text, uint64_t& out) -> bool {
        const size_t pos = text.find(L"0x");
        if (pos == std::wstring::npos) {
            return false;
        }
        size_t end = pos + 2;
        while (end < text.size() && std::iswxdigit(text[end])) {
            ++end;
        }
        return ParseUInt64(text.substr(pos, end - pos), out);
    };

    while (!queue.empty() && blocks.size() < maxBlocks) {
        const uint64_t blockStart = queue.front();
        queue.pop_front();
        if (seen.find(blockStart) != seen.end()) {
            continue;
        }
        seen.insert(blockStart);

        Block block = Block();
        block.start = blockStart;
        uint64_t current = blockStart;
        bool ended = false;

        for (size_t i = 0; i < 32; ++i) {
            std::array<uint8_t, 16> bytes = std::array<uint8_t, 16>();
            SIZE_T read = 0;
            if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(current), bytes.data(), bytes.size(), &read) || read == 0) {
                break;
            }
            const auto decoded = DecodeInstruction(current, bytes.data(), static_cast<size_t>(read), disassemblyModeBits);
            if (decoded.length == 0) {
                break;
            }
            const std::wstring displayText = RewriteImportedThunkSymbols(decoded.text);

            std::wstringstream line;
            line << ToHex(current) << L"  " << displayText;
            block.lines.push_back(line.str());

            const std::wstring lower = ToLower(displayText);
            const uint64_t fallThrough = current + decoded.length;
            uint64_t target = 0;

            if (lower.rfind(L"ret", 0) == 0) {
                ended = true;
            } else if (lower.rfind(L"jmp ", 0) == 0) {
                if (parseTargetAddress(displayText, target)) {
                    block.successors.push_back(target);
                }
                ended = true;
            } else if (lower.rfind(L"j", 0) == 0 && lower.rfind(L"jmp ", 0) != 0) {
                if (parseTargetAddress(displayText, target)) {
                    block.successors.push_back(target);
                }
                block.successors.push_back(fallThrough);
                ended = true;
            } else if (lower.rfind(L"call ", 0) == 0) {
                block.successors.push_back(fallThrough);
                ended = true;
            }

            current = fallThrough;
            if (ended) {
                break;
            }
        }

        if (!ended && !block.lines.empty()) {
            block.successors.push_back(current);
        }

        std::sort(block.successors.begin(), block.successors.end());
        block.successors.erase(std::unique(block.successors.begin(), block.successors.end()), block.successors.end());
 for (auto __rangeIt26 = (block.successors).begin(); __rangeIt26 != (block.successors).end(); ++__rangeIt26) {
            uint64_t succ = *__rangeIt26;
            if (seen.find(succ) == seen.end() && blocks.size() + queue.size() < maxBlocks) {
                queue.push_back(succ);
            }
        }

        blocks.push_back(std::move(block));
    }

    std::unordered_map<uint64_t, size_t> blockIndexByStart;
    for (size_t i = 0; i < blocks.size(); ++i) {
        blockIndexByStart[blocks[i].start] = i;
    }

    std::wcout << L"--- Flow Graph @ " << ToHex(address) << L" ---\n";
    for (size_t i = 0; i < blocks.size(); ++i) {
        const auto& block = blocks[i];
        std::wcout << L"[B" << (i + 1) << L"] start=" << ToHex(block.start) << L"\n";
 for (auto __rangeIt27 = (block.lines).begin(); __rangeIt27 != (block.lines).end(); ++__rangeIt27) {
            const auto& line = *__rangeIt27;
            std::wcout << L"  " << line << L"\n";
        }
        if (block.successors.empty()) {
            std::wcout << L"  -> (end)\n";
        } else {
 for (auto __rangeIt28 = (block.successors).begin(); __rangeIt28 != (block.successors).end(); ++__rangeIt28) {
                uint64_t succ = *__rangeIt28;
                auto it = blockIndexByStart.find(succ);
                if (it != blockIndexByStart.end()) {
                    std::wcout << L"  -> B" << (it->second + 1) << L" (" << ToHex(succ) << L")\n";
                } else {
                    std::wcout << L"  -> " << ToHex(succ) << L"\n";
                }
            }
        }
    }
    std::wcout << L"--- End Flow Graph ---\n";
}

bool Debugger::ConfigureExceptionIgnoreAll(ExceptionScope scope, bool enabled) {
    ExceptionRuleSet* rules = nullptr;
    if (scope == ExceptionScope::Debugging) {
        rules = &debuggingExceptionRules_;
    } else if (scope == ExceptionScope::Runtime) {
        rules = &runtimeExceptionRules_;
    } else {
        rules = &steppingExceptionRules_;
    }
    rules->ignoreAll = enabled;
    std::wcout << L"Exception ignore-all for " << ExceptionScopeToString(scope)
               << L" is now " << (enabled ? L"ON" : L"OFF") << L".\n";
    return true;
}

bool Debugger::AddIgnoredExceptionCode(ExceptionScope scope, DWORD code) {
    ExceptionRuleSet* rules = nullptr;
    if (scope == ExceptionScope::Debugging) {
        rules = &debuggingExceptionRules_;
    } else if (scope == ExceptionScope::Runtime) {
        rules = &runtimeExceptionRules_;
    } else {
        rules = &steppingExceptionRules_;
    }
    rules->ignoredCodes.insert(code);
    std::wcout << L"Added ignored exception code " << ExceptionCodeToString(code)
               << L" to " << ExceptionScopeToString(scope) << L".\n";
    return true;
}

bool Debugger::RemoveIgnoredExceptionCode(ExceptionScope scope, DWORD code) {
    ExceptionRuleSet* rules = nullptr;
    if (scope == ExceptionScope::Debugging) {
        rules = &debuggingExceptionRules_;
    } else if (scope == ExceptionScope::Runtime) {
        rules = &runtimeExceptionRules_;
    } else {
        rules = &steppingExceptionRules_;
    }
    if (rules->ignoredCodes.erase(code) == 0) {
        std::wcout << L"Exception code was not configured in " << ExceptionScopeToString(scope) << L".\n";
        return false;
    }
    std::wcout << L"Removed ignored exception code " << ExceptionCodeToString(code)
               << L" from " << ExceptionScopeToString(scope) << L".\n";
    return true;
}

void Debugger::ClearIgnoredExceptionCodes(ExceptionScope scope) {
    ExceptionRuleSet* rules = nullptr;
    if (scope == ExceptionScope::Debugging) {
        rules = &debuggingExceptionRules_;
    } else if (scope == ExceptionScope::Runtime) {
        rules = &runtimeExceptionRules_;
    } else {
        rules = &steppingExceptionRules_;
    }
    rules->ignoredCodes.clear();
    std::wcout << L"Cleared ignored exception list for " << ExceptionScopeToString(scope) << L".\n";
}

void Debugger::ListExceptionSettings() const {
    auto printScope = [&](ExceptionScope scope, const ExceptionRuleSet& rules) {
        std::wcout << L"[" << ExceptionScopeToString(scope) << L"] ignoreAll="
                   << (rules.ignoreAll ? L"ON" : L"OFF") << L"\n";
        if (rules.ignoredCodes.empty()) {
            std::wcout << L"  ignored: (none)\n";
            return;
        }
        std::wcout << L"  ignored:";
 for (auto __rangeIt29 = (rules.ignoredCodes).begin(); __rangeIt29 != (rules.ignoredCodes).end(); ++__rangeIt29) {
            DWORD code = *__rangeIt29;
            std::wcout << L" " << ExceptionCodeToString(code);
        }
        std::wcout << L"\n";
    };

    std::wcout << L"--- Exception Settings ---\n";
    printScope(ExceptionScope::Debugging, debuggingExceptionRules_);
    printScope(ExceptionScope::Runtime, runtimeExceptionRules_);
    printScope(ExceptionScope::Stepping, steppingExceptionRules_);
    ListRunStopExpressions();
}

bool Debugger::AddRunStopExpression(const std::wstring& expression) {
    const std::wstring trimmed = TrimWhitespace(expression);
    if (trimmed.empty()) {
        std::wcout << L"Run-stop expression cannot be empty.\n";
        return false;
    }
    bool matched = false;
    std::wstring error;
    if (!EvaluateBreakpointCondition(trimmed, 1, 1, 0, 0, matched, error)) {
        std::wcout << L"Invalid run-stop expression: " << error << L"\n";
        return false;
    }
    runStopExpressions_.push_back(trimmed);
    std::wcout << L"Added run-stop expression #" << runStopExpressions_.size()
               << L": " << trimmed << L"\n";
    return true;
}

bool Debugger::RemoveRunStopExpression(size_t index) {
    if (index == 0 || index > runStopExpressions_.size()) {
        std::wcout << L"Invalid run-stop expression index.\n";
        return false;
    }
    const std::wstring removed = runStopExpressions_[index - 1];
    runStopExpressions_.erase(runStopExpressions_.begin() + static_cast<std::ptrdiff_t>(index - 1));
    std::wcout << L"Removed run-stop expression: " << removed << L"\n";
    return true;
}

void Debugger::ClearRunStopExpressions() {
    runStopExpressions_.clear();
    std::wcout << L"Cleared all run-stop expressions.\n";
}

void Debugger::ListRunStopExpressions() const {
    std::wcout << L"--- Run Stop Expressions ---\n";
    if (runStopExpressions_.empty()) {
        std::wcout << L"(none)\n";
        return;
    }
    for (size_t i = 0; i < runStopExpressions_.size(); ++i) {
        std::wcout << L"  [" << (i + 1) << L"] " << runStopExpressions_[i] << L"\n";
    }
}

bool Debugger::EvaluateRunStopExpressions(bool& matched, std::wstring& detail) const {
    matched = false;
    detail.clear();
    if (runStopExpressions_.empty()) {
        return true;
    }
    if (!pendingEvent_.valid || !stopState_.valid) {
        detail = L"No paused state for run-stop evaluation.";
        return false;
    }

    const uint64_t hitCount = 1;
 for (auto __rangeIt30 = (runStopExpressions_).begin(); __rangeIt30 != (runStopExpressions_).end(); ++__rangeIt30) {
        const auto& expression = *__rangeIt30;
        bool exprMatched = false;
        std::wstring error;
        if (!EvaluateBreakpointCondition(
                expression,
                hitCount,
                stopState_.threadId,
                GetInstructionPointer(stopState_.context),
                stopState_.address,
                exprMatched,
                error)) {
            detail = L"Expression parse error: " + error;
            return false;
        }
        if (exprMatched) {
            matched = true;
            detail = expression;
            return true;
        }
    }
    return true;
}

bool Debugger::ShouldIgnoreException(DWORD code) const {
    const auto matchesRule = [&](const ExceptionRuleSet& rules) -> bool {
        return rules.ignoreAll || rules.ignoredCodes.find(code) != rules.ignoredCodes.end();
    };
    if (matchesRule(debuggingExceptionRules_)) {
        return true;
    }
    if (stepRequested_) {
        return matchesRule(steppingExceptionRules_);
    }
    return matchesRule(runtimeExceptionRules_);
}

void Debugger::ListBreakpoints() const {
    std::wcout << L"--- Breakpoints ---\n";
    for (auto it = softwareBreakpoints_.begin(); it != softwareBreakpoints_.end(); ++it) {
        const int id = it->first;
        const SoftwareBreakpoint& bp = it->second;
        std::wcout << L"[#" << id << L"] SW  addr=" << ToHex(bp.address)
                   << L" enabled=" << (bp.enabled ? L"yes" : L"no")
                   << L" hits=" << bp.hitCount;
        if (!bp.condition.empty()) {
            std::wcout << L" cond=\"" << bp.condition << L"\"";
        }
        std::wcout << L"\n";
    }
    for (auto it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
        const int id = it->first;
        const HardwareBreakpoint& bp = it->second;
        std::wstring mode = L"exec";
        if (bp.access == HardwareAccessType::Write) mode = L"write";
        if (bp.access == HardwareAccessType::Access) mode = L"access";
        std::wcout << L"[#" << id << L"] HW  slot=" << bp.slot << L" addr=" << ToHex(bp.address)
                   << L" type=" << mode << L" len=" << bp.length
                   << L" tid=" << (bp.threadId == 0 ? L"all" : ToWStringCompat(bp.threadId))
                   << L" enabled=" << (bp.enabled ? L"yes" : L"no")
                   << L" hits=" << bp.hitCount;
        if (!bp.condition.empty()) {
            std::wcout << L" cond=\"" << bp.condition << L"\"";
        }
        std::wcout << L"\n";
    }
    for (auto it = memoryBreakpoints_.begin(); it != memoryBreakpoints_.end(); ++it) {
        const int id = it->first;
        const MemoryBreakpoint& bp = it->second;
        std::wcout << L"[#" << id << L"] MEM addr=" << ToHex(bp.address)
                   << L" size=" << bp.size
                   << L" access=" << MemoryAccessToString(bp.access)
                   << L" enabled=" << (bp.enabled ? L"yes" : L"no")
                   << L" hits=" << bp.hitCount;
        if (!bp.condition.empty()) {
            std::wcout << L" cond=\"" << bp.condition << L"\"";
        }
        std::wcout << L"\n";
    }
}

void Debugger::PrintStopSummary() const {
    if (!stopState_.valid) {
        return;
    }
    std::wcout << L"\n=== Paused ===\n";
    std::wcout << L"Reason    : " << stopState_.reason << L"\n";
    std::wcout << L"PID/TID   : " << stopState_.processId << L"/" << stopState_.threadId << L"\n";
    std::wcout << L"Exception : " << ExceptionCodeToString(stopState_.exceptionCode)
               << (stopState_.firstChance ? L" (first chance)" : L" (second chance)") << L"\n";
    std::wcout << L"Address   : " << ToHex(stopState_.address) << L"\n";
    uint64_t ip = GetInstructionPointer(stopState_.context);
#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (CaptureWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            ip = static_cast<uint64_t>(wowCtx.Eip);
        }
    }
#endif
    std::wcout << L"IP        : " << ToHex(ip) << L"\n";
    std::wstring filePath;
    uint32_t line = 0;
    uint32_t displacement = 0;
    if (ResolveSourceLocation(ip, filePath, line, displacement)) {
        std::wcout << L"Source    : " << filePath << L":" << line;
        if (displacement != 0) {
            std::wcout << L" (+" << displacement << L")";
        }
        std::wcout << L"\n";
    }
    PrintDisassembly(ip, 8);
}

void Debugger::PrintProcessList() const {
    const auto printLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    EnsureConsoleColorEnabled();
    printLine(L"--- Processes ---");

    std::vector<WDBL_PROCESS_ENUM_ENTRY> processes;
    if (wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverProcessList(&processes) &&
        !processes.empty()) {
        for (size_t i = 0; i < processes.size(); ++i) {
            const WDBL_PROCESS_ENUM_ENTRY& p = processes[i];
            std::wstringstream line;
            line << L"PID=" << p.ProcessId
                 << L" PPID=" << p.ParentProcessId
                 << L" Threads=" << p.ThreadCount
                 << L" Session=" << p.SessionId
                 << L" " << p.ImageName;
            printLine(line.str());
        }
        return;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcout << L"CreateToolhelp32Snapshot failed.\n";
        return;
    }

    PROCESSENTRY32W pe = PROCESSENTRY32W();
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snapshot, &pe)) {
        CloseHandle(snapshot);
        return;
    }

    do {
        std::wstringstream line;
        line << L"PID=" << pe.th32ProcessID
             << L" PPID=" << pe.th32ParentProcessID
             << L" Threads=" << pe.cntThreads
             << L" " << pe.szExeFile;
        printLine(line.str());
    } while (Process32NextW(snapshot, &pe));
    CloseHandle(snapshot);
}

void Debugger::PrintProcessInfo() const {
    if (!EnsureDebuggee()) {
        return;
    }
    const auto printProcessLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    const auto formatBytes = [](uint64_t bytes) -> std::wstring {
        std::wstringstream ss;
        ss << bytes << L" bytes";
        if (bytes >= (1024ull * 1024ull)) {
            ss << L" (" << (bytes / (1024ull * 1024ull)) << L" MB)";
        } else if (bytes >= 1024ull) {
            ss << L" (" << (bytes / 1024ull) << L" KB)";
        }
        return ss.str();
    };
    const auto formatFileTimeDuration = [](const FILETIME& ft) -> std::wstring {
        ULARGE_INTEGER value = ULARGE_INTEGER();
        value.LowPart = ft.dwLowDateTime;
        value.HighPart = ft.dwHighDateTime;
        const uint64_t totalSeconds = value.QuadPart / 10000000ull;
        const uint64_t hours = totalSeconds / 3600ull;
        const uint64_t minutes = (totalSeconds / 60ull) % 60ull;
        const uint64_t seconds = totalSeconds % 60ull;
        std::wstringstream ss;
        ss << hours << L"h " << minutes << L"m " << seconds << L"s";
        return ss.str();
    };
    const auto formatFileTimeStamp = [](const FILETIME& ft) -> std::wstring {
        FILETIME localFt = FILETIME();
        SYSTEMTIME st = SYSTEMTIME();
        if (!FileTimeToLocalFileTime(&ft, &localFt) || !FileTimeToSystemTime(&localFt, &st)) {
            return std::wstring(L"(unknown)");
        }
        wchar_t buffer[64] = {};
        swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u:%02u",
                   static_cast<unsigned>(st.wYear),
                   static_cast<unsigned>(st.wMonth),
                   static_cast<unsigned>(st.wDay),
                   static_cast<unsigned>(st.wHour),
                   static_cast<unsigned>(st.wMinute),
                   static_cast<unsigned>(st.wSecond));
        return std::wstring(buffer);
    };

    EnsureConsoleColorEnabled();
    printProcessLine(L"--- Process ---");
    printProcessLine(L"PID: " + ToWStringCompat(processId_));

    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(processHandle_, 0, path, &size)) {
        printProcessLine(L"Image: " + std::wstring(path));
    }

    USHORT processMachine = 0;
    USHORT nativeMachine = 0;
    bool printedMachine = false;
    typedef BOOL(WINAPI* IsWow64Process2Fn)(HANDLE, USHORT*, USHORT*);
    HMODULE kernel32Module = GetModuleHandleW(L"kernel32.dll");
    if (kernel32Module != NULL) {
        IsWow64Process2Fn isWow64Process2Fn =
            reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(kernel32Module, "IsWow64Process2"));
        if (isWow64Process2Fn != NULL && isWow64Process2Fn(processHandle_, &processMachine, &nativeMachine)) {
            std::wstringstream line;
            line << L"Machine: process=0x" << std::hex << processMachine << L" native=0x" << nativeMachine << std::dec;
            printProcessLine(line.str());
            printedMachine = true;
        }
    }
    if (!printedMachine) {
        BOOL wow64 = FALSE;
        if (IsWow64Process(processHandle_, &wow64)) {
            printProcessLine(std::wstring(L"Machine: ") + (wow64 ? L"x86-on-x64 (WOW64)" : L"native"));
        }
    }
    printProcessLine(L"Priority class: " + ToWStringCompat(GetPriorityClass(processHandle_)));

    std::vector<ModuleRecord> modules;
    uint64_t moduleBytes = 0;
    if (CollectModuleRecords(modules)) {
        for (size_t i = 0; i < modules.size(); ++i) {
            moduleBytes += static_cast<uint64_t>(modules[i].size);
        }
        std::wstringstream line;
        line << L"Modules: " << modules.size() << L"  image-bytes=" << formatBytes(moduleBytes);
        printProcessLine(line.str());
    }

    const std::vector<DWORD> threadIds = EnumerateThreadIds();
    {
        std::wstringstream line;
        line << L"Threads: " << threadIds.size();
        if (stopState_.valid) {
            line << L"  current=" << stopState_.threadId;
        }
        printProcessLine(line.str());
    }

    DWORD handleCount = 0;
    if (GetProcessHandleCount(processHandle_, &handleCount)) {
        printProcessLine(L"Handles: " + ToWStringCompat(handleCount));
    }

    PROCESS_MEMORY_COUNTERS_EX pmc = PROCESS_MEMORY_COUNTERS_EX();
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(
            processHandle_,
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
            sizeof(pmc))) {
        std::wstringstream line;
        line << L"Memory: WorkingSet=" << formatBytes(static_cast<uint64_t>(pmc.WorkingSetSize))
             << L" PeakWorkingSet=" << formatBytes(static_cast<uint64_t>(pmc.PeakWorkingSetSize));
        printProcessLine(line.str());

        line.str(L"");
        line.clear();
        line << L"Commit: PrivateUsage=" << formatBytes(static_cast<uint64_t>(pmc.PrivateUsage))
             << L" Pagefile=" << formatBytes(static_cast<uint64_t>(pmc.PagefileUsage))
             << L" PeakPagefile=" << formatBytes(static_cast<uint64_t>(pmc.PeakPagefileUsage));
        printProcessLine(line.str());

        line.str(L"");
        line.clear();
        line << L"PagedPool/NonPagedPool: "
             << formatBytes(static_cast<uint64_t>(pmc.QuotaPagedPoolUsage))
             << L" / "
             << formatBytes(static_cast<uint64_t>(pmc.QuotaNonPagedPoolUsage));
        printProcessLine(line.str());
    }

    FILETIME createTime = FILETIME();
    FILETIME exitTime = FILETIME();
    FILETIME kernelTime = FILETIME();
    FILETIME userTime = FILETIME();
    if (GetProcessTimes(processHandle_, &createTime, &exitTime, &kernelTime, &userTime)) {
        std::wstringstream line;
        line << L"Started: " << formatFileTimeStamp(createTime);
        printProcessLine(line.str());

        line.str(L"");
        line.clear();
        line << L"CPU: kernel=" << formatFileTimeDuration(kernelTime)
             << L" user=" << formatFileTimeDuration(userTime);
        printProcessLine(line.str());
    }

    SYSTEM_INFO si = SYSTEM_INFO();
    GetNativeSystemInfo(&si);
    uint64_t freeBytes = 0;
    uint64_t reserveBytes = 0;
    uint64_t commitBytes = 0;
    size_t freeRegions = 0;
    size_t reserveRegions = 0;
    size_t commitRegions = 0;
    uint64_t address = reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress);
    const uint64_t maxAddress = reinterpret_cast<uint64_t>(si.lpMaximumApplicationAddress);
    while (address < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
        const SIZE_T got = VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
        if (got == 0) {
            address += 0x10000;
            continue;
        }
        const uint64_t regionSize = static_cast<uint64_t>(mbi.RegionSize);
        if (mbi.State == MEM_FREE) {
            freeBytes += regionSize;
            ++freeRegions;
        } else if (mbi.State == MEM_RESERVE) {
            reserveBytes += regionSize;
            ++reserveRegions;
        } else if (mbi.State == MEM_COMMIT) {
            commitBytes += regionSize;
            ++commitRegions;
        }
        const uint64_t next = reinterpret_cast<uint64_t>(mbi.BaseAddress) + regionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }
    {
        std::wstringstream line;
        line << L"VirtualMemory: committed=" << formatBytes(commitBytes) << L" (" << commitRegions << L" regions)"
             << L" reserved=" << formatBytes(reserveBytes) << L" (" << reserveRegions << L" regions)";
        printProcessLine(line.str());
        line.str(L"");
        line.clear();
        line << L"VirtualFree: " << formatBytes(freeBytes) << L" (" << freeRegions << L" regions)";
        printProcessLine(line.str());
    }
}

void Debugger::PrintThreadInfo() const {
    if (!EnsureDebuggee()) {
        return;
    }

    const auto printThreadLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };
    const auto queryThreadTeb = [](DWORD tid, uint64_t& teb) -> bool {
        teb = 0;
        HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (thread == NULL) {
            return false;
        }
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto ntQueryInformationThread = ntdll != NULL
            ? reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(ntdll, "NtQueryInformationThread"))
            : nullptr;
        if (ntQueryInformationThread == nullptr) {
            CloseHandle(thread);
            return false;
        }
        THREAD_BASIC_INFORMATION_LOCAL tbi = THREAD_BASIC_INFORMATION_LOCAL();
        ULONG retLen = 0;
        NTSTATUS status = ntQueryInformationThread(
            thread,
            static_cast<THREADINFOCLASS>(0),
            &tbi,
            sizeof(tbi),
            &retLen);
        CloseHandle(thread);
        if (status < 0 || tbi.TebBaseAddress == nullptr) {
            return false;
        }
        teb = reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
        return true;
    };

    EnsureConsoleColorEnabled();
    printThreadLine(L"--- Threads ---");

    std::vector<WDBL_THREAD_ENUM_ENTRY> driverThreads;
    if (wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverThreadList(processId_, &driverThreads) &&
        !driverThreads.empty()) {
        for (size_t i = 0; i < driverThreads.size(); ++i) {
            const WDBL_THREAD_ENUM_ENTRY& te = driverThreads[i];
            std::wstringstream line;
            line << L"~" << i
                 << L" TID=" << te.ThreadId
                 << L" Start=" << hexNoPrefix(te.StartAddress, sizeof(void*) * 2)
                 << L" pri=" << te.Priority
                 << L" basePri=" << te.BasePriority
                 << L" state=" << te.ThreadState
                 << L" wait=" << te.WaitReason;
            if (stopState_.valid && te.ThreadId == stopState_.threadId) {
                line << L" <current>";
            }
            printThreadLine(line.str());
        }
        return;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcout << L"CreateToolhelp32Snapshot failed.\n";
        return;
    }
    THREADENTRY32 te = THREADENTRY32();
    te.dwSize = sizeof(te);
    if (!Thread32First(snapshot, &te)) {
        CloseHandle(snapshot);
        return;
    }
    size_t index = 0;
    do {
        if (te.th32OwnerProcessID == processId_) {
            const DWORD tid = te.th32ThreadID;
            std::wstringstream line;
            line << L"~" << index << L"  TID=" << tid;

            uint64_t teb = 0;
            if (queryThreadTeb(tid, teb)) {
                line << L" TEB=" << hexNoPrefix(teb, sizeof(void*) * 2);
            }

            CONTEXT ctx = CONTEXT();
            if (stopState_.valid && CaptureThreadContext(tid, ctx)) {
                const uint64_t ip = GetInstructionPointer(ctx);
                const uint64_t sp = GetStackPointer(ctx);
                line << L" IP=" << hexNoPrefix(ip, sizeof(void*) * 2)
                     << L" SP=" << hexNoPrefix(sp, sizeof(void*) * 2);
                const std::wstring symbol = ResolveSymbol(ip);
                if (!symbol.empty()) {
                    line << L" " << symbol;
                }
            }

            HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
            if (thread != NULL) {
                const int priority = GetThreadPriority(thread);
                if (priority != THREAD_PRIORITY_ERROR_RETURN) {
                    line << L" pri=" << priority;
                }
                CloseHandle(thread);
            }
            line << L" basePri=" << te.tpBasePri << L" deltaPri=" << te.tpDeltaPri;
            if (stopState_.valid && tid == stopState_.threadId) {
                line << L" <current>";
            }
            printThreadLine(line.str());
            ++index;
        }
    } while (Thread32Next(snapshot, &te));
    CloseHandle(snapshot);
}

void Debugger::PrintCurrentThreadInfo() const {
    if (!EnsurePaused()) {
        return;
    }

    const auto printThreadLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };

    EnsureConsoleColorEnabled();
    printThreadLine(L"--- Current Thread ---");

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        ctx = stopState_.context;
    }

    uint64_t ip = GetInstructionPointer(ctx);
    uint64_t sp = GetStackPointer(ctx);
    size_t pointerWidth = sizeof(void*) * 2;
#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (CaptureWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            ip = static_cast<uint64_t>(wowCtx.Eip);
            sp = static_cast<uint64_t>(wowCtx.Esp);
            pointerWidth = 8;
        }
    }
#endif

    std::wstringstream line;
    line << L"PID/TID   : " << stopState_.processId << L"/" << stopState_.threadId;
    printThreadLine(line.str());

    line.str(L"");
    line.clear();
    line << L"Reason    : " << stopState_.reason;
    printThreadLine(line.str());

    line.str(L"");
    line.clear();
    line << L"Exception : " << ExceptionCodeToString(stopState_.exceptionCode)
         << (stopState_.firstChance ? L" (first chance)" : L" (second chance)");
    printThreadLine(line.str());

    line.str(L"");
    line.clear();
    line << L"IP/SP     : " << hexNoPrefix(ip, pointerWidth) << L" / " << hexNoPrefix(sp, pointerWidth);
    const std::wstring symbol = ResolveSymbol(ip);
    if (!symbol.empty()) {
        line << L"  " << symbol;
    }
    printThreadLine(line.str());

    HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, stopState_.threadId);
    if (thread != NULL) {
        const int priority = GetThreadPriority(thread);
        line.str(L"");
        line.clear();
        line << L"Priority  : " << priority;
        printThreadLine(line.str());
        CloseHandle(thread);
    }

    PrintStackInfo(32);
}

void Debugger::PrintPebInfo() const {
    if (!EnsureDebuggee()) {
        return;
    }

    const auto printPebLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };
    const auto readMemory = [&](uint64_t address, void* buffer, size_t size) -> bool {
        SIZE_T read = 0;
        return ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), buffer, size, &read) && read == size;
    };
    const auto readU8 = [&](uint64_t address, uint8_t& value) -> bool {
        return readMemory(address, &value, sizeof(value));
    };
    const auto readU32 = [&](uint64_t address, uint32_t& value) -> bool {
        return readMemory(address, &value, sizeof(value));
    };
    const auto readPtr = [&](uint64_t address, size_t ptrSize, uint64_t& value) -> bool {
        if (ptrSize == 4) {
            uint32_t v = 0;
            if (!readMemory(address, &v, sizeof(v))) {
                return false;
            }
            value = v;
            return true;
        }
        return readMemory(address, &value, sizeof(value));
    };
    const auto readUnicodeString = [&](uint64_t address, size_t ptrSize) -> std::wstring {
        USHORT length = 0;
        uint64_t buffer = 0;
        if (ptrSize == 4) {
            UNICODE_STRING32_LOCAL us = UNICODE_STRING32_LOCAL();
            if (!readMemory(address, &us, sizeof(us))) {
                return std::wstring();
            }
            length = us.Length;
            buffer = us.Buffer;
        } else {
            UNICODE_STRING64_LOCAL us = UNICODE_STRING64_LOCAL();
            if (!readMemory(address, &us, sizeof(us))) {
                return std::wstring();
            }
            length = us.Length;
            buffer = us.Buffer;
        }
        if (buffer == 0 || length == 0) {
            return std::wstring();
        }
        const size_t byteCount = std::min<size_t>(length, 2048);
        std::vector<wchar_t> chars((byteCount / sizeof(wchar_t)) + 1, L'\0');
        SIZE_T read = 0;
        if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(buffer), chars.data(), byteCount, &read) || read == 0) {
            return std::wstring();
        }
        chars[std::min<size_t>(chars.size() - 1, read / sizeof(wchar_t))] = L'\0';
        return std::wstring(chars.data());
    };
    const auto printPebAt = [&](uint64_t peb, size_t ptrSize, const std::wstring& label) -> void {
        const size_t width = ptrSize * 2;
        printPebLine(label + L" PEB " + hexNoPrefix(peb, width));
        if (peb == 0) {
            return;
        }
        const uint64_t imageOffset = ptrSize == 4 ? 0x08 : 0x10;
        const uint64_t ldrOffset = ptrSize == 4 ? 0x0C : 0x18;
        const uint64_t paramsOffset = ptrSize == 4 ? 0x10 : 0x20;
        const uint64_t ntGlobalFlagOffset = ptrSize == 4 ? 0x68 : 0xBC;
        const uint64_t sessionOffset = ptrSize == 4 ? 0x1D4 : 0x2C0;
        const uint64_t imagePathOffset = ptrSize == 4 ? 0x38 : 0x60;
        const uint64_t commandLineOffset = ptrSize == 4 ? 0x40 : 0x70;

        uint8_t beingDebugged = 0;
        uint8_t bitField = 0;
        uint32_t ntGlobalFlag = 0;
        uint32_t sessionId = 0;
        uint64_t imageBase = 0;
        uint64_t ldr = 0;
        uint64_t params = 0;
        readU8(peb + 0x02, beingDebugged);
        readU8(peb + 0x03, bitField);
        readPtr(peb + imageOffset, ptrSize, imageBase);
        readPtr(peb + ldrOffset, ptrSize, ldr);
        readPtr(peb + paramsOffset, ptrSize, params);
        readU32(peb + ntGlobalFlagOffset, ntGlobalFlag);
        readU32(peb + sessionOffset, sessionId);

        std::wstringstream line;
        line << L"BeingDebugged " << static_cast<unsigned>(beingDebugged)
             << L"  BitField " << hexNoPrefix(bitField, 2)
             << L"  NtGlobalFlag " << hexNoPrefix(ntGlobalFlag, 8)
             << L"  SessionId " << sessionId;
        printPebLine(line.str());

        line.str(L"");
        line.clear();
        line << L"ImageBaseAddress " << hexNoPrefix(imageBase, width)
             << L"  Ldr " << hexNoPrefix(ldr, width)
             << L"  ProcessParameters " << hexNoPrefix(params, width);
        printPebLine(line.str());

        if (params != 0) {
            const std::wstring imagePath = readUnicodeString(params + imagePathOffset, ptrSize);
            const std::wstring commandLine = readUnicodeString(params + commandLineOffset, ptrSize);
            if (!imagePath.empty()) {
                printPebLine(L"ImagePathName " + imagePath);
            }
            if (!commandLine.empty()) {
                printPebLine(L"CommandLine   " + commandLine);
            }
        }
    };

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueryInformationProcess = ntdll != nullptr
        ? reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(ntdll, "NtQueryInformationProcess"))
        : nullptr;
    if (ntQueryInformationProcess == nullptr) {
        std::wcout << L"NtQueryInformationProcess unavailable.\n";
        return;
    }

    PROCESS_BASIC_INFORMATION_LOCAL pbi = PROCESS_BASIC_INFORMATION_LOCAL();
    ULONG retLen = 0;
    NTSTATUS status = ntQueryInformationProcess(processHandle_, 0, &pbi, sizeof(pbi), &retLen);
    if (status < 0) {
        std::wcout << L"NtQueryInformationProcess(ProcessBasicInformation) failed: 0x" << std::hex << status << std::dec << L"\n";
        return;
    }

    EnsureConsoleColorEnabled();
    printPebLine(L"--- PEB ---");
    printPebAt(reinterpret_cast<uint64_t>(pbi.PebBaseAddress), sizeof(void*), L"Native");

#if defined(_M_X64)
    ULONG_PTR wow64Peb = 0;
    retLen = 0;
    status = ntQueryInformationProcess(processHandle_, 26, &wow64Peb, sizeof(wow64Peb), &retLen);
    if (status >= 0 && wow64Peb != 0) {
        printPebAt(static_cast<uint64_t>(wow64Peb), 4, L"WOW64");
    }
#endif
}

void Debugger::PrintTebInfo() const {
    if (!EnsurePaused()) {
        return;
    }

    const auto printTebLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };
    const auto readMemory = [&](uint64_t address, void* buffer, size_t size) -> bool {
        SIZE_T read = 0;
        return ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), buffer, size, &read) && read == size;
    };
    const auto readU32 = [&](uint64_t address, uint32_t& value) -> bool {
        return readMemory(address, &value, sizeof(value));
    };
    const auto readPtr = [&](uint64_t address, size_t ptrSize, uint64_t& value) -> bool {
        if (ptrSize == 4) {
            uint32_t v = 0;
            if (!readMemory(address, &v, sizeof(v))) {
                return false;
            }
            value = v;
            return true;
        }
        return readMemory(address, &value, sizeof(value));
    };
    const auto printTebAt = [&](uint64_t teb, size_t ptrSize, const std::wstring& label) -> void {
        const size_t width = ptrSize * 2;
        printTebLine(label + L" TEB " + hexNoPrefix(teb, width));
        if (teb == 0) {
            return;
        }
        const uint64_t stackBaseOffset = ptrSize == 4 ? 0x04 : 0x08;
        const uint64_t stackLimitOffset = ptrSize == 4 ? 0x08 : 0x10;
        const uint64_t selfOffset = ptrSize == 4 ? 0x18 : 0x30;
        const uint64_t clientIdOffset = ptrSize == 4 ? 0x20 : 0x40;
        const uint64_t tlsOffset = ptrSize == 4 ? 0x2C : 0x58;
        const uint64_t pebOffset = ptrSize == 4 ? 0x30 : 0x60;
        const uint64_t lastErrorOffset = ptrSize == 4 ? 0x34 : 0x68;
        const uint64_t deallocationStackOffset = ptrSize == 4 ? 0xE0C : 0x1478;

        uint64_t exceptionList = 0;
        uint64_t stackBase = 0;
        uint64_t stackLimit = 0;
        uint64_t self = 0;
        uint64_t cidProcess = 0;
        uint64_t cidThread = 0;
        uint64_t tls = 0;
        uint64_t peb = 0;
        uint64_t deallocationStack = 0;
        uint32_t lastError = 0;
        readPtr(teb + 0x00, ptrSize, exceptionList);
        readPtr(teb + stackBaseOffset, ptrSize, stackBase);
        readPtr(teb + stackLimitOffset, ptrSize, stackLimit);
        readPtr(teb + selfOffset, ptrSize, self);
        readPtr(teb + clientIdOffset, ptrSize, cidProcess);
        readPtr(teb + clientIdOffset + ptrSize, ptrSize, cidThread);
        readPtr(teb + tlsOffset, ptrSize, tls);
        readPtr(teb + pebOffset, ptrSize, peb);
        readU32(teb + lastErrorOffset, lastError);
        readPtr(teb + deallocationStackOffset, ptrSize, deallocationStack);

        std::wstringstream line;
        line << L"ClientId " << cidProcess << L"." << cidThread
             << L"  LastError " << hexNoPrefix(lastError, 8);
        printTebLine(line.str());

        line.str(L"");
        line.clear();
        line << L"StackBase " << hexNoPrefix(stackBase, width)
             << L"  StackLimit " << hexNoPrefix(stackLimit, width)
             << L"  DeallocationStack " << hexNoPrefix(deallocationStack, width);
        printTebLine(line.str());

        line.str(L"");
        line.clear();
        line << L"PEB " << hexNoPrefix(peb, width)
             << L"  Self " << hexNoPrefix(self, width)
             << L"  TLS " << hexNoPrefix(tls, width);
        printTebLine(line.str());

        line.str(L"");
        line.clear();
        line << L"ExceptionList " << hexNoPrefix(exceptionList, width);
        printTebLine(line.str());
    };

    HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, stopState_.threadId);
    if (thread == nullptr) {
        std::wcout << L"OpenThread failed.\n";
        return;
    }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueryInformationThread = ntdll != nullptr
        ? reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(ntdll, "NtQueryInformationThread"))
        : nullptr;
    if (ntQueryInformationThread == nullptr) {
        CloseHandle(thread);
        std::wcout << L"NtQueryInformationThread unavailable.\n";
        return;
    }

    THREAD_BASIC_INFORMATION_LOCAL tbi = THREAD_BASIC_INFORMATION_LOCAL();
    ULONG retLen = 0;
    NTSTATUS status = ntQueryInformationThread(thread, static_cast<THREADINFOCLASS>(0), &tbi, sizeof(tbi), &retLen);
    CloseHandle(thread);
    if (status < 0 || tbi.TebBaseAddress == nullptr) {
        std::wcout << L"NtQueryInformationThread failed: 0x" << std::hex << status << std::dec << L"\n";
        return;
    }

    EnsureConsoleColorEnabled();
    printTebLine(L"--- TEB ---");
    const uint64_t nativeTeb = reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
    printTebAt(nativeTeb, sizeof(void*), L"Native");

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        uint32_t teb32 = 0;
        if (readU32(nativeTeb, teb32) && teb32 != 0) {
            printTebAt(static_cast<uint64_t>(teb32), 4, L"WOW64");
        }
    }
#endif
}

void Debugger::PrintVirtualMemoryInfo() const {
    if (!EnsureDebuggee()) {
        return;
    }

    const auto printVmLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    const auto formatBytes = [](uint64_t bytes) -> std::wstring {
        std::wstringstream ss;
        ss << bytes << L" bytes";
        if (bytes >= (1024ull * 1024ull)) {
            ss << L" (" << (bytes / (1024ull * 1024ull)) << L" MB)";
        } else if (bytes >= 1024ull) {
            ss << L" (" << (bytes / 1024ull) << L" KB)";
        }
        return ss.str();
    };
    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };

    EnsureConsoleColorEnabled();
    printVmLine(L"--- Virtual Memory ---");

    MEMORYSTATUSEX status = MEMORYSTATUSEX();
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        std::wstringstream line;
        line << L"PhysicalMemory Load=" << status.dwMemoryLoad << L"%"
             << L" Total=" << formatBytes(status.ullTotalPhys)
             << L" Avail=" << formatBytes(status.ullAvailPhys);
        printVmLine(line.str());

        line.str(L"");
        line.clear();
        line << L"PageFile       Total=" << formatBytes(status.ullTotalPageFile)
             << L" Avail=" << formatBytes(status.ullAvailPageFile);
        printVmLine(line.str());

        line.str(L"");
        line.clear();
        line << L"UserVA         Total=" << formatBytes(status.ullTotalVirtual)
             << L" Avail=" << formatBytes(status.ullAvailVirtual);
        printVmLine(line.str());
    }

    SYSTEM_INFO si = SYSTEM_INFO();
    GetNativeSystemInfo(&si);

    uint64_t freeBytes = 0;
    uint64_t reserveBytes = 0;
    uint64_t commitBytes = 0;
    uint64_t privateBytes = 0;
    uint64_t mappedBytes = 0;
    uint64_t imageBytes = 0;
    uint64_t guardBytes = 0;
    uint64_t noAccessBytes = 0;
    size_t freeRegions = 0;
    size_t reserveRegions = 0;
    size_t commitRegions = 0;

    uint64_t address = reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress);
    const uint64_t maxAddress = reinterpret_cast<uint64_t>(si.lpMaximumApplicationAddress);
    while (address < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
        const SIZE_T got = VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
        if (got == 0) {
            address += 0x10000;
            continue;
        }

        const uint64_t regionSize = static_cast<uint64_t>(mbi.RegionSize);
        if (mbi.State == MEM_FREE) {
            freeBytes += regionSize;
            ++freeRegions;
        } else if (mbi.State == MEM_RESERVE) {
            reserveBytes += regionSize;
            ++reserveRegions;
        } else if (mbi.State == MEM_COMMIT) {
            commitBytes += regionSize;
            ++commitRegions;
            if (mbi.Type == MEM_PRIVATE) {
                privateBytes += regionSize;
            } else if (mbi.Type == MEM_MAPPED) {
                mappedBytes += regionSize;
            } else if (mbi.Type == MEM_IMAGE) {
                imageBytes += regionSize;
            }
            if ((mbi.Protect & PAGE_GUARD) != 0) {
                guardBytes += regionSize;
            }
            if ((mbi.Protect & PAGE_NOACCESS) != 0) {
                noAccessBytes += regionSize;
            }
        }

        const uint64_t next = reinterpret_cast<uint64_t>(mbi.BaseAddress) + regionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }

    std::wstringstream line;
    line << L"Range          " << hexNoPrefix(reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress), sizeof(void*) * 2)
         << L" - " << hexNoPrefix(maxAddress, sizeof(void*) * 2);
    printVmLine(line.str());

    line.str(L"");
    line.clear();
    line << L"Committed      " << formatBytes(commitBytes) << L"  regions=" << commitRegions;
    printVmLine(line.str());

    line.str(L"");
    line.clear();
    line << L"Reserved       " << formatBytes(reserveBytes) << L"  regions=" << reserveRegions;
    printVmLine(line.str());

    line.str(L"");
    line.clear();
    line << L"Free           " << formatBytes(freeBytes) << L"  regions=" << freeRegions;
    printVmLine(line.str());

    line.str(L"");
    line.clear();
    line << L"Private/Image/Mapped  "
         << formatBytes(privateBytes) << L" / "
         << formatBytes(imageBytes) << L" / "
         << formatBytes(mappedBytes);
    printVmLine(line.str());

    line.str(L"");
    line.clear();
    line << L"Guard/NoAccess " << formatBytes(guardBytes) << L" / " << formatBytes(noAccessBytes);
    printVmLine(line.str());
}

void Debugger::PrintMemoryMapInfo() const {
    if (!EnsureDebuggee()) {
        return;
    }

    const auto printLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };
    const auto stateToString = [](DWORD state) -> const wchar_t* {
        switch (state) {
            case MEM_COMMIT: return L"commit";
            case MEM_RESERVE: return L"reserve";
            case MEM_FREE: return L"free";
            default: return L"unknown";
        }
    };

    EnsureConsoleColorEnabled();
    printLine(L"--- Memory Map ---");

    std::vector<WDBL_MEMORY_ENUM_ENTRY> regions;
    if (wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverMemoryMap(processId_, 0, &regions) &&
        !regions.empty()) {
        for (size_t i = 0; i < regions.size(); ++i) {
            const WDBL_MEMORY_ENUM_ENTRY& r = regions[i];
            std::wstringstream line;
            line << hexNoPrefix(r.BaseAddress, sizeof(void*) * 2)
                 << L" " << hexNoPrefix(r.BaseAddress + r.RegionSize, sizeof(void*) * 2)
                 << L" " << stateToString(r.State)
                 << L" " << MemoryProtectionToString(r.Protect)
                 << L" type=" << hexNoPrefix(r.Type, 8)
                 << L" alloc=" << hexNoPrefix(r.AllocationBase, sizeof(void*) * 2)
                 << L" size=" << hexNoPrefix(r.RegionSize, 8);
            printLine(line.str());
        }
        return;
    }

    SYSTEM_INFO si = SYSTEM_INFO();
    GetNativeSystemInfo(&si);
    uint64_t address = reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress);
    const uint64_t maxAddress = reinterpret_cast<uint64_t>(si.lpMaximumApplicationAddress);
    while (address < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
        const SIZE_T got = VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
        if (got == 0) {
            address += 0x10000;
            continue;
        }

        const uint64_t next = reinterpret_cast<uint64_t>(mbi.BaseAddress) + static_cast<uint64_t>(mbi.RegionSize);
        std::wstringstream line;
        line << hexNoPrefix(reinterpret_cast<uint64_t>(mbi.BaseAddress), sizeof(void*) * 2)
             << L" " << hexNoPrefix(next, sizeof(void*) * 2)
             << L" " << stateToString(mbi.State)
             << L" " << MemoryProtectionToString(mbi.Protect)
             << L" type=" << hexNoPrefix(mbi.Type, 8)
             << L" alloc=" << hexNoPrefix(reinterpret_cast<uint64_t>(mbi.AllocationBase), sizeof(void*) * 2)
             << L" size=" << hexNoPrefix(static_cast<uint64_t>(mbi.RegionSize), 8);
        printLine(line.str());
        if (next <= address) {
            break;
        }
        address = next;
    }
}

bool Debugger::ExecuteThreadCommand(const std::wstring& expression) {
    if (!EnsureDebuggee()) {
        return false;
    }

    std::vector<DWORD> threadIds = EnumerateThreadIds();
    if (threadIds.empty()) {
        std::wcout << L"No threads found.\n";
        return false;
    }

    const auto printThreadLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };
    const auto queryThreadTeb = [](DWORD tid, uint64_t& teb) -> bool {
        teb = 0;
        HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (thread == NULL) {
            return false;
        }
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto ntQueryInformationThread = ntdll != NULL
            ? reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(ntdll, "NtQueryInformationThread"))
            : nullptr;
        if (ntQueryInformationThread == nullptr) {
            CloseHandle(thread);
            return false;
        }
        THREAD_BASIC_INFORMATION_LOCAL tbi = THREAD_BASIC_INFORMATION_LOCAL();
        ULONG retLen = 0;
        NTSTATUS status = ntQueryInformationThread(
            thread,
            static_cast<THREADINFOCLASS>(0),
            &tbi,
            sizeof(tbi),
            &retLen);
        CloseHandle(thread);
        if (status < 0 || tbi.TebBaseAddress == nullptr) {
            return false;
        }
        teb = reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
        return true;
    };
    const auto findThreadEntry = [&](DWORD tid, THREADENTRY32& entry) -> bool {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }
        THREADENTRY32 te = THREADENTRY32();
        te.dwSize = sizeof(te);
        bool found = false;
        if (Thread32First(snapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId_ && te.th32ThreadID == tid) {
                    entry = te;
                    found = true;
                    break;
                }
            } while (Thread32Next(snapshot, &te));
        }
        CloseHandle(snapshot);
        return found;
    };
    const auto printSelectedThreadInfo = [&](size_t index, DWORD tid, const CONTEXT* ctx) -> void {
        EnsureConsoleColorEnabled();
        printThreadLine(L"--- Thread ---");

        std::wstringstream line;
        line << L"Index    : ~" << index;
        printThreadLine(line.str());

        line.str(L"");
        line.clear();
        line << L"PID/TID  : " << processId_ << L"/" << tid;
        if (stopState_.valid && tid == stopState_.threadId) {
            line << L" <current>";
        }
        printThreadLine(line.str());

        uint64_t teb = 0;
        if (queryThreadTeb(tid, teb)) {
            line.str(L"");
            line.clear();
            line << L"TEB      : " << hexNoPrefix(teb, sizeof(void*) * 2);
            printThreadLine(line.str());
        }

        if (ctx != nullptr) {
            const uint64_t ip = GetInstructionPointer(*ctx);
            const uint64_t sp = GetStackPointer(*ctx);
            line.str(L"");
            line.clear();
            line << L"IP/SP    : " << hexNoPrefix(ip, sizeof(void*) * 2)
                 << L" / " << hexNoPrefix(sp, sizeof(void*) * 2);
            const std::wstring symbol = ResolveSymbol(ip);
            if (!symbol.empty()) {
                line << L"  " << symbol;
            }
            printThreadLine(line.str());
        }

        HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (thread != NULL) {
            const int priority = GetThreadPriority(thread);
            if (priority != THREAD_PRIORITY_ERROR_RETURN) {
                line.str(L"");
                line.clear();
                line << L"Priority : " << priority;
                printThreadLine(line.str());
            }
            CloseHandle(thread);
        }

        THREADENTRY32 te = THREADENTRY32();
        te.dwSize = sizeof(te);
        if (findThreadEntry(tid, te)) {
            line.str(L"");
            line.clear();
            line << L"BasePri  : " << te.tpBasePri << L"  DeltaPri=" << te.tpDeltaPri;
            printThreadLine(line.str());
        }
    };
    const auto showThreads = [&]() -> void {
        EnsureConsoleColorEnabled();
        printThreadLine(L"--- Threads ---");
        for (size_t i = 0; i < threadIds.size(); ++i) {
            const DWORD tid = threadIds[i];
            std::wstringstream line;
            line << L"~" << i << L"  TID=" << tid;

            uint64_t teb = 0;
            if (queryThreadTeb(tid, teb)) {
                line << L" TEB=" << hexNoPrefix(teb, sizeof(void*) * 2);
            }

            CONTEXT ctx = CONTEXT();
            if (stopState_.valid && CaptureThreadContext(tid, ctx)) {
                const uint64_t ip = GetInstructionPointer(ctx);
                const uint64_t sp = GetStackPointer(ctx);
                line << L" IP=" << hexNoPrefix(ip, sizeof(void*) * 2)
                     << L" SP=" << hexNoPrefix(sp, sizeof(void*) * 2);
                const std::wstring symbol = ResolveSymbol(ip);
                if (!symbol.empty()) {
                    line << L" " << symbol;
                }
            }

            HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
            if (thread != NULL) {
                const int priority = GetThreadPriority(thread);
                if (priority != THREAD_PRIORITY_ERROR_RETURN) {
                    line << L" pri=" << priority;
                }
                CloseHandle(thread);
            }
            if (stopState_.valid && tid == stopState_.threadId) {
                line << L"  <current>";
            }
            printThreadLine(line.str());
        }
    };

    std::wstring expr = TrimWhitespace(expression);
    if (!expr.empty() && expr[0] == L'~') {
        expr.erase(expr.begin());
    }
    expr = ToLower(TrimWhitespace(expr));

    if (expr.empty() || expr == L"*" || expr == L"*s") {
        showThreads();
        return true;
    }

    if (expr == L"*k") {
        for (size_t i = 0; i < threadIds.size(); ++i) {
            const DWORD tid = threadIds[i];
            PrintThreadStackInfo(tid, 32);
            if (i + 1 < threadIds.size()) {
                std::wcout << L"\n";
            }
        }
        return true;
    }

    if (expr.size() >= 2 && expr[expr.size() - 1] == L's') {
        const std::wstring indexText = expr.substr(0, expr.size() - 1);
        uint32_t index = 0;
        if (!ParseUInt32(indexText, index) || index >= threadIds.size()) {
            std::wcout << L"Invalid thread index.\n";
            return false;
        }
        const DWORD tid = threadIds[index];
        const bool paused = pendingEvent_.valid && stopState_.valid;
        CONTEXT ctx = CONTEXT();
        bool haveContext = false;
        if (paused) {
            haveContext = CaptureThreadContext(tid, ctx);
            if (haveContext) {
                EnterCriticalSection(&stateLock_);
                stopState_.threadId = tid;
                stopState_.context = ctx;
                stopState_.address = GetInstructionPointer(ctx);
                LeaveCriticalSection(&stateLock_);
            }
        }

        std::wstringstream line;
        line << (paused && haveContext ? L"Current thread is ~" : L"Thread ~")
             << index << L" (TID=" << tid << L").";
        printThreadLine(line.str());
        if (paused && haveContext) {
            PrintCurrentThreadInfo();
        } else {
            printSelectedThreadInfo(index, tid, haveContext ? &ctx : nullptr);
            if (paused && !haveContext) {
                std::wcout << L"GetThreadContext failed for TID " << tid << L".\n";
            }
        }
        return true;
    }

    std::wcout << L"Usage: ~ | ~* | ~*s | ~*k | ~<index>s\n";
    return false;
}

void Debugger::PrintModuleInfo(const std::wstring& filter) const {
    if (!EnsureDebuggee()) {
        return;
    }
    const std::wstring filterText = ToLower(TrimWhitespace(filter));
    const bool useFilter = !filterText.empty() && filterText != L"*";
    const auto printModuleLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };
    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };

    EnsureConsoleColorEnabled();
    printModuleLine(useFilter ? (L"--- Modules: " + filter + L" ---") : L"--- Modules ---");
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId_);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcout << L"CreateToolhelp32Snapshot failed.\n";
        return;
    }
    MODULEENTRY32W me = MODULEENTRY32W();
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snapshot, &me)) {
        CloseHandle(snapshot);
        return;
    }
    size_t shown = 0;
    do {
        const std::wstring moduleName = me.szModule;
        const std::wstring imagePath = me.szExePath;
        if (useFilter) {
            const std::wstring lowerName = ToLower(moduleName);
            const std::wstring lowerPath = ToLower(imagePath);
            if (lowerName.find(filterText) == std::wstring::npos &&
                lowerPath.find(filterText) == std::wstring::npos) {
                continue;
            }
        }

        std::wstringstream line;
        line << hexNoPrefix(reinterpret_cast<uint64_t>(me.modBaseAddr), sizeof(void*) * 2)
             << L" "
             << hexNoPrefix(reinterpret_cast<uint64_t>(me.modBaseAddr) + static_cast<uint64_t>(me.modBaseSize), sizeof(void*) * 2)
             << L" "
             << std::left << std::setw(24) << moduleName
             << L" size=" << std::right << std::setw(8) << std::setfill(L'0') << std::uppercase << std::hex << me.modBaseSize
             << std::setfill(L' ') << L" " << imagePath;
        printModuleLine(line.str());
        ++shown;
    } while (Module32NextW(snapshot, &me));
    CloseHandle(snapshot);
    if (shown == 0) {
        printModuleLine(L"No modules matched.");
    }
}

void Debugger::PrintVadInfo() const {
    if (!EnsureDebuggee()) {
        return;
    }

    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };
    const auto typeToString = [](DWORD type) -> const wchar_t* {
        switch (type) {
            case MEM_PRIVATE: return L"private";
            case MEM_IMAGE: return L"image";
            case MEM_MAPPED: return L"mapped";
            default: return L"unknown";
        }
    };

    std::vector<WDBL_MEMORY_ENUM_ENTRY> regions;
    if (!(wdbl::winapi::IsProcessMemoryDriverActive() &&
          wdbl::winapi::QueryDriverMemoryMap(processId_, 0, &regions))) {
        SYSTEM_INFO si = SYSTEM_INFO();
        GetNativeSystemInfo(&si);
        uint64_t address = reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress);
        const uint64_t maximum = reinterpret_cast<uint64_t>(si.lpMaximumApplicationAddress);
        while (address < maximum) {
            MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
            if (VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
                address += 0x1000;
                continue;
            }
            WDBL_MEMORY_ENUM_ENTRY entry = WDBL_MEMORY_ENUM_ENTRY();
            entry.BaseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            entry.AllocationBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
            entry.RegionSize = static_cast<uint64_t>(mbi.RegionSize);
            entry.State = mbi.State;
            entry.Protect = mbi.Protect;
            entry.Type = mbi.Type;
            entry.AllocationProtect = mbi.AllocationProtect;
            regions.push_back(entry);
            const uint64_t next = entry.BaseAddress + entry.RegionSize;
            if (next <= address) {
                break;
            }
            address = next;
        }
    }

    EnsureConsoleColorEnabled();
    std::wcout << L"--- VAD Risk Scan (" << regions.size() << L" regions) ---\n";
    size_t suspicious = 0;
    for (size_t i = 0; i < regions.size(); ++i) {
        const WDBL_MEMORY_ENUM_ENTRY& region = regions[i];
        if (region.State != MEM_COMMIT || region.RegionSize == 0) {
            continue;
        }

        const DWORD protection = region.Protect & 0xFF;
        const bool executable = IsExecutableProtection(region.Protect);
        const bool writable = protection == PAGE_READWRITE ||
                              protection == PAGE_EXECUTE_READWRITE ||
                              protection == PAGE_WRITECOPY ||
                              protection == PAGE_EXECUTE_WRITECOPY;
        const bool rwx = executable && writable;
        const bool rxPrivate = executable && !writable && region.Type == MEM_PRIVATE;
        bool hasPeHeader = false;
        if (region.Type == MEM_PRIVATE && IsReadableProtection(region.Protect)) {
            USHORT mz = 0;
            SIZE_T bytesRead = 0;
            hasPeHeader = ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(region.BaseAddress),
                &mz,
                sizeof(mz),
                &bytesRead) != FALSE &&
                bytesRead == sizeof(mz) &&
                mz == 0x5A4D;
        }

        if (!rwx && !rxPrivate && !hasPeHeader) {
            continue;
        }
        ++suspicious;

        std::wstringstream reason;
        if (rwx) {
            reason << L"RWX ";
        }
        if (rxPrivate) {
            reason << L"RX_PRIVATE ";
        }
        if (hasPeHeader) {
            reason << L"PRIVATE_PE_HEADER ";
        }

        std::wcout << L"[" << reason.str() << L"] "
                   << L"index=" << i << L" "
                   << hexNoPrefix(region.BaseAddress, sizeof(void*) * 2)
                   << L"-"
                   << hexNoPrefix(region.BaseAddress + region.RegionSize, sizeof(void*) * 2)
                   << L" type=" << typeToString(region.Type)
                   << L" state=" << (region.State == MEM_COMMIT ? L"commit" : L"other")
                   << L" protect=" << MemoryProtectionToString(region.Protect)
                   << L" size=0x" << hexNoPrefix(region.RegionSize, 0)
                   << L"\n";
    }
    if (suspicious == 0) {
        std::wcout << L"No suspicious VAD regions found.\n";
    } else {
        std::wcout << L"Suspicious regions: " << suspicious << L"\n";
    }
}

void Debugger::PrintVadDump(const std::wstring& selector, const std::wstring& filePath) const {
    if (!EnsureDebuggee()) {
        return;
    }
    if (selector.empty() || filePath.empty()) {
        std::wcout << L"Usage: vad dump <index|0xaddress> <file>\n";
        return;
    }

    std::vector<WDBL_MEMORY_ENUM_ENTRY> regions;
    if (!(wdbl::winapi::IsProcessMemoryDriverActive() &&
          wdbl::winapi::QueryDriverMemoryMap(processId_, 0, &regions))) {
        SYSTEM_INFO si = SYSTEM_INFO();
        GetNativeSystemInfo(&si);
        uint64_t address = reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress);
        const uint64_t maximum = reinterpret_cast<uint64_t>(si.lpMaximumApplicationAddress);
        while (address < maximum) {
            MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
            if (VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
                address += 0x1000;
                continue;
            }
            WDBL_MEMORY_ENUM_ENTRY entry = WDBL_MEMORY_ENUM_ENTRY();
            entry.BaseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            entry.AllocationBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
            entry.RegionSize = static_cast<uint64_t>(mbi.RegionSize);
            entry.State = mbi.State;
            entry.Protect = mbi.Protect;
            entry.Type = mbi.Type;
            entry.AllocationProtect = mbi.AllocationProtect;
            regions.push_back(entry);
            const uint64_t next = entry.BaseAddress + entry.RegionSize;
            if (next <= address) {
                break;
            }
            address = next;
        }
    }

    const std::wstring normalized = ToLower(TrimWhitespace(selector));
    const bool addressSelector = normalized.rfind(L"0x", 0) == 0 ||
                                 normalized.find_first_of(L"abcdef") != std::wstring::npos;
    size_t selectedIndex = (std::numeric_limits<size_t>::max)();
    uint64_t selectedAddress = 0;
    if (addressSelector) {
        if (!ParseUInt64(normalized, selectedAddress)) {
            std::wcout << L"Invalid VAD address.\n";
            return;
        }
        for (size_t i = 0; i < regions.size(); ++i) {
            const uint64_t end = regions[i].BaseAddress + regions[i].RegionSize;
            if (selectedAddress >= regions[i].BaseAddress && selectedAddress < end) {
                selectedIndex = i;
                break;
            }
        }
    } else {
        uint64_t parsedIndex = 0;
        if (!ParseUInt64(normalized, parsedIndex) ||
            parsedIndex >= regions.size()) {
            std::wcout << L"Invalid VAD region index.\n";
            return;
        }
        selectedIndex = static_cast<size_t>(parsedIndex);
    }

    if (selectedIndex == (std::numeric_limits<size_t>::max)()) {
        std::wcout << L"VAD region not found: " << selector << L"\n";
        return;
    }

    const WDBL_MEMORY_ENUM_ENTRY& region = regions[selectedIndex];
    const uint64_t maxDumpSize = 256ull * 1024ull * 1024ull;
    if (region.State != MEM_COMMIT || region.RegionSize == 0) {
        std::wcout << L"VAD region is not committed or empty.\n";
        return;
    }
    if (region.RegionSize > maxDumpSize) {
        std::wcout << L"VAD region is larger than the 256 MB dump limit.\n";
        return;
    }

    if (DumpMemoryRangeToFile(
            filePath,
            region.BaseAddress,
            static_cast<size_t>(region.RegionSize))) {
        std::wcout << L"VAD dump index=" << selectedIndex
                   << L" base=" << ToHex(region.BaseAddress)
                   << L" size=0x" << std::hex << region.RegionSize << std::dec
                   << L" protect=" << MemoryProtectionToString(region.Protect)
                   << L"\n";
    }
}

void Debugger::PrintIatCheck(const std::wstring& moduleName) const {
    if (!EnsureDebuggee()) {
        return;
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules) || modules.empty()) {
        std::wcout << L"Cannot enumerate target modules.\n";
        return;
    }

    const auto moduleDisplayName = [](const ModuleRecord& module) -> std::wstring {
        return module.moduleName.empty()
            ? GetModuleNameFromPath(module.imagePath)
            : module.moduleName;
    };
    const auto findModule = [&](const std::wstring& name) -> const ModuleRecord* {
        const std::wstring wanted = ToLower(GetModuleNameFromPath(name));
        for (size_t i = 0; i < modules.size(); ++i) {
            const std::wstring candidate = ToLower(GetModuleNameFromPath(moduleDisplayName(modules[i])));
            if (candidate == wanted) {
                return &modules[i];
            }
        }
        return nullptr;
    };

    std::vector<const ModuleRecord*> targets;
    const std::wstring wanted = ToLower(TrimWhitespace(moduleName));
    if (wanted.empty()) {
        uint64_t mainBase = 0;
        size_t mainSize = 0;
        if (ResolveMainModuleRange(mainBase, mainSize)) {
            for (size_t i = 0; i < modules.size(); ++i) {
                if (modules[i].baseAddress == mainBase) {
                    targets.push_back(&modules[i]);
                    break;
                }
            }
        }
    } else if (wanted == L"all" || wanted == L"*") {
        for (size_t i = 0; i < modules.size(); ++i) {
            targets.push_back(&modules[i]);
        }
    } else {
        const ModuleRecord* target = findModule(wanted);
        if (target != nullptr) {
            targets.push_back(target);
        }
    }

    if (targets.empty()) {
        std::wcout << L"IAT module not found: "
                   << (moduleName.empty() ? L"<main>" : moduleName) << L"\n";
        return;
    }

    size_t checked = 0;
    size_t suspicious = 0;
    for (size_t targetIndex = 0; targetIndex < targets.size(); ++targetIndex) {
        const ModuleRecord& target = *targets[targetIndex];
        IMAGE_DOS_HEADER dos = IMAGE_DOS_HEADER();
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(target.baseAddress),
                &dos,
                sizeof(dos),
                &bytesRead) ||
            bytesRead != sizeof(dos) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE ||
            dos.e_lfanew <= 0 ||
            dos.e_lfanew > 0x100000) {
            std::wcout << L"[" << moduleDisplayName(target) << L"] invalid PE header.\n";
            continue;
        }

        const uint64_t ntAddress = target.baseAddress + static_cast<uint64_t>(dos.e_lfanew);
        IMAGE_NT_HEADERS64 nt64 = IMAGE_NT_HEADERS64();
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(ntAddress),
                &nt64,
                sizeof(nt64),
                &bytesRead) ||
            bytesRead < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD) ||
            nt64.Signature != IMAGE_NT_SIGNATURE) {
            std::wcout << L"[" << moduleDisplayName(target) << L"] invalid NT header.\n";
            continue;
        }

        bool is64Bit = nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        DWORD importRva = 0;
        DWORD importSize = 0;
        WORD sectionCount = nt64.FileHeader.NumberOfSections;
        if (is64Bit) {
            importRva = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            importSize = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        } else {
            IMAGE_NT_HEADERS32 nt32 = IMAGE_NT_HEADERS32();
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(ntAddress),
                    &nt32,
                    sizeof(nt32),
                    &bytesRead) ||
                bytesRead != sizeof(nt32) ||
                nt32.Signature != IMAGE_NT_SIGNATURE) {
                std::wcout << L"[" << moduleDisplayName(target) << L"] invalid 32-bit NT header.\n";
                continue;
            }
            importRva = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            importSize = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            sectionCount = nt32.FileHeader.NumberOfSections;
        }

        std::wcout << L"--- IAT Check: " << moduleDisplayName(target)
                   << L" imports=0x" << std::hex << importRva
                   << L" size=0x" << importSize << std::dec << L" ---\n";
        if (importRva == 0 || importSize == 0) {
            std::wcout << L"  No import directory.\n";
            continue;
        }

        const size_t thunkSize = is64Bit ? sizeof(uint64_t) : sizeof(uint32_t);
        const uint64_t ordinalFlag = is64Bit ? (1ull << 63) : (1ull << 31);
        size_t moduleChecked = 0;
        size_t moduleSuspicious = 0;
        const DWORD maxDescriptors = std::min<DWORD>(
            1024,
            std::max<DWORD>(1, importSize / sizeof(IMAGE_IMPORT_DESCRIPTOR) + 1));
        for (DWORD descIndex = 0; descIndex < maxDescriptors; ++descIndex) {
            IMAGE_IMPORT_DESCRIPTOR desc = IMAGE_IMPORT_DESCRIPTOR();
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(
                        target.baseAddress + static_cast<uint64_t>(importRva) +
                        static_cast<uint64_t>(descIndex) * sizeof(desc)),
                    &desc,
                    sizeof(desc),
                    &bytesRead) ||
                bytesRead != sizeof(desc)) {
                break;
            }
            if (desc.Name == 0 && desc.FirstThunk == 0 && desc.OriginalFirstThunk == 0) {
                break;
            }
            if (desc.FirstThunk == 0) {
                continue;
            }

            std::string dllAnsi;
            ReadProcessAnsiCString(
                processHandle_,
                target.baseAddress + static_cast<uint64_t>(desc.Name),
                dllAnsi,
                512);
            const std::wstring importedDll = MultiByteToWide(dllAnsi, CP_ACP, 0);
            const ModuleRecord* expectedModule = findModule(importedDll);
            const uint64_t thunkBase = target.baseAddress + static_cast<uint64_t>(desc.FirstThunk);
            const uint64_t nameThunkBase = target.baseAddress + static_cast<uint64_t>(
                desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk);

            for (DWORD thunkIndex = 0; thunkIndex < 4096; ++thunkIndex) {
                uint64_t thunkValue = 0;
                if (thunkSize == sizeof(uint64_t)) {
                    if (!ReadProcessMemory(
                            processHandle_,
                            reinterpret_cast<LPCVOID>(thunkBase + static_cast<uint64_t>(thunkIndex) * thunkSize),
                            &thunkValue,
                            sizeof(thunkValue),
                            &bytesRead) ||
                        bytesRead != sizeof(thunkValue) ||
                        thunkValue == 0) {
                        break;
                    }
                } else {
                    uint32_t thunkValue32 = 0;
                    if (!ReadProcessMemory(
                            processHandle_,
                            reinterpret_cast<LPCVOID>(thunkBase + static_cast<uint64_t>(thunkIndex) * thunkSize),
                            &thunkValue32,
                            sizeof(thunkValue32),
                            &bytesRead) ||
                        bytesRead != sizeof(thunkValue32) ||
                        thunkValue32 == 0) {
                        break;
                    }
                    thunkValue = thunkValue32;
                }

                ++checked;
                ++moduleChecked;
                std::wstring importedName;
                uint64_t originalValue = 0;
                if (thunkSize == sizeof(uint64_t)) {
                    ReadProcessMemory(
                        processHandle_,
                        reinterpret_cast<LPCVOID>(nameThunkBase + static_cast<uint64_t>(thunkIndex) * thunkSize),
                        &originalValue,
                        sizeof(originalValue),
                        &bytesRead);
                } else {
                    uint32_t originalValue32 = 0;
                    ReadProcessMemory(
                        processHandle_,
                        reinterpret_cast<LPCVOID>(nameThunkBase + static_cast<uint64_t>(thunkIndex) * thunkSize),
                        &originalValue32,
                        sizeof(originalValue32),
                        &bytesRead);
                    originalValue = originalValue32;
                }
                if ((originalValue & ordinalFlag) != 0) {
                    importedName = L"#" + ToWStringCompat(originalValue & 0xFFFF);
                } else if (originalValue != 0) {
                    std::string nameAnsi;
                    if (ReadProcessAnsiCString(
                            processHandle_,
                            target.baseAddress + originalValue + sizeof(WORD),
                            nameAnsi,
                            512)) {
                        importedName = MultiByteToWide(nameAnsi, CP_ACP, 0);
                    }
                }

                const uint64_t actualAddress = thunkValue;
                const ModuleRecord* actualModule = nullptr;
                for (size_t mi = 0; mi < modules.size(); ++mi) {
                    const uint64_t end = modules[mi].baseAddress + static_cast<uint64_t>(modules[mi].size);
                    if (actualAddress >= modules[mi].baseAddress && actualAddress < end) {
                        actualModule = &modules[mi];
                        break;
                    }
                }
                const bool inExpected = expectedModule != nullptr &&
                    actualAddress >= expectedModule->baseAddress &&
                    actualAddress < expectedModule->baseAddress + static_cast<uint64_t>(expectedModule->size);
                if (inExpected) {
                    continue;
                }

                ++suspicious;
                ++moduleSuspicious;
                std::wcout << L"  DIFFERENT module=" << importedDll.c_str()
                           << L"!" << (importedName.empty() ? L"?" : importedName)
                           << L" iat=" << ToHex(thunkBase + static_cast<uint64_t>(thunkIndex) * thunkSize)
                           << L" value=" << ToHex(actualAddress)
                           << L" actual=";
                if (actualModule != nullptr) {
                    std::wcout << moduleDisplayName(*actualModule);
                } else {
                    std::wcout << L"<outside-loaded-modules>";
                }
                std::wcout << L"\n";
            }
        }
        std::wcout << L"  Checked=" << moduleChecked
                   << L" differences=" << moduleSuspicious << L"\n";
    }
    std::wcout << L"IAT total checked=" << checked
               << L" differences=" << suspicious << L"\n";
}

void Debugger::PrintModifyCheck(const std::wstring& moduleName) const {
    if (!EnsureDebuggee()) {
        return;
    }

    const std::wstring wanted = ToLower(TrimWhitespace(moduleName));
    if (wanted == L"all" || wanted == L"*") {
        std::vector<ModuleRecord> modules;
        if (!CollectModuleRecords(modules) || modules.empty()) {
            std::wcout << L"Cannot enumerate target modules.\n";
            return;
        }
        std::wcout << L"--- Modify Check: all modules (" << modules.size() << L") ---\n";
        for (size_t i = 0; i < modules.size(); ++i) {
            const std::wstring name = modules[i].moduleName.empty()
                ? GetModuleNameFromPath(modules[i].imagePath)
                : modules[i].moduleName;
            if (!name.empty()) {
                PrintModifyCheck(name);
            }
        }
        return;
    }

    MODULEENTRY32W targetModule = MODULEENTRY32W();
    targetModule.dwSize = sizeof(targetModule);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId_);
    if (snapshot == INVALID_HANDLE_VALUE || !Module32FirstW(snapshot, &targetModule)) {
        if (snapshot != INVALID_HANDLE_VALUE) {
            CloseHandle(snapshot);
        }
        std::wcout << L"Cannot enumerate target modules.\n";
        return;
    }

    bool found = false;
    do {
        if (ToLower(targetModule.szModule) == wanted ||
            ToLower(FileNameFromPath(targetModule.szExePath)) == wanted) {
            found = true;
            break;
        }
    } while (Module32NextW(snapshot, &targetModule));
    CloseHandle(snapshot);
    if (!found) {
        std::wcout << L"Module not found: " << moduleName << L"\n";
        return;
    }

    std::vector<uint8_t> diskImage;
    const bool diskBaselineReady = ReadFileToVectorCompat(targetModule.szExePath, diskImage);
    HMODULE localModule = GetModuleHandleW(targetModule.szModule);
    if (!diskBaselineReady && localModule == NULL) {
        std::wcout << L"No disk or local baseline available for " << targetModule.szModule << L"\n";
        return;
    }

    const std::wstring moduleLower = ToLower(targetModule.szModule);
    const char* const ntdllApiNames[] = {
        "NtQueryInformationProcess",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtContinue",
        "NtGetContextThread",
        "NtSetContextThread"
    };
    const char* const winApiNames[] = {
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "VirtualProtect",
        "VirtualAlloc",
        "CreateRemoteThread",
        "LoadLibraryW",
        "GetProcAddress"
    };
    const char* const* apiNames = nullptr;
    size_t apiNameCount = 0;
    if (moduleLower == L"ntdll.dll") {
        apiNames = ntdllApiNames;
        apiNameCount = sizeof(ntdllApiNames) / sizeof(ntdllApiNames[0]);
    } else if (moduleLower == L"kernel32.dll" || moduleLower == L"kernelbase.dll") {
        apiNames = winApiNames;
        apiNameCount = sizeof(winApiNames) / sizeof(winApiNames[0]);
    }
    std::wcout << L"--- Modify Check: " << targetModule.szModule << L" ---\n";
    std::wcout << L"Baseline: "
               << (diskBaselineReady ? L"disk image " : L"current local loaded module ")
               << targetModule.szExePath << L"\n";
    size_t checked = 0;
    size_t different = 0;

    for (size_t i = 0; i < apiNameCount; ++i) {
        DWORD functionRva = 0;
        uint8_t baselineBytes[16] = {};
        bool haveBaseline = false;
        if (diskBaselineReady &&
            DiskPeResolveExportRva(diskImage, apiNames[i], functionRva) &&
            DiskPeRead(diskImage, functionRva, baselineBytes, sizeof(baselineBytes))) {
            haveBaseline = true;
        } else if (localModule != NULL) {
            FARPROC localAddress = GetProcAddress(localModule, apiNames[i]);
            if (localAddress != NULL) {
                const uint64_t localBase = reinterpret_cast<uint64_t>(localModule);
                const uint64_t localFunction = reinterpret_cast<uint64_t>(localAddress);
                if (localFunction >= localBase) {
                    functionRva = static_cast<DWORD>(localFunction - localBase);
                    std::memcpy(baselineBytes, localAddress, sizeof(baselineBytes));
                    haveBaseline = true;
                }
            }
        }
        if (!haveBaseline) {
            continue;
        }
        const uint64_t remoteAddress = reinterpret_cast<uint64_t>(targetModule.modBaseAddr) + functionRva;
        uint8_t remoteBytes[16] = {};
        SIZE_T remoteRead = 0;
        const bool remoteOk = ReadProcessMemory(
            processHandle_,
            reinterpret_cast<LPCVOID>(remoteAddress),
            remoteBytes,
            sizeof(remoteBytes),
            &remoteRead) != FALSE && remoteRead == sizeof(remoteBytes);
        if (!remoteOk) {
            std::wcout << L"  " << apiNames[i] << L": remote read failed\n";
            continue;
        }
        ++checked;
        const bool same = std::memcmp(baselineBytes, remoteBytes, sizeof(baselineBytes)) == 0;
        if (!same) {
            ++different;
        }
        std::wcout << L"  " << apiNames[i]
                   << (same ? L": OK" : L": DIFFERENT")
                   << L" remote=" << ToHex(remoteAddress)
                   << L" bytes=" << BytesToHex(remoteBytes, sizeof(remoteBytes))
                   << L"\n";
    }

    uint8_t baselineHeader[64] = {};
    uint8_t remoteHeader[64] = {};
    SIZE_T remoteHeaderRead = 0;
    bool haveHeaderBaseline = false;
    if (diskBaselineReady && diskImage.size() >= sizeof(baselineHeader)) {
        std::memcpy(baselineHeader, &diskImage[0], sizeof(baselineHeader));
        haveHeaderBaseline = true;
    } else if (localModule != NULL) {
        std::memcpy(baselineHeader, localModule, sizeof(baselineHeader));
        haveHeaderBaseline = true;
    }
    if (haveHeaderBaseline &&
        ReadProcessMemory(
            processHandle_,
            targetModule.modBaseAddr,
            remoteHeader,
            sizeof(remoteHeader),
            &remoteHeaderRead) != FALSE &&
        remoteHeaderRead == sizeof(remoteHeader)) {
        const bool sameHeader = std::memcmp(baselineHeader, remoteHeader, sizeof(baselineHeader)) == 0;
        std::wcout << L"  module-header:" << (sameHeader ? L" OK" : L" DIFFERENT")
                   << L" bytes=" << BytesToHex(remoteHeader, sizeof(remoteHeader)) << L"\n";
        if (!sameHeader) {
            ++different;
        }
    }

    if (diskBaselineReady) {
        DWORD exportRva = 0;
        DWORD exportSize = 0;
        if (DiskPeDataDirectory(
                diskImage,
                IMAGE_DIRECTORY_ENTRY_EXPORT,
                exportRva,
                exportSize) &&
            exportRva != 0 &&
            exportSize >= sizeof(IMAGE_EXPORT_DIRECTORY)) {
            IMAGE_EXPORT_DIRECTORY exportDirectory = IMAGE_EXPORT_DIRECTORY();
            DWORD namesOffset = 0;
            DWORD ordinalsOffset = 0;
            DWORD functionsOffset = 0;
            if (DiskPeRead(diskImage, exportRva, &exportDirectory, sizeof(exportDirectory)) &&
                DiskPeRvaToOffset(diskImage, exportDirectory.AddressOfNames, namesOffset) &&
                DiskPeRvaToOffset(diskImage, exportDirectory.AddressOfNameOrdinals, ordinalsOffset) &&
                DiskPeRvaToOffset(diskImage, exportDirectory.AddressOfFunctions, functionsOffset)) {
                const DWORD exportCount = std::min<DWORD>(exportDirectory.NumberOfNames, 2048);
                size_t exportChecked = 0;
                size_t exportDifferent = 0;
                for (DWORD exportIndex = 0; exportIndex < exportCount; ++exportIndex) {
                    DWORD nameRva = 0;
                    WORD ordinal = 0;
                    DWORD expectedFunctionRva = 0;
                    if (!DiskPeRead(
                            diskImage,
                            exportDirectory.AddressOfNames + exportIndex * sizeof(DWORD),
                            &nameRva,
                            sizeof(nameRva)) ||
                        !DiskPeRead(
                            diskImage,
                            exportDirectory.AddressOfNameOrdinals + exportIndex * sizeof(WORD),
                            &ordinal,
                            sizeof(ordinal)) ||
                        ordinal >= exportDirectory.NumberOfFunctions ||
                        !DiskPeRead(
                            diskImage,
                            exportDirectory.AddressOfFunctions + ordinal * sizeof(DWORD),
                            &expectedFunctionRva,
                            sizeof(expectedFunctionRva))) {
                        continue;
                    }
                    if (expectedFunctionRva >= exportRva &&
                        expectedFunctionRva < exportRva + exportSize) {
                        continue;
                    }

                    DWORD actualFunctionRva = 0;
                    SIZE_T exportRead = 0;
                    const uint64_t functionSlot =
                        reinterpret_cast<uint64_t>(targetModule.modBaseAddr) +
                        static_cast<uint64_t>(exportDirectory.AddressOfFunctions) +
                        static_cast<uint64_t>(ordinal) * sizeof(DWORD);
                    if (!ReadProcessMemory(
                            processHandle_,
                            reinterpret_cast<LPCVOID>(functionSlot),
                            &actualFunctionRva,
                            sizeof(actualFunctionRva),
                            &exportRead) ||
                        exportRead != sizeof(actualFunctionRva)) {
                        continue;
                    }
                    ++exportChecked;
                    if (actualFunctionRva == expectedFunctionRva) {
                        continue;
                    }

                    std::string exportNameAnsi;
                    DiskPeReadAnsiString(diskImage, nameRva, exportNameAnsi, 256);
                    ++exportDifferent;
                    ++different;
                    std::wcout << L"  EAT DIFFERENT "
                               << (exportNameAnsi.empty()
                                       ? L"<ordinal>"
                                       : MultiByteToWide(exportNameAnsi, CP_ACP, 0))
                               << L" expected_rva=0x" << std::hex << expectedFunctionRva
                               << L" actual_rva=0x" << actualFunctionRva
                               << std::dec << L"\n";
                }
                std::wcout << L"  EAT checked=" << exportChecked
                           << L" differences=" << exportDifferent << L"\n";
            }
        }
    }

    std::wcout << L"Checked=" << checked << L" differences=" << different << L"\n";
    if (different != 0) {
        std::wcout << L"Difference indicates a possible code modification; verify against a clean disk image before concluding.\n";
    }
    if (moduleLower == L"ntdll.dll" ||
        moduleLower == L"kernel32.dll" ||
        moduleLower == L"kernelbase.dll") {
        PrintIatCheck(targetModule.szModule);
    }
}

void Debugger::PrintSyscallCheck(const std::wstring& moduleName) const {
    if (!EnsureDebuggee()) {
        return;
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules) || modules.empty()) {
        std::wcout << L"Cannot enumerate target modules.\n";
        return;
    }

    const std::wstring wanted = ToLower(GetModuleNameFromPath(
        TrimWhitespace(moduleName).empty() ? L"ntdll.dll" : TrimWhitespace(moduleName)));
    const ModuleRecord* target = nullptr;
    for (size_t i = 0; i < modules.size(); ++i) {
        const std::wstring candidate = ToLower(GetModuleNameFromPath(
            modules[i].moduleName.empty() ? modules[i].imagePath : modules[i].moduleName));
        if (candidate == wanted) {
            target = &modules[i];
            break;
        }
    }
    if (target == nullptr) {
        std::wcout << L"Syscall module not found: " << moduleName << L"\n";
        return;
    }

    const char* const apiNames[] = {
        "NtQueryInformationProcess",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtContinue",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtCreateFile",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection"
    };
    std::vector<uint8_t> diskImage;
    const bool diskReady = !target->imagePath.empty() &&
        ReadFileToVectorCompat(target->imagePath, diskImage);

    std::wcout << L"--- Syscall Check: "
               << (target->moduleName.empty() ? GetModuleNameFromPath(target->imagePath)
                                               : target->moduleName)
               << L" ---\n";
    std::wcout << L"Baseline: "
               << (diskReady ? L"disk image" : L"unavailable")
               << L" (heuristic; syscall stubs may legitimately vary by Windows build)\n";

    size_t checked = 0;
    size_t different = 0;
    for (size_t i = 0; i < sizeof(apiNames) / sizeof(apiNames[0]); ++i) {
        DWORD functionRva = 0;
        uint8_t baseline[32] = {};
        const bool haveBaseline = diskReady &&
            DiskPeResolveExportRva(diskImage, apiNames[i], functionRva) &&
            DiskPeRead(diskImage, functionRva, baseline, sizeof(baseline));
        if (!haveBaseline) {
            std::wcout << L"  " << apiNames[i] << L": baseline unavailable\n";
            continue;
        }

        const uint64_t address = target->baseAddress + static_cast<uint64_t>(functionRva);
        uint8_t remote[32] = {};
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(address),
                remote,
                sizeof(remote),
                &bytesRead) ||
            bytesRead != sizeof(remote)) {
            std::wcout << L"  " << apiNames[i] << L": remote read failed\n";
            continue;
        }

        ++checked;
        const bool same = std::memcmp(baseline, remote, sizeof(remote)) == 0;
        if (!same) {
            ++different;
        }
        bool hasSyscall = false;
        bool hasInt2e = false;
        for (size_t b = 0; b + 1 < sizeof(remote); ++b) {
            if (remote[b] == 0x0F && remote[b + 1] == 0x05) {
                hasSyscall = true;
            }
            if (remote[b] == 0xCD && remote[b + 1] == 0x2E) {
                hasInt2e = true;
            }
        }
        const bool startsNearJump = remote[0] == 0xE9 ||
            remote[0] == 0xEB ||
            (remote[0] == 0xFF && remote[1] == 0x25) ||
            (remote[0] == 0x48 && remote[1] == 0xB8 &&
             remote[10] == 0xFF && remote[11] == 0xE0);

        std::wcout << L"  " << apiNames[i]
                   << (same ? L": OK" : L": DIFFERENT")
                   << L" address=" << ToHex(address)
                   << L" syscall=" << (hasSyscall ? L"yes" : L"no")
                   << L" int2e=" << (hasInt2e ? L"yes" : L"no")
                   << L" jump_prefix=" << (startsNearJump ? L"yes" : L"no")
                   << L" bytes=" << BytesToHex(remote, sizeof(remote))
                   << L"\n";
    }
    std::wcout << L"Syscall stubs checked=" << checked
               << L" baseline_differences=" << different << L"\n";
    std::wcout << L"Absence of syscall/int2e is not by itself evidence of tampering; "
                  L"forwarders, WOW64 and OS build differences are possible.\n";
}

void Debugger::PrintThreadCheck() const {
    if (!EnsureDebuggee()) {
        return;
    }

    std::vector<ModuleRecord> modules;
    CollectModuleRecords(modules);
    const auto moduleForAddress = [&](uint64_t address) -> const ModuleRecord* {
        for (size_t i = 0; i < modules.size(); ++i) {
            const uint64_t end = modules[i].baseAddress +
                static_cast<uint64_t>(modules[i].size);
            if (address >= modules[i].baseAddress && address < end) {
                return &modules[i];
            }
        }
        return nullptr;
    };
    const auto moduleName = [](const ModuleRecord* module) -> std::wstring {
        if (module == nullptr) {
            return L"<private-or-unknown>";
        }
        return module->moduleName.empty()
            ? GetModuleNameFromPath(module->imagePath)
            : module->moduleName;
    };

    std::vector<WDBL_THREAD_ENUM_ENTRY> threads;
    if (!(wdbl::winapi::IsProcessMemoryDriverActive() &&
          wdbl::winapi::QueryDriverThreadList(processId_, &threads))) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 entry = THREADENTRY32();
            entry.dwSize = sizeof(entry);
            if (Thread32First(snapshot, &entry)) {
                do {
                    if (entry.th32OwnerProcessID != processId_) {
                        continue;
                    }
                    WDBL_THREAD_ENUM_ENTRY item = WDBL_THREAD_ENUM_ENTRY();
                    item.ProcessId = processId_;
                    item.ThreadId = entry.th32ThreadID;
                    HANDLE thread = OpenThread(
                        THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
                    item.Priority = thread != nullptr
                        ? GetThreadPriority(thread)
                        : THREAD_PRIORITY_ERROR_RETURN;
                    if (thread != nullptr) {
                        CloseHandle(thread);
                    }
                    threads.push_back(item);
                } while (Thread32Next(snapshot, &entry));
            }
            CloseHandle(snapshot);
        }
    }

    if (threads.empty()) {
        std::wcout << L"No target threads found.\n";
        return;
    }

    std::wcout << L"--- Thread Check (" << threads.size() << L" threads) ---\n";
    size_t candidates = 0;
    for (size_t i = 0; i < threads.size(); ++i) {
        const WDBL_THREAD_ENUM_ENTRY& item = threads[i];
        uint64_t startAddress = item.StartAddress;
        WDBL_THREAD_INFO_RESULT detail = WDBL_THREAD_INFO_RESULT();
        if (startAddress == 0 &&
            wdbl::winapi::IsProcessMemoryDriverActive() &&
            wdbl::winapi::QueryDriverThreadInfo(item.ThreadId, &detail)) {
            startAddress = detail.StartAddress;
        }

        uint64_t currentIp = 0;
        if (stopState_.valid && item.ThreadId == stopState_.threadId) {
            CONTEXT context = stopState_.context;
            currentIp = GetInstructionPointer(context);
        }

        MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
        const bool queried = startAddress != 0 &&
            VirtualQueryEx(
                processHandle_,
                reinterpret_cast<LPCVOID>(startAddress),
                &mbi,
                sizeof(mbi)) != 0;
        const DWORD protection = queried ? (mbi.Protect & 0xff) : 0;
        const bool privateExecutable = queried &&
            mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            IsExecutableProtection(protection);
        const ModuleRecord* startModule = moduleForAddress(startAddress);
        const bool outsideModule = startAddress != 0 && startModule == nullptr;
        const bool candidate = privateExecutable || outsideModule;
        if (candidate) {
            ++candidates;
        }

        std::wcout << L"  tid=" << item.ThreadId
                   << L" start=" << ToHex(startAddress)
                   << L" start_module=" << moduleName(startModule);
        if (currentIp != 0) {
            std::wcout << L" current_ip=" << ToHex(currentIp)
                       << L" current_module=" << moduleName(moduleForAddress(currentIp));
        }
        std::wcout << L" private_exec=" << (privateExecutable ? L"yes" : L"no")
                   << L" remote_thread_candidate=" << (candidate ? L"yes" : L"no")
                   << L"\n";
    }
    std::wcout << L"Candidate threads=" << candidates
               << L" (heuristic; thread start addresses can be runtime-generated legitimately)\n";
}

void Debugger::PrintTimeline(size_t maxEvents) const {
    if (!EnsureDebuggee()) {
        return;
    }
    if (maxEvents == 0) {
        maxEvents = 1;
    }
    maxEvents = std::min<size_t>(maxEvents, 256);

    std::vector<WDBL_DRIVER_EVENT_ENTRY> events;
    if (wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverEvents(
            processId_,
            static_cast<DWORD>(maxEvents),
            &events)) {
        for (size_t i = 0; i < events.size(); ++i) {
            const WDBL_DRIVER_EVENT_ENTRY& event = events[i];
            const wchar_t* type = L"unknown";
            if (event.Type == WDBL_DRIVER_EVENT_PROCESS) type = L"process";
            else if (event.Type == WDBL_DRIVER_EVENT_THREAD) type = L"thread";
            else if (event.Type == WDBL_DRIVER_EVENT_IMAGE) type = L"image";
            else if (event.Type == WDBL_DRIVER_EVENT_MEMORY_PROTECT) type = L"memory-protect";
            else if (event.Type == WDBL_DRIVER_EVENT_REMOTE_THREAD) type = L"remote-thread";
            std::wcout << L"[driver " << i << L"] " << type
                       << L" pid=" << event.ProcessId
                       << L" tid=" << event.ThreadId
                       << L" address=" << ToHex(event.Address)
                       << L" size=0x" << std::hex << event.Size << std::dec
                       << L" status=0x" << std::hex
                       << static_cast<ULONG>(event.Status) << std::dec;
            if (event.Name[0] != L'\0') {
                std::wcout << L" " << event.Name;
            }
            std::wcout << L"\n";
        }
    } else {
        std::wcout << L"[driver] event queue unavailable\n";
    }

    if (stopState_.valid) {
        std::wcout << L"[debugger] stop tid=" << stopState_.threadId
                   << L" reason=" << stopState_.reason
                   << L" address=" << ToHex(stopState_.address)
                   << L" ip=" << ToHex(GetInstructionPointer(stopState_.context))
                   << L" exception=" << ExceptionCodeToString(stopState_.exceptionCode)
                   << L"\n";
    } else {
        std::wcout << L"[debugger] no current stop state\n";
    }
    if (events.empty()) {
        std::wcout << L"No driver events available. The driver queue is consumptive; "
                      L"already-read events cannot be reconstructed here.\n";
    }
}

void Debugger::PrintAnalysisReport() const {
    if (!EnsureDebuggee()) {
        return;
    }
    std::wcout << L"=== Analysis Report pid=" << processId_ << L" ===\n";

    if (wdbl::winapi::IsProcessMemoryDriverActive()) {
        WDBL_ANTI_DEBUG_QUERY_RESULT anti = WDBL_ANTI_DEBUG_QUERY_RESULT();
        if (wdbl::winapi::QueryDriverAntiDebug(processId_, 0, &anti)) {
            std::wcout << L"[anti-debug] peb=0x" << std::hex << anti.PebAddress
                       << L" debug_port=0x" << anti.DebugPort
                       << L" debug_object=0x" << anti.DebugObjectHandle
                       << L" debug_flags=0x" << anti.DebugFlags
                       << L" heap_flags=0x" << anti.HeapFlags
                       << L" heap_force_flags=0x" << anti.HeapForceFlags
                       << std::dec << L"\n";
        } else {
            std::wcout << L"[anti-debug] query failed\n";
        }
    } else {
        std::wcout << L"[anti-debug] driver unavailable\n";
    }

    std::vector<WDBL_MEMORY_ENUM_ENTRY> regions;
    size_t suspiciousVad = 0;
    if (wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverMemoryMap(processId_, 0, &regions)) {
        for (size_t i = 0; i < regions.size(); ++i) {
            const DWORD protection = regions[i].Protect & 0xff;
            const bool executable = IsExecutableProtection(protection);
            const bool writable = protection == PAGE_READWRITE ||
                protection == PAGE_EXECUTE_READWRITE ||
                protection == PAGE_WRITECOPY ||
                protection == PAGE_EXECUTE_WRITECOPY;
            if (regions[i].State == MEM_COMMIT && executable &&
                (writable || regions[i].Type == MEM_PRIVATE)) {
                ++suspiciousVad;
            }
        }
    }
    std::wcout << L"[vad] suspicious_regions=" << suspiciousVad << L"\n";

    std::vector<WDBL_HANDLE_ENUM_ENTRY> handles;
    if (wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverHandleList(processId_, &handles)) {
        std::wcout << L"[handles] total=" << handles.size() << L"\n";
    } else {
        std::wcout << L"[handles] unavailable\n";
    }

    std::vector<WDBL_DRIVER_EVENT_ENTRY> events;
    if (wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverEvents(processId_, 256, &events)) {
        std::wcout << L"[timeline] pending_driver_events=" << events.size() << L"\n";
    } else {
        std::wcout << L"[timeline] unavailable\n";
    }

    std::wcout << L"\n--- Detailed checks ---\n";
    PrintThreadCheck();
    PrintSyscallCheck(L"ntdll.dll");
    PrintModifyCheck(L"ntdll.dll");
}

void Debugger::PrintExceptionCheck() const {
    if (!EnsureDebuggee()) {
        return;
    }

    std::vector<ModuleRecord> modules;
    CollectModuleRecords(modules);
    const auto moduleForAddress = [&](uint64_t address) -> const ModuleRecord* {
        for (size_t i = 0; i < modules.size(); ++i) {
            const uint64_t end = modules[i].baseAddress +
                static_cast<uint64_t>(modules[i].size);
            if (address >= modules[i].baseAddress && address < end) {
                return &modules[i];
            }
        }
        return nullptr;
    };
    const auto moduleName = [](const ModuleRecord* module) -> std::wstring {
        if (module == nullptr) {
            return L"<private-or-unknown>";
        }
        return module->moduleName.empty()
            ? GetModuleNameFromPath(module->imagePath)
            : module->moduleName;
    };

    std::wcout << L"--- Exception Check ---\n";
    if (!stopState_.valid) {
        std::wcout << L"No paused thread; dispatcher and linked SEH checks are limited.\n";
    } else {
        std::wcout << L"Current exception=" << ExceptionCodeToString(stopState_.exceptionCode)
                   << L" address=" << ToHex(stopState_.address)
                   << L" tid=" << stopState_.threadId << L"\n";
    }

    // On x64 the TEB exception-list head is normally -1; on x86 inspect the
    // linked list and classify handlers by their owning memory/module.
    if (stopState_.valid) {
        auto ntQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
        HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, stopState_.threadId);
        THREAD_BASIC_INFORMATION_LOCAL tbi = THREAD_BASIC_INFORMATION_LOCAL();
        NTSTATUS status = static_cast<NTSTATUS>(-1);
        if (thread != nullptr && ntQueryInformationThread != nullptr) {
            status = ntQueryInformationThread(
                thread, static_cast<THREADINFOCLASS>(0), &tbi, sizeof(tbi), nullptr);
        }
        if (thread != nullptr) {
            CloseHandle(thread);
        }
        if (NT_SUCCESS(status) && tbi.TebBaseAddress != nullptr) {
#if defined(_M_X64)
            uint64_t exceptionList = 0;
            SIZE_T read = 0;
            if (ReadProcessMemory(processHandle_, tbi.TebBaseAddress,
                                   &exceptionList, sizeof(exceptionList), &read) &&
                read == sizeof(exceptionList)) {
                std::wcout << L"SEH head=" << ToHex(exceptionList);
                if (exceptionList == (std::numeric_limits<uint64_t>::max)()) {
                    std::wcout << L" (table-based unwind; linked list inactive)\n";
                } else {
                    std::wcout << L"\n";
                }
            } else {
                std::wcout << L"SEH head read failed.\n";
            }
#else
            uint32_t node = 0;
            SIZE_T read = 0;
            if (ReadProcessMemory(processHandle_, tbi.TebBaseAddress,
                                   &node, sizeof(node), &read) &&
                read == sizeof(node)) {
                size_t count = 0;
                while (node != 0 && node != 0xFFFFFFFF && count < 64) {
                    struct SehRecord32 {
                        uint32_t next;
                        uint32_t handler;
                    } record = SehRecord32();
                    if (!ReadProcessMemory(processHandle_,
                            reinterpret_cast<LPCVOID>(static_cast<uint64_t>(node)),
                            &record, sizeof(record), &read) ||
                        read != sizeof(record)) {
                        break;
                    }
                    const ModuleRecord* owner = moduleForAddress(record.handler);
                    MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
                    const bool valid = VirtualQueryEx(
                        processHandle_,
                        reinterpret_cast<LPCVOID>(static_cast<uint64_t>(record.handler)),
                        &mbi, sizeof(mbi)) != 0;
                    std::wcout << L"SEH[" << count << L"] handler=" << ToHex(record.handler)
                               << L" module=" << moduleName(owner)
                               << L" private_exec=" << (valid && mbi.Type == MEM_PRIVATE &&
                                    IsExecutableProtection(mbi.Protect) ? L"yes" : L"no")
                               << L"\n";
                    node = record.next;
                    ++count;
                }
            } else {
                std::wcout << L"SEH head read failed.\n";
            }
#endif
        }
    }

    const ModuleRecord* ntdll = nullptr;
    for (size_t i = 0; i < modules.size(); ++i) {
        if (ToLower(GetModuleNameFromPath(
                modules[i].moduleName.empty() ? modules[i].imagePath : modules[i].moduleName)) ==
            L"ntdll.dll") {
            ntdll = &modules[i];
            break;
        }
    }
    if (ntdll == nullptr) {
        std::wcout << L"ntdll.dll is not loaded in the target.\n";
        return;
    }

    HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC localDispatcher = localNtdll == nullptr
        ? nullptr
        : GetProcAddress(localNtdll, "KiUserExceptionDispatcher");
    if (localDispatcher == nullptr) {
        std::wcout << L"KiUserExceptionDispatcher export unavailable.\n";
        return;
    }
    const uint64_t localBase = reinterpret_cast<uint64_t>(localNtdll);
    const uint64_t localAddress = reinterpret_cast<uint64_t>(localDispatcher);
    if (localAddress < localBase) {
        std::wcout << L"Cannot calculate dispatcher RVA.\n";
        return;
    }
    const uint64_t remoteAddress = ntdll->baseAddress + (localAddress - localBase);
    uint8_t localBytes[32] = {};
    uint8_t remoteBytes[32] = {};
    std::memcpy(localBytes, localDispatcher, sizeof(localBytes));
    SIZE_T read = 0;
    const bool remoteRead = ReadProcessMemory(
        processHandle_, reinterpret_cast<LPCVOID>(remoteAddress),
        remoteBytes, sizeof(remoteBytes), &read) != FALSE &&
        read == sizeof(remoteBytes);
    std::wcout << L"KiUserExceptionDispatcher remote=" << ToHex(remoteAddress)
               << L" read=" << (remoteRead ? L"yes" : L"no");
    if (remoteRead) {
        std::wcout << L" compare=" << (std::memcmp(localBytes, remoteBytes, sizeof(remoteBytes)) == 0
            ? L"same" : L"different")
                   << L" bytes=" << BytesToHex(remoteBytes, sizeof(remoteBytes));
    }
    std::wcout << L"\n";
    std::wcout << L"VEH handlers are opaque to this user-mode query; use driver/agent logs "
                  L"for registration and dispatch evidence.\n";
}

void Debugger::PrintModuleCheck() const {
    if (!EnsureDebuggee()) {
        return;
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules)) {
        std::wcout << L"Cannot enumerate target modules.\n";
        return;
    }
    std::wcout << L"--- Module Check (" << modules.size() << L" modules) ---\n";
    size_t suspicious = 0;
    for (size_t i = 0; i < modules.size(); ++i) {
        const ModuleRecord& module = modules[i];
        uint8_t diskHeader[64] = {};
        std::vector<uint8_t> diskImage;
        const bool diskReady = !module.imagePath.empty() &&
            ReadFileToVectorCompat(module.imagePath, diskImage) &&
            diskImage.size() >= sizeof(diskHeader);
        if (diskReady) {
            std::memcpy(diskHeader, &diskImage[0], sizeof(diskHeader));
        }
        uint8_t remoteHeader[64] = {};
        SIZE_T read = 0;
        const bool remoteReady = ReadProcessMemory(
            processHandle_, reinterpret_cast<LPCVOID>(module.baseAddress),
            remoteHeader, sizeof(remoteHeader), &read) != FALSE &&
            read == sizeof(remoteHeader);
        MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
        const bool regionReady = VirtualQueryEx(
            processHandle_, reinterpret_cast<LPCVOID>(module.baseAddress),
            &mbi, sizeof(mbi)) != 0;
        const bool headerDifferent = diskReady && remoteReady &&
            std::memcmp(diskHeader, remoteHeader, sizeof(remoteHeader)) != 0;
        const bool validImage = remoteReady &&
            remoteHeader[0] == 'M' && remoteHeader[1] == 'Z';
        const bool privateImage = regionReady && mbi.Type == MEM_PRIVATE;
        const bool suspiciousModule = headerDifferent || !validImage || privateImage;
        if (suspiciousModule) {
            ++suspicious;
        }
        std::wcout << L"  " << (module.moduleName.empty()
            ? GetModuleNameFromPath(module.imagePath) : module.moduleName)
                   << L" base=" << ToHex(module.baseAddress)
                   << L" size=0x" << std::hex << module.size << std::dec
                   << L" header=" << (validImage ? L"PE-like" : L"invalid")
                   << L" disk_compare=" << (diskReady && remoteReady
                        ? (headerDifferent ? L"different" : L"same") : L"unavailable")
                   << L" private_image=" << (privateImage ? L"yes" : L"no")
                   << L" candidate=" << (suspiciousModule ? L"yes" : L"no")
                   << L" path=" << module.imagePath << L"\n";
    }
    std::wcout << L"Module candidates=" << suspicious
               << L" (heuristic; headers can change legitimately during loading/unpacking)\n";
}

bool Debugger::ExportAnalysisReport(
    const std::wstring& filePath,
    const std::wstring& format) const {
    if (!EnsureDebuggee()) {
        return false;
    }
    const std::wstring path = TrimWhitespace(filePath);
    const std::wstring selectedFormat = ToLower(TrimWhitespace(format));
    if (path.empty()) {
        std::wcout << L"Report output path cannot be empty.\n";
        return false;
    }
    if (selectedFormat != L"txt" && selectedFormat != L"text" &&
        selectedFormat != L"json") {
        std::wcout << L"Report format must be txt or json.\n";
        return false;
    }

    std::vector<ModuleRecord> modules;
    CollectModuleRecords(modules);
    std::vector<WDBL_DRIVER_EVENT_ENTRY> events;
    const bool haveEvents = wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverEvents(processId_, 256, &events);

    std::wstringstream output;
    if (selectedFormat == L"json") {
        output << L"{\n"
               << L"  \"process_id\": " << processId_ << L",\n"
               << L"  \"paused\": " << (stopState_.valid ? L"true" : L"false") << L",\n"
               << L"  \"module_count\": " << modules.size() << L",\n"
               << L"  \"driver_event_count\": " << (haveEvents ? events.size() : 0) << L",\n"
               << L"  \"stop\": ";
        if (stopState_.valid) {
            output << L"{\"tid\":" << stopState_.threadId
                   << L",\"address\":\"" << ToHex(stopState_.address)
                   << L"\",\"ip\":\"" << ToHex(GetInstructionPointer(stopState_.context))
                   << L"\",\"exception\":\"" << ExceptionCodeToString(stopState_.exceptionCode)
                   << L"\"}";
        } else {
            output << L"null";
        }
        output << L",\n  \"modules\": [\n";
        for (size_t i = 0; i < modules.size(); ++i) {
            if (i != 0) output << L",\n";
            output << L"    {\"name\":\"" << (modules[i].moduleName.empty()
                ? GetModuleNameFromPath(modules[i].imagePath) : modules[i].moduleName)
                   << L"\",\"base\":\"" << ToHex(modules[i].baseAddress)
                   << L"\",\"size\":" << modules[i].size << L"}";
        }
        output << L"\n  ]\n}\n";
    } else {
        output << L"WinDbgLite Analysis Report\n"
               << L"Generated: " << NowTimestamp() << L"\n"
               << L"process_id=" << processId_ << L"\n"
               << L"paused=" << (stopState_.valid ? L"yes" : L"no") << L"\n"
               << L"module_count=" << modules.size() << L"\n"
               << L"driver_event_count=" << (haveEvents ? events.size() : 0) << L"\n";
        if (stopState_.valid) {
            output << L"stop_tid=" << stopState_.threadId << L"\n"
                   << L"stop_address=" << ToHex(stopState_.address) << L"\n"
                   << L"stop_exception=" << ExceptionCodeToString(stopState_.exceptionCode) << L"\n";
        }
        output << L"\n[Modules]\n";
        for (size_t i = 0; i < modules.size(); ++i) {
            output << modules[i].moduleName << L" base=" << ToHex(modules[i].baseAddress)
                   << L" size=0x" << std::hex << modules[i].size << std::dec
                   << L" path=" << modules[i].imagePath << L"\n";
        }
    }

    std::wstring error;
    if (!WriteWideTextUtf8File(path, output.str(), error)) {
        std::wcout << L"Failed to export report: " << error << L"\n";
        return false;
    }
    std::wcout << L"Analysis report exported to: " << path << L"\n";
    return true;
}

void Debugger::PrintApiTrace(size_t maxEvents, const std::wstring& filter) const {
    if (!EnsureDebuggee()) {
        return;
    }
    maxEvents = std::min<size_t>(maxEvents == 0 ? 1 : maxEvents, 256);
    const std::wstring wanted = ToLower(TrimWhitespace(filter));
    std::vector<WDBL_DRIVER_EVENT_ENTRY> events;
    if (!wdbl::winapi::IsProcessMemoryDriverActive() ||
        !wdbl::winapi::QueryDriverEvents(processId_, static_cast<DWORD>(maxEvents), &events)) {
        std::wcout << L"API trace requires the driver event queue.\n";
        return;
    }
    std::wcout << L"--- API Trace Approximation (" << events.size()
               << L" events; driver behavior events) ---\n";
    size_t shown = 0;
    for (size_t i = 0; i < events.size(); ++i) {
        const WDBL_DRIVER_EVENT_ENTRY& event = events[i];
        const std::wstring name = event.Name;
        std::wstring type = L"unknown";
        if (event.Type == WDBL_DRIVER_EVENT_PROCESS) type = L"process";
        else if (event.Type == WDBL_DRIVER_EVENT_THREAD) type = L"thread";
        else if (event.Type == WDBL_DRIVER_EVENT_IMAGE) type = L"image";
        else if (event.Type == WDBL_DRIVER_EVENT_MEMORY_PROTECT) type = L"memory-protect";
        else if (event.Type == WDBL_DRIVER_EVENT_REMOTE_THREAD) type = L"remote-thread";
        if (!wanted.empty() && ToLower(type).find(wanted) == std::wstring::npos &&
            ToLower(name).find(wanted) == std::wstring::npos) {
            continue;
        }
        ++shown;
        std::wcout << L"[" << shown - 1 << L"] " << type
                   << L" pid=" << event.ProcessId
                   << L" tid=" << event.ThreadId
                   << L" address=" << ToHex(event.Address)
                   << L" size=0x" << std::hex << event.Size << std::dec;
        if (!name.empty()) {
            std::wcout << L" name=" << name;
        }
        std::wcout << L"\n";
    }
    std::wcout << L"Shown=" << shown
               << L". This is not instruction-level API interception; "
                  L"add agent hooks for exact API call arguments.\n";
}

void Debugger::PrintExceptionInfo() const {
    if (!stopState_.valid) {
        std::wcout << L"No current exception context.\n";
        return;
    }
    std::wcout << L"--- Exception ---\n";
    std::wcout << L"Code: " << ExceptionCodeToString(stopState_.exceptionCode) << L"\n";
    std::wcout << L"Address: " << ToHex(stopState_.address) << L"\n";
    std::wcout << L"First chance: " << (stopState_.firstChance ? L"yes" : L"no") << L"\n";
    std::wcout << L"Reason: " << stopState_.reason << L"\n";
}

namespace {

std::wstring HexNoPrefix(uint64_t value, size_t width) {
    std::wstringstream ss;
    ss << std::uppercase << std::hex << std::setfill(L'0');
    if (width != 0) {
        ss << std::setw(static_cast<int>(width));
    }
    ss << value;
    return ss.str();
}

std::wstring StripHexPrefix(std::wstring text) {
    if (text.rfind(L"0x", 0) == 0 || text.rfind(L"0X", 0) == 0) {
        return text.substr(2);
    }
    return text;
}

void PrintRegisterLine(const std::wstring& line) {
    std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
}

void PrintStackLine(const std::wstring& line) {
    std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
}

void PrintStackTopLine(const std::wstring& line) {
    std::wcout << L"\x1b[38;2;255;255;255;48;2;180;0;0m" << line << L"\x1b[0m\n";
}

std::wstring FlagValue(uint64_t flags, uint64_t bit) {
    return (flags & bit) != 0 ? L"1" : L"0";
}

std::wstring EflSummary(uint64_t flags) {
    std::wstring out = L"(";
    out += (flags & (1ull << 11)) ? L"OV" : L"NO";
    out += L",";
    out += (flags & 1ull) ? L"CY" : L"NB";
    out += L",";
    out += (flags & (1ull << 6)) ? L"ZR" : L"NZ";
    out += L",";
    out += (flags & (1ull << 7)) ? L"NG" : L"NS";
    out += L",";
    out += (flags & (1ull << 2)) ? L"PE" : L"PO";
    out += L",";
    out += (flags & (1ull << 4)) ? L"AC" : L"NA";
    out += L",";
    out += (flags & (1ull << 10)) ? L"DN" : L"UP";
    out += L")";
    return out;
}

std::wstring LastErrorName(DWORD errorCode) {
    switch (errorCode) {
        case ERROR_SUCCESS:
            return L"ERROR_SUCCESS";
        case ERROR_FILE_NOT_FOUND:
            return L"ERROR_FILE_NOT_FOUND";
        case ERROR_PATH_NOT_FOUND:
            return L"ERROR_PATH_NOT_FOUND";
        case ERROR_ACCESS_DENIED:
            return L"ERROR_ACCESS_DENIED";
        case ERROR_INVALID_HANDLE:
            return L"ERROR_INVALID_HANDLE";
        case ERROR_NOT_ENOUGH_MEMORY:
            return L"ERROR_NOT_ENOUGH_MEMORY";
        case ERROR_INVALID_PARAMETER:
            return L"ERROR_INVALID_PARAMETER";
        case ERROR_ALREADY_EXISTS:
            return L"ERROR_ALREADY_EXISTS";
        default:
            return L"ERROR_" + ToWStringCompat(errorCode);
    }
}

struct SymbolSearchContext {
    size_t count;
    size_t limit;

    SymbolSearchContext()
        : count(0),
          limit(512) {}
};

BOOL CALLBACK PrintSymbolCallback(PSYMBOL_INFOW symInfo, ULONG symbolSize, PVOID userContext) {
    if (symInfo == nullptr || userContext == nullptr) {
        return TRUE;
    }
    SymbolSearchContext* context = reinterpret_cast<SymbolSearchContext*>(userContext);
    std::wstringstream line;
    line << HexNoPrefix(symInfo->Address, 16) << L" ";
    if (symInfo->NameLen > 0 && symInfo->Name != nullptr) {
        line << std::wstring(symInfo->Name, symInfo->Name + symInfo->NameLen);
    }
    if (symbolSize != 0) {
        line << L" size=" << symbolSize;
    }
    PrintRegisterLine(line.str());
    ++context->count;
    return context->count < context->limit ? TRUE : FALSE;
}

} // namespace

void Debugger::PrintRegisterInfo() const {
    if (!stopState_.valid) {
        std::wcout << L"No paused context.\n";
        return;
    }
    EnsureConsoleColorEnabled();

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        ctx = stopState_.context;
    }

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (CaptureWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            const auto formatWow64Symbol = [&](uint32_t value) -> std::wstring {
                if (value == 0) {
                    return L"";
                }
                const uint64_t value64 = static_cast<uint64_t>(value);
                std::vector<ModuleRecord> modules;
                if (CollectModuleRecords(modules)) {
                    for (size_t i = 0; i < modules.size(); ++i) {
                        uint64_t entry = 0;
                        if (ResolveEntryPointFromModuleBase(modules[i].baseAddress, entry) && entry == value64) {
                            const std::wstring moduleName = modules[i].moduleName.empty()
                                ? GetModuleNameFromPath(modules[i].imagePath)
                                : modules[i].moduleName;
                            return moduleName + L"." + L"\x5165\x53E3\x70B9";
                        }
                    }
                }
                return ResolveSymbol(value64);
            };

            const auto wowRegLine = [&](const wchar_t* name, uint32_t value) -> void {
                std::wstringstream ss;
                ss << std::left << std::setw(4) << name << L" " << HexNoPrefix(value, 8);
                const std::wstring symbol = formatWow64Symbol(value);
                if (!symbol.empty()) {
                    ss << L" " << symbol;
                }
                PrintRegisterLine(ss.str());
            };

            wowRegLine(L"EAX", wowCtx.Eax);
            wowRegLine(L"ECX", wowCtx.Ecx);
            wowRegLine(L"EDX", wowCtx.Edx);
            wowRegLine(L"EBX", wowCtx.Ebx);
            wowRegLine(L"ESP", wowCtx.Esp);
            wowRegLine(L"EBP", wowCtx.Ebp);
            wowRegLine(L"ESI", wowCtx.Esi);
            wowRegLine(L"EDI", wowCtx.Edi);
            wowRegLine(L"EIP", wowCtx.Eip);
            PrintRegisterLine(L"EFLAGS " + HexNoPrefix(wowCtx.EFlags, 8));

            DWORD lastErrorValue = 0;
            HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, stopState_.threadId);
            if (thread != nullptr) {
                auto ntQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
                    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
                if (ntQueryInformationThread != nullptr) {
                    THREAD_BASIC_INFORMATION_LOCAL tbi = THREAD_BASIC_INFORMATION_LOCAL();
                    ULONG retLen = 0;
                    NTSTATUS status = ntQueryInformationThread(
                        thread,
                        static_cast<THREADINFOCLASS>(0),
                        &tbi,
                        sizeof(tbi),
                        &retLen);
                    if (status >= 0 && tbi.TebBaseAddress != nullptr) {
                        SIZE_T read = 0;
                        uint32_t teb32 = 0;
                        ReadProcessMemory(
                            processHandle_,
                            tbi.TebBaseAddress,
                            &teb32,
                            sizeof(teb32),
                            &read);
                        if (teb32 == 0 || read != sizeof(teb32)) {
                            teb32 = static_cast<uint32_t>(reinterpret_cast<uint64_t>(tbi.TebBaseAddress));
                        }
                        ReadProcessMemory(
                            processHandle_,
                            reinterpret_cast<LPCVOID>(static_cast<uint64_t>(teb32) + 0x34),
                            &lastErrorValue,
                            sizeof(lastErrorValue),
                            &read);
                    }
                }
                CloseHandle(thread);
            }

            PrintRegisterLine(L"CF " + FlagValue(wowCtx.EFlags, 1ull) +
                              L"   ES " + HexNoPrefix(wowCtx.SegEs, 4) + L" 32\x4F4D 0(FFFFFFFF)");
            PrintRegisterLine(L"PF " + FlagValue(wowCtx.EFlags, 1ull << 2) +
                              L"   CS " + HexNoPrefix(wowCtx.SegCs, 4) + L" 32\x4F4D 0(FFFFFFFF)");
            PrintRegisterLine(L"AF " + FlagValue(wowCtx.EFlags, 1ull << 4) +
                              L"   SS " + HexNoPrefix(wowCtx.SegSs, 4) + L" 32\x4F4D 0(FFFFFFFF)");
            PrintRegisterLine(L"ZF " + FlagValue(wowCtx.EFlags, 1ull << 6) +
                              L"   DS " + HexNoPrefix(wowCtx.SegDs, 4) + L" 32\x4F4D 0(FFFFFFFF)");
            PrintRegisterLine(L"SF " + FlagValue(wowCtx.EFlags, 1ull << 7) +
                              L"   FS " + HexNoPrefix(wowCtx.SegFs, 4) + L" 32\x4F4D 0(FFF)");
            PrintRegisterLine(L"TF " + FlagValue(wowCtx.EFlags, 1ull << 8) +
                              L"   GS " + HexNoPrefix(wowCtx.SegGs, 4) + L" 32\x4F4D 0(FFFFFFFF)");
            PrintRegisterLine(L"DF " + FlagValue(wowCtx.EFlags, 1ull << 10) +
                              L"   IF " + FlagValue(wowCtx.EFlags, 1ull << 9));
            PrintRegisterLine(L"OF " + FlagValue(wowCtx.EFlags, 1ull << 11) +
                              L"   LastErr " + LastErrorName(lastErrorValue) +
                              L" (" + HexNoPrefix(lastErrorValue, 8) + L")");
            PrintRegisterLine(L"EFL " + HexNoPrefix(wowCtx.EFlags, 8) + L" " + EflSummary(wowCtx.EFlags));
            PrintRegisterLine(L"DR0 " + HexNoPrefix(wowCtx.Dr0, 8));
            PrintRegisterLine(L"DR1 " + HexNoPrefix(wowCtx.Dr1, 8));
            PrintRegisterLine(L"DR2 " + HexNoPrefix(wowCtx.Dr2, 8));
            PrintRegisterLine(L"DR3 " + HexNoPrefix(wowCtx.Dr3, 8));
            PrintRegisterLine(L"DR4 Reserved");
            PrintRegisterLine(L"DR5 Reserved");
            PrintRegisterLine(L"DR6 " + HexNoPrefix(wowCtx.Dr6, 8));
            PrintRegisterLine(L"DR7 " + HexNoPrefix(wowCtx.Dr7, 8));
            return;
        }
    }

    const auto formatSymbol = [&](uint64_t value) -> std::wstring {
        if (value == 0) {
            return L"";
        }
        std::vector<ModuleRecord> modules;
        if (CollectModuleRecords(modules)) {
            for (size_t i = 0; i < modules.size(); ++i) {
                uint64_t entry = 0;
                if (ResolveEntryPointFromModuleBase(modules[i].baseAddress, entry) && entry == value) {
                    const std::wstring moduleName = modules[i].moduleName.empty()
                        ? GetModuleNameFromPath(modules[i].imagePath)
                        : modules[i].moduleName;
                    return moduleName + L"." + L"\x5165\x53E3\x70B9";
                }
            }
        }
        return ResolveSymbol(value);
    };

    const auto regLine = [&](const wchar_t* name, uint64_t value) -> void {
        std::wstringstream ss;
        ss << std::left << std::setw(4) << name << L" " << HexNoPrefix(value, 16);
        const std::wstring symbol = formatSymbol(value);
        if (!symbol.empty()) {
            ss << L" " << symbol;
        }
        PrintRegisterLine(ss.str());
    };

    regLine(L"RAX", ctx.Rax);
    regLine(L"RCX", ctx.Rcx);
    regLine(L"RDX", ctx.Rdx);
    regLine(L"RBX", ctx.Rbx);
    regLine(L"RSP", ctx.Rsp);
    regLine(L"RBP", ctx.Rbp);
    regLine(L"RSI", ctx.Rsi);
    regLine(L"RDI", ctx.Rdi);
    regLine(L"R8", ctx.R8);
    regLine(L"R9", ctx.R9);
    regLine(L"R10", ctx.R10);
    regLine(L"R11", ctx.R11);
    regLine(L"R12", ctx.R12);
    regLine(L"R13", ctx.R13);
    regLine(L"R14", ctx.R14);
    regLine(L"R15", ctx.R15);
    regLine(L"RIP", ctx.Rip);
    PrintRegisterLine(L"RFLAGS " + HexNoPrefix(ctx.EFlags, 16));

    DWORD lastErrorValue = 0;
    HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, stopState_.threadId);
    if (thread != nullptr) {
        auto ntQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
        if (ntQueryInformationThread != nullptr) {
            THREAD_BASIC_INFORMATION_LOCAL tbi = THREAD_BASIC_INFORMATION_LOCAL();
            ULONG retLen = 0;
            NTSTATUS status = ntQueryInformationThread(
                thread,
                static_cast<THREADINFOCLASS>(0),
                &tbi,
                sizeof(tbi),
                &retLen);
            if (status >= 0 && tbi.TebBaseAddress != nullptr) {
                SIZE_T read = 0;
                ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(reinterpret_cast<uint64_t>(tbi.TebBaseAddress) + 0x68),
                    &lastErrorValue,
                    sizeof(lastErrorValue),
                    &read);
            }
        }
        CloseHandle(thread);
    }

    PrintRegisterLine(L"CF " + FlagValue(ctx.EFlags, 1ull) +
                      L"   ES " + HexNoPrefix(ctx.SegEs, 4) + L" 64\x4F4D 0(FFFFFFFFFFFFFFFF)");
    PrintRegisterLine(L"PF " + FlagValue(ctx.EFlags, 1ull << 2) +
                      L"   CS " + HexNoPrefix(ctx.SegCs, 4) + L" 64\x4F4D 0(FFFFFFFFFFFFFFFF)");
    PrintRegisterLine(L"AF " + FlagValue(ctx.EFlags, 1ull << 4) +
                      L"   SS " + HexNoPrefix(ctx.SegSs, 4) + L" 64\x4F4D 0(FFFFFFFFFFFFFFFF)");
    PrintRegisterLine(L"ZF " + FlagValue(ctx.EFlags, 1ull << 6) +
                      L"   DS " + HexNoPrefix(ctx.SegDs, 4) + L" 64\x4F4D 0(FFFFFFFFFFFFFFFF)");
    PrintRegisterLine(L"SF " + FlagValue(ctx.EFlags, 1ull << 7) +
                      L"   FS " + HexNoPrefix(ctx.SegFs, 4) + L" 64\x4F4D 0(FFF)");
    PrintRegisterLine(L"TF " + FlagValue(ctx.EFlags, 1ull << 8) +
                      L"   GS " + HexNoPrefix(ctx.SegGs, 4) + L" 64\x4F4D 0(FFFFFFFFFFFFFFFF)");
    PrintRegisterLine(L"DF " + FlagValue(ctx.EFlags, 1ull << 10) +
                      L"   IF " + FlagValue(ctx.EFlags, 1ull << 9));
    PrintRegisterLine(L"OF " + FlagValue(ctx.EFlags, 1ull << 11) +
                      L"   LastErr " + LastErrorName(lastErrorValue) +
                      L" (" + HexNoPrefix(lastErrorValue, 8) + L")");
    PrintRegisterLine(L"EFL " + HexNoPrefix(ctx.EFlags, 8) + L" " + EflSummary(ctx.EFlags));

    PrintDebugRegisterInfo();
#else
    std::wstringstream ss;
    ss << L"EAX " << HexNoPrefix(ctx.Eax, 8);
    PrintRegisterLine(ss.str());
    ss.str(L""); ss.clear(); ss << L"ECX " << HexNoPrefix(ctx.Ecx, 8); PrintRegisterLine(ss.str());
    ss.str(L""); ss.clear(); ss << L"EDX " << HexNoPrefix(ctx.Edx, 8); PrintRegisterLine(ss.str());
    ss.str(L""); ss.clear(); ss << L"EBX " << HexNoPrefix(ctx.Ebx, 8); PrintRegisterLine(ss.str());
    ss.str(L""); ss.clear(); ss << L"ESP " << HexNoPrefix(ctx.Esp, 8); PrintRegisterLine(ss.str());
    ss.str(L""); ss.clear(); ss << L"EBP " << HexNoPrefix(ctx.Ebp, 8); PrintRegisterLine(ss.str());
    ss.str(L""); ss.clear(); ss << L"ESI " << HexNoPrefix(ctx.Esi, 8); PrintRegisterLine(ss.str());
    ss.str(L""); ss.clear(); ss << L"EDI " << HexNoPrefix(ctx.Edi, 8); PrintRegisterLine(ss.str());
    ss.str(L""); ss.clear(); ss << L"EIP " << HexNoPrefix(ctx.Eip, 8); PrintRegisterLine(ss.str());
    ss.str(L""); ss.clear(); ss << L"EFLAGS " << HexNoPrefix(ctx.EFlags, 8); PrintRegisterLine(ss.str());
    PrintDebugRegisterInfo();
#endif
}

void Debugger::PrintMmxRegisterInfo() const {
    if (!stopState_.valid) {
        std::wcout << L"No paused context.\n";
        return;
    }
    EnsureConsoleColorEnabled();

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        ctx = stopState_.context;
    }

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (CaptureWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            for (int i = 0; i < 8; ++i) {
                uint64_t value = 0;
                memcpy(&value, &wowCtx.FloatSave.RegisterArea[i * 10], sizeof(value));
                std::wstringstream ss;
                ss << L"MM" << i << L" " << HexNoPrefix(value, 16);
                PrintRegisterLine(ss.str());
            }
            return;
        }
    }
    for (int i = 0; i < 8; ++i) {
        std::wstringstream ss;
        ss << L"MM" << i << L" " << HexNoPrefix(ctx.FltSave.FloatRegisters[i].Low, 16);
        PrintRegisterLine(ss.str());
    }
#else
    for (int i = 0; i < 8; ++i) {
        uint64_t value = 0;
        memcpy(&value, &ctx.FloatSave.RegisterArea[i * 10], sizeof(value));
        std::wstringstream ss;
        ss << L"MM" << i << L" " << HexNoPrefix(value, 16);
        PrintRegisterLine(ss.str());
    }
#endif
}

void Debugger::PrintFloatRegisterInfo() const {
    if (!stopState_.valid) {
        std::wcout << L"No paused context.\n";
        return;
    }
    EnsureConsoleColorEnabled();

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        ctx = stopState_.context;
    }

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (CaptureWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            PrintRegisterLine(L"FloatControl " + HexNoPrefix(wowCtx.FloatSave.ControlWord, 4) +
                              L"  FloatStatus " + HexNoPrefix(wowCtx.FloatSave.StatusWord, 4) +
                              L"  FloatTag " + HexNoPrefix(wowCtx.FloatSave.TagWord, 4));
            for (int i = 0; i < 8; ++i) {
                std::wstringstream ss;
                ss << L"ST" << i << L" ";
                ss << std::uppercase << std::hex << std::setfill(L'0');
                const uint8_t* stBytes = &wowCtx.FloatSave.RegisterArea[i * 10];
                for (int b = 9; b >= 0; --b) {
                    ss << std::setw(2) << static_cast<unsigned int>(stBytes[b]);
                }
                PrintRegisterLine(ss.str());
            }
            return;
        }
    }
    PrintRegisterLine(L"FloatControl " + HexNoPrefix(ctx.FltSave.ControlWord, 4) +
                      L"  FloatStatus " + HexNoPrefix(ctx.FltSave.StatusWord, 4) +
                      L"  FloatTag " + HexNoPrefix(ctx.FltSave.TagWord, 4));
    PrintRegisterLine(L"MXCSR " + HexNoPrefix(ctx.MxCsr, 8));
    for (int i = 0; i < 8; ++i) {
        std::wstringstream ss;
        ss << L"ST" << i << L" " << StripHexPrefix(ToHex128(ctx.FltSave.FloatRegisters[i]));
        PrintRegisterLine(ss.str());
    }
#else
    PrintRegisterLine(L"FloatControl " + HexNoPrefix(ctx.FloatSave.ControlWord, 4) +
                      L"  FloatStatus " + HexNoPrefix(ctx.FloatSave.StatusWord, 4) +
                      L"  FloatTag " + HexNoPrefix(ctx.FloatSave.TagWord, 4));
    for (int i = 0; i < 8; ++i) {
        std::wstringstream ss;
        ss << L"ST" << i << L" ";
        ss << std::uppercase << std::hex << std::setfill(L'0');
        const uint8_t* stBytes = &ctx.FloatSave.RegisterArea[i * 10];
        for (int b = 9; b >= 0; --b) {
            ss << std::setw(2) << static_cast<unsigned int>(stBytes[b]);
        }
        PrintRegisterLine(ss.str());
    }
#endif
}

void Debugger::PrintDebugRegisterInfo() const {
    if (!stopState_.valid) {
        std::wcout << L"No paused context.\n";
        return;
    }
    EnsureConsoleColorEnabled();

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        ctx = stopState_.context;
    }

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (CaptureWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            PrintRegisterLine(L"DR0 " + HexNoPrefix(wowCtx.Dr0, 8));
            PrintRegisterLine(L"DR1 " + HexNoPrefix(wowCtx.Dr1, 8));
            PrintRegisterLine(L"DR2 " + HexNoPrefix(wowCtx.Dr2, 8));
            PrintRegisterLine(L"DR3 " + HexNoPrefix(wowCtx.Dr3, 8));
            PrintRegisterLine(L"DR4 Reserved");
            PrintRegisterLine(L"DR5 Reserved");
            PrintRegisterLine(L"DR6 " + HexNoPrefix(wowCtx.Dr6, 8));
            PrintRegisterLine(L"DR7 " + HexNoPrefix(wowCtx.Dr7, 8));
            return;
        }
    }
    PrintRegisterLine(L"DR0 " + HexNoPrefix(ctx.Dr0, 16));
    PrintRegisterLine(L"DR1 " + HexNoPrefix(ctx.Dr1, 16));
    PrintRegisterLine(L"DR2 " + HexNoPrefix(ctx.Dr2, 16));
    PrintRegisterLine(L"DR3 " + HexNoPrefix(ctx.Dr3, 16));
    PrintRegisterLine(L"DR4 Reserved");
    PrintRegisterLine(L"DR5 Reserved");
    PrintRegisterLine(L"DR6 " + HexNoPrefix(ctx.Dr6, 16));
    PrintRegisterLine(L"DR7 " + HexNoPrefix(ctx.Dr7, 16));
#else
    PrintRegisterLine(L"DR0 " + HexNoPrefix(ctx.Dr0, 8));
    PrintRegisterLine(L"DR1 " + HexNoPrefix(ctx.Dr1, 8));
    PrintRegisterLine(L"DR2 " + HexNoPrefix(ctx.Dr2, 8));
    PrintRegisterLine(L"DR3 " + HexNoPrefix(ctx.Dr3, 8));
    PrintRegisterLine(L"DR4 Reserved");
    PrintRegisterLine(L"DR5 Reserved");
    PrintRegisterLine(L"DR6 " + HexNoPrefix(ctx.Dr6, 8));
    PrintRegisterLine(L"DR7 " + HexNoPrefix(ctx.Dr7, 8));
#endif
}

bool Debugger::SetRegisterValue(const std::wstring& assignment) {
    if (!EnsurePaused()) {
        return false;
    }
    const size_t eqPos = assignment.find(L'=');
    if (eqPos == std::wstring::npos || eqPos == 0 || eqPos + 1 >= assignment.size()) {
        std::wcout << L"Usage: r <register>=<value>\n";
        return false;
    }

    const std::wstring reg = ToLower(TrimWhitespace(assignment.substr(0, eqPos)));
    const std::wstring valueText = TrimWhitespace(assignment.substr(eqPos + 1));
    uint64_t value = 0;
    if (!ParseUInt64(valueText, value)) {
        const std::wstring prefixed = L"0x" + valueText;
        if (!ParseUInt64(prefixed, value)) {
            std::wstring resolved;
            if (!ResolveAddressExpression(valueText, value, resolved)) {
                std::wcout << L"Invalid register value.\n";
                return false;
            }
        }
    }

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (!CaptureWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            std::wcout << L"Wow64GetThreadContext failed.\n";
            return false;
        }
        const DWORD v = static_cast<DWORD>(value);
        if (reg == L"eax") wowCtx.Eax = v;
        else if (reg == L"ebx") wowCtx.Ebx = v;
        else if (reg == L"ecx") wowCtx.Ecx = v;
        else if (reg == L"edx") wowCtx.Edx = v;
        else if (reg == L"esi") wowCtx.Esi = v;
        else if (reg == L"edi") wowCtx.Edi = v;
        else if (reg == L"ebp") wowCtx.Ebp = v;
        else if (reg == L"esp") wowCtx.Esp = v;
        else if (reg == L"eip") wowCtx.Eip = v;
        else if (reg == L"efl" || reg == L"eflags") wowCtx.EFlags = v;
        else {
            std::wcout << L"Unsupported WOW64 register: " << reg << L"\n";
            return false;
        }
        wowCtx.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_DEBUG_REGISTERS;
        if (!ApplyWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            std::wcout << L"Wow64SetThreadContext failed.\n";
            return false;
        }
        std::wcout << L"Register " << reg << L" set to " << HexNoPrefix(v, 8) << L".\n";
        return true;
    }
#endif

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        std::wcout << L"GetThreadContext failed.\n";
        return false;
    }
#if defined(_M_X64)
    if (reg == L"rax") ctx.Rax = value;
    else if (reg == L"rbx") ctx.Rbx = value;
    else if (reg == L"rcx") ctx.Rcx = value;
    else if (reg == L"rdx") ctx.Rdx = value;
    else if (reg == L"rsi") ctx.Rsi = value;
    else if (reg == L"rdi") ctx.Rdi = value;
    else if (reg == L"rbp") ctx.Rbp = value;
    else if (reg == L"rsp") ctx.Rsp = value;
    else if (reg == L"rip") ctx.Rip = value;
    else if (reg == L"r8") ctx.R8 = value;
    else if (reg == L"r9") ctx.R9 = value;
    else if (reg == L"r10") ctx.R10 = value;
    else if (reg == L"r11") ctx.R11 = value;
    else if (reg == L"r12") ctx.R12 = value;
    else if (reg == L"r13") ctx.R13 = value;
    else if (reg == L"r14") ctx.R14 = value;
    else if (reg == L"r15") ctx.R15 = value;
    else if (reg == L"efl" || reg == L"eflags" || reg == L"rflags") ctx.EFlags = static_cast<DWORD>(value);
    else {
        std::wcout << L"Unsupported register: " << reg << L"\n";
        return false;
    }
#else
    if (reg == L"eax") ctx.Eax = static_cast<DWORD>(value);
    else if (reg == L"ebx") ctx.Ebx = static_cast<DWORD>(value);
    else if (reg == L"ecx") ctx.Ecx = static_cast<DWORD>(value);
    else if (reg == L"edx") ctx.Edx = static_cast<DWORD>(value);
    else if (reg == L"esi") ctx.Esi = static_cast<DWORD>(value);
    else if (reg == L"edi") ctx.Edi = static_cast<DWORD>(value);
    else if (reg == L"ebp") ctx.Ebp = static_cast<DWORD>(value);
    else if (reg == L"esp") ctx.Esp = static_cast<DWORD>(value);
    else if (reg == L"eip") ctx.Eip = static_cast<DWORD>(value);
    else if (reg == L"efl" || reg == L"eflags") ctx.EFlags = static_cast<DWORD>(value);
    else {
        std::wcout << L"Unsupported register: " << reg << L"\n";
        return false;
    }
#endif
    if (!ApplyThreadContext(stopState_.threadId, ctx)) {
        std::wcout << L"SetThreadContext failed.\n";
        return false;
    }
    std::wcout << L"Register " << reg << L" set.\n";
    return true;
}

void Debugger::PrintAsciiMemory(uint64_t address, size_t byteCount) const {
    if (!EnsureDebuggee()) {
        return;
    }
    if (byteCount == 0) {
        byteCount = 256;
    }
    std::vector<uint8_t> data(byteCount, 0);
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), data.data(), data.size(), &read) || read == 0) {
        std::wcout << L"ReadProcessMemory failed at " << ToHex(address) << L".\n";
        return;
    }
    EnsureConsoleColorEnabled();
    const size_t kBytesPerLine = 8;
    for (size_t row = 0; row < static_cast<size_t>(read); row += kBytesPerLine) {
        const size_t count = std::min(kBytesPerLine, static_cast<size_t>(read) - row);
        std::wstringstream line;
        line << HexNoPrefix(address + row, sizeof(void*) * 2) << L"  ";
        for (size_t i = 0; i < count; ++i) {
            line << HexNoPrefix(data[row + i], 2);
        }
        if (count < kBytesPerLine) {
            line << std::wstring((kBytesPerLine - count) * 2, L' ');
        }
        line << L"  ";
        for (size_t i = 0; i < count; ++i) {
            const uint8_t ch = data[row + i];
            line << static_cast<wchar_t>((ch >= 0x20 && ch <= 0x7E) ? ch : '.');
        }
        PrintRegisterLine(line.str());
    }
}

bool Debugger::DisplayType(const std::wstring& typeName, uint64_t address, size_t depth) const {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (!symbolsInitialized_) {
        const_cast<Debugger*>(this)->InitializeSymbolEngine();
    }
    if (!symbolsInitialized_) {
        std::wcout << L"Symbol engine is not initialized.\n";
        return false;
    }

    depth = std::max<size_t>(1, std::min<size_t>(depth, 8));
    std::wstring query = TrimWhitespace(typeName);
    if (query.empty()) {
        std::wcout << L"Usage: dt <type> <address|symbol|module+offset> [depth]\n";
        return false;
    }

    ULONG64 moduleBase = 0;
    const size_t bang = query.find(L'!');
    if (bang != std::wstring::npos) {
        const std::wstring moduleToken = query.substr(0, bang);
        query = query.substr(bang + 1);
        std::vector<ModuleRecord> modules;
        if (CollectModuleRecords(modules)) {
            const std::wstring wanted = ToLower(GetModuleNameFromPath(moduleToken));
            for (size_t i = 0; i < modules.size(); ++i) {
                std::wstring name = ToLower(modules[i].moduleName.empty() ? GetModuleNameFromPath(modules[i].imagePath) : modules[i].moduleName);
                if (name.size() > 4 && name.substr(name.size() - 4) == L".dll") {
                    name = name.substr(0, name.size() - 4);
                }
                std::wstring wantedName = wanted;
                if (wantedName.size() > 4 && wantedName.substr(wantedName.size() - 4) == L".dll") {
                    wantedName = wantedName.substr(0, wantedName.size() - 4);
                }
                if (name == wantedName) {
                    moduleBase = modules[i].baseAddress;
                    break;
                }
            }
        }
    }

    std::vector<BYTE> symBuffer(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t));
    PSYMBOL_INFOW sym = reinterpret_cast<PSYMBOL_INFOW>(symBuffer.data());
    sym->SizeOfStruct = sizeof(SYMBOL_INFOW);
    sym->MaxNameLen = MAX_SYM_NAME;
    if (!SymGetTypeFromNameW(processHandle_, moduleBase, query.c_str(), sym)) {
        const DWORD err = GetLastError();
        std::wcout << L"Type not found: " << typeName << L" (error=" << err << L")\n";
        return false;
    }

    const ULONG typeId = sym->TypeIndex;
    const DWORD64 modBase = sym->ModBase;
    ULONG64 typeLength = 0;
    SymGetTypeInfo(processHandle_, modBase, typeId, TI_GET_LENGTH, &typeLength);

    EnsureConsoleColorEnabled();
    std::wcout << typeName << L" @ " << ToHex(address, sizeof(void*) * 2);
    if (typeLength != 0) {
        std::wcout << L" size=" << ToHex(typeLength);
    }
    std::wcout << L"\n";

    const size_t pointerSize = IsWow64TargetProcess(processHandle_) ? 4 : sizeof(void*);

    const auto typeNameFromId = [&](ULONG id) -> std::wstring {
        WCHAR* rawName = nullptr;
        std::wstring out = L"?";
        if (SymGetTypeInfo(processHandle_, modBase, id, TI_GET_SYMNAME, &rawName) && rawName != nullptr) {
            out = rawName;
            LocalFree(rawName);
        } else {
            DWORD tag = 0;
            if (SymGetTypeInfo(processHandle_, modBase, id, TI_GET_SYMTAG, &tag)) {
                switch (tag) {
                    case kSymTagPointerType: out = L"ptr"; break;
                    case kSymTagArrayType: out = L"array"; break;
                    case kSymTagBaseType: out = L"base"; break;
                    case kSymTagUDT: out = L"udt"; break;
                    default: out = L"type"; break;
                }
            }
        }
        return out;
    };

    const std::function<std::wstring(ULONG, uint64_t)> readValue = [&](ULONG fieldType, uint64_t fieldAddress) -> std::wstring {
        DWORD tag = 0;
        ULONG64 len = 0;
        SymGetTypeInfo(processHandle_, modBase, fieldType, TI_GET_SYMTAG, &tag);
        SymGetTypeInfo(processHandle_, modBase, fieldType, TI_GET_LENGTH, &len);
        if (tag == kSymTagPointerType) {
            len = pointerSize;
        }
        if (len != 1 && len != 2 && len != 4 && len != 8) {
            return L"";
        }
        uint64_t value = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(fieldAddress), &value, static_cast<SIZE_T>(len), &read) ||
            read != static_cast<SIZE_T>(len)) {
            return L"<unreadable>";
        }
        if (tag == kSymTagPointerType) {
            const std::wstring symText = ResolveSymbol(value);
            return ToHex(value, pointerSize * 2) + (symText.empty() ? L"" : L" " + symText);
        }
        DWORD baseType = 0;
        if (tag == kSymTagBaseType && SymGetTypeInfo(processHandle_, modBase, fieldType, TI_GET_BASETYPE, &baseType)) {
            if (baseType == kBasicTypeChar || baseType == kBasicTypeWChar) {
                std::wstringstream ss;
                ss << ToHex(value, static_cast<size_t>(len) * 2);
                if (value >= 0x20 && value <= 0x7E) {
                    ss << L" '" << static_cast<wchar_t>(value) << L"'";
                }
                return ss.str();
            }
            if (baseType == kBasicTypeBool) {
                return value == 0 ? L"false" : L"true";
            }
        }
        return ToHex(value, static_cast<size_t>(len) * 2);
    };

    std::function<void(ULONG, uint64_t, size_t, size_t)> dumpType;
    dumpType = [&](ULONG currentType, uint64_t baseAddress, size_t remainingDepth, size_t indent) {
        DWORD childrenCount = 0;
        if (!SymGetTypeInfo(processHandle_, modBase, currentType, TI_GET_CHILDRENCOUNT, &childrenCount) || childrenCount == 0) {
            return;
        }
        const size_t allocSize = sizeof(TI_FINDCHILDREN_PARAMS) + (childrenCount > 0 ? (childrenCount - 1) * sizeof(ULONG) : 0);
        std::vector<BYTE> childStorage(allocSize, 0);
        TI_FINDCHILDREN_PARAMS* children = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(childStorage.data());
        children->Count = childrenCount;
        children->Start = 0;
        if (!SymGetTypeInfo(processHandle_, modBase, currentType, TI_FINDCHILDREN, children)) {
            return;
        }

        for (DWORD i = 0; i < childrenCount; ++i) {
            const ULONG childId = children->ChildId[i];
            DWORD childTag = 0;
            if (!SymGetTypeInfo(processHandle_, modBase, childId, TI_GET_SYMTAG, &childTag) || childTag != kSymTagData) {
                continue;
            }
            ULONG offset = 0;
            ULONG fieldType = 0;
            SymGetTypeInfo(processHandle_, modBase, childId, TI_GET_OFFSET, &offset);
            SymGetTypeInfo(processHandle_, modBase, childId, TI_GET_TYPEID, &fieldType);

            WCHAR* rawName = nullptr;
            std::wstring fieldName = L"?";
            if (SymGetTypeInfo(processHandle_, modBase, childId, TI_GET_SYMNAME, &rawName) && rawName != nullptr) {
                fieldName = rawName;
                LocalFree(rawName);
            }

            const uint64_t fieldAddress = baseAddress + offset;
            DWORD fieldTag = 0;
            ULONG pointeeType = 0;
            SymGetTypeInfo(processHandle_, modBase, fieldType, TI_GET_SYMTAG, &fieldTag);
            if (fieldTag == kSymTagPointerType) {
                SymGetTypeInfo(processHandle_, modBase, fieldType, TI_GET_TYPEID, &pointeeType);
            }

            std::wstringstream line;
            line << std::wstring(indent, L' ')
                 << L"+" << ToHex(offset, 4)
                 << L" " << fieldName
                 << L" : " << typeNameFromId(fieldType);
            const std::wstring value = readValue(fieldType, fieldAddress);
            if (!value.empty()) {
                line << L" = " << value;
            }
            std::wcout << line.str() << L"\n";

            if (remainingDepth <= 1) {
                continue;
            }
            if (fieldTag == kSymTagUDT) {
                dumpType(fieldType, fieldAddress, remainingDepth - 1, indent + 2);
            } else if (fieldTag == kSymTagPointerType && pointeeType != 0) {
                DWORD pointeeTag = 0;
                if (SymGetTypeInfo(processHandle_, modBase, pointeeType, TI_GET_SYMTAG, &pointeeTag) && pointeeTag == kSymTagUDT) {
                    uint64_t ptrValue = 0;
                    SIZE_T read = 0;
                    if (ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(fieldAddress), &ptrValue, pointerSize, &read) &&
                        read == pointerSize && ptrValue != 0) {
                        std::wcout << std::wstring(indent + 2, L' ') << L"-> " << typeNameFromId(pointeeType)
                                   << L" @ " << ToHex(ptrValue, pointerSize * 2) << L"\n";
                        dumpType(pointeeType, ptrValue, remainingDepth - 1, indent + 4);
                    }
                }
            }
        }
    };

    dumpType(typeId, address, depth, 0);
    return true;
}

void Debugger::PrintCallStack(size_t maxFrames, bool showParams, bool verbose) const {
    (void)showParams;
    (void)verbose;
    PrintStackInfo(maxFrames == 0 ? 32 : maxFrames);
}

bool Debugger::CollectStackUiRows(size_t maxFrames, std::vector<StackUiRow>& rows, uint64_t& stackPointer) const {
    rows.clear();
    stackPointer = 0;
    if (!EnsurePaused()) {
        return false;
    }

    const auto addRow = [&](size_t index, uint64_t address, const std::wstring& value, const std::wstring& symbol, size_t addressWidth) -> void {
        StackUiRow row;
        std::wstringstream idx;
        idx << L"#" << index;
        row.index = idx.str();
        row.addressValue = address;
        row.address = HexNoPrefix(address, addressWidth);
        row.value = value;
        row.symbol = symbol;
        rows.push_back(row);
    };

    const auto readMemory = [&](uint64_t address, void* buffer, size_t size) -> bool {
        SIZE_T read = 0;
        return ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), buffer, size, &read) && read == size;
    };

    const auto readPtr = [&](uint64_t address, size_t ptrSize, uint64_t& value) -> bool {
        value = 0;
        if (ptrSize == 4) {
            uint32_t v = 0;
            if (!readMemory(address, &v, sizeof(v))) {
                return false;
            }
            value = v;
            return true;
        }
        return readMemory(address, &value, sizeof(value));
    };

    const auto isReadableProtect = [](DWORD protect) -> bool {
        if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) {
            return false;
        }
        const DWORD baseProtect = protect & 0xff;
        return baseProtect == PAGE_READONLY ||
            baseProtect == PAGE_READWRITE ||
            baseProtect == PAGE_WRITECOPY ||
            baseProtect == PAGE_EXECUTE_READ ||
            baseProtect == PAGE_EXECUTE_READWRITE ||
            baseProtect == PAGE_EXECUTE_WRITECOPY;
    };

    const auto findVirtualStackBounds = [&](uint64_t sp, uint64_t& begin, uint64_t& end) -> bool {
        begin = sp;
        end = sp;
        MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
        if (!VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(sp), &mbi, sizeof(mbi))) {
            return false;
        }
        const uint64_t allocationBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
        begin = allocationBase;
        end = reinterpret_cast<uint64_t>(mbi.BaseAddress) + static_cast<uint64_t>(mbi.RegionSize);
        for (;;) {
            MEMORY_BASIC_INFORMATION next = MEMORY_BASIC_INFORMATION();
            if (!VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(end), &next, sizeof(next))) {
                break;
            }
            if (reinterpret_cast<uint64_t>(next.BaseAddress) != end ||
                reinterpret_cast<uint64_t>(next.AllocationBase) != allocationBase) {
                break;
            }
            const uint64_t nextEnd = reinterpret_cast<uint64_t>(next.BaseAddress) + static_cast<uint64_t>(next.RegionSize);
            if (nextEnd <= end) {
                break;
            }
            end = nextEnd;
        }
        return end > begin;
    };

    const auto findTebStackBounds = [&](bool wow64, uint64_t sp, size_t ptrSize, uint64_t& begin, uint64_t& end) -> bool {
        begin = 0;
        end = 0;
        uint64_t teb = 0;
        if (!QueryThreadTeb(stopState_.threadId, teb) || teb == 0) {
            return false;
        }
#if defined(_M_X64)
        if (wow64) {
            uint32_t teb32 = 0;
            if (!readMemory(teb, &teb32, sizeof(teb32)) || teb32 == 0) {
                return false;
            }
            teb = static_cast<uint64_t>(teb32);
            ptrSize = 4;
        }
#else
        (void)wow64;
#endif
        const uint64_t stackBaseOffset = ptrSize == 4 ? 0x04 : 0x08;
        const uint64_t stackLimitOffset = ptrSize == 4 ? 0x08 : 0x10;
        uint64_t stackBase = 0;
        uint64_t stackLimit = 0;
        if (!readPtr(teb + stackBaseOffset, ptrSize, stackBase) ||
            !readPtr(teb + stackLimitOffset, ptrSize, stackLimit) ||
            stackLimit == 0 ||
            stackBase <= stackLimit ||
            sp < stackLimit ||
            sp >= stackBase) {
            return false;
        }
        begin = stackLimit;
        end = stackBase;
        return true;
    };

    const auto findStackBounds = [&](bool wow64, uint64_t sp, size_t ptrSize, uint64_t& begin, uint64_t& end) -> bool {
        if (findTebStackBounds(wow64, sp, ptrSize, begin, end)) {
            return true;
        }
        return findVirtualStackBounds(sp, begin, end);
    };

    std::vector<ModuleRecord> modules;
    CollectModuleRecords(modules);
    const auto resolveStackValue = [&](uint64_t value) -> std::wstring {
        if (value == 0) {
            return L"";
        }
        for (size_t i = 0; i < modules.size(); ++i) {
            const uint64_t begin = modules[i].baseAddress;
            const uint64_t end = begin + static_cast<uint64_t>(modules[i].size);
            if (value >= begin && value < end) {
                return ResolveSymbol(value);
            }
        }
        return L"";
    };

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (!CaptureWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            std::wcout << L"Wow64GetThreadContext failed for TID " << stopState_.threadId << L".\n";
            return false;
        }
        const uint32_t esp = wowCtx.Esp;
        stackPointer = static_cast<uint64_t>(esp);
        uint64_t stackBegin = 0;
        uint64_t stackEnd = 0;
        if (!findStackBounds(true, stackPointer, 4, stackBegin, stackEnd)) {
            return false;
        }
        size_t maxEntries = stackEnd > stackBegin ? static_cast<size_t>((stackEnd - stackBegin) / sizeof(uint32_t)) : 0;
        if (maxFrames != 0) {
            maxEntries = std::min<size_t>(maxEntries, maxFrames);
        }
        for (size_t i = 0; i < maxEntries; ++i) {
            const uint64_t slotAddress64 = stackBegin + static_cast<uint64_t>(i * sizeof(uint32_t));
            const uint32_t slotAddress = static_cast<uint32_t>(slotAddress64);
            uint32_t slotValue = 0;
            SIZE_T read = 0;
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(slotAddress64),
                    &slotValue,
                    sizeof(slotValue),
                    &read) ||
                read != sizeof(slotValue)) {
                addRow(i, slotAddress64, L"<unreadable>", L"", 8);
                continue;
            }
            const uint64_t value64 = static_cast<uint64_t>(slotValue);
            addRow(i, slotAddress64, HexNoPrefix(value64, 8), resolveStackValue(value64), 8);
        }
        return true;
    }

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        ctx = stopState_.context;
    }
    const uint64_t rsp = ctx.Rsp;
    stackPointer = rsp;
    uint64_t stackBegin = 0;
    uint64_t stackEnd = 0;
        if (!findStackBounds(false, stackPointer, sizeof(void*), stackBegin, stackEnd)) {
        return false;
    }
    size_t maxEntries = stackEnd > stackBegin ? static_cast<size_t>((stackEnd - stackBegin) / sizeof(uint64_t)) : 0;
    if (maxFrames != 0) {
        maxEntries = std::min<size_t>(maxEntries, maxFrames);
    }
    for (size_t i = 0; i < maxEntries; ++i) {
        const uint64_t slotAddress = stackBegin + static_cast<uint64_t>(i * sizeof(uint64_t));
        uint64_t slotValue = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(slotAddress),
                &slotValue,
                sizeof(slotValue),
                &read) ||
            read != sizeof(slotValue)) {
            addRow(i, slotAddress, L"<unreadable>", L"", 16);
            continue;
        }
        addRow(i, slotAddress, HexNoPrefix(slotValue, 16), resolveStackValue(slotValue), 16);
    }
    return true;
#else
    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        ctx = stopState_.context;
    }
    const uint32_t esp = ctx.Esp;
    stackPointer = static_cast<uint64_t>(esp);
    uint64_t stackBegin = 0;
    uint64_t stackEnd = 0;
    if (!findStackBounds(false, stackPointer, sizeof(void*), stackBegin, stackEnd)) {
        return false;
    }
    size_t maxEntries = stackEnd > stackBegin ? static_cast<size_t>((stackEnd - stackBegin) / sizeof(uint32_t)) : 0;
    if (maxFrames != 0) {
        maxEntries = std::min<size_t>(maxEntries, maxFrames);
    }
    for (size_t i = 0; i < maxEntries; ++i) {
        const uint64_t slotAddress64 = stackBegin + static_cast<uint64_t>(i * sizeof(uint32_t));
        const uint32_t slotAddress = static_cast<uint32_t>(slotAddress64);
        uint32_t slotValue = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(slotAddress64),
                &slotValue,
                sizeof(slotValue),
                &read) ||
            read != sizeof(slotValue)) {
            addRow(i, slotAddress64, L"<unreadable>", L"", 8);
            continue;
        }
        const uint64_t value64 = static_cast<uint64_t>(slotValue);
        addRow(i, slotAddress64, HexNoPrefix(value64, 8), resolveStackValue(value64), 8);
    }
    return true;
#endif
}

void Debugger::PrintThreadStackInfo(DWORD threadId, size_t maxFrames, bool showHeader) const {
    EnsureConsoleColorEnabled();
    if (showHeader) {
        std::wstringstream header;
        header << L"--- Stack (TID=" << threadId << L") ---";
        PrintStackLine(header.str());
    }
    if (!EnsurePaused()) {
        return;
    }
#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (!CaptureWow64ThreadContextById(threadId, wowCtx)) {
            std::wcout << L"Wow64GetThreadContext failed for TID " << threadId << L".\n";
            return;
        }

        const uint32_t esp = wowCtx.Esp;
        PrintStackLine(L"ESP=" + HexNoPrefix(static_cast<uint64_t>(esp), 8));
        if (maxFrames == 0) {
            return;
        }

        const size_t maxEntries = std::min<size_t>(maxFrames, 1024);
        for (size_t i = 0; i < maxEntries; ++i) {
            const uint32_t slotAddress = esp + static_cast<uint32_t>(i * sizeof(uint32_t));
            uint32_t slotValue = 0;
            SIZE_T read = 0;
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(static_cast<uint64_t>(slotAddress)),
                    &slotValue,
                    sizeof(slotValue),
                    &read) ||
                read != sizeof(slotValue)) {
                std::wstringstream line;
                line << L"#" << i << L" " << HexNoPrefix(static_cast<uint64_t>(slotAddress), 8)
                     << L" : <unreadable>";
                if (i == 0) {
                    PrintStackTopLine(line.str());
                } else {
                    PrintStackLine(line.str());
                }
                continue;
            }

            const uint64_t value64 = static_cast<uint64_t>(slotValue);
            std::wstringstream line;
            line << L"#" << i << L" " << HexNoPrefix(static_cast<uint64_t>(slotAddress), 8)
                 << L" : " << HexNoPrefix(value64, 8) << L"  " << ResolveSymbol(value64);
            if (i == 0) {
                PrintStackTopLine(line.str());
            } else {
                PrintStackLine(line.str());
            }
        }
        return;
    }
#endif

    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!thread) {
        std::wcout << L"OpenThread failed for TID " << threadId << L".\n";
        return;
    }

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(threadId, ctx)) {
        CloseHandle(thread);
        std::wcout << L"GetThreadContext failed for TID " << threadId << L".\n";
        return;
    }

#if defined(_M_X64)
    const uint64_t rsp = ctx.Rsp;
    PrintStackLine(L"RSP=" + HexNoPrefix(rsp, 16));
    if (maxFrames == 0) {
        CloseHandle(thread);
        return;
    }

    const size_t maxEntries = std::min<size_t>(maxFrames, 512);
    for (size_t i = 0; i < maxEntries; ++i) {
        const uint64_t slotAddress = rsp + static_cast<uint64_t>(i * sizeof(uint64_t));
        uint64_t slotValue = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(slotAddress),
                &slotValue,
                sizeof(slotValue),
                &read) ||
            read != sizeof(slotValue)) {
            std::wstringstream line;
            line << L"#" << i << L" " << HexNoPrefix(slotAddress, 16) << L" : <unreadable>";
            if (i == 0) {
                PrintStackTopLine(line.str());
            } else {
                PrintStackLine(line.str());
            }
            continue;
        }

        std::wstringstream line;
        line << L"#" << i << L" " << HexNoPrefix(slotAddress, 16)
             << L" : " << HexNoPrefix(slotValue, 16) << L"  " << ResolveSymbol(slotValue);
        if (i == 0) {
            PrintStackTopLine(line.str());
        } else {
            PrintStackLine(line.str());
        }
    }

    CloseHandle(thread);
    return;
#else
    STACKFRAME64 frame = STACKFRAME64();
    DWORD machineType = IMAGE_FILE_MACHINE_I386;
    frame.AddrPC.Offset = ctx.Eip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = ctx.Ebp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = ctx.Esp;
    frame.AddrStack.Mode = AddrModeFlat;

    auto printFrame = [&](size_t index, uint64_t address) {
        std::wstringstream out;
        out << L"#" << index << L" " << HexNoPrefix(address, sizeof(void*) * 2) << L" " << ResolveSymbol(address);
        std::wstring filePath;
        uint32_t sourceLine = 0;
        uint32_t displacement = 0;
        if (ResolveSourceLocation(address, filePath, sourceLine, displacement)) {
            out << L"  [" << filePath << L":" << sourceLine;
            if (displacement != 0) {
                out << L" +" << displacement;
            }
            out << L"]";
        }
        PrintStackLine(out.str());
    };

    if (maxFrames > 0) {
        uint64_t previousAddress = ctx.Eip;
        printFrame(0, previousAddress);

        size_t frameIndex = 1;
        while (frameIndex < maxFrames) {
            if (!StackWalk64(machineType, processHandle_, thread, &frame, &ctx, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
                break;
            }
            if (frame.AddrPC.Offset == 0) {
                break;
            }
            if (frame.AddrPC.Offset == previousAddress) {
                continue;
            }
            printFrame(frameIndex, frame.AddrPC.Offset);
            previousAddress = frame.AddrPC.Offset;
            ++frameIndex;
        }
    }

    CloseHandle(thread);
#endif
}

void Debugger::PrintStackInfo(size_t maxFrames) const {
    if (!EnsurePaused()) {
        return;
    }
    if (!stopState_.valid) {
        std::wcout << L"No active stop state.\n";
        return;
    }
    PrintStackLine(L"--- Stack ---");
    PrintThreadStackInfo(stopState_.threadId, maxFrames, false);
}

bool Debugger::ExamineSymbols(const std::wstring& pattern) const {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (!symbolsInitialized_) {
        const_cast<Debugger*>(this)->InitializeSymbolEngine();
    }
    if (!symbolsInitialized_) {
        std::wcout << L"Symbol engine is not initialized.\n";
        return false;
    }
    const std::wstring mask = TrimWhitespace(pattern).empty() ? L"*" : TrimWhitespace(pattern);
    EnsureConsoleColorEnabled();
    SymbolSearchContext context;
    if (!SymEnumSymbolsW(processHandle_, 0, mask.c_str(), &PrintSymbolCallback, &context)) {
        const DWORD err = GetLastError();
        if (context.count == 0) {
            std::wcout << L"No symbols matched: " << mask << L" (error=" << err << L")\n";
            return false;
        }
    }
    std::wcout << L"Symbols: " << context.count << L"\n";
    return true;
}

bool Debugger::GoUp() {
    if (!EnsurePaused()) {
        return false;
    }
    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        std::wcout << L"GetThreadContext failed.\n";
        return false;
    }
    const uint64_t sp = GetStackPointer(ctx);
    const size_t pointerSize = DetermineDisassemblyModeBits(processHandle_) == 32 ? 4 : 8;
    uint64_t returnAddress = 0;
    SIZE_T read = 0;
    if (pointerSize == 4) {
        uint32_t value32 = 0;
        if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(sp), &value32, sizeof(value32), &read) || read != sizeof(value32)) {
            std::wcout << L"Unable to read return address from stack.\n";
            return false;
        }
        returnAddress = value32;
    } else {
        if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(sp), &returnAddress, sizeof(returnAddress), &read) || read != sizeof(returnAddress)) {
            std::wcout << L"Unable to read return address from stack.\n";
            return false;
        }
    }
    const int tempId = AddSoftwareBreakpoint(returnAddress);
    if (tempId < 0) {
        return false;
    }
    stepOverBreakpointId_ = tempId;
    std::wcout << L"Go up to " << ToHex(returnAddress, pointerSize * 2) << L".\n";
    return ContinueExecution();
}

bool Debugger::TraceWatch(uint64_t maxSteps) {
    if (!EnsurePaused()) {
        return false;
    }
    if (maxSteps == 0) {
        maxSteps = 1000;
    }
    const DWORD startTick = GetTickCount();
    uint64_t steps = 0;
    for (; steps < maxSteps && active_; ++steps) {
        if (!SingleStep()) {
            return false;
        }
        if (!stopState_.valid) {
            break;
        }
    }
    const DWORD elapsed = GetTickCount() - startTick;
    std::wcout << L"wt: steps=" << steps << L" elapsed_ms=" << elapsed << L"\n";
    return true;
}

void Debugger::PrintSehChain() const {
    if (!EnsurePaused()) {
        return;
    }

    auto ntQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    if (!ntQueryInformationThread) {
        std::wcout << L"NtQueryInformationThread unavailable.\n";
        return;
    }

    HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, stopState_.threadId);
    if (!thread) {
        std::wcout << L"OpenThread failed.\n";
        return;
    }

    THREAD_BASIC_INFORMATION_LOCAL tbi = THREAD_BASIC_INFORMATION_LOCAL();
    NTSTATUS status = ntQueryInformationThread(thread, static_cast<THREADINFOCLASS>(0), &tbi, sizeof(tbi), nullptr);
    CloseHandle(thread);
    if (!NT_SUCCESS(status)) {
        std::wcout << L"NtQueryInformationThread failed: 0x" << std::hex << status << std::dec << L"\n";
        return;
    }

    std::wcout << L"--- SEH Chain ---\n";
    std::wcout << L"TEB: " << ToHex(reinterpret_cast<uint64_t>(tbi.TebBaseAddress)) << L"\n";

#if defined(_M_X64)
    uint64_t exceptionList = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, tbi.TebBaseAddress, &exceptionList, sizeof(exceptionList), &read) || read != sizeof(exceptionList)) {
        std::wcout << L"ReadProcessMemory(TEB.ExceptionList) failed.\n";
        return;
    }
    if (exceptionList == std::numeric_limits<uint64_t>::max()) {
        std::wcout << L"Native x64 uses table-based unwind; linked-list SEH is not active (-1 head).\n";
        return;
    }
    struct SehRecord64 {
        uint64_t next;
        uint64_t handler;
    };
    uint64_t node = exceptionList;
    for (size_t i = 0; i < 32 && node != 0 && node != std::numeric_limits<uint64_t>::max(); ++i) {
        SehRecord64 rec = SehRecord64();
        if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(node), &rec, sizeof(rec), &read) || read != sizeof(rec)) {
            break;
        }
        std::wcout << L"#" << i << L" node=" << ToHex(node) << L" handler=" << ToHex(rec.handler) << L"\n";
        node = rec.next;
    }
#else
    uint32_t exceptionList = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, tbi.TebBaseAddress, &exceptionList, sizeof(exceptionList), &read) || read != sizeof(exceptionList)) {
        std::wcout << L"ReadProcessMemory(TEB.ExceptionList) failed.\n";
        return;
    }
    struct SehRecord32 {
        uint32_t next;
        uint32_t handler;
    };
    uint32_t node = exceptionList;
    for (size_t i = 0; i < 64 && node != 0 && node != 0xFFFFFFFF; ++i) {
        SehRecord32 rec = SehRecord32();
        if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(node), &rec, sizeof(rec), &read) || read != sizeof(rec)) {
            break;
        }
        std::wcout << L"#" << i << L" node=" << ToHex(node) << L" handler=" << ToHex(rec.handler) << L"\n";
        node = rec.next;
    }
#endif
}

void Debugger::PrintHandleInfo(size_t maxHandles) const {
    if (!EnsureDebuggee()) {
        return;
    }

    auto ntQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!ntQuerySystemInformation) {
        std::wcout << L"NtQuerySystemInformation unavailable.\n";
        return;
    }

    ULONG length = 1 << 20;
    std::vector<uint8_t> buffer(length);
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH_VALUE;
    while (status == STATUS_INFO_LENGTH_MISMATCH_VALUE) {
        status = ntQuerySystemInformation(SystemExtendedHandleInformationClass, buffer.data(), length, &length);
        if (status == STATUS_INFO_LENGTH_MISMATCH_VALUE) {
            buffer.resize(length * 2);
            length = static_cast<ULONG>(buffer.size());
        }
    }
    if (!NT_SUCCESS(status)) {
        std::wcout << L"NtQuerySystemInformation failed: 0x" << std::hex << status << std::dec << L"\n";
        return;
    }

    auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX_LOCAL*>(buffer.data());
    std::vector<const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL*> selected;
    selected.reserve(512);
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& entry = info->Handles[i];
        if (entry.UniqueProcessId == processId_) {
            selected.push_back(&entry);
        }
    }

    std::sort(selected.begin(), selected.end(),
              [](const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL* a, const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL* b) -> bool {
                  return a->HandleValue < b->HandleValue;
              });

    std::wcout << L"--- Handles ---\n";
    std::wcout << L"Total handles in process: " << selected.size() << L"\n";
    const size_t count = (maxHandles == 0) ? selected.size() : std::min(selected.size(), maxHandles);
    for (size_t i = 0; i < count; ++i) {
        const auto* e = selected[i];
        std::wcout << L"Handle=" << ToHex(e->HandleValue)
                   << L" TypeIdx=" << e->ObjectTypeIndex
                   << L" Access=" << ToHex(e->GrantedAccess)
                   << L" Attr=" << ToHex(e->HandleAttributes) << L"\n";
    }
    if (maxHandles != 0 && selected.size() > count) {
        std::wcout << L"... truncated, use handles <max>\n";
    }
}

void Debugger::PrintMemoryStrings(size_t minLength, size_t maxMatches) const {
    if (!EnsureDebuggee()) {
        return;
    }

    std::wcout << L"--- Memory Strings ---\n";
    const uint64_t maxAddress =
#if defined(_M_X64)
        0x00007FFFFFFFFFFFULL;
#else
        0x7FFEFFFFu;
#endif

    uint64_t address = 0;
    size_t matches = 0;
    const size_t maxScanBytes = 256ull * 1024ull * 1024ull;
    size_t scannedBytes = 0;

    while (address < maxAddress && matches < maxMatches && scannedBytes < maxScanBytes) {
        MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
        if (!VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
            break;
        }

        const uint64_t regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t regionSize = static_cast<uint64_t>(mbi.RegionSize);
        address = regionBase + regionSize;

        if (mbi.State != MEM_COMMIT) {
            continue;
        }
        if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS)) {
            continue;
        }
        if (!IsReadableProtection(mbi.Protect)) {
            continue;
        }

        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(regionSize, 1ull << 20));
        std::vector<uint8_t> data(chunk);
        SIZE_T read = 0;
        if (!ReadProcessMemory(processHandle_, mbi.BaseAddress, data.data(), chunk, &read) || read == 0) {
            continue;
        }
        scannedBytes += read;

        size_t i = 0;
        while (i < read && matches < maxMatches) {
            size_t start = i;
            while (i < read && data[i] >= 0x20 && data[i] <= 0x7E) {
                ++i;
            }
            if (i - start >= minLength) {
                std::string s(reinterpret_cast<char*>(data.data() + start), i - start);
                std::wcout << ToHex(regionBase + start) << L" A \"" << std::wstring(s.begin(), s.end()) << L"\"\n";
                ++matches;
            }
            ++i;
        }

        i = 0;
        while (i + 1 < read && matches < maxMatches) {
            size_t start = i;
            while (i + 1 < read) {
                const uint16_t ch = static_cast<uint16_t>(data[i] | (data[i + 1] << 8));
                if (ch < 0x20 || ch > 0x7E) {
                    break;
                }
                i += 2;
            }
            if ((i - start) / 2 >= minLength) {
                std::wstring s;
                for (size_t j = start; j < i; j += 2) {
                    const uint16_t ch = static_cast<uint16_t>(data[j] | (data[j + 1] << 8));
                    s.push_back(static_cast<wchar_t>(ch));
                }
                std::wcout << ToHex(regionBase + start) << L" W \"" << s << L"\"\n";
                ++matches;
            }
            i += 2;
        }
    }
    std::wcout << L"Matches: " << matches << L"\n";
}

bool Debugger::SearchMemory(const std::vector<std::wstring>& tokens) const {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (tokens.size() < 2) {
        PrintMemoryStrings();
        return true;
    }

    const auto printSearchLine = [](const std::wstring& line) -> void {
        std::wcout << line << L"\n";
    };
    const auto parseByteToken = [&](const std::wstring& text, uint8_t& value) -> bool {
        uint64_t tmp = 0;
        if (!ParseUInt64(text, tmp) || tmp > 0xFF) {
            return false;
        }
        value = static_cast<uint8_t>(tmp);
        return true;
    };
    const auto encodeUtf16 = [](const std::wstring& text) -> std::vector<uint8_t> {
        std::vector<uint8_t> bytes;
        bytes.reserve(text.size() * 2);
        for (size_t i = 0; i < text.size(); ++i) {
            const uint16_t ch = static_cast<uint16_t>(text[i]);
            bytes.push_back(static_cast<uint8_t>(ch & 0xFF));
            bytes.push_back(static_cast<uint8_t>((ch >> 8) & 0xFF));
        }
        return bytes;
    };
    const auto bytesToHex = [](const std::vector<uint8_t>& bytes) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i != 0) {
                ss << L' ';
            }
            ss << std::setw(2) << static_cast<unsigned>(bytes[i]);
        }
        return ss.str();
    };
    const auto searchPattern = [&](const std::vector<uint8_t>& pattern, const std::wstring& label, size_t maxMatches) -> bool {
        if (pattern.empty()) {
            std::wcout << L"Search pattern cannot be empty.\n";
            return false;
        }

        std::wcout << L"--- Memory Search " << label << L" ---\n";
        const uint64_t maxAddress =
#if defined(_M_X64)
            0x00007FFFFFFFFFFFULL;
#else
            0x7FFEFFFFu;
#endif

        uint64_t address = 0;
        size_t matches = 0;
        const size_t maxScanBytes = 256ull * 1024ull * 1024ull;
        size_t scannedBytes = 0;

        while (address < maxAddress && matches < maxMatches && scannedBytes < maxScanBytes) {
            MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
            if (!VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                break;
            }

            const uint64_t regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            const uint64_t regionSize = static_cast<uint64_t>(mbi.RegionSize);
            address = regionBase + regionSize;

            if (mbi.State != MEM_COMMIT) {
                continue;
            }
            if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS)) {
                continue;
            }
            if (!IsReadableProtection(mbi.Protect)) {
                continue;
            }

            const size_t chunk = static_cast<size_t>(std::min<uint64_t>(regionSize, 1ull << 20));
            std::vector<uint8_t> data(chunk);
            SIZE_T read = 0;
            if (!ReadProcessMemory(processHandle_, mbi.BaseAddress, data.data(), chunk, &read) || read < pattern.size()) {
                scannedBytes += static_cast<size_t>(read);
                continue;
            }
            scannedBytes += static_cast<size_t>(read);

            size_t pos = 0;
            while (pos + pattern.size() <= static_cast<size_t>(read) && matches < maxMatches) {
                auto begin = data.begin() + static_cast<std::ptrdiff_t>(pos);
                auto end = data.begin() + static_cast<std::ptrdiff_t>(read);
                auto found = std::search(begin, end, pattern.begin(), pattern.end());
                if (found == end) {
                    break;
                }
                const size_t offset = static_cast<size_t>(found - data.begin());
                std::wstringstream line;
                line << ToHex(regionBase + offset) << L" " << label;
                printSearchLine(line.str());
                ++matches;
                pos = offset + 1;
            }
        }
        std::wcout << L"Matches: " << matches << L"\n";
        return true;
    };

    const std::wstring mode = ToLower(tokens[1]);
    if (!mode.empty() && mode[0] == L'-') {
        if (mode == L"-a" || mode == L"-u") {
            if (tokens.size() < 3) {
                std::wcout << L"Usage: s " << mode << L" <text>\n";
                return false;
            }
            const std::wstring text = JoinTokens(tokens, 2);
            if (mode == L"-a") {
                std::vector<uint8_t> pattern;
                pattern.reserve(text.size());
                for (size_t i = 0; i < text.size(); ++i) {
                    pattern.push_back(static_cast<uint8_t>(text[i] & 0xFF));
                }
                return searchPattern(pattern, L"A \"" + text + L"\"", 200);
            }
            return searchPattern(encodeUtf16(text), L"W \"" + text + L"\"", 200);
        }

        if (mode == L"-b") {
            if (tokens.size() < 3) {
                std::wcout << L"Usage: s -b <byte...>\n";
                return false;
            }
            std::vector<uint8_t> pattern;
            for (size_t i = 2; i < tokens.size(); ++i) {
                uint8_t value = 0;
                if (!parseByteToken(tokens[i], value)) {
                    std::wcout << L"Invalid byte token: " << tokens[i] << L"\n";
                    return false;
                }
                pattern.push_back(value);
            }
            return searchPattern(pattern, L"B " + bytesToHex(pattern), 200);
        }

        if (mode == L"-d" || mode == L"-q") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: s " << mode << L" <value>\n";
                return false;
            }
            uint64_t value = 0;
            if (!ParseUInt64(tokens[2], value)) {
                std::wcout << L"Invalid numeric value.\n";
                return false;
            }
            const size_t size = (mode == L"-d") ? 4 : 8;
            std::vector<uint8_t> pattern(size);
            for (size_t i = 0; i < size; ++i) {
                pattern[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
            }
            return searchPattern(pattern, (mode == L"-d" ? L"D " : L"Q ") + ToHex(value, size * 2), 200);
        }

        std::wcout << L"Usage: s -a|-u <text> | -b <byte...> | -d <value> | -q <value>\n";
        return false;
    }

    if (tokens.size() == 2 || tokens.size() == 3) {
        uint64_t minLen = 0;
        uint64_t maxMatches = 200;
        if (!ParseUInt64(tokens[1], minLen) || minLen == 0) {
            std::wcout << L"Invalid search length.\n";
            return false;
        }
        if (tokens.size() == 3 && (!ParseUInt64(tokens[2], maxMatches) || maxMatches == 0)) {
            std::wcout << L"Invalid match count.\n";
            return false;
        }
        PrintMemoryStrings(static_cast<size_t>(minLen), static_cast<size_t>(maxMatches));
        return true;
    }

    std::wcout << L"Usage: s -a|-u <text> | -b <byte...> | -d <value> | -q <value> | s <min_len> [max]\n";
    return false;
}

void Debugger::PrintMemoryBinary(uint64_t address, size_t size) const {
    if (!EnsureDebuggee()) {
        return;
    }
    if (size == 0) {
        std::wcout << L"Size must be greater than zero.\n";
        return;
    }

    const size_t kMaxBytes = 4096;
    if (size > kMaxBytes) {
        std::wcout << L"Requested size too large, capping to " << kMaxBytes << L" bytes.\n";
        size = kMaxBytes;
    }

    std::vector<uint8_t> data(size);
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), data.data(), size, &read) || read == 0) {
        std::wcout << L"ReadProcessMemory failed at " << ToHex(address) << L".\n";
        return;
    }

    std::wcout << L"--- Memory Binary ---\n";
    std::wcout << L"Base: " << ToHex(address) << L"  Bytes: " << read << L"\n";

    const size_t kBytesPerLine = 8;
    for (size_t row = 0; row < read; row += kBytesPerLine) {
        const size_t count = std::min(kBytesPerLine, static_cast<size_t>(read - row));
        std::wcout << ToHex(address + row, sizeof(void*) * 2) << L"  ";
        for (size_t i = 0; i < count; ++i) {
            if (i != 0) {
                std::wcout << L' ';
            }
            std::wcout << ByteToBinary(data[row + i]);
        }
        std::wcout << L"\n";
    }
}

void Debugger::PrintMemoryDump(uint64_t address, size_t byteCount, size_t unitSize, size_t unitsPerLine) const {
    if (!EnsureDebuggee()) {
        return;
    }
    if (address == 0) {
        std::wcout << L"Invalid memory address.\n";
        return;
    }
    if (byteCount == 0) {
        byteCount = 16 * 16;
    }
    if (unitSize != 1 && unitSize != 2 && unitSize != 4 && unitSize != 8) {
        std::wcout << L"Invalid dump unit size.\n";
        return;
    }
    if (unitsPerLine == 0) {
        unitsPerLine = 16;
    }

    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };
    const auto printDumpLine = [](const std::wstring& line) -> void {
        std::wcout << L"\x1b[38;2;0;0;0;48;2;255;251;241m" << line << L"\x1b[0m\n";
    };

    const size_t kMaxDumpBytes = 1024 * 1024;
    if (byteCount > kMaxDumpBytes) {
        std::wcout << L"Requested size too large, capping to " << kMaxDumpBytes << L" bytes.\n";
        byteCount = kMaxDumpBytes;
    }

    std::vector<uint8_t> data(byteCount, 0);
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), data.data(), data.size(), &read) || read == 0) {
        std::wcout << L"ReadProcessMemory failed at " << ToHex(address) << L".\n";
        return;
    }

    EnsureConsoleColorEnabled();
    const size_t valueWidth = unitSize * 2;
    const size_t addressWidth = sizeof(void*) * 2;
    const size_t bytesPerLine = std::max<size_t>(unitSize, unitSize * unitsPerLine);
    const size_t dataFieldWidth = (unitsPerLine * valueWidth) + (unitsPerLine > 0 ? (unitsPerLine - 1) : 0);

    for (size_t row = 0; row < static_cast<size_t>(read); row += bytesPerLine) {
        const size_t rowBytes = std::min(bytesPerLine, static_cast<size_t>(read) - row);
        const size_t rowUnits = (rowBytes + unitSize - 1) / unitSize;
        std::wstringstream line;
        line << hexNoPrefix(address + row, addressWidth) << L"  ";
        for (size_t i = 0; i < rowUnits; ++i) {
            if (i != 0) {
                line << L' ';
            }
            uint64_t value = 0;
            const size_t unitOffset = row + i * unitSize;
            const size_t available = std::min(unitSize, static_cast<size_t>(read) - unitOffset);
            for (size_t b = 0; b < available; ++b) {
                value |= static_cast<uint64_t>(data[unitOffset + b]) << (8 * b);
            }
            line << hexNoPrefix(value, valueWidth);
        }

        const size_t currentFieldWidth = (rowUnits * valueWidth) + (rowUnits > 0 ? (rowUnits - 1) : 0);
        if (currentFieldWidth < dataFieldWidth) {
            line << std::wstring(dataFieldWidth - currentFieldWidth, L' ');
        }

        if (unitSize == 1) {
            std::wstring ascii;
            ascii.reserve(unitsPerLine);
            for (size_t i = 0; i < rowBytes; ++i) {
                const uint8_t ch = data[row + i];
                ascii.push_back((ch >= 0x20 && ch <= 0x7E) ? static_cast<wchar_t>(ch) : L'.');
            }
            if (ascii.size() < unitsPerLine) {
                ascii.append(unitsPerLine - ascii.size(), L' ');
            }
            line << L"  |" << ascii << L"|";
        } else if (unitSize == 2) {
            std::wstring unicode;
            unicode.reserve(unitsPerLine);
            for (size_t i = 0; i + 1 < rowBytes; i += 2) {
                const uint16_t ch = static_cast<uint16_t>(data[row + i] | (data[row + i + 1] << 8));
                unicode.push_back((ch >= 0x20 && ch <= 0x7E) ? static_cast<wchar_t>(ch) : L'.');
            }
            if (unicode.size() < unitsPerLine) {
                unicode.append(unitsPerLine - unicode.size(), L' ');
            }
            line << L"  |" << unicode << L"|";
        }

        printDumpLine(line.str());
    }
}

bool Debugger::WriteMemoryRangeToFile(const std::wstring& filePath, uint64_t address, size_t size) const {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (filePath.empty()) {
        std::wcout << L"Output file path cannot be empty.\n";
        return false;
    }
    if (address == 0 || size == 0) {
        std::wcout << L"Invalid .writemem address/size.\n";
        return false;
    }

    std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
    if (!out) {
        std::wcout << L"Unable to open output file: " << filePath << L"\n";
        return false;
    }

    const size_t kChunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(kChunkSize, 0);
    size_t totalWritten = 0;
    while (totalWritten < size) {
        const size_t want = std::min(kChunkSize, size - totalWritten);
        SIZE_T read = 0;
        const uint64_t current = address + static_cast<uint64_t>(totalWritten);
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(current),
                buffer.data(),
                want,
                &read) ||
            read == 0) {
            std::wcout << L"ReadProcessMemory failed at " << ToHex(current) << L".\n";
            return false;
        }

        out.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(read));
        if (!out) {
            std::wcout << L"Failed while writing output file: " << filePath << L"\n";
            return false;
        }
        totalWritten += static_cast<size_t>(read);
        if (read < want) {
            break;
        }
    }

    std::wcout << L"Wrote " << totalWritten << L" byte(s) from " << ToHex(address)
               << L" to " << filePath << L"\n";
    return totalWritten != 0;
}

bool Debugger::DumpMemoryRangeToFile(const std::wstring& filePath, uint64_t address, size_t size) const {
    return WriteMemoryRangeToFile(filePath, address, size);
}

bool Debugger::ResolveMainModuleRange(uint64_t& moduleBase, size_t& moduleSize) const {
    moduleBase = 0;
    moduleSize = 0;
    if (!EnsureDebuggee()) {
        return false;
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules) || modules.empty()) {
        return false;
    }

    std::wstring processImagePath;
    wchar_t processPathBuffer[MAX_PATH] = {};
    DWORD processPathLength = MAX_PATH;
    if (QueryFullProcessImageNameW(processHandle_, 0, processPathBuffer, &processPathLength)) {
        processImagePath = NormalizePathForCompare(std::wstring(processPathBuffer, processPathLength));
    }

    const ModuleRecord* best = nullptr;
    if (!processImagePath.empty()) {
        for (size_t mi = 0; mi < modules.size(); ++mi) {
            const ModuleRecord& module = modules[mi];
            if (NormalizePathForCompare(module.imagePath) == processImagePath) {
                best = &module;
                break;
            }
        }
    }

    if (best == nullptr) {
        best = &modules.front();
    }

    moduleBase = best->baseAddress;
    moduleSize = static_cast<size_t>(best->size);
    return moduleBase != 0 && moduleSize != 0;
}

bool Debugger::DumpCurrentImageToFile(const std::wstring& filePath) const {
    uint64_t moduleBase = 0;
    size_t moduleSize = 0;
    if (!ResolveMainModuleRange(moduleBase, moduleSize)) {
        std::wcout << L"Unable to resolve main module image range.\n";
        return false;
    }
    return DumpMemoryRangeToFile(filePath, moduleBase, moduleSize);
}

bool Debugger::AllocateVirtualMemory(size_t size) const {
    if (!EnsureDebuggee()) {
        return false;
    }
    if (size == 0) {
        std::wcout << L"Allocation size must be greater than zero.\n";
        return false;
    }

    LPVOID base = VirtualAllocEx(
        processHandle_,
        nullptr,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (base == nullptr) {
        std::wcout << L"VirtualAllocEx failed: " << GetLastError() << L"\n";
        return false;
    }

    std::wcout << L"Allocated " << size << L" byte(s) at "
               << ToHex(reinterpret_cast<uint64_t>(base), sizeof(void*) * 2) << L"\n";
    return true;
}

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

void Debugger::SetDisasmColorEnabled(bool enabled) {
    disasmColorEnabled_ = enabled;
    if (disasmColorEnabled_) {
        EnsureConsoleColorEnabled();
    }
}

void Debugger::EnsureConsoleColorEnabled() const {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != NULL && GetConsoleMode(h, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(h, mode);
    }
    SetConsoleOutputCP(CP_UTF8);
}

namespace {
// ANSI truecolor escape sequences. ESC is built from wchar_t(0x1b) to avoid any
// hex/octal escape-parsing ambiguity in the source literals below.
const std::wstring& ColorEscape(const wchar_t* suffix) {
    static std::wstring esc;
    esc.clear();
    esc.push_back(wchar_t(0x1b));
    esc.append(suffix);
    return esc;
}

// Styles:
//   cyan background (0,255,255), black foreground
//   yellow background (255,255,0), black foreground
//   black background (0,0,0), white foreground
struct AnsiStyle {
    const wchar_t* on;
    const wchar_t* off;
};

std::wstring ApplyStyle(const std::wstring& text, const AnsiStyle& style) {
    std::wstring out;
    out.append(ColorEscape(style.on));
    out.append(text);
    out.append(ColorEscape(style.off));
    return out;
}

std::wstring TrimSpace(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t");
    if (a == std::wstring::npos) {
        return std::wstring();
    }
    size_t b = s.find_last_not_of(L" \t");
    return s.substr(a, b - a + 1);
}

std::vector<std::wstring> SplitOperands(const std::wstring& rest) {
    std::vector<std::wstring> ops;
    std::wstring cur;
    int depth = 0;
    for (size_t i = 0; i < rest.size(); ++i) {
        const wchar_t ch = rest[i];
        if (ch == L'[' || ch == L'(') {
            ++depth;
            cur.push_back(ch);
        } else if (ch == L']' || ch == L')') {
            if (depth > 0) {
                --depth;
            }
            cur.push_back(ch);
        } else if (ch == L',' && depth == 0) {
            ops.push_back(TrimSpace(cur));
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    const std::wstring last = TrimSpace(cur);
    if (!last.empty()) {
        ops.push_back(last);
    }
    return ops;
}

bool TryParseBareHexAddress(const std::wstring& text, uint64_t& value) {
    const std::wstring trimmed = TrimSpace(text);
    if (trimmed.empty()) {
        return false;
    }

    size_t end = 0;
    while (end < trimmed.size() && std::iswxdigit(trimmed[end])) {
        ++end;
    }
    if (end == 0) {
        return false;
    }

    try {
        size_t idx = 0;
        value = std::stoull(trimmed.substr(0, end), &idx, 16);
        return idx == end;
    } catch (...) {
        return false;
    }
}

bool ReadProcessAnsiCString(HANDLE processHandle, uint64_t address, std::string& outText, size_t maxChars = 512) {
    outText.clear();
    if (processHandle == nullptr || address == 0 || maxChars == 0) {
        return false;
    }

    for (size_t i = 0; i < maxChars; ++i) {
        char ch = '\0';
        SIZE_T read = 0;
        if (!ReadProcessMemory(
                processHandle,
                reinterpret_cast<LPCVOID>(address + static_cast<uint64_t>(i)),
                &ch,
                sizeof(ch),
                &read) ||
            read != sizeof(ch)) {
            return false;
        }
        if (ch == '\0') {
            return true;
        }
        outText.push_back(ch);
    }
    return false;
}

static const AnsiStyle kDisasmPaleBlack = { L"[38;2;0;0;0;48;2;255;251;241m", L"[0m" };
static const AnsiStyle kDisasmCyanBlack = { L"[38;2;0;0;0;48;2;0;255;255m", L"[0m" };
static const AnsiStyle kDisasmPaleRed = { L"[38;2;255;0;0;48;2;255;251;241m", L"[0m" };
static const AnsiStyle kJumpRedYellow = { L"[38;2;255;0;0;48;2;255;255;0m", L"[0m" };
static const AnsiStyle kCallCyanBlack = { L"[38;2;0;0;0;48;2;0;255;255m", L"[0m" };
static const AnsiStyle kCallYellowBlack = { L"[38;2;0;0;0;48;2;255;255;0m", L"[0m" };
static const AnsiStyle kCallYellowRed = { L"[38;2;255;0;0;48;2;255;255;0m", L"[0m" };
static const AnsiStyle kMnemonicBlue = { L"[38;2;0;0;255;48;2;255;251;241m", L"[0m" };
static const AnsiStyle kAnnotationBlue = { L"[38;2;0;64;160;48;2;255;251;241m", L"[0m" };
}  // namespace

void Debugger::BuildColoredInstructionSegments(const std::wstring& text, std::vector<DisasmTextSegment>& segments) const {
    segments.clear();
    const std::wstring displayText = RewriteImportedThunkSymbols(text);
    if (displayText.empty()) {
        return;
    }

    size_t sp = displayText.find_first_of(L" \t");
    std::wstring mnem;
    std::wstring rest;
    if (sp == std::wstring::npos) {
        mnem = displayText;
    } else {
        mnem = displayText.substr(0, sp);
        rest = TrimSpace(displayText.substr(sp));
    }

    const std::vector<std::wstring> ops = SplitOperands(rest);
    const size_t opCount = ops.size();

    const COLORREF kPaleBg = RGB(255, 251, 241);
    const COLORREF kCyanBg = RGB(0, 255, 255);
    const COLORREF kYellowBg = RGB(255, 255, 0);
    const COLORREF kBlackFg = RGB(0, 0, 0);
    const COLORREF kRedFg = RGB(255, 0, 0);
    const COLORREF kBlueFg = RGB(0, 0, 255);

    const std::wstring lowerMnem = ToLowerLocal(mnem);
    const bool isJump = lowerMnem.size() >= 2 && lowerMnem[0] == L'j';
    const bool isCall = lowerMnem == L"call";
    const bool isRet = lowerMnem == L"ret";
    const bool isPushPop = lowerMnem == L"push" || lowerMnem == L"pop";
    uint64_t callTargetAddress = 0;
    const bool hasDirectCallTarget = isCall && opCount >= 1 && TryParseBareHexAddress(ops[0], callTargetAddress);
    const bool callTargetIsImport = hasDirectCallTarget && IsImportedFunctionAddress(callTargetAddress);

    struct SegEmitter {
        std::vector<DisasmTextSegment>& segs;
        SegEmitter(std::vector<DisasmTextSegment>& s) : segs(s) {}
        void emit(const std::wstring& segText, COLORREF fg, COLORREF bg) {
            if (!segText.empty()) {
                DisasmTextSegment seg;
                seg.text = segText;
                seg.fg = fg;
                seg.bg = bg;
                seg.hasBg = true;
                segs.push_back(seg);
            }
        }
    } emitter(segments);


    if (opCount == 0) {
        if (isRet) {
            emitter.emit(mnem, kBlackFg, kCyanBg);
        } else if (isPushPop) {
            emitter.emit(mnem, kBlueFg, kPaleBg);
        } else {
            emitter.emit(mnem, kBlackFg, kPaleBg);
        }
    } else if (opCount == 1) {
        if (isJump) {
            emitter.emit(mnem, kRedFg, kYellowBg);
            emitter.emit(L" ", kRedFg, kYellowBg);
            emitter.emit(ops[0], kBlackFg, kYellowBg);
        } else if (isCall) {
            emitter.emit(mnem, kBlackFg, kCyanBg);
            emitter.emit(L" ", kBlackFg, kCyanBg);
            emitter.emit(ops[0], callTargetIsImport ? kRedFg : kBlackFg, kYellowBg);
        } else if (isRet) {
            emitter.emit(mnem, kBlackFg, kCyanBg);
            emitter.emit(L" ", kBlackFg, kCyanBg);
            emitter.emit(ops[0], kBlackFg, kCyanBg);
        } else {
            emitter.emit(mnem, isPushPop ? kBlueFg : kBlackFg, kPaleBg);
            emitter.emit(L" ", kBlackFg, kPaleBg);
            const COLORREF bg = (ops[0].find(L'[') != std::wstring::npos) ? kCyanBg : kPaleBg;
            emitter.emit(ops[0], kBlackFg, bg);
        }
    } else {
        emitter.emit(
            mnem,
            isJump ? kRedFg : (isPushPop ? kBlueFg : kBlackFg),
            isJump ? kYellowBg : (isCall || isRet ? kCyanBg : kPaleBg));
        for (size_t i = 0; i < opCount; ++i) {
            emitter.emit(
                i == 0 ? L" " : L", ",
                isJump ? kRedFg : kBlackFg,
                isJump || isCall ? kYellowBg : (isRet ? kCyanBg : kPaleBg));
            const bool memoryOperand = ops[i].find(L'[') != std::wstring::npos;
            emitter.emit(
                ops[i],
                isCall && i == 0 && callTargetIsImport ? kRedFg : kBlackFg,
                isJump || isCall ? kYellowBg : (isRet || memoryOperand ? kCyanBg : kPaleBg));
        }
    }
}

void Debugger::PrintColoredInstructionText(const std::wstring& text) const {
    const std::wstring displayText = RewriteImportedThunkSymbols(text);
    if (displayText.empty()) {
        std::wcout << displayText;
        return;
    }

    // Split mnemonic vs operand string.
    size_t sp = displayText.find_first_of(L" \t");
    std::wstring mnem;
    std::wstring rest;
    if (sp == std::wstring::npos) {
        mnem = displayText;
    } else {
        mnem = displayText.substr(0, sp);
        rest = TrimSpace(displayText.substr(sp));
    }

    const std::vector<std::wstring> ops = SplitOperands(rest);
    const size_t opCount = ops.size();
    const auto isMemoryOperand = [](const std::wstring& op) -> bool {
        return op.find(L'[') != std::wstring::npos;
    };
    const auto operandStyle = [&](const std::wstring& op) -> const AnsiStyle& {
        return isMemoryOperand(op) ? kDisasmCyanBlack : kDisasmPaleBlack;
    };

    std::wstring out;
    const std::wstring lowerMnem = ToLowerLocal(mnem);
    const bool isJump = lowerMnem.size() >= 2 && lowerMnem[0] == L'j';
    const bool isCall = lowerMnem == L"call";
    const bool isRet = lowerMnem == L"ret";
    const bool isPushPop = lowerMnem == L"push" || lowerMnem == L"pop";
    uint64_t callTargetAddress = 0;
    const bool hasDirectCallTarget = isCall && opCount >= 1 && TryParseBareHexAddress(ops[0], callTargetAddress);
    const bool callTargetIsImport = hasDirectCallTarget && IsImportedFunctionAddress(callTargetAddress);
    if (opCount == 0) {
        if (isRet) {
            out = ApplyStyle(mnem, kCallCyanBlack);
        } else if (isPushPop) {
            out = ApplyStyle(mnem, kMnemonicBlue);
        } else {
            out = ApplyStyle(mnem, kDisasmPaleBlack);
        }
    } else if (opCount == 1) {
        if (isJump) {
            out = ApplyStyle(mnem, kJumpRedYellow)
                + ApplyStyle(L" ", kJumpRedYellow)
                + ApplyStyle(ops[0], kCallYellowBlack);
        } else if (isCall) {
            out = ApplyStyle(mnem, kCallCyanBlack)
                + ApplyStyle(L" ", kCallCyanBlack)
                + ApplyStyle(ops[0], callTargetIsImport ? kCallYellowRed : kCallYellowBlack);
        } else if (isRet) {
            out = ApplyStyle(mnem, kCallCyanBlack)
                + ApplyStyle(L" ", kCallCyanBlack)
                + ApplyStyle(ops[0], kCallCyanBlack);
        } else {
            out = ApplyStyle(mnem, isPushPop ? kMnemonicBlue : kDisasmPaleBlack)
                + ApplyStyle(L" ", kDisasmPaleBlack)
                + ApplyStyle(ops[0], operandStyle(ops[0]));
        }
    } else {
        out = ApplyStyle(mnem,
                         isJump ? kJumpRedYellow
                         : (isCall ? kCallCyanBlack
                            : (isRet ? kCallCyanBlack
                               : (isPushPop ? kMnemonicBlue : kDisasmPaleBlack))));
        for (size_t i = 0; i < opCount; ++i) {
            out += ApplyStyle(i == 0 ? L" " : L", ",
                              isJump ? kJumpRedYellow
                              : (isCall ? kCallYellowBlack
                                 : (isRet ? kCallCyanBlack
                                    : (isPushPop ? kDisasmPaleBlack : kDisasmPaleBlack))));
            out += ApplyStyle(ops[i],
                              isJump ? kCallYellowBlack
                              : (isCall ? (i == 0 && callTargetIsImport ? kCallYellowRed : kCallYellowBlack)
                                 : (isRet ? kCallCyanBlack
                                    : operandStyle(ops[i]))));
        }
    }
    out.append(ColorEscape(L"[0m"));
    std::wcout << out;
}

bool Debugger::IsBreakpointAtAddress(uint64_t address) const {
    if (address == 0) {
        return false;
    }
    if (softwareBreakpointByAddress_.find(address) != softwareBreakpointByAddress_.end()) {
        return true;
    }
    for (std::map<int, HardwareBreakpoint>::const_iterator it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
        if (it->second.address == address) {
            return true;
        }
    }
    for (std::map<int, MemoryBreakpoint>::const_iterator it = memoryBreakpoints_.begin(); it != memoryBreakpoints_.end(); ++it) {
        const MemoryBreakpoint& mb = it->second;
        if (address >= mb.address && address < mb.address + mb.size) {
            return true;
        }
    }
    return false;
}

void Debugger::PrintDisassembly(uint64_t address, size_t instructionCount) const {
    if (disasmColorEnabled_) {
        EnsureConsoleColorEnabled();
    }
    if (!EnsureDebuggee()) {
        return;
    }
    if (address == 0) {
        std::wcout << L"Invalid disassembly address.\n";
        return;
    }

    MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
    if (!VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) ||
        mbi.State != MEM_COMMIT) {
        std::wcout << L"Cannot disassemble at " << ToHex(address)
                   << L": memory is not committed.\n";
        return;
    }
    if (!IsExecutableProtection(mbi.Protect)) {
        std::wcout << L"Cannot disassemble at " << ToHex(address)
                   << L": memory protection is " << MemoryProtectionToString(mbi.Protect) << L".\n";
        return;
    }

    const size_t kDefaultReadBytes = 256;
    const size_t kMaxReadBytes = 4096;
    const size_t kEstimatedBytesPerInstruction = 16;
    size_t estimatedReadBytes = kDefaultReadBytes;
    if (instructionCount > 0) {
        if (instructionCount > (kMaxReadBytes / kEstimatedBytesPerInstruction)) {
            estimatedReadBytes = kMaxReadBytes;
        } else {
            estimatedReadBytes = instructionCount * kEstimatedBytesPerInstruction;
            if (estimatedReadBytes < kDefaultReadBytes) {
                estimatedReadBytes = kDefaultReadBytes;
            }
        }
    }
    if (estimatedReadBytes > kMaxReadBytes) {
        estimatedReadBytes = kMaxReadBytes;
    }
    const uint64_t regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    const uint64_t regionEnd = regionBase + static_cast<uint64_t>(mbi.RegionSize);
    if (address >= regionEnd) {
        std::wcout << L"Cannot disassemble at " << ToHex(address)
                   << L": address is outside the queried memory region.\n";
        return;
    }
    const size_t regionRemaining = static_cast<size_t>(std::min<uint64_t>(
        static_cast<uint64_t>(estimatedReadBytes),
        regionEnd - address));
    estimatedReadBytes = std::max<size_t>(1, regionRemaining);

    std::vector<uint8_t> code(estimatedReadBytes, 0);
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), code.data(), code.size(), &read) || read == 0) {
        const size_t retryBytes = std::min<size_t>(16, code.size());
        read = 0;
        if (retryBytes == 0 ||
            !ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), code.data(), retryBytes, &read) ||
            read == 0) {
            std::wcout << L"Cannot read instruction bytes at " << ToHex(address)
                       << L" for disassembly. protect=" << MemoryProtectionToString(mbi.Protect)
                       << L" region=" << ToHex(regionBase) << L"-" << ToHex(regionEnd) << L"\n";
            return;
        }
    }

    const uint8_t disassemblyModeBits = DetermineDisassemblyModeBits(processHandle_);
    const size_t addressWidth = disassemblyModeBits == 64 ? 16 : 8;
    std::wcout << L"--- Disassembly @ " << ToHex(address, addressWidth) << L" ---\n";
    const uint64_t currentStopIp = stopState_.valid ? GetInstructionPointer(stopState_.context) : 0;
    size_t offset = 0;
    for (size_t i = 0; i < instructionCount && offset < read; ++i) {
        const auto decoded = DecodeInstruction(address + offset, code.data() + offset, read - offset, disassemblyModeBits);
        const std::wstring displayText = RewriteImportedThunkSymbols(decoded.text);
        const size_t remaining = static_cast<size_t>(read - offset);
        size_t len = decoded.length;
        if (len > remaining) {
            len = remaining;
        }
        if (len < 1) {
            len = 1;
        }
        const size_t displayLen = std::min<size_t>(len, 8);
        const auto bytes = BytesToHex(code.data() + offset, displayLen);
        const uint64_t insnAddr = address + offset;
        const bool isCurrentIp = (currentStopIp != 0 && insnAddr == currentStopIp);
        const bool isBreakpointLine = IsBreakpointAtAddress(insnAddr);
        if (isCurrentIp || isBreakpointLine) {
            std::wstringstream line;
            line << ToHex(insnAddr, addressWidth) << L"  "
                 << std::left << std::setw(24) << bytes << L"  "
                 << displayText;
            const std::wstring exactSymbol = ResolveExactSymbol(insnAddr);
            if (!exactSymbol.empty()) {
                line << L"  " << exactSymbol;
            }
            const auto commentIt = instructionComments_.find(insnAddr);
            if (commentIt != instructionComments_.end() && !commentIt->second.empty()) {
                line << L"  ; " << commentIt->second;
            }
            const wchar_t* bg = isCurrentIp ? L"\x1b[48;2;196;0;0m" : L"\x1b[48;2;128;0;0m";
            std::wcout << L"\x1b[0m" << bg << L"\x1b[38;2;255;255;255m"
                       << line.str() << L"\x1b[0m" << std::right << L"\n";
            offset += len;
            continue;
        }

        std::wstringstream linePrefix;
        linePrefix << ToHex(insnAddr, addressWidth) << L"  " << std::left << std::setw(24) << bytes << L"  ";
        std::wcout << ApplyStyle(linePrefix.str(), kDisasmPaleBlack);
        if (disasmColorEnabled_) {
            PrintColoredInstructionText(displayText);
        } else {
            std::wcout << ApplyStyle(displayText, kDisasmPaleBlack);
        }
        const std::wstring exactSymbol = ResolveExactSymbol(insnAddr);
        if (!exactSymbol.empty()) {
            std::wcout << ApplyStyle(L"  " + exactSymbol, kAnnotationBlue);
        }
        const auto commentIt = instructionComments_.find(insnAddr);
        if (commentIt != instructionComments_.end() && !commentIt->second.empty()) {
            std::wcout << ApplyStyle(L"  ; " + commentIt->second, kDisasmPaleBlack);
        }
        std::wcout << std::right << L"\n";
        offset += len;
    }
}

void Debugger::PrintPseudoC(uint64_t address, size_t instructionCount, bool showUi) const {
    if (!EnsureDebuggee()) {
        return;
    }
    if (address == 0) {
        std::wcout << L"Invalid pseudo C address.\n";
        return;
    }
    if (instructionCount == 0) {
        instructionCount = 1;
    }
    if (instructionCount > 512) {
        instructionCount = 512;
    }

    MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
    if (!VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) ||
        mbi.State != MEM_COMMIT) {
        std::wcout << L"Cannot pseudo-decompile at " << ToHex(address)
                   << L": memory is not committed.\n";
        return;
    }
    if (!IsExecutableProtection(mbi.Protect)) {
        std::wcout << L"Cannot pseudo-decompile at " << ToHex(address)
                   << L": memory protection is " << MemoryProtectionToString(mbi.Protect) << L".\n";
        return;
    }

    const size_t kMaxReadBytes = 8192;
    size_t readBytesWanted = instructionCount * 16;
    if (readBytesWanted < 256) {
        readBytesWanted = 256;
    }
    if (readBytesWanted > kMaxReadBytes) {
        readBytesWanted = kMaxReadBytes;
    }

    const uint64_t regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    const uint64_t regionEnd = regionBase + static_cast<uint64_t>(mbi.RegionSize);
    if (address >= regionEnd) {
        std::wcout << L"Cannot pseudo-decompile at " << ToHex(address)
                   << L": address is outside the queried memory region.\n";
        return;
    }
    readBytesWanted = static_cast<size_t>(std::min<uint64_t>(static_cast<uint64_t>(readBytesWanted), regionEnd - address));
    if (readBytesWanted == 0) {
        std::wcout << L"Cannot pseudo-decompile at " << ToHex(address) << L": empty readable range.\n";
        return;
    }

    std::vector<uint8_t> code(readBytesWanted, 0);
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), code.data(), code.size(), &read) || read == 0) {
        std::wcout << L"Cannot read instruction bytes at " << ToHex(address) << L" for pseudo C.\n";
        return;
    }

    const uint8_t disassemblyModeBits = DetermineDisassemblyModeBits(processHandle_);
    std::vector<WdblPseudoInstruction> instructions;
    instructions.reserve(instructionCount);
    size_t offset = 0;
    for (size_t i = 0; i < instructionCount && offset < read; ++i) {
        const DecodedInstruction decoded = DecodeInstruction(address + offset, code.data() + offset, read - offset, disassemblyModeBits);
        size_t len = decoded.length;
        const size_t remaining = static_cast<size_t>(read - offset);
        if (len > remaining) {
            len = remaining;
        }
        if (len < 1) {
            len = 1;
        }

        WdblPseudoInstruction item;
        item.address = address + offset;
        item.text = RewriteImportedThunkSymbols(decoded.text);
        instructions.push_back(item);

        const std::wstring lower = ToLower(item.text);
        offset += len;
        if (lower.rfind(L"ret", 0) == 0 || lower == L"int3" || lower == L"ud2") {
            break;
        }
    }

    const std::wstring pseudoC = WdblBuildPseudoC(instructions);
    if (showUi && pseudoCUiCallback_) {
        pseudoCUiCallback_(pseudoC, address);
        return;
    }
    std::wcout << L"--- Pseudo C @ " << ToHex(address, disassemblyModeBits == 64 ? 16 : 8) << L" ---\n";
    std::wcout << pseudoC;
}

void Debugger::SetDisassemblyUiCallback(DisassemblyUiCallback callback) {
    disassemblyUiCallback_ = std::move(callback);
}

void Debugger::SetMemoryUiCallback(MemoryUiCallback callback) {
    memoryUiCallback_ = std::move(callback);
}

void Debugger::SetRegisterUiCallback(RegisterUiCallback callback) {
    registerUiCallback_ = std::move(callback);
}

void Debugger::SetStackUiCallback(StackUiCallback callback) {
    stackUiCallback_ = std::move(callback);
}

void Debugger::SetPseudoCUiCallback(PseudoCUiCallback callback) {
    pseudoCUiCallback_ = std::move(callback);
}

bool Debugger::CollectRegisterUiRows(const std::wstring& view, std::vector<RegisterUiRow>& rows) const {
    rows.clear();
    if (!stopState_.valid) {
        std::wcout << L"No paused context.\n";
        return false;
    }

    const std::wstring lowerView = ToLower(TrimWhitespace(view));
    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(stopState_.threadId, ctx)) {
        ctx = stopState_.context;
    }

    const auto addRow = [&](const std::wstring& name, const std::wstring& value, const std::wstring& info) -> void {
        RegisterUiRow row;
        row.name = name;
        row.value = value;
        row.info = info;
        rows.push_back(row);
    };

    const auto addDebugRows32 = [&](uint32_t dr0, uint32_t dr1, uint32_t dr2, uint32_t dr3, uint32_t dr6, uint32_t dr7) -> void {
        addRow(L"DR0", HexNoPrefix(dr0, 8), L"Debug");
        addRow(L"DR1", HexNoPrefix(dr1, 8), L"Debug");
        addRow(L"DR2", HexNoPrefix(dr2, 8), L"Debug");
        addRow(L"DR3", HexNoPrefix(dr3, 8), L"Debug");
        addRow(L"DR4", L"Reserved", L"Debug");
        addRow(L"DR5", L"Reserved", L"Debug");
        addRow(L"DR6", HexNoPrefix(dr6, 8), L"Debug");
        addRow(L"DR7", HexNoPrefix(dr7, 8), L"Debug");
    };

#if defined(_M_X64)
    const auto addDebugRows64 = [&](uint64_t dr0, uint64_t dr1, uint64_t dr2, uint64_t dr3, uint64_t dr6, uint64_t dr7) -> void {
        addRow(L"DR0", HexNoPrefix(dr0, 16), L"Debug");
        addRow(L"DR1", HexNoPrefix(dr1, 16), L"Debug");
        addRow(L"DR2", HexNoPrefix(dr2, 16), L"Debug");
        addRow(L"DR3", HexNoPrefix(dr3, 16), L"Debug");
        addRow(L"DR4", L"Reserved", L"Debug");
        addRow(L"DR5", L"Reserved", L"Debug");
        addRow(L"DR6", HexNoPrefix(dr6, 16), L"Debug");
        addRow(L"DR7", HexNoPrefix(dr7, 16), L"Debug");
    };

    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (CaptureWow64ThreadContextById(stopState_.threadId, wowCtx)) {
            if (lowerView == L"debug" || lowerView == L"dr") {
                addDebugRows32(wowCtx.Dr0, wowCtx.Dr1, wowCtx.Dr2, wowCtx.Dr3, wowCtx.Dr6, wowCtx.Dr7);
                return true;
            }
            if (lowerView == L"mmx") {
                for (int i = 0; i < 8; ++i) {
                    uint64_t value = 0;
                    memcpy(&value, &wowCtx.FloatSave.RegisterArea[i * 10], sizeof(value));
                    std::wstringstream name;
                    name << L"MM" << i;
                    addRow(name.str(), HexNoPrefix(value, 16), L"MMX");
                }
                return true;
            }
            if (lowerView == L"float" || lowerView == L"fpu") {
                addRow(L"FloatControl", HexNoPrefix(wowCtx.FloatSave.ControlWord, 4), L"FPU");
                addRow(L"FloatStatus", HexNoPrefix(wowCtx.FloatSave.StatusWord, 4), L"FPU");
                addRow(L"FloatTag", HexNoPrefix(wowCtx.FloatSave.TagWord, 4), L"FPU");
                for (int i = 0; i < 8; ++i) {
                    std::wstringstream name;
                    std::wstringstream value;
                    name << L"ST" << i;
                    value << std::uppercase << std::hex << std::setfill(L'0');
                    const uint8_t* stBytes = &wowCtx.FloatSave.RegisterArea[i * 10];
                    for (int b = 9; b >= 0; --b) {
                        value << std::setw(2) << static_cast<unsigned int>(stBytes[b]);
                    }
                    addRow(name.str(), value.str(), L"FPU");
                }
                return true;
            }

            const auto formatWow64Symbol = [&](uint32_t value) -> std::wstring {
                if (value == 0) {
                    return L"";
                }
                const uint64_t value64 = static_cast<uint64_t>(value);
                std::vector<ModuleRecord> modules;
                if (CollectModuleRecords(modules)) {
                    for (size_t i = 0; i < modules.size(); ++i) {
                        uint64_t entry = 0;
                        if (ResolveEntryPointFromModuleBase(modules[i].baseAddress, entry) && entry == value64) {
                            const std::wstring moduleName = modules[i].moduleName.empty()
                                ? GetModuleNameFromPath(modules[i].imagePath)
                                : modules[i].moduleName;
                            return moduleName + L"." + L"\x5165\x53E3\x70B9";
                        }
                    }
                }
                return ResolveSymbol(value64);
            };
            const auto addReg32 = [&](const wchar_t* name, uint32_t value) -> void {
                addRow(name, HexNoPrefix(value, 8), formatWow64Symbol(value));
            };
            addReg32(L"EAX", wowCtx.Eax);
            addReg32(L"ECX", wowCtx.Ecx);
            addReg32(L"EDX", wowCtx.Edx);
            addReg32(L"EBX", wowCtx.Ebx);
            addReg32(L"ESP", wowCtx.Esp);
            addReg32(L"EBP", wowCtx.Ebp);
            addReg32(L"ESI", wowCtx.Esi);
            addReg32(L"EDI", wowCtx.Edi);
            addReg32(L"EIP", wowCtx.Eip);
            addRow(L"EFLAGS", HexNoPrefix(wowCtx.EFlags, 8), EflSummary(wowCtx.EFlags));
            addRow(L"CF", FlagValue(wowCtx.EFlags, 1ull), L"ES " + HexNoPrefix(wowCtx.SegEs, 4));
            addRow(L"PF", FlagValue(wowCtx.EFlags, 1ull << 2), L"CS " + HexNoPrefix(wowCtx.SegCs, 4));
            addRow(L"AF", FlagValue(wowCtx.EFlags, 1ull << 4), L"SS " + HexNoPrefix(wowCtx.SegSs, 4));
            addRow(L"ZF", FlagValue(wowCtx.EFlags, 1ull << 6), L"DS " + HexNoPrefix(wowCtx.SegDs, 4));
            addRow(L"SF", FlagValue(wowCtx.EFlags, 1ull << 7), L"FS " + HexNoPrefix(wowCtx.SegFs, 4));
            addRow(L"TF", FlagValue(wowCtx.EFlags, 1ull << 8), L"GS " + HexNoPrefix(wowCtx.SegGs, 4));
            addRow(L"DF", FlagValue(wowCtx.EFlags, 1ull << 10), L"IF " + FlagValue(wowCtx.EFlags, 1ull << 9));
            addRow(L"OF", FlagValue(wowCtx.EFlags, 1ull << 11), L"");
            addDebugRows32(wowCtx.Dr0, wowCtx.Dr1, wowCtx.Dr2, wowCtx.Dr3, wowCtx.Dr6, wowCtx.Dr7);
            return true;
        }
    }

    if (lowerView == L"debug" || lowerView == L"dr") {
        addDebugRows64(ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7);
        return true;
    }
    if (lowerView == L"mmx") {
        for (int i = 0; i < 8; ++i) {
            std::wstringstream name;
            name << L"MM" << i;
            addRow(name.str(), HexNoPrefix(ctx.FltSave.FloatRegisters[i].Low, 16), L"MMX");
        }
        return true;
    }
    if (lowerView == L"float" || lowerView == L"fpu") {
        addRow(L"FloatControl", HexNoPrefix(ctx.FltSave.ControlWord, 4), L"FPU");
        addRow(L"FloatStatus", HexNoPrefix(ctx.FltSave.StatusWord, 4), L"FPU");
        addRow(L"FloatTag", HexNoPrefix(ctx.FltSave.TagWord, 4), L"FPU");
        addRow(L"MXCSR", HexNoPrefix(ctx.MxCsr, 8), L"SSE");
        for (int i = 0; i < 8; ++i) {
            std::wstringstream name;
            name << L"ST" << i;
            addRow(name.str(), StripHexPrefix(ToHex128(ctx.FltSave.FloatRegisters[i])), L"FPU");
        }
        return true;
    }

    const auto formatSymbol = [&](uint64_t value) -> std::wstring {
        if (value == 0) {
            return L"";
        }
        std::vector<ModuleRecord> modules;
        if (CollectModuleRecords(modules)) {
            for (size_t i = 0; i < modules.size(); ++i) {
                uint64_t entry = 0;
                if (ResolveEntryPointFromModuleBase(modules[i].baseAddress, entry) && entry == value) {
                    const std::wstring moduleName = modules[i].moduleName.empty()
                        ? GetModuleNameFromPath(modules[i].imagePath)
                        : modules[i].moduleName;
                    return moduleName + L"." + L"\x5165\x53E3\x70B9";
                }
            }
        }
        return ResolveSymbol(value);
    };
    const auto addReg64 = [&](const wchar_t* name, uint64_t value) -> void {
        addRow(name, HexNoPrefix(value, 16), formatSymbol(value));
    };
    addReg64(L"RAX", ctx.Rax);
    addReg64(L"RCX", ctx.Rcx);
    addReg64(L"RDX", ctx.Rdx);
    addReg64(L"RBX", ctx.Rbx);
    addReg64(L"RSP", ctx.Rsp);
    addReg64(L"RBP", ctx.Rbp);
    addReg64(L"RSI", ctx.Rsi);
    addReg64(L"RDI", ctx.Rdi);
    addReg64(L"R8", ctx.R8);
    addReg64(L"R9", ctx.R9);
    addReg64(L"R10", ctx.R10);
    addReg64(L"R11", ctx.R11);
    addReg64(L"R12", ctx.R12);
    addReg64(L"R13", ctx.R13);
    addReg64(L"R14", ctx.R14);
    addReg64(L"R15", ctx.R15);
    addReg64(L"RIP", ctx.Rip);
    addRow(L"RFLAGS", HexNoPrefix(ctx.EFlags, 16), EflSummary(ctx.EFlags));
    addRow(L"CF", FlagValue(ctx.EFlags, 1ull), L"ES " + HexNoPrefix(ctx.SegEs, 4));
    addRow(L"PF", FlagValue(ctx.EFlags, 1ull << 2), L"CS " + HexNoPrefix(ctx.SegCs, 4));
    addRow(L"AF", FlagValue(ctx.EFlags, 1ull << 4), L"SS " + HexNoPrefix(ctx.SegSs, 4));
    addRow(L"ZF", FlagValue(ctx.EFlags, 1ull << 6), L"DS " + HexNoPrefix(ctx.SegDs, 4));
    addRow(L"SF", FlagValue(ctx.EFlags, 1ull << 7), L"FS " + HexNoPrefix(ctx.SegFs, 4));
    addRow(L"TF", FlagValue(ctx.EFlags, 1ull << 8), L"GS " + HexNoPrefix(ctx.SegGs, 4));
    addRow(L"DF", FlagValue(ctx.EFlags, 1ull << 10), L"IF " + FlagValue(ctx.EFlags, 1ull << 9));
    addRow(L"OF", FlagValue(ctx.EFlags, 1ull << 11), L"");
    addDebugRows64(ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7);
#else
    if (lowerView == L"debug" || lowerView == L"dr") {
        addDebugRows32(ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7);
        return true;
    }
    if (lowerView == L"mmx") {
        for (int i = 0; i < 8; ++i) {
            uint64_t value = 0;
            memcpy(&value, &ctx.FloatSave.RegisterArea[i * 10], sizeof(value));
            std::wstringstream name;
            name << L"MM" << i;
            addRow(name.str(), HexNoPrefix(value, 16), L"MMX");
        }
        return true;
    }
    if (lowerView == L"float" || lowerView == L"fpu") {
        addRow(L"FloatControl", HexNoPrefix(ctx.FloatSave.ControlWord, 4), L"FPU");
        addRow(L"FloatStatus", HexNoPrefix(ctx.FloatSave.StatusWord, 4), L"FPU");
        addRow(L"FloatTag", HexNoPrefix(ctx.FloatSave.TagWord, 4), L"FPU");
        for (int i = 0; i < 8; ++i) {
            std::wstringstream name;
            std::wstringstream value;
            name << L"ST" << i;
            value << std::uppercase << std::hex << std::setfill(L'0');
            const uint8_t* stBytes = &ctx.FloatSave.RegisterArea[i * 10];
            for (int b = 9; b >= 0; --b) {
                value << std::setw(2) << static_cast<unsigned int>(stBytes[b]);
            }
            addRow(name.str(), value.str(), L"FPU");
        }
        return true;
    }
    addRow(L"EAX", HexNoPrefix(ctx.Eax, 8), L"");
    addRow(L"ECX", HexNoPrefix(ctx.Ecx, 8), L"");
    addRow(L"EDX", HexNoPrefix(ctx.Edx, 8), L"");
    addRow(L"EBX", HexNoPrefix(ctx.Ebx, 8), L"");
    addRow(L"ESP", HexNoPrefix(ctx.Esp, 8), L"");
    addRow(L"EBP", HexNoPrefix(ctx.Ebp, 8), L"");
    addRow(L"ESI", HexNoPrefix(ctx.Esi, 8), L"");
    addRow(L"EDI", HexNoPrefix(ctx.Edi, 8), L"");
    addRow(L"EIP", HexNoPrefix(ctx.Eip, 8), L"");
    addRow(L"EFLAGS", HexNoPrefix(ctx.EFlags, 8), EflSummary(ctx.EFlags));
    addDebugRows32(ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7);
#endif
    return true;
}

bool Debugger::CollectMemoryUiRows(uint64_t address, size_t unitSize, size_t unitsPerLine, bool compactHex, std::vector<MemoryUiRow>& rows, uint64_t& regionBase) const {
    rows.clear();
    regionBase = address;
    if (!EnsureDebuggee()) {
        return false;
    }
    if (address == 0) {
        std::wcout << L"Invalid memory address.\n";
        return false;
    }
    if (unitSize != 1 && unitSize != 2 && unitSize != 4 && unitSize != 8) {
        std::wcout << L"Invalid dump unit size.\n";
        return false;
    }
    if (unitsPerLine == 0) {
        unitsPerLine = 16;
    }

    MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
    if (!VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) ||
        mbi.State != MEM_COMMIT) {
        std::wcout << L"Cannot open memory UI at " << ToHex(address) << L": memory is not committed.\n";
        return false;
    }

    regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    uint64_t regionEnd = regionBase + static_cast<uint64_t>(mbi.RegionSize);
    if (regionEnd <= regionBase || address < regionBase || address >= regionEnd) {
        std::wcout << L"Cannot open memory UI: invalid memory region.\n";
        return false;
    }

    const size_t valueWidth = unitSize * 2;
    const size_t addressWidth = 16;
    const size_t bytesPerLine = std::max<size_t>(unitSize, unitSize * unitsPerLine);

    uint64_t readBase = regionBase;
    uint64_t readSize64 = regionEnd - regionBase;
    if (compactHex && bytesPerLine != 0) {
        const uint64_t rowsBeforeTarget = (address - regionBase) / static_cast<uint64_t>(bytesPerLine);
        readBase = address - rowsBeforeTarget * static_cast<uint64_t>(bytesPerLine);
        readSize64 = regionEnd - readBase;
    }
    const size_t kMaxDumpBytes = 1024 * 1024;
    if (readSize64 > static_cast<uint64_t>(kMaxDumpBytes)) {
        const uint64_t half = kMaxDumpBytes / 2;
        readBase = address > regionBase + half ? address - half : regionBase;
        const size_t align = bytesPerLine;
        if (align > 0) {
            if (compactHex) {
                readBase = address > half ? address - half : address;
                readBase -= ((address - readBase) % align);
                if (readBase < regionBase) {
                    readBase = regionBase;
                }
            } else {
                readBase -= (readBase - regionBase) % align;
            }
        }
        if (readBase + kMaxDumpBytes > regionEnd) {
            readBase = regionEnd - kMaxDumpBytes;
            if (align > 0) {
                if (compactHex) {
                    readBase -= ((address >= readBase ? address - readBase : 0) % align);
                    if (readBase < regionBase) {
                        readBase = regionBase;
                    }
                } else {
                    readBase -= (readBase - regionBase) % align;
                }
            }
        }
        readSize64 = std::min<uint64_t>(kMaxDumpBytes, regionEnd - readBase);
    }

    const size_t byteCount = static_cast<size_t>(readSize64);
    std::vector<uint8_t> data(byteCount, 0);
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(readBase), data.data(), data.size(), &read) || read == 0) {
        std::wcout << L"ReadProcessMemory failed at " << ToHex(readBase) << L".\n";
        return false;
    }
    regionBase = readBase;

    const auto hexNoPrefix = [](uint64_t value, size_t width) -> std::wstring {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width != 0) {
            ss << std::setw(static_cast<int>(width));
        }
        ss << value;
        return ss.str();
    };

    rows.reserve((static_cast<size_t>(read) + bytesPerLine - 1) / bytesPerLine);

    for (size_t row = 0; row < static_cast<size_t>(read); row += bytesPerLine) {
        const size_t rowBytes = std::min(bytesPerLine, static_cast<size_t>(read) - row);
        const size_t rowUnits = (rowBytes + unitSize - 1) / unitSize;
        MemoryUiRow uiRow;
        uiRow.address = readBase + row;
        uiRow.addressText = hexNoPrefix(uiRow.address, addressWidth);

        std::wstringstream hex;
        for (size_t i = 0; i < rowUnits; ++i) {
            if (i != 0 && !compactHex) {
                hex << L' ';
            }
            uint64_t value = 0;
            const size_t unitOffset = row + i * unitSize;
            const size_t available = std::min(unitSize, static_cast<size_t>(read) - unitOffset);
            for (size_t b = 0; b < available; ++b) {
                value |= static_cast<uint64_t>(data[unitOffset + b]) << (8 * b);
            }
            hex << hexNoPrefix(value, valueWidth);
        }
        uiRow.hexText = hex.str();

        uiRow.ansiText.reserve(rowBytes);
        for (size_t i = 0; i < rowBytes; ++i) {
            const uint8_t ch = data[row + i];
            uiRow.ansiText.push_back((ch >= 0x20 && ch <= 0x7E) ? static_cast<wchar_t>(ch) : L'.');
        }
        rows.push_back(uiRow);
    }
    return !rows.empty();
}

std::wstring Debugger::GetDebuggeeImagePath() const {
    if (processHandle_ == nullptr) {
        return L"";
    }

    wchar_t buffer[MAX_PATH] = {};
    DWORD length = MAX_PATH;
    if (QueryFullProcessImageNameW(processHandle_, 0, buffer, &length) && length > 0) {
        return std::wstring(buffer, length);
    }
    return L"";
}

bool Debugger::CollectDisassemblyUiRows(uint64_t address, std::vector<DisassemblyUiRow>& rows, uint64_t& regionBase, uint64_t& regionEnd, size_t preferredPlacementStart, size_t preciseBytes, size_t* exactPlacementStart) const {
    rows.clear();
    regionBase = 0;
    regionEnd = 0;
    if (!EnsureDebuggee()) {
        return false;
    }
    if (address == 0) {
        std::wcout << L"Invalid disassembly address.\n";
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi = MEMORY_BASIC_INFORMATION();
    if (!VirtualQueryEx(processHandle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) ||
        mbi.State != MEM_COMMIT) {
        std::wcout << L"Cannot open disassembly UI at " << ToHex(address)
                   << L": memory is not committed.\n";
        return false;
    }
    if (!IsExecutableProtection(mbi.Protect)) {
        std::wcout << L"Cannot open disassembly UI at " << ToHex(address)
                   << L": memory protection is " << MemoryProtectionToString(mbi.Protect) << L".\n";
        return false;
    }

    regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    regionEnd = regionBase + static_cast<uint64_t>(mbi.RegionSize);
    std::vector<ModuleRecord> modules;
    if (CollectModuleRecords(modules)) {
        const ModuleRecord* ownerModule = nullptr;
        for (size_t i = 0; i < modules.size(); ++i) {
            const uint64_t moduleBase = modules[i].baseAddress;
            const uint64_t moduleEnd = moduleBase + static_cast<uint64_t>(modules[i].size);
            if (address >= moduleBase && address < moduleEnd) {
                ownerModule = &modules[i];
                break;
            }
        }
        if (ownerModule != nullptr && ownerModule->baseAddress != 0) {
            SIZE_T bytesRead = 0;
            IMAGE_DOS_HEADER dos = IMAGE_DOS_HEADER();
            if (ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(ownerModule->baseAddress),
                    &dos,
                    sizeof(dos),
                    &bytesRead) &&
                bytesRead == sizeof(dos) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE &&
                dos.e_lfanew > 0) {
                const uint64_t ntAddress = ownerModule->baseAddress + static_cast<uint64_t>(dos.e_lfanew);
                IMAGE_NT_HEADERS64 nt64 = IMAGE_NT_HEADERS64();
                bytesRead = 0;
                if (ReadProcessMemory(
                        processHandle_,
                        reinterpret_cast<LPCVOID>(ntAddress),
                        &nt64,
                        sizeof(nt64),
                        &bytesRead) &&
                    bytesRead >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) &&
                    nt64.Signature == IMAGE_NT_SIGNATURE) {
                    const WORD sectionCount = nt64.FileHeader.NumberOfSections;
                    const uint64_t sectionTable = ntAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt64.FileHeader.SizeOfOptionalHeader;
                    for (WORD i = 0; i < sectionCount; ++i) {
                        IMAGE_SECTION_HEADER section = IMAGE_SECTION_HEADER();
                        bytesRead = 0;
                        if (!ReadProcessMemory(
                                processHandle_,
                                reinterpret_cast<LPCVOID>(sectionTable + static_cast<uint64_t>(i) * sizeof(section)),
                                &section,
                                sizeof(section),
                                &bytesRead) ||
                            bytesRead != sizeof(section)) {
                            break;
                        }
                        const uint64_t sectionSize = std::max<uint64_t>(
                            static_cast<uint64_t>(section.Misc.VirtualSize),
                            static_cast<uint64_t>(section.SizeOfRawData));
                        if (sectionSize == 0) {
                            continue;
                        }
                        const uint64_t sectionBase = ownerModule->baseAddress + static_cast<uint64_t>(section.VirtualAddress);
                        const uint64_t sectionEnd = std::min<uint64_t>(
                            ownerModule->baseAddress + static_cast<uint64_t>(ownerModule->size),
                            sectionBase + sectionSize);
                        const bool codeLike = (section.Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0;
                        if (codeLike && address >= sectionBase && address < sectionEnd) {
                            regionBase = sectionBase;
                            regionEnd = sectionEnd;
                            break;
                        }
                    }
                }
            }
        }
    }
    if (regionEnd <= regionBase) {
        std::wcout << L"Cannot open disassembly UI: invalid memory region.\n";
        return false;
    }

    if (exactPlacementStart != nullptr) {
        *exactPlacementStart = static_cast<size_t>(-1);
    }
    const bool exactOnly = exactPlacementStart != nullptr;

    const uint64_t regionSize64 = regionEnd - regionBase;
    if (regionSize64 > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        std::wcout << L"Cannot open disassembly UI: memory region is too large.\n";
        return false;
    }

    const uint8_t disassemblyModeBits = DetermineDisassemblyModeBits(processHandle_);
    const size_t addressWidth = disassemblyModeBits == 64 ? 16 : 8;
    const uint64_t currentStopIp = stopState_.valid ? GetInstructionPointer(stopState_.context) : 0;
    const size_t estimatedRows = std::max<size_t>(1, static_cast<size_t>((regionSize64 + 1) / 2));
    if (!exactOnly) {
        rows.resize(estimatedRows);
    }

    const uint64_t kPreciseUiDisasmBytes = std::max<uint64_t>(0x80, static_cast<uint64_t>(preciseBytes));
    const uint64_t kPreciseUiDisasmBytesBefore = 0x800;
    const uint64_t kPreciseUiScrollBacktrackBytes = std::min<uint64_t>(0x200, kPreciseUiDisasmBytes / 3);
    const bool hasPreferredPlacement = preferredPlacementStart != static_cast<size_t>(-1);
    uint64_t exactStart = regionBase;
    if (hasPreferredPlacement) {
        exactStart = address > regionBase + kPreciseUiScrollBacktrackBytes
            ? address - kPreciseUiScrollBacktrackBytes
            : regionBase;
    } else {
        exactStart = address > regionBase + kPreciseUiDisasmBytesBefore
            ? address - kPreciseUiDisasmBytesBefore
            : regionBase;
    }
    uint64_t exactEnd = std::min<uint64_t>(regionEnd, exactStart + kPreciseUiDisasmBytes);
    if (exactEnd < regionEnd && exactEnd <= address) {
        exactEnd = std::min<uint64_t>(regionEnd, address + 16);
    }
    if (!hasPreferredPlacement && exactEnd - exactStart < kPreciseUiDisasmBytes && exactEnd == regionEnd && regionEnd - regionBase > kPreciseUiDisasmBytes) {
        exactStart = regionEnd - kPreciseUiDisasmBytes;
    }
    const uint64_t readSize64 = exactEnd > exactStart ? exactEnd - exactStart : 0;
    if (readSize64 == 0 || readSize64 > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        std::wcout << L"Cannot open disassembly UI: invalid exact disassembly range.\n";
        return false;
    }

    const size_t readSize = static_cast<size_t>(readSize64);
    std::vector<uint8_t> code(readSize, 0);
    size_t totalRead = 0;
    while (totalRead < readSize) {
        const size_t chunk = std::min<size_t>(0x10000, readSize - totalRead);
        SIZE_T got = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(exactStart + totalRead),
                code.data() + totalRead,
                chunk,
                &got) || got == 0) {
            break;
        }
        totalRead += static_cast<size_t>(got);
        if (got < chunk) {
            break;
        }
    }
    if (totalRead == 0) {
        std::wcout << L"Cannot read code region at " << ToHex(exactStart)
                   << L" for disassembly UI.\n";
        return false;
    }

    std::vector<uint8_t> decodeBytes = code;
    for (std::map<int, SoftwareBreakpoint>::const_iterator it = softwareBreakpoints_.begin(); it != softwareBreakpoints_.end(); ++it) {
        const SoftwareBreakpoint& bp = it->second;
        if (!bp.enabled || bp.address < exactStart || bp.address >= exactStart + totalRead) {
            continue;
        }
        const size_t bpOffset = static_cast<size_t>(bp.address - exactStart);
        if (bpOffset < decodeBytes.size()) {
            decodeBytes[bpOffset] = bp.originalByte;
        }
    }

    std::vector<DisassemblyUiRow> exactRows;
    size_t targetOrdinal = 0;
    bool targetOrdinalSet = false;
    size_t offset = 0;
    while (offset < totalRead) {
        const uint64_t insnAddr = exactStart + offset;
        const DecodedInstruction decoded = DecodeInstruction(insnAddr, decodeBytes.data() + offset, totalRead - offset, disassemblyModeBits);
        const std::wstring displayText = RewriteImportedThunkSymbols(decoded.text);
        size_t len = decoded.length;
        if (len > totalRead - offset) {
            len = totalRead - offset;
        }
        if (len < 1) {
            len = 1;
        }

        DisassemblyUiRow row;
        row.address = insnAddr;
        row.addressText = ToHex(insnAddr, addressWidth);
        row.hexBytes = BytesToHex(code.data() + offset, len);
        row.instruction = displayText;
        BuildColoredInstructionSegments(displayText, row.instructionSegments);
        row.currentIp = currentStopIp != 0 && insnAddr == currentStopIp;
        row.breakpoint = IsBreakpointAtAddress(insnAddr);
        row.comment = ResolveExactSymbol(insnAddr);
        const std::map<uint64_t, std::wstring>::const_iterator commentIt = instructionComments_.find(insnAddr);
        if (commentIt != instructionComments_.end() && !commentIt->second.empty()) {
            if (!row.comment.empty()) {
                row.comment += L"  ";
            }
            row.comment += L"; " + commentIt->second;
        }
        if (!targetOrdinalSet && insnAddr >= address) {
            targetOrdinal = exactRows.size();
            targetOrdinalSet = true;
        }
        exactRows.push_back(row);
        offset += len;
    }
    if (!hasPreferredPlacement && address >= exactStart && address < exactStart + totalRead) {
        const size_t targetOffset = static_cast<size_t>(address - exactStart);
        const DecodedInstruction decoded = DecodeInstruction(address, decodeBytes.data() + targetOffset, totalRead - targetOffset, disassemblyModeBits);
        size_t len = decoded.length;
        if (len > totalRead - targetOffset) {
            len = totalRead - targetOffset;
        }
        if (len < 1) {
            len = 1;
        }

        DisassemblyUiRow row;
        row.address = address;
        row.addressText = ToHex(address, addressWidth);
        row.hexBytes = BytesToHex(code.data() + targetOffset, len);
        const std::wstring displayText = RewriteImportedThunkSymbols(decoded.text);
        row.instruction = displayText;
        BuildColoredInstructionSegments(displayText, row.instructionSegments);
        row.currentIp = currentStopIp != 0 && address == currentStopIp;
        row.breakpoint = IsBreakpointAtAddress(address);
        row.comment = ResolveExactSymbol(address);
        const std::map<uint64_t, std::wstring>::const_iterator commentIt = instructionComments_.find(address);
        if (commentIt != instructionComments_.end() && !commentIt->second.empty()) {
            if (!row.comment.empty()) {
                row.comment += L"  ";
            }
            row.comment += L"; " + commentIt->second;
        }
        if (!targetOrdinalSet) {
            targetOrdinal = exactRows.size();
            targetOrdinalSet = true;
        }
        if (targetOrdinal < exactRows.size() && exactRows[targetOrdinal].address == address) {
            exactRows[targetOrdinal] = row;
        } else {
            exactRows.insert(exactRows.begin() + targetOrdinal, row);
        }
    }

    const size_t estimatedTargetIndex = static_cast<size_t>((address - regionBase) / 2);
    size_t placementStart = hasPreferredPlacement
        ? (preferredPlacementStart > targetOrdinal ? preferredPlacementStart - targetOrdinal : 0)
        : (estimatedTargetIndex > targetOrdinal ? estimatedTargetIndex - targetOrdinal : 0);
    if (placementStart + exactRows.size() > estimatedRows) {
        placementStart = exactRows.size() < estimatedRows ? estimatedRows - exactRows.size() : 0;
    }
    if (exactOnly) {
        *exactPlacementStart = placementStart;
        rows.swap(exactRows);
        return !rows.empty();
    }
    for (size_t i = 0; i < exactRows.size() && placementStart + i < rows.size(); ++i) {
        rows[placementStart + i] = exactRows[i];
    }
    if (targetOrdinal < exactRows.size()) {
        const size_t targetRowIndex = placementStart + targetOrdinal;
        if (targetRowIndex < rows.size()) {
            rows[targetRowIndex].currentIp = rows[targetRowIndex].currentIp || (currentStopIp != 0 && rows[targetRowIndex].address == currentStopIp);
        }
    }
    return !rows.empty();
}

bool Debugger::ShowDisassemblyUi(uint64_t address) const {
    if (!disassemblyUiCallback_) {
        std::wcout << L"Disassembly UI is not available in this build.\n";
        return false;
    }
    std::vector<DisassemblyUiRow> rows;
    uint64_t regionBase = 0;
    uint64_t regionEnd = 0;
    if (!CollectDisassemblyUiRows(address, rows, regionBase, regionEnd)) {
        return false;
    }
    disassemblyUiCallback_(rows, address, regionBase, regionEnd);
    return true;
}

bool Debugger::ShowMemoryUi(uint64_t address, size_t byteCount, size_t unitSize, size_t unitsPerLine, bool compactHex) const {
    if (!memoryUiCallback_) {
        std::wcout << L"Memory UI is not available in this build.\n";
        return false;
    }
    std::vector<MemoryUiRow> rows;
    uint64_t regionBase = 0;
    if (!CollectMemoryUiRows(address, unitSize, unitsPerLine, compactHex, rows, regionBase)) {
        return false;
    }
    memoryUiCallback_(rows, address, regionBase, byteCount, unitSize, unitsPerLine);
    return true;
}

bool Debugger::ShowRegisterUi(const std::wstring& view) const {
    if (!registerUiCallback_) {
        std::wcout << L"Register UI is not available in this build.\n";
        return false;
    }
    std::vector<RegisterUiRow> rows;
    if (!CollectRegisterUiRows(view, rows)) {
        return false;
    }
    registerUiCallback_(rows, view);
    return true;
}

bool Debugger::ShowStackUi(size_t maxFrames, const std::wstring& view) const {
    if (!stackUiCallback_) {
        std::wcout << L"Stack UI is not available in this build.\n";
        return false;
    }
    std::vector<StackUiRow> rows;
    uint64_t stackPointer = 0;
    if (!CollectStackUiRows(maxFrames, rows, stackPointer)) {
        return false;
    }
    stackUiCallback_(rows, view, stackPointer);
    return true;
}

bool Debugger::SetInstructionComment(uint64_t address, const std::wstring& comment) {
    if (address == 0) {
        std::wcout << L"Invalid comment address.\n";
        return false;
    }
    const std::wstring text = TrimWhitespace(comment);
    if (text.empty()) {
        std::wcout << L"Comment text cannot be empty.\n";
        return false;
    }
    instructionComments_[address] = text;
    std::wcout << L"Comment set at " << ToHex(address) << L": " << text << L"\n";
    return true;
}

bool Debugger::RemoveInstructionComment(uint64_t address) {
    if (address == 0) {
        std::wcout << L"Invalid comment address.\n";
        return false;
    }
    if (instructionComments_.erase(address) == 0) {
        std::wcout << L"No comment exists at " << ToHex(address) << L".\n";
        return false;
    }
    std::wcout << L"Comment removed at " << ToHex(address) << L".\n";
    return true;
}

void Debugger::ListInstructionComments() const {
    std::wcout << L"--- Instruction Comments ---\n";
    if (instructionComments_.empty()) {
        std::wcout << L"(none)\n";
        return;
    }
    for (auto it = instructionComments_.begin(); it != instructionComments_.end(); ++it) {
        const uint64_t address = it->first;
        const std::wstring& text = it->second;
        std::wcout << ToHex(address) << L" : " << text << L"\n";
    }
}

std::wstring Debugger::ResolveSymbol(uint64_t address) const {
    if (symbolsInitialized_ && processHandle_ != nullptr) {
        std::array<char, sizeof(SYMBOL_INFO) + MAX_SYM_NAME> buffer = std::array<char, sizeof(SYMBOL_INFO) + MAX_SYM_NAME>();
        auto* sym = reinterpret_cast<SYMBOL_INFO*>(buffer.data());
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (SymFromAddr(processHandle_, address, &displacement, sym)) {
            std::wstring name(sym->Name, sym->Name + std::strlen(sym->Name));
            if (displacement == 0) {
                return name;
            }
            return name + L"+" + ToHex(displacement);
        }
    }

    const std::wstring importedAlias = ResolveImportedThunkSymbol(address);
    if (!importedAlias.empty()) {
        return importedAlias;
    }
    return ResolveExportSymbol(address);
}

std::wstring Debugger::ResolveExactSymbol(uint64_t address) const {
    if (symbolsInitialized_ && processHandle_ != nullptr) {
        std::array<char, sizeof(SYMBOL_INFO) + MAX_SYM_NAME> buffer = std::array<char, sizeof(SYMBOL_INFO) + MAX_SYM_NAME>();
        auto* sym = reinterpret_cast<SYMBOL_INFO*>(buffer.data());
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (SymFromAddr(processHandle_, address, &displacement, sym) && displacement == 0) {
            return std::wstring(sym->Name, sym->Name + std::strlen(sym->Name));
        }
    }

    const std::wstring importedAlias = ResolveImportedThunkSymbol(address);
    if (!importedAlias.empty()) {
        return importedAlias;
    }
    return ResolveExportSymbol(address);
}

std::wstring Debugger::ResolveImportedThunkSymbol(uint64_t address) const {
    if (address == 0 || !EnsureDebuggee()) {
        return L"";
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules)) {
        return L"";
    }

    for (size_t mi = 0; mi < modules.size(); ++mi) {
        const ModuleRecord& module = modules[mi];
        const uint64_t moduleEnd = module.baseAddress + static_cast<uint64_t>(module.size);
        if (address < module.baseAddress || address >= moduleEnd) {
            continue;
        }

        IMAGE_DOS_HEADER dos = IMAGE_DOS_HEADER();
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(module.baseAddress),
                &dos,
                sizeof(dos),
                &bytesRead) ||
            bytesRead != sizeof(dos) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE ||
            dos.e_lfanew <= 0) {
            return L"";
        }

        const uint64_t ntAddress = module.baseAddress + static_cast<uint64_t>(dos.e_lfanew);
        IMAGE_NT_HEADERS64 nt64 = IMAGE_NT_HEADERS64();
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(ntAddress),
                &nt64,
                sizeof(nt64),
                &bytesRead) ||
            bytesRead < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) ||
            nt64.Signature != IMAGE_NT_SIGNATURE) {
            return L"";
        }

        DWORD importRva = 0;
        bool is64BitModule = (nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        if (is64BitModule) {
            const IMAGE_DATA_DIRECTORY& importDir = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            importRva = importDir.VirtualAddress;
        } else {
            IMAGE_NT_HEADERS32 nt32 = IMAGE_NT_HEADERS32();
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(ntAddress),
                    &nt32,
                    sizeof(nt32),
                    &bytesRead) ||
                bytesRead < sizeof(nt32) ||
                nt32.Signature != IMAGE_NT_SIGNATURE) {
                return L"";
            }
            const IMAGE_DATA_DIRECTORY& importDir = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            importRva = importDir.VirtualAddress;
        }

        if (importRva == 0) {
            return L"";
        }

        const uint64_t importBase = module.baseAddress + static_cast<uint64_t>(importRva);
        const size_t thunkSize = is64BitModule ? sizeof(uint64_t) : sizeof(uint32_t);
        const uint64_t ordinalFlag = is64BitModule ? (1ull << 63) : (1ull << 31);

        for (DWORD descIndex = 0; descIndex < 512; ++descIndex) {
            IMAGE_IMPORT_DESCRIPTOR desc = IMAGE_IMPORT_DESCRIPTOR();
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(importBase + static_cast<uint64_t>(descIndex) * sizeof(desc)),
                    &desc,
                    sizeof(desc),
                    &bytesRead) ||
                bytesRead != sizeof(desc)) {
                break;
            }

            if (desc.Name == 0 && desc.FirstThunk == 0 && desc.OriginalFirstThunk == 0) {
                break;
            }
            if (desc.FirstThunk == 0) {
                continue;
            }

            const uint64_t thunkBase = module.baseAddress + static_cast<uint64_t>(desc.FirstThunk);
            const uint64_t nameThunkBase = module.baseAddress + static_cast<uint64_t>(
                desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk);

            std::wstring importedModuleName;
            if (desc.Name != 0) {
                std::string dllNameAnsi;
                if (ReadProcessAnsiCString(processHandle_, module.baseAddress + static_cast<uint64_t>(desc.Name), dllNameAnsi)) {
                    importedModuleName = MultiByteToWide(dllNameAnsi, CP_ACP, 0);
                }
            }
            if (!importedModuleName.empty()) {
                importedModuleName = GetModuleNameFromPath(importedModuleName);
            }
            if (importedModuleName.empty()) {
                importedModuleName = module.moduleName.empty() ? GetModuleNameFromPath(module.imagePath) : module.moduleName;
            }

            for (DWORD thunkIndex = 0; thunkIndex < 2048; ++thunkIndex) {
                const uint64_t thunkAddress = thunkBase + static_cast<uint64_t>(thunkIndex) * thunkSize;
                if (thunkAddress == address) {
                    uint64_t importEntry = 0;
                    if (thunkSize == sizeof(uint64_t)) {
                        if (!ReadProcessMemory(
                                processHandle_,
                                reinterpret_cast<LPCVOID>(nameThunkBase + static_cast<uint64_t>(thunkIndex) * thunkSize),
                                &importEntry,
                                sizeof(importEntry),
                                &bytesRead) ||
                            bytesRead != sizeof(importEntry) ||
                            importEntry == 0) {
                            break;
                        }
                    } else {
                        uint32_t importEntry32 = 0;
                        if (!ReadProcessMemory(
                                processHandle_,
                                reinterpret_cast<LPCVOID>(nameThunkBase + static_cast<uint64_t>(thunkIndex) * thunkSize),
                                &importEntry32,
                                sizeof(importEntry32),
                                &bytesRead) ||
                            bytesRead != sizeof(importEntry32) ||
                            importEntry32 == 0) {
                            break;
                        }
                        importEntry = importEntry32;
                    }

                    std::wstring importedName;
                    if ((importEntry & ordinalFlag) != 0) {
                        const uint64_t ordinal = importEntry & 0xFFFF;
                        importedName = L"#" + ToWStringCompat(ordinal);
                    } else {
                        const uint64_t nameAddress = module.baseAddress + importEntry + sizeof(WORD);
                        std::string importedNameAnsi;
                        if (!ReadProcessAnsiCString(processHandle_, nameAddress, importedNameAnsi)) {
                            break;
                        }
                        importedName = MultiByteToWide(importedNameAnsi, CP_ACP, 0);
                    }

                    if (!importedName.empty() && !importedModuleName.empty()) {
                        return importedModuleName + L"!" + importedName;
                    }
                    return L"";
                }

                if (thunkSize == sizeof(uint64_t)) {
                    uint64_t thunkValue = 0;
                    if (!ReadProcessMemory(
                            processHandle_,
                            reinterpret_cast<LPCVOID>(thunkAddress),
                            &thunkValue,
                            sizeof(thunkValue),
                            &bytesRead) ||
                        bytesRead != sizeof(thunkValue) ||
                        thunkValue == 0) {
                        break;
                    }
                } else {
                    uint32_t thunkValue = 0;
                    if (!ReadProcessMemory(
                            processHandle_,
                            reinterpret_cast<LPCVOID>(thunkAddress),
                            &thunkValue,
                            sizeof(thunkValue),
                            &bytesRead) ||
                        bytesRead != sizeof(thunkValue) ||
                        thunkValue == 0) {
                        break;
                    }
                }
            }
        }
    }

    return L"";
}

std::wstring Debugger::ResolveExportSymbol(uint64_t address) const {
    if (address == 0 || !EnsureDebuggee()) {
        return L"";
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules)) {
        return L"";
    }

    for (size_t mi = 0; mi < modules.size(); ++mi) {
        const ModuleRecord& module = modules[mi];
        const uint64_t moduleEnd = module.baseAddress + static_cast<uint64_t>(module.size);
        if (address < module.baseAddress || address >= moduleEnd) {
            continue;
        }

        IMAGE_DOS_HEADER dos = IMAGE_DOS_HEADER();
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(module.baseAddress),
                &dos,
                sizeof(dos),
                &bytesRead) ||
            bytesRead != sizeof(dos) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE ||
            dos.e_lfanew <= 0) {
            return L"";
        }

        const uint64_t ntAddress = module.baseAddress + static_cast<uint64_t>(dos.e_lfanew);
        IMAGE_NT_HEADERS64 nt64 = IMAGE_NT_HEADERS64();
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(ntAddress),
                &nt64,
                sizeof(nt64),
                &bytesRead) ||
            bytesRead < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) ||
            nt64.Signature != IMAGE_NT_SIGNATURE) {
            return L"";
        }

        DWORD exportRva = 0;
        bool is64BitModule = (nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        if (is64BitModule) {
            const IMAGE_DATA_DIRECTORY& exportDir = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            exportRva = exportDir.VirtualAddress;
        } else {
            IMAGE_NT_HEADERS32 nt32 = IMAGE_NT_HEADERS32();
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(ntAddress),
                    &nt32,
                    sizeof(nt32),
                    &bytesRead) ||
                bytesRead < sizeof(nt32) ||
                nt32.Signature != IMAGE_NT_SIGNATURE) {
                return L"";
            }
            const IMAGE_DATA_DIRECTORY& exportDir = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            exportRva = exportDir.VirtualAddress;
        }

        if (exportRva == 0) {
            return L"";
        }

        IMAGE_EXPORT_DIRECTORY exportDir = IMAGE_EXPORT_DIRECTORY();
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(module.baseAddress + static_cast<uint64_t>(exportRva)),
                &exportDir,
                sizeof(exportDir),
                &bytesRead) ||
            bytesRead != sizeof(exportDir) ||
            exportDir.NumberOfFunctions == 0) {
            return L"";
        }

        std::wstring moduleName = module.moduleName.empty() ? GetModuleNameFromPath(module.imagePath) : module.moduleName;
        if (moduleName.empty()) {
            return L"";
        }

        std::vector<DWORD> nameRvas;
        nameRvas.resize(exportDir.NumberOfNames);
        if (!nameRvas.empty()) {
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(module.baseAddress + static_cast<uint64_t>(exportDir.AddressOfNames)),
                    &nameRvas[0],
                    static_cast<SIZE_T>(nameRvas.size() * sizeof(DWORD)),
                    &bytesRead) ||
                bytesRead < sizeof(DWORD)) {
                return L"";
            }
        }

        std::vector<WORD> ordinals;
        ordinals.resize(exportDir.NumberOfNames);
        if (!ordinals.empty()) {
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(module.baseAddress + static_cast<uint64_t>(exportDir.AddressOfNameOrdinals)),
                    &ordinals[0],
                    static_cast<SIZE_T>(ordinals.size() * sizeof(WORD)),
                    &bytesRead) ||
                bytesRead < sizeof(WORD)) {
                return L"";
            }
        }

        std::vector<DWORD> funcRvas;
        funcRvas.resize(exportDir.NumberOfFunctions);
        if (!funcRvas.empty()) {
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(module.baseAddress + static_cast<uint64_t>(exportDir.AddressOfFunctions)),
                    &funcRvas[0],
                    static_cast<SIZE_T>(funcRvas.size() * sizeof(DWORD)),
                    &bytesRead) ||
                bytesRead < sizeof(DWORD)) {
                return L"";
            }
        }

        const DWORD targetRva = static_cast<DWORD>(address - module.baseAddress);
        for (size_t i = 0; i < funcRvas.size(); ++i) {
            if (funcRvas[i] == targetRva) {
                for (size_t nameIndex = 0; nameIndex < nameRvas.size(); ++nameIndex) {
                    if (static_cast<size_t>(ordinals[nameIndex]) != i) {
                        continue;
                    }
                    std::string exportNameAnsi;
                    if (ReadProcessAnsiCString(
                            processHandle_,
                            module.baseAddress + static_cast<uint64_t>(nameRvas[nameIndex]),
                            exportNameAnsi)) {
                        const std::wstring exportName = MultiByteToWide(exportNameAnsi, CP_ACP, 0);
                        if (!exportName.empty()) {
                            return moduleName + L"!" + exportName;
                        }
                    }
                    break;
                }
                return moduleName + L"!" + L"#" + ToWStringCompat(static_cast<uint32_t>(exportDir.Base + static_cast<DWORD>(i)));
            }
        }
    }

    return L"";
}

std::wstring Debugger::RewriteImportedThunkSymbols(const std::wstring& text) const {
    if (text.empty()) {
        return text;
    }

    std::wstring rewritten;
    size_t cursor = 0;
    while (cursor < text.size()) {
        const size_t open = text.find(L'[', cursor);
        if (open == std::wstring::npos) {
            rewritten.append(text.substr(cursor));
            break;
        }
        const size_t close = text.find(L']', open + 1);
        if (close == std::wstring::npos) {
            rewritten.append(text.substr(cursor));
            break;
        }

        rewritten.append(text.substr(cursor, open - cursor + 1));
        const std::wstring inner = TrimWhitespace(text.substr(open + 1, close - open - 1));
        uint64_t operandAddress = 0;
        std::wstring importedSymbol;
        if (TryParseBareHexAddress(inner, operandAddress)) {
            importedSymbol = ResolveImportedThunkSymbol(operandAddress);
        }
        rewritten.append(importedSymbol.empty() ? inner : importedSymbol);
        rewritten.push_back(L']');
        cursor = close + 1;
    }

    return rewritten;
}

bool Debugger::IsImportedFunctionAddress(uint64_t address) const {
    if (address == 0 || !EnsureDebuggee()) {
        return false;
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules)) {
        return false;
    }

    for (size_t mi = 0; mi < modules.size(); ++mi) {
        const ModuleRecord& module = modules[mi];
        const uint64_t moduleEnd = module.baseAddress + static_cast<uint64_t>(module.size);
        if (address < module.baseAddress || address >= moduleEnd) {
            continue;
        }

        IMAGE_DOS_HEADER dos = IMAGE_DOS_HEADER();
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(module.baseAddress),
                &dos,
                sizeof(dos),
                &bytesRead) ||
            bytesRead != sizeof(dos) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE ||
            dos.e_lfanew <= 0) {
            return false;
        }

        const uint64_t ntAddress = module.baseAddress + static_cast<uint64_t>(dos.e_lfanew);
        IMAGE_NT_HEADERS64 nt64 = IMAGE_NT_HEADERS64();
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(ntAddress),
                &nt64,
                sizeof(nt64),
                &bytesRead) ||
            bytesRead < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) ||
            nt64.Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        DWORD importRva = 0;
        bool is64BitModule = (nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        if (is64BitModule) {
            const IMAGE_DATA_DIRECTORY& importDir = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            importRva = importDir.VirtualAddress;
        } else {
            IMAGE_NT_HEADERS32 nt32 = IMAGE_NT_HEADERS32();
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(ntAddress),
                    &nt32,
                    sizeof(nt32),
                    &bytesRead) ||
                bytesRead < sizeof(nt32) ||
                nt32.Signature != IMAGE_NT_SIGNATURE) {
                return false;
            }
            const IMAGE_DATA_DIRECTORY& importDir = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            importRva = importDir.VirtualAddress;
        }

        if (importRva == 0) {
            return false;
        }

        const uint64_t importBase = module.baseAddress + static_cast<uint64_t>(importRva);
        const size_t thunkSize = is64BitModule ? sizeof(uint64_t) : sizeof(uint32_t);

        for (DWORD descIndex = 0; descIndex < 512; ++descIndex) {
            IMAGE_IMPORT_DESCRIPTOR desc = IMAGE_IMPORT_DESCRIPTOR();
            if (!ReadProcessMemory(
                    processHandle_,
                    reinterpret_cast<LPCVOID>(importBase + static_cast<uint64_t>(descIndex) * sizeof(desc)),
                    &desc,
                    sizeof(desc),
                    &bytesRead) ||
                bytesRead != sizeof(desc)) {
                break;
            }

            if (desc.Name == 0 && desc.FirstThunk == 0 && desc.OriginalFirstThunk == 0) {
                break;
            }
            if (desc.FirstThunk == 0) {
                continue;
            }

            const uint64_t thunkBase = module.baseAddress + static_cast<uint64_t>(desc.FirstThunk);
            for (DWORD thunkIndex = 0; thunkIndex < 2048; ++thunkIndex) {
                const uint64_t thunkAddress = thunkBase + static_cast<uint64_t>(thunkIndex) * thunkSize;
                if (thunkAddress == address) {
                    return true;
                }

                if (thunkSize == sizeof(uint64_t)) {
                    uint64_t thunkValue = 0;
                    if (!ReadProcessMemory(
                            processHandle_,
                            reinterpret_cast<LPCVOID>(thunkAddress),
                            &thunkValue,
                            sizeof(thunkValue),
                            &bytesRead) ||
                        bytesRead != sizeof(thunkValue) ||
                        thunkValue == 0) {
                        break;
                    }
                } else {
                    uint32_t thunkValue = 0;
                    if (!ReadProcessMemory(
                            processHandle_,
                            reinterpret_cast<LPCVOID>(thunkAddress),
                            &thunkValue,
                            sizeof(thunkValue),
                            &bytesRead) ||
                        bytesRead != sizeof(thunkValue) ||
                        thunkValue == 0) {
                        break;
                    }
                }
            }
        }
    }

    return false;
}

std::vector<DWORD> Debugger::EnumerateThreadIds() const {
    std::vector<DWORD> result;
    if (!active_) {
        return result;
    }

    std::vector<WDBL_THREAD_ENUM_ENTRY> driverThreads;
    if (wdbl::winapi::IsProcessMemoryDriverActive() &&
        wdbl::winapi::QueryDriverThreadList(processId_, &driverThreads) &&
        !driverThreads.empty()) {
        result.reserve(driverThreads.size());
        for (size_t i = 0; i < driverThreads.size(); ++i) {
            result.push_back(driverThreads[i].ThreadId);
        }
        return result;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return result;
    }
    THREADENTRY32 te = THREADENTRY32();
    te.dwSize = sizeof(te);
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == processId_) {
                result.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);
    return result;
}

PluginModule* Debugger::FindPluginModule(const std::wstring& token) {
    const std::wstring trimmed = TrimWhitespace(token);
    if (trimmed.empty()) {
        return nullptr;
    }

    std::wstring idToken = trimmed;
    if (!idToken.empty() && idToken.front() == L'#') {
        idToken.erase(idToken.begin());
    }
    uint32_t pluginId = 0;
    if (ParseUInt32(idToken, pluginId)) {
 for (auto __rangeIt31 = (pluginModules_).begin(); __rangeIt31 != (pluginModules_).end(); ++__rangeIt31) {
            auto& module = *__rangeIt31;
            if (module.id == static_cast<int>(pluginId)) {
                return &module;
            }
        }
    }

    const std::wstring lowered = ToLower(trimmed);
 for (auto __rangeIt32 = (pluginModules_).begin(); __rangeIt32 != (pluginModules_).end(); ++__rangeIt32) {
        auto& module = *__rangeIt32;
        if (ToLower(module.name) == lowered || ToLower(module.path) == lowered) {
            return &module;
        }
    }
    return nullptr;
}

const PluginModule* Debugger::FindPluginModule(const std::wstring& token) const {
    const std::wstring trimmed = TrimWhitespace(token);
    if (trimmed.empty()) {
        return nullptr;
    }

    std::wstring idToken = trimmed;
    if (!idToken.empty() && idToken.front() == L'#') {
        idToken.erase(idToken.begin());
    }
    uint32_t pluginId = 0;
    if (ParseUInt32(idToken, pluginId)) {
 for (auto __rangeIt33 = (pluginModules_).begin(); __rangeIt33 != (pluginModules_).end(); ++__rangeIt33) {
            const auto& module = *__rangeIt33;
            if (module.id == static_cast<int>(pluginId)) {
                return &module;
            }
        }
    }

    const std::wstring lowered = ToLower(trimmed);
 for (auto __rangeIt34 = (pluginModules_).begin(); __rangeIt34 != (pluginModules_).end(); ++__rangeIt34) {
        const auto& module = *__rangeIt34;
        if (ToLower(module.name) == lowered || ToLower(module.path) == lowered) {
            return &module;
        }
    }
    return nullptr;
}

void WDBL_CALL Debugger::PluginHostLogThunk(void* context, const wchar_t* text) {
    auto* debugger = static_cast<Debugger*>(context);
    if (debugger != nullptr) {
        debugger->PluginHostLog(text);
    }
}

int32_t WDBL_CALL Debugger::PluginHostExecuteThunk(void* context, const wchar_t* command) {
    auto* debugger = static_cast<Debugger*>(context);
    if (debugger == nullptr) {
        return 0;
    }
    return debugger->PluginHostExecute(command);
}

int32_t WDBL_CALL Debugger::PluginHostGetStopInfoThunk(void* context, WdblStopInfo* outInfo) {
    auto* debugger = static_cast<Debugger*>(context);
    if (debugger == nullptr) {
        return 0;
    }
    return debugger->PluginHostGetStopInfo(outInfo);
}

int32_t WDBL_CALL Debugger::PluginHostSubscribeEventsThunk(void* context, int32_t enabled) {
    auto* debugger = static_cast<Debugger*>(context);
    if (debugger == nullptr) {
        return 0;
    }
    return debugger->PluginHostSubscribeEvents(enabled);
}

int32_t WDBL_CALL Debugger::DebuggerApiLaunchThunk(void* context, const wchar_t* commandLine) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiLaunch(commandLine) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiAttachThunk(void* context, uint32_t processId) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiAttach(processId) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiDetachThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiDetach() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiContinueThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiContinue() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiSingleStepThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiSingleStep() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiStepOverThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiStepOver() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiReadMemoryThunk(void* context, uint64_t address, void* buffer, uint32_t bufferSize, uint32_t* bytesRead) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiReadMemory(address, buffer, bufferSize, bytesRead) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiWriteMemoryThunk(void* context, uint64_t address, const void* buffer, uint32_t bufferSize, uint32_t* bytesWritten) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiWriteMemory(address, buffer, bufferSize, bytesWritten) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiResolveSymbolThunk(void* context, uint64_t address, wchar_t* outText, uint32_t outTextChars) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiResolveSymbol(address, outText, outTextChars) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiResolveAddressExpressionThunk(void* context, const wchar_t* expression, uint64_t* outAddress, wchar_t* outText, uint32_t outTextChars) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiResolveAddressExpression(expression, outAddress, outText, outTextChars) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiAddSoftwareBreakpointThunk(void* context, uint64_t address, int32_t* outBreakpointId) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiAddSoftwareBreakpoint(address, outBreakpointId) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiAddHardwareBreakpointThunk(void* context, int32_t slot, uint64_t address, int32_t access, int32_t length, uint32_t threadId, int32_t* outBreakpointId) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiAddHardwareBreakpoint(slot, address, access, length, threadId, outBreakpointId) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiAddMemoryBreakpointThunk(void* context, uint64_t address, uint64_t size, uint32_t access, int32_t* outBreakpointId) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiAddMemoryBreakpoint(address, size, access, outBreakpointId) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiEnableBreakpointThunk(void* context, int32_t breakpointId) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiEnableBreakpoint(breakpointId) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiDisableBreakpointThunk(void* context, int32_t breakpointId) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiDisableBreakpoint(breakpointId) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiRemoveBreakpointThunk(void* context, int32_t breakpointId) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiRemoveBreakpoint(breakpointId) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiSetBreakpointConditionThunk(void* context, int32_t breakpointId, const wchar_t* expression) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiSetBreakpointCondition(breakpointId, expression) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiClearBreakpointConditionThunk(void* context, int32_t breakpointId) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiClearBreakpointCondition(breakpointId) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiLoadSymbolsThunk(void* context, const wchar_t* target, wchar_t* outPdbPath, uint32_t outPdbPathChars) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiLoadSymbols(target, outPdbPath, outPdbPathChars) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiDownloadSymbolsThunk(void* context, const wchar_t* target, const wchar_t* cacheDir, const wchar_t* serverUrl, wchar_t* outPdbPath, uint32_t outPdbPathChars) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiDownloadSymbols(target, cacheDir, serverUrl, outPdbPath, outPdbPathChars) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiSetSymbolSearchPathThunk(void* context, const wchar_t* symbolPath) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiSetSymbolSearchPath(symbolPath) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetSymbolSearchPathThunk(void* context, wchar_t* outText, uint32_t outTextChars) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetSymbolSearchPath(outText, outTextChars) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiSelectThreadThunk(void* context, uint32_t index) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiSelectThread(index) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiSetRegisterValueThunk(void* context, const wchar_t* assignment) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiSetRegisterValue(assignment) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiWriteMemoryPatchThunk(void* context, uint64_t address, const void* bytes, uint32_t size) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiWriteMemoryPatch(address, bytes, size) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiUndoMemoryPatchThunk(void* context, uint32_t count) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiUndoMemoryPatch(count) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiSaveCurrentStopSnapshotThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiSaveCurrentStopSnapshot() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiSaveNamedSnapshotThunk(void* context, const wchar_t* name) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiSaveNamedSnapshot(name) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiRestoreNamedSnapshotThunk(void* context, const wchar_t* name, int32_t rerunAfterRestore) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiRestoreNamedSnapshot(name, rerunAfterRestore) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiListNamedSnapshotsThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiListNamedSnapshots() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiStepBackToPreviousSnapshotThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiStepBackToPreviousSnapshot() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiAddSourceRootThunk(void* context, const wchar_t* path) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiAddSourceRoot(path) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiRemoveSourceRootThunk(void* context, const wchar_t* path) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiRemoveSourceRoot(path) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiClearSourceRootsThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiClearSourceRoots() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiListSourceRootsThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiListSourceRoots() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiLoadScriptFileThunk(void* context, const wchar_t* path) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiLoadScriptFile(path) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiSetScriptBreakpointThunk(void* context, uint32_t line) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiSetScriptBreakpoint(line) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiRemoveScriptBreakpointThunk(void* context, uint32_t line) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiRemoveScriptBreakpoint(line) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiListScriptBreakpointsThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiListScriptBreakpoints() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiConfigureExceptionIgnoreAllThunk(void* context, int32_t scope, int32_t enabled) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiConfigureExceptionIgnoreAll(scope, enabled) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiAddIgnoredExceptionCodeThunk(void* context, int32_t scope, uint32_t code) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiAddIgnoredExceptionCode(scope, code) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiRemoveIgnoredExceptionCodeThunk(void* context, int32_t scope, uint32_t code) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiRemoveIgnoredExceptionCode(scope, code) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiClearIgnoredExceptionCodesThunk(void* context, int32_t scope) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiClearIgnoredExceptionCodes(scope) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiListExceptionSettingsThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiListExceptionSettings() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiAddRunStopExpressionThunk(void* context, const wchar_t* expression) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiAddRunStopExpression(expression) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiRemoveRunStopExpressionThunk(void* context, uint32_t index) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiRemoveRunStopExpression(index) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiClearRunStopExpressionsThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiClearRunStopExpressions() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiListRunStopExpressionsThunk(void* context) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiListRunStopExpressions() : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiStepUntilConditionThunk(void* context, const wchar_t* condition, uint64_t maxSteps) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiStepUntilCondition(condition, maxSteps) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiRunUntilConditionThunk(void* context, const wchar_t* condition, uint64_t maxPauses) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiRunUntilCondition(condition, maxPauses) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiAutoStepThunk(void* context, uint64_t steps, uint32_t delayMs) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiAutoStep(steps, delayMs) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiAutoRunThunk(void* context, uint64_t pauses, uint32_t delayMs) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiAutoRun(pauses, delayMs) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetStopInfoThunk(void* context, WdblStopInfo* outInfo) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetStopInfo(outInfo) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetThreadCountThunk(void* context, uint32_t* outCount) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetThreadCount(outCount) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetThreadInfoThunk(void* context, uint32_t index, WdblThreadInfo* outInfo) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetThreadInfo(index, outInfo) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetRegisterInfoThunk(void* context, uint32_t index, WdblRegisterInfo* outInfo) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetRegisterInfo(index, outInfo) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetStackFrameInfoThunk(void* context, uint32_t index, uint32_t frameIndex, WdblStackFrameInfo* outInfo) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetStackFrameInfo(index, frameIndex, outInfo) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetModuleCountThunk(void* context, uint32_t* outCount) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetModuleCount(outCount) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetModuleInfoThunk(void* context, uint32_t index, WdblModuleInfo* outInfo) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetModuleInfo(index, outInfo) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetBreakpointCountThunk(void* context, uint32_t* outCount) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetBreakpointCount(outCount) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiGetBreakpointInfoThunk(void* context, uint32_t index, WdblBreakpointInfo* outInfo) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiGetBreakpointInfo(index, outInfo) : 0;
}

int32_t WDBL_CALL Debugger::DebuggerApiExecuteCommandThunk(void* context, const wchar_t* command) {
    auto* debugger = static_cast<Debugger*>(context);
    return debugger != nullptr ? debugger->DebuggerApiExecuteCommand(command) : 0;
}

void Debugger::PluginHostLog(const wchar_t* text) {
    if (text == nullptr || text[0] == L'\0') {
        return;
    }
    if (activePluginDispatchIndex_ >= 0 &&
        activePluginDispatchIndex_ < static_cast<int>(pluginModules_.size())) {
        const auto& module = pluginModules_[static_cast<size_t>(activePluginDispatchIndex_)];
        std::wcout << L"[Plugin:" << module.name << L"] " << text << L"\n";
        return;
    }
    std::wcout << L"[Plugin] " << text << L"\n";
}

int32_t Debugger::PluginHostExecute(const wchar_t* command) {
    if (command == nullptr) {
        return 0;
    }
    const std::wstring text = TrimWhitespace(command);
    if (text.empty()) {
        return 0;
    }
    const auto tokens = Tokenize(text);
    if (tokens.empty()) {
        return 0;
    }
    return ExecuteCommand(tokens, false) ? 1 : 0;
}

int32_t Debugger::PluginHostGetStopInfo(WdblStopInfo* outInfo) const {
    if (outInfo == nullptr || outInfo->size < sizeof(WdblStopInfo)) {
        return 0;
    }
    WdblStopInfo info = WdblStopInfo();
    info.size = sizeof(WdblStopInfo);
    if (pendingEvent_.valid && stopState_.valid) {
        info.paused = 1;
        info.processId = stopState_.processId;
        info.threadId = stopState_.threadId;
        info.exceptionCode = stopState_.exceptionCode;
        info.firstChance = stopState_.firstChance ? 1 : 0;
        info.exceptionAddress = stopState_.address;
        info.instructionPointer = GetInstructionPointer(stopState_.context);
        CopyWideText(info.reason, stopState_.reason);
    }
    *outInfo = info;
    return 1;
}

int32_t Debugger::PluginHostSubscribeEvents(int32_t enabled) {
    if (activePluginDispatchIndex_ < 0 ||
        activePluginDispatchIndex_ >= static_cast<int>(pluginModules_.size())) {
        return 0;
    }
    pluginModules_[static_cast<size_t>(activePluginDispatchIndex_)].subscribedEvents = (enabled != 0);
    return 1;
}

int32_t Debugger::DebuggerApiLaunch(const wchar_t* commandLine) {
    if (commandLine == nullptr || TrimWhitespace(commandLine).empty()) {
        return 0;
    }
    return Launch(commandLine) ? 1 : 0;
}

int32_t Debugger::DebuggerApiAttach(uint32_t processId) {
    return Attach(static_cast<DWORD>(processId)) ? 1 : 0;
}

int32_t Debugger::DebuggerApiDetach() {
    return Detach() ? 1 : 0;
}

int32_t Debugger::DebuggerApiContinue() {
    return ContinueExecution() ? 1 : 0;
}

int32_t Debugger::DebuggerApiSingleStep() {
    return SingleStep() ? 1 : 0;
}

int32_t Debugger::DebuggerApiStepOver() {
    return StepOver() ? 1 : 0;
}

int32_t Debugger::DebuggerApiReadMemory(uint64_t address, void* buffer, uint32_t bufferSize, uint32_t* bytesRead) const {
    if (bytesRead != nullptr) {
        *bytesRead = 0;
    }
    if (buffer == nullptr || bufferSize == 0) {
        return 0;
    }
    if (!EnsureDebuggee()) {
        return 0;
    }

    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), buffer, static_cast<SIZE_T>(bufferSize), &read)) {
        return 0;
    }
    if (bytesRead != nullptr) {
        *bytesRead = static_cast<uint32_t>(read);
    }
    return read > 0 ? 1 : 0;
}

int32_t Debugger::DebuggerApiWriteMemory(uint64_t address, const void* buffer, uint32_t bufferSize, uint32_t* bytesWritten) {
    if (bytesWritten != nullptr) {
        *bytesWritten = 0;
    }
    if (buffer == nullptr || bufferSize == 0) {
        return 0;
    }
    if (!EnsureDebuggee()) {
        return 0;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(processHandle_, reinterpret_cast<LPVOID>(address), buffer, static_cast<SIZE_T>(bufferSize), &written)) {
        return 0;
    }
    if (bytesWritten != nullptr) {
        *bytesWritten = static_cast<uint32_t>(written);
    }
    return written > 0 ? 1 : 0;
}

int32_t Debugger::DebuggerApiResolveSymbol(uint64_t address, wchar_t* outText, uint32_t outTextChars) const {
    if (outText == nullptr || outTextChars == 0) {
        return 0;
    }
    const std::wstring text = ResolveSymbol(address);
    wcsncpy_s(outText, outTextChars, text.c_str(), _TRUNCATE);
    return 1;
}

int32_t Debugger::DebuggerApiResolveAddressExpression(const wchar_t* expression, uint64_t* outAddress, wchar_t* outText, uint32_t outTextChars) const {
    if (expression == nullptr) {
        return 0;
    }

    uint64_t address = 0;
    std::wstring resolvedText;
    if (!ResolveAddressExpression(expression, address, resolvedText)) {
        return 0;
    }

    if (outAddress != nullptr) {
        *outAddress = address;
    }
    if (outText != nullptr && outTextChars != 0) {
        wcsncpy_s(outText, outTextChars, resolvedText.c_str(), _TRUNCATE);
    }
    return 1;
}

int32_t Debugger::DebuggerApiAddSoftwareBreakpoint(uint64_t address, int32_t* outBreakpointId) {
    const int id = AddSoftwareBreakpoint(address);
    if (id < 0) {
        return 0;
    }
    if (outBreakpointId != nullptr) {
        *outBreakpointId = static_cast<int32_t>(id);
    }
    return 1;
}

int32_t Debugger::DebuggerApiAddHardwareBreakpoint(int32_t slot, uint64_t address, int32_t access, int32_t length, uint32_t threadId, int32_t* outBreakpointId) {
    const HardwareAccessType::Enum accessEnum = static_cast<HardwareAccessType::Enum>(access);
    const int id = AddHardwareBreakpoint(slot, address, HardwareAccessType(accessEnum), length, static_cast<DWORD>(threadId));
    if (id < 0) {
        return 0;
    }
    if (outBreakpointId != nullptr) {
        *outBreakpointId = static_cast<int32_t>(id);
    }
    return 1;
}

int32_t Debugger::DebuggerApiAddMemoryBreakpoint(uint64_t address, uint64_t size, uint32_t access, int32_t* outBreakpointId) {
    const MemoryAccessType accessType(static_cast<MemoryAccessType::Enum>(access));
    const int id = AddMemoryBreakpoint(address, static_cast<size_t>(size), accessType);
    if (id < 0) {
        return 0;
    }
    if (outBreakpointId != nullptr) {
        *outBreakpointId = static_cast<int32_t>(id);
    }
    return 1;
}

int32_t Debugger::DebuggerApiEnableBreakpoint(int32_t breakpointId) {
    return EnableBreakpoint(breakpointId) ? 1 : 0;
}

int32_t Debugger::DebuggerApiDisableBreakpoint(int32_t breakpointId) {
    return DisableBreakpoint(breakpointId) ? 1 : 0;
}

int32_t Debugger::DebuggerApiRemoveBreakpoint(int32_t breakpointId) {
    return RemoveBreakpoint(breakpointId) ? 1 : 0;
}

int32_t Debugger::DebuggerApiSetBreakpointCondition(int32_t breakpointId, const wchar_t* expression) {
    if (expression == nullptr) {
        return 0;
    }
    return SetBreakpointCondition(breakpointId, expression) ? 1 : 0;
}

int32_t Debugger::DebuggerApiClearBreakpointCondition(int32_t breakpointId) {
    return ClearBreakpointCondition(breakpointId) ? 1 : 0;
}

int32_t Debugger::DebuggerApiLoadSymbols(const wchar_t* target, wchar_t* outPdbPath, uint32_t outPdbPathChars) const {
    std::wstring pdbPath;
    const std::wstring targetText = target != nullptr ? TrimWhitespace(std::wstring(target)) : L"";
    const std::optional<std::wstring> filter = targetText.empty() || targetText == L"*"
        ? std::nullopt
        : std::optional<std::wstring>(targetText);
    const bool ok = const_cast<Debugger*>(this)->ReloadSymbolsDetailed(false, filter, &pdbPath);
    if (!ok) {
        return 0;
    }
    if (outPdbPath != nullptr && outPdbPathChars != 0) {
        wcsncpy_s(outPdbPath, outPdbPathChars, pdbPath.c_str(), _TRUNCATE);
    }
    return 1;
}

int32_t Debugger::DebuggerApiDownloadSymbols(const wchar_t* target, const wchar_t* cacheDir, const wchar_t* serverUrl, wchar_t* outPdbPath, uint32_t outPdbPathChars) const {
    Debugger* self = const_cast<Debugger*>(this);
    const std::wstring cache = cacheDir != nullptr ? TrimWhitespace(std::wstring(cacheDir)) : L"";
    const std::wstring server = serverUrl != nullptr ? TrimWhitespace(std::wstring(serverUrl)) : L"";
    const std::wstring targetText = target != nullptr ? TrimWhitespace(std::wstring(target)) : L"";

    if (!cache.empty() || !server.empty()) {
        if (cache.empty() || server.empty()) {
            std::wcout << L"Both cache_dir and server_url are required when overriding symbol download location.\n";
            return 0;
        }
        self->symbolCacheDirectory_ = cache;
        self->symbolServerUrl_ = server;
        EnsureDirectoryRecursive(self->symbolCacheDirectory_, nullptr);
        if (!self->SetSymbolSearchPath(std::wstring(L"srv*") + self->symbolCacheDirectory_ + L"*" + self->symbolServerUrl_)) {
            return 0;
        }
    } else {
        self->ConfigureDefaultSymbolPath(false);
    }

    std::wstring pdbPath;
    const std::optional<std::wstring> filter = targetText.empty() || targetText == L"*"
        ? std::nullopt
        : std::optional<std::wstring>(targetText);
    const bool ok = self->ReloadSymbolsDetailed(true, filter, &pdbPath);
    if (!ok) {
        return 0;
    }
    if (outPdbPath != nullptr && outPdbPathChars != 0) {
        wcsncpy_s(outPdbPath, outPdbPathChars, pdbPath.c_str(), _TRUNCATE);
    }
    return 1;
}

int32_t Debugger::DebuggerApiSetSymbolSearchPath(const wchar_t* symbolPath) const {
    if (symbolPath == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->SetSymbolSearchPath(symbolPath) ? 1 : 0;
}

int32_t Debugger::DebuggerApiGetSymbolSearchPath(wchar_t* outText, uint32_t outTextChars) const {
    if (outText == nullptr || outTextChars == 0) {
        return 0;
    }
    const std::wstring path = GetSymbolSearchPath();
    wcsncpy_s(outText, outTextChars, path.c_str(), _TRUNCATE);
    return 1;
}

int32_t Debugger::DebuggerApiSelectThread(uint32_t index) const {
    Debugger* self = const_cast<Debugger*>(this);
    if (!self->EnsureDebuggee()) {
        return 0;
    }

    std::vector<DWORD> threadIds = self->EnumerateThreadIds();
    if (index >= threadIds.size()) {
        return 0;
    }

    const DWORD tid = threadIds[index];
    if (!self->pendingEvent_.valid || !self->stopState_.valid) {
        std::wcout << L"Debuggee is not paused on a debug event.\n";
        return 0;
    }

    CONTEXT ctx = CONTEXT();
    if (!self->CaptureThreadContext(tid, ctx)) {
        return 0;
    }

    EnterCriticalSection(&self->stateLock_);
    self->stopState_.threadId = tid;
    self->stopState_.context = ctx;
    self->stopState_.address = self->GetInstructionPointer(ctx);
    LeaveCriticalSection(&self->stateLock_);
    return 1;
}

int32_t Debugger::DebuggerApiSetRegisterValue(const wchar_t* assignment) const {
    if (assignment == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->SetRegisterValue(assignment) ? 1 : 0;
}

int32_t Debugger::DebuggerApiWriteMemoryPatch(uint64_t address, const void* bytes, uint32_t size) const {
    if (bytes == nullptr || size == 0) {
        return 0;
    }
    const uint8_t* data = static_cast<const uint8_t*>(bytes);
    std::vector<uint8_t> patch(data, data + size);
    return const_cast<Debugger*>(this)->WriteMemoryPatch(address, patch, true) ? 1 : 0;
}

int32_t Debugger::DebuggerApiUndoMemoryPatch(uint32_t count) const {
    return const_cast<Debugger*>(this)->UndoMemoryPatch(static_cast<size_t>(count)) ? 1 : 0;
}

int32_t Debugger::DebuggerApiSaveCurrentStopSnapshot() const {
    const_cast<Debugger*>(this)->SaveCurrentStopSnapshot();
    return 1;
}

int32_t Debugger::DebuggerApiSaveNamedSnapshot(const wchar_t* name) const {
    if (name == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->SaveNamedSnapshot(name) ? 1 : 0;
}

int32_t Debugger::DebuggerApiRestoreNamedSnapshot(const wchar_t* name, int32_t rerunAfterRestore) const {
    if (name == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->RestoreNamedSnapshot(name, rerunAfterRestore != 0) ? 1 : 0;
}

int32_t Debugger::DebuggerApiListNamedSnapshots() const {
    const_cast<Debugger*>(this)->ListNamedSnapshots();
    return 1;
}

int32_t Debugger::DebuggerApiStepBackToPreviousSnapshot() const {
    return const_cast<Debugger*>(this)->StepBackToPreviousSnapshot() ? 1 : 0;
}

int32_t Debugger::DebuggerApiAddSourceRoot(const wchar_t* path) const {
    if (path == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->AddSourceRoot(path) ? 1 : 0;
}

int32_t Debugger::DebuggerApiRemoveSourceRoot(const wchar_t* path) const {
    if (path == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->RemoveSourceRoot(path) ? 1 : 0;
}

int32_t Debugger::DebuggerApiClearSourceRoots() const {
    const_cast<Debugger*>(this)->ClearSourceRoots();
    return 1;
}

int32_t Debugger::DebuggerApiListSourceRoots() const {
    const_cast<Debugger*>(this)->ListSourceRoots();
    return 1;
}

int32_t Debugger::DebuggerApiLoadScriptFile(const wchar_t* path) const {
    if (path == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->LoadScriptFile(path) ? 1 : 0;
}

int32_t Debugger::DebuggerApiSetScriptBreakpoint(uint32_t line) const {
    return const_cast<Debugger*>(this)->SetScriptBreakpoint(static_cast<size_t>(line)) ? 1 : 0;
}

int32_t Debugger::DebuggerApiRemoveScriptBreakpoint(uint32_t line) const {
    return const_cast<Debugger*>(this)->RemoveScriptBreakpoint(static_cast<size_t>(line)) ? 1 : 0;
}

int32_t Debugger::DebuggerApiListScriptBreakpoints() const {
    const_cast<Debugger*>(this)->ListScriptBreakpoints();
    return 1;
}

int32_t Debugger::DebuggerApiConfigureExceptionIgnoreAll(int32_t scope, int32_t enabled) const {
    return const_cast<Debugger*>(this)->ConfigureExceptionIgnoreAll(static_cast<ExceptionScope::Enum>(scope), enabled != 0) ? 1 : 0;
}

int32_t Debugger::DebuggerApiAddIgnoredExceptionCode(int32_t scope, uint32_t code) const {
    return const_cast<Debugger*>(this)->AddIgnoredExceptionCode(static_cast<ExceptionScope::Enum>(scope), code) ? 1 : 0;
}

int32_t Debugger::DebuggerApiRemoveIgnoredExceptionCode(int32_t scope, uint32_t code) const {
    return const_cast<Debugger*>(this)->RemoveIgnoredExceptionCode(static_cast<ExceptionScope::Enum>(scope), code) ? 1 : 0;
}

int32_t Debugger::DebuggerApiClearIgnoredExceptionCodes(int32_t scope) const {
    const_cast<Debugger*>(this)->ClearIgnoredExceptionCodes(static_cast<ExceptionScope::Enum>(scope));
    return 1;
}

int32_t Debugger::DebuggerApiListExceptionSettings() const {
    const_cast<Debugger*>(this)->ListExceptionSettings();
    return 1;
}

int32_t Debugger::DebuggerApiAddRunStopExpression(const wchar_t* expression) const {
    if (expression == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->AddRunStopExpression(expression) ? 1 : 0;
}

int32_t Debugger::DebuggerApiRemoveRunStopExpression(uint32_t index) const {
    return const_cast<Debugger*>(this)->RemoveRunStopExpression(static_cast<size_t>(index)) ? 1 : 0;
}

int32_t Debugger::DebuggerApiClearRunStopExpressions() const {
    const_cast<Debugger*>(this)->ClearRunStopExpressions();
    return 1;
}

int32_t Debugger::DebuggerApiListRunStopExpressions() const {
    const_cast<Debugger*>(this)->ListRunStopExpressions();
    return 1;
}

int32_t Debugger::DebuggerApiStepUntilCondition(const wchar_t* condition, uint64_t maxSteps) const {
    if (condition == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->StepUntilCondition(condition, maxSteps) ? 1 : 0;
}

int32_t Debugger::DebuggerApiRunUntilCondition(const wchar_t* condition, uint64_t maxPauses) const {
    if (condition == nullptr) {
        return 0;
    }
    return const_cast<Debugger*>(this)->RunUntilCondition(condition, maxPauses) ? 1 : 0;
}

int32_t Debugger::DebuggerApiAutoStep(uint64_t steps, uint32_t delayMs) const {
    return const_cast<Debugger*>(this)->AutoStep(steps, delayMs) ? 1 : 0;
}

int32_t Debugger::DebuggerApiAutoRun(uint64_t pauses, uint32_t delayMs) const {
    return const_cast<Debugger*>(this)->AutoRun(pauses, delayMs) ? 1 : 0;
}

int32_t Debugger::DebuggerApiGetStopInfo(WdblStopInfo* outInfo) const {
    return PluginHostGetStopInfo(outInfo);
}

int32_t Debugger::DebuggerApiGetThreadCount(uint32_t* outCount) const {
    if (outCount == nullptr) {
        return 0;
    }
    *outCount = static_cast<uint32_t>(EnumerateThreadIds().size());
    return 1;
}

int32_t Debugger::DebuggerApiGetThreadInfo(uint32_t index, WdblThreadInfo* outInfo) const {
    if (outInfo == nullptr || outInfo->size < sizeof(WdblThreadInfo)) {
        return 0;
    }
    if (!FillThreadInfoByIndex(index, *outInfo)) {
        return 0;
    }
    return 1;
}

int32_t Debugger::DebuggerApiGetRegisterInfo(uint32_t index, WdblRegisterInfo* outInfo) const {
    if (outInfo == nullptr || outInfo->size < sizeof(WdblRegisterInfo)) {
        return 0;
    }
    if (!FillRegisterInfoByIndex(index, *outInfo)) {
        return 0;
    }
    return 1;
}

int32_t Debugger::DebuggerApiGetStackFrameInfo(uint32_t index, uint32_t frameIndex, WdblStackFrameInfo* outInfo) const {
    if (outInfo == nullptr || outInfo->size < sizeof(WdblStackFrameInfo)) {
        return 0;
    }
    if (!FillStackFrameByIndex(index, frameIndex, *outInfo)) {
        return 0;
    }
    return 1;
}

int32_t Debugger::DebuggerApiGetModuleCount(uint32_t* outCount) const {
    if (outCount == nullptr) {
        return 0;
    }
    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules)) {
        return 0;
    }
    *outCount = static_cast<uint32_t>(modules.size());
    return 1;
}

int32_t Debugger::DebuggerApiGetModuleInfo(uint32_t index, WdblModuleInfo* outInfo) const {
    if (outInfo == nullptr || outInfo->size < sizeof(WdblModuleInfo)) {
        return 0;
    }
    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules) || index >= modules.size()) {
        return 0;
    }
    const ModuleRecord& module = modules[index];
    outInfo->baseAddress = module.baseAddress;
    outInfo->imageSize = module.size;
    CopyWideText(outInfo->imagePath, module.imagePath);
    CopyWideText(outInfo->moduleName, module.moduleName);
    return 1;
}

int32_t Debugger::DebuggerApiGetBreakpointCount(uint32_t* outCount) const {
    if (outCount == nullptr) {
        return 0;
    }
    *outCount = static_cast<uint32_t>(softwareBreakpoints_.size() + hardwareBreakpoints_.size() + memoryBreakpoints_.size());
    return 1;
}

int32_t Debugger::DebuggerApiGetBreakpointInfo(uint32_t index, WdblBreakpointInfo* outInfo) const {
    if (outInfo == nullptr || outInfo->size < sizeof(WdblBreakpointInfo)) {
        return 0;
    }

    struct Item {
        int id;
        WdblBreakpointKind kind;
        uint64_t address;
        int slot;
        uint32_t threadId;
        bool enabled;
        uint64_t hitCount;
        uint32_t length;
        uint32_t access;
        std::wstring condition;
    };

    std::vector<Item> items;
    items.reserve(softwareBreakpoints_.size() + hardwareBreakpoints_.size() + memoryBreakpoints_.size());
    for (auto it = softwareBreakpoints_.begin(); it != softwareBreakpoints_.end(); ++it) {
        const SoftwareBreakpoint& bp = it->second;
        Item item = {};
        item.id = bp.id;
        item.kind = WDBL_BREAKPOINT_SOFTWARE;
        item.address = bp.address;
        item.slot = -1;
        item.threadId = 0;
        item.enabled = bp.enabled;
        item.hitCount = bp.hitCount;
        item.length = 1;
        item.access = 0;
        item.condition = bp.condition;
        items.push_back(item);
    }
    for (auto it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
        const HardwareBreakpoint& bp = it->second;
        Item item = {};
        item.id = bp.id;
        item.kind = WDBL_BREAKPOINT_HARDWARE;
        item.address = bp.address;
        item.slot = bp.slot;
        item.threadId = bp.threadId;
        item.enabled = bp.enabled;
        item.hitCount = bp.hitCount;
        item.length = static_cast<uint32_t>(bp.length);
        item.access = static_cast<uint32_t>(bp.access);
        item.condition = bp.condition;
        items.push_back(item);
    }
    for (auto it = memoryBreakpoints_.begin(); it != memoryBreakpoints_.end(); ++it) {
        const MemoryBreakpoint& bp = it->second;
        Item item = {};
        item.id = bp.id;
        item.kind = WDBL_BREAKPOINT_MEMORY;
        item.address = bp.address;
        item.slot = -1;
        item.threadId = 0;
        item.enabled = bp.enabled;
        item.hitCount = bp.hitCount;
        item.length = static_cast<uint32_t>(bp.size);
        item.access = static_cast<uint32_t>(bp.access);
        item.condition = bp.condition;
        items.push_back(item);
    }
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) { return a.id < b.id; });
    if (index >= items.size()) {
        return 0;
    }

    const Item& item = items[index];
    outInfo->id = item.id;
    outInfo->kind = static_cast<uint32_t>(item.kind);
    outInfo->address = item.address;
    outInfo->slot = item.slot;
    outInfo->threadId = item.threadId;
    outInfo->enabled = item.enabled ? 1 : 0;
    outInfo->hitCount = item.hitCount;
    outInfo->length = item.length;
    outInfo->access = item.access;
    CopyWideText(outInfo->condition, item.condition);
    return 1;
}

int32_t Debugger::DebuggerApiExecuteCommand(const wchar_t* command) {
    if (command == nullptr) {
        return 0;
    }
    const std::wstring text = TrimWhitespace(command);
    if (text.empty()) {
        return 0;
    }
    const auto tokens = Tokenize(text);
    if (tokens.empty()) {
        return 0;
    }
    return ExecuteCommand(tokens, false) ? 1 : 0;
}

bool Debugger::QueryThreadTeb(DWORD tid, uint64_t& teb) const {
    teb = 0;
    HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (thread == NULL) {
        return false;
    }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntQueryInformationThread = ntdll != NULL
        ? reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(ntdll, "NtQueryInformationThread"))
        : nullptr;
    if (ntQueryInformationThread == nullptr) {
        CloseHandle(thread);
        return false;
    }
    THREAD_BASIC_INFORMATION_LOCAL tbi = THREAD_BASIC_INFORMATION_LOCAL();
    ULONG retLen = 0;
    NTSTATUS status = ntQueryInformationThread(
        thread,
        static_cast<THREADINFOCLASS>(0),
        &tbi,
        sizeof(tbi),
        &retLen);
    CloseHandle(thread);
    if (status < 0 || tbi.TebBaseAddress == nullptr) {
        return false;
    }
    teb = reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
    return true;
}

bool Debugger::FillThreadInfoByIndex(uint32_t index, WdblThreadInfo& outInfo) const {
    outInfo = WdblThreadInfo();
    std::vector<DWORD> threadIds = EnumerateThreadIds();
    if (index >= threadIds.size()) {
        return false;
    }

    const DWORD tid = threadIds[index];
    outInfo.index = index;
    outInfo.processId = processId_;
    outInfo.threadId = tid;
    outInfo.isCurrent = (stopState_.valid && tid == stopState_.threadId) ? 1u : 0u;

    uint64_t teb = 0;
    if (QueryThreadTeb(tid, teb)) {
        outInfo.teb = teb;
    }

    CONTEXT ctx = CONTEXT();
    if (CaptureThreadContext(tid, ctx)) {
        outInfo.hasContext = 1;
        outInfo.instructionPointer = GetInstructionPointer(ctx);
        outInfo.stackPointer = GetStackPointer(ctx);
        const std::wstring symbol = ResolveSymbol(outInfo.instructionPointer);
        if (!symbol.empty()) {
            CopyWideText(outInfo.symbol, symbol);
        }
    }

    HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (thread != NULL) {
        const int priority = GetThreadPriority(thread);
        if (priority != THREAD_PRIORITY_ERROR_RETURN) {
            outInfo.priority = priority;
        }
        CloseHandle(thread);
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = THREADENTRY32();
        te.dwSize = sizeof(te);
        if (Thread32First(snapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId_ && te.th32ThreadID == tid) {
                    outInfo.basePriority = te.tpBasePri;
                    outInfo.deltaPriority = te.tpDeltaPri;
                    break;
                }
            } while (Thread32Next(snapshot, &te));
        }
        CloseHandle(snapshot);
    }
    return true;
}

bool Debugger::FillRegisterInfoByIndex(uint32_t index, WdblRegisterInfo& outInfo) const {
    outInfo = WdblRegisterInfo();
    std::vector<DWORD> threadIds = EnumerateThreadIds();
    if (index >= threadIds.size()) {
        return false;
    }

    const DWORD tid = threadIds[index];
    outInfo.threadId = tid;

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (!CaptureWow64ThreadContextById(tid, wowCtx)) {
            return false;
        }
        outInfo.isWow64 = 1;
        outInfo.architectureBits = 32;
        outInfo.instructionPointer = wowCtx.Eip;
        outInfo.stackPointer = wowCtx.Esp;
        outInfo.framePointer = wowCtx.Ebp;
        outInfo.flags = wowCtx.EFlags;
        outInfo.rip = wowCtx.Eip;
        outInfo.rsp = wowCtx.Esp;
        outInfo.rbp = wowCtx.Ebp;
        outInfo.rax = wowCtx.Eax;
        outInfo.rbx = wowCtx.Ebx;
        outInfo.rcx = wowCtx.Ecx;
        outInfo.rdx = wowCtx.Edx;
        outInfo.rsi = wowCtx.Esi;
        outInfo.rdi = wowCtx.Edi;
        outInfo.r8 = 0;
        outInfo.r9 = 0;
        outInfo.r10 = 0;
        outInfo.r11 = 0;
        outInfo.r12 = 0;
        outInfo.r13 = 0;
        outInfo.r14 = 0;
        outInfo.r15 = 0;
        outInfo.dr0 = wowCtx.Dr0;
        outInfo.dr1 = wowCtx.Dr1;
        outInfo.dr2 = wowCtx.Dr2;
        outInfo.dr3 = wowCtx.Dr3;
        outInfo.dr6 = wowCtx.Dr6;
        outInfo.dr7 = wowCtx.Dr7;
        outInfo.eax = wowCtx.Eax;
        outInfo.ebx = wowCtx.Ebx;
        outInfo.ecx = wowCtx.Ecx;
        outInfo.edx = wowCtx.Edx;
        outInfo.esi = wowCtx.Esi;
        outInfo.edi = wowCtx.Edi;
        outInfo.ebp = wowCtx.Ebp;
        outInfo.esp = wowCtx.Esp;
        outInfo.eip = wowCtx.Eip;
        outInfo.eflags = wowCtx.EFlags;
        return true;
    }
#endif

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(tid, ctx)) {
        return false;
    }

#if defined(_M_X64)
    outInfo.isWow64 = 0;
    outInfo.architectureBits = 64;
    outInfo.instructionPointer = ctx.Rip;
    outInfo.stackPointer = ctx.Rsp;
    outInfo.framePointer = ctx.Rbp;
    outInfo.flags = ctx.EFlags;
    outInfo.rax = ctx.Rax;
    outInfo.rbx = ctx.Rbx;
    outInfo.rcx = ctx.Rcx;
    outInfo.rdx = ctx.Rdx;
    outInfo.rsi = ctx.Rsi;
    outInfo.rdi = ctx.Rdi;
    outInfo.rbp = ctx.Rbp;
    outInfo.rsp = ctx.Rsp;
    outInfo.rip = ctx.Rip;
    outInfo.r8 = ctx.R8;
    outInfo.r9 = ctx.R9;
    outInfo.r10 = ctx.R10;
    outInfo.r11 = ctx.R11;
    outInfo.r12 = ctx.R12;
    outInfo.r13 = ctx.R13;
    outInfo.r14 = ctx.R14;
    outInfo.r15 = ctx.R15;
    outInfo.dr0 = ctx.Dr0;
    outInfo.dr1 = ctx.Dr1;
    outInfo.dr2 = ctx.Dr2;
    outInfo.dr3 = ctx.Dr3;
    outInfo.dr6 = ctx.Dr6;
    outInfo.dr7 = ctx.Dr7;
    outInfo.eax = static_cast<uint64_t>(static_cast<uint32_t>(ctx.Rax));
    outInfo.ebx = static_cast<uint64_t>(static_cast<uint32_t>(ctx.Rbx));
    outInfo.ecx = static_cast<uint64_t>(static_cast<uint32_t>(ctx.Rcx));
    outInfo.edx = static_cast<uint64_t>(static_cast<uint32_t>(ctx.Rdx));
    outInfo.esi = static_cast<uint64_t>(static_cast<uint32_t>(ctx.Rsi));
    outInfo.edi = static_cast<uint64_t>(static_cast<uint32_t>(ctx.Rdi));
    outInfo.ebp = static_cast<uint64_t>(static_cast<uint32_t>(ctx.Rbp));
    outInfo.esp = static_cast<uint64_t>(static_cast<uint32_t>(ctx.Rsp));
    outInfo.eip = static_cast<uint64_t>(static_cast<uint32_t>(ctx.Rip));
    outInfo.eflags = ctx.EFlags;
#else
    outInfo.isWow64 = 0;
    outInfo.architectureBits = 32;
    outInfo.instructionPointer = ctx.Eip;
    outInfo.stackPointer = ctx.Esp;
    outInfo.framePointer = ctx.Ebp;
    outInfo.flags = ctx.EFlags;
    outInfo.rax = ctx.Eax;
    outInfo.rbx = ctx.Ebx;
    outInfo.rcx = ctx.Ecx;
    outInfo.rdx = ctx.Edx;
    outInfo.rsi = ctx.Esi;
    outInfo.rdi = ctx.Edi;
    outInfo.rbp = ctx.Ebp;
    outInfo.rsp = ctx.Esp;
    outInfo.rip = ctx.Eip;
    outInfo.r8 = 0;
    outInfo.r9 = 0;
    outInfo.r10 = 0;
    outInfo.r11 = 0;
    outInfo.r12 = 0;
    outInfo.r13 = 0;
    outInfo.r14 = 0;
    outInfo.r15 = 0;
    outInfo.dr0 = ctx.Dr0;
    outInfo.dr1 = ctx.Dr1;
    outInfo.dr2 = ctx.Dr2;
    outInfo.dr3 = ctx.Dr3;
    outInfo.dr6 = ctx.Dr6;
    outInfo.dr7 = ctx.Dr7;
    outInfo.eax = ctx.Eax;
    outInfo.ebx = ctx.Ebx;
    outInfo.ecx = ctx.Ecx;
    outInfo.edx = ctx.Edx;
    outInfo.esi = ctx.Esi;
    outInfo.edi = ctx.Edi;
    outInfo.ebp = ctx.Ebp;
    outInfo.esp = ctx.Esp;
    outInfo.eip = ctx.Eip;
    outInfo.eflags = ctx.EFlags;
#endif
    return true;
}

bool Debugger::FillStackFrameByIndex(uint32_t index, uint32_t frameIndex, WdblStackFrameInfo& outInfo) const {
    outInfo = WdblStackFrameInfo();
    std::vector<DWORD> threadIds = EnumerateThreadIds();
    if (index >= threadIds.size()) {
        return false;
    }

    const DWORD tid = threadIds[index];
    outInfo.index = frameIndex;
    outInfo.threadId = tid;
    outInfo.isCurrent = (stopState_.valid && tid == stopState_.threadId) ? 1u : 0u;

#if defined(_M_X64)
    if (IsWow64TargetProcess(processHandle_)) {
        WOW64_CONTEXT wowCtx = WOW64_CONTEXT();
        if (!CaptureWow64ThreadContextById(tid, wowCtx)) {
            return false;
        }
        const uint32_t sp = wowCtx.Esp;
        const size_t pointerSize = 4;
        const uint64_t slotAddress = static_cast<uint64_t>(sp) + static_cast<uint64_t>(frameIndex) * pointerSize;
        uint32_t slotValue = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(
                processHandle_,
                reinterpret_cast<LPCVOID>(slotAddress),
                &slotValue,
                sizeof(slotValue),
                &read) ||
            read != sizeof(slotValue)) {
            return false;
        }
        const uint64_t value64 = static_cast<uint64_t>(slotValue);
        outInfo.instructionPointer = value64;
        outInfo.stackPointer = slotAddress;
        outInfo.framePointer = static_cast<uint64_t>(sp);
        outInfo.returnAddress = value64;
        outInfo.sourceLine = 0;
        outInfo.sourceDisplacement = 0;
        CopyWideText(outInfo.symbol, ResolveSymbol(value64));
        std::wstring filePath;
        uint32_t line = 0;
        uint32_t displacement = 0;
        if (ResolveSourceLocation(value64, filePath, line, displacement)) {
            outInfo.sourceLine = line;
            outInfo.sourceDisplacement = displacement;
            CopyWideText(outInfo.sourcePath, filePath);
        }
        return true;
    }
#endif

    CONTEXT ctx = CONTEXT();
    if (!CaptureThreadContext(tid, ctx)) {
        return false;
    }

#if defined(_M_X64)
    const uint64_t rsp = ctx.Rsp;
    const size_t pointerSize = 8;
    const uint64_t slotAddress = rsp + static_cast<uint64_t>(frameIndex) * pointerSize;
    uint64_t slotValue = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(
            processHandle_,
            reinterpret_cast<LPCVOID>(slotAddress),
            &slotValue,
            sizeof(slotValue),
            &read) ||
        read != sizeof(slotValue)) {
        return false;
    }
    outInfo.instructionPointer = slotValue;
    outInfo.stackPointer = slotAddress;
    outInfo.framePointer = rsp;
    outInfo.returnAddress = slotValue;
    CopyWideText(outInfo.symbol, ResolveSymbol(slotValue));
    std::wstring filePath;
    uint32_t line = 0;
    uint32_t displacement = 0;
    if (ResolveSourceLocation(slotValue, filePath, line, displacement)) {
        outInfo.sourceLine = line;
        outInfo.sourceDisplacement = displacement;
        CopyWideText(outInfo.sourcePath, filePath);
    }
    return true;
#else
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!thread) {
        return false;
    }
    STACKFRAME64 frame = STACKFRAME64();
    DWORD machineType = IMAGE_FILE_MACHINE_I386;
    frame.AddrPC.Offset = ctx.Eip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = ctx.Ebp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = ctx.Esp;
    frame.AddrStack.Mode = AddrModeFlat;
    for (uint32_t i = 0; i < frameIndex; ++i) {
        if (!StackWalk64(machineType, processHandle_, thread, &frame, &ctx, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
            CloseHandle(thread);
            return false;
        }
        if (frame.AddrPC.Offset == 0) {
            CloseHandle(thread);
            return false;
        }
    }
    outInfo.instructionPointer = frame.AddrPC.Offset;
    outInfo.stackPointer = frame.AddrStack.Offset;
    outInfo.framePointer = frame.AddrFrame.Offset;
    outInfo.returnAddress = frame.AddrPC.Offset;
    CopyWideText(outInfo.symbol, ResolveSymbol(frame.AddrPC.Offset));
    std::wstring filePath;
    uint32_t line = 0;
    uint32_t displacement = 0;
    if (ResolveSourceLocation(frame.AddrPC.Offset, filePath, line, displacement)) {
        outInfo.sourceLine = line;
        outInfo.sourceDisplacement = displacement;
        CopyWideText(outInfo.sourcePath, filePath);
    }
    CloseHandle(thread);
    return true;
#endif
}

std::wstring Debugger::ModulePathFromBase(uint64_t moduleBase, DWORD processId) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return L"";
    }

    MODULEENTRY32W me = MODULEENTRY32W();
    me.dwSize = sizeof(me);
    std::wstring result;
    if (Module32FirstW(snapshot, &me)) {
        do {
            const uint64_t base = reinterpret_cast<uint64_t>(me.modBaseAddr);
            if (base == moduleBase) {
                result = me.szExePath;
                break;
            }
        } while (Module32NextW(snapshot, &me));
    }
    CloseHandle(snapshot);
    return result;
}

void Debugger::DispatchPluginEvent(const WdblPluginEvent& eventData) {
    if (pluginEventDispatchActive_) {
        return;
    }
    pluginEventDispatchActive_ = true;
    std::vector<int> targets;
    targets.reserve(pluginModules_.size());
 for (auto __rangeIt35 = (pluginModules_).begin(); __rangeIt35 != (pluginModules_).end(); ++__rangeIt35) {
        const auto& module = *__rangeIt35;
        if (module.enabled && module.subscribedEvents && module.onEvent != nullptr) {
            targets.push_back(module.id);
        }
    }

 for (auto __rangeIt36 = (targets).begin(); __rangeIt36 != (targets).end(); ++__rangeIt36) {
        int moduleId = *__rangeIt36;
        auto it = std::find_if(pluginModules_.begin(), pluginModules_.end(), [&](const PluginModule& module) {
            return module.id == moduleId;
        });
        if (it == pluginModules_.end() || !it->enabled || !it->subscribedEvents || it->onEvent == nullptr) {
            continue;
        }
        activePluginDispatchIndex_ = static_cast<int>(std::distance(pluginModules_.begin(), it));
        it->onEvent(it->context, &eventData);
    }
    activePluginDispatchIndex_ = -1;
    pluginEventDispatchActive_ = false;
}

bool Debugger::LoadPluginModule(const std::wstring& path) {
    std::wstring pluginPath = TrimWhitespace(path);
    if (pluginPath.empty()) {
        std::wcout << L"Plugin path cannot be empty.\n";
        return false;
    }

    pluginPath = CanonicalizePathBestEffort(pluginPath);

    const std::wstring loweredPath = ToLower(pluginPath);
 for (auto __rangeIt37 = (pluginModules_).begin(); __rangeIt37 != (pluginModules_).end(); ++__rangeIt37) {
        const auto& module = *__rangeIt37;
        if (ToLower(module.path) == loweredPath) {
            std::wcout << L"Plugin already loaded: #" << module.id << L" " << module.name << L"\n";
            return true;
        }
    }

    HMODULE handle = LoadLibraryW(pluginPath.c_str());
    if (handle == nullptr) {
        std::wcout << L"LoadLibrary failed for plugin: " << pluginPath << L"\n";
        return false;
    }

    auto getInfo = reinterpret_cast<WdblPluginGetInfoFn>(GetProcAddress(handle, "WdblPluginGetInfo"));
    auto initialize = reinterpret_cast<WdblPluginInitializeFn>(GetProcAddress(handle, "WdblPluginInitialize"));
    auto execute = reinterpret_cast<WdblPluginExecuteFn>(GetProcAddress(handle, "WdblPluginExecute"));
    auto shutdown = reinterpret_cast<WdblPluginShutdownFn>(GetProcAddress(handle, "WdblPluginShutdown"));
    auto onEvent = reinterpret_cast<WdblPluginOnEventFn>(GetProcAddress(handle, "WdblPluginOnEvent"));
    if (getInfo == nullptr || initialize == nullptr || execute == nullptr) {
        std::wcout << L"Plugin exports are incomplete. Required: WdblPluginGetInfo, WdblPluginInitialize, WdblPluginExecute\n";
        FreeLibrary(handle);
        return false;
    }

    WdblPluginInfo info = WdblPluginInfo();
    info.size = sizeof(WdblPluginInfo);
    if (getInfo(&info) == 0) {
        std::wcout << L"WdblPluginGetInfo failed.\n";
        FreeLibrary(handle);
        return false;
    }
    if (info.apiVersion != WDBL_PLUGIN_API_VERSION) {
        std::wcout << L"Incompatible plugin API version. Plugin=" << info.apiVersion
                   << L", Host=" << WDBL_PLUGIN_API_VERSION << L"\n";
        FreeLibrary(handle);
        return false;
    }

    std::wstring pluginName = TrimWhitespace(info.name);
    if (pluginName.empty()) {
        pluginName = FileNameFromPath(pluginPath);
    }
    if (pluginName.empty()) {
        pluginName = L"Plugin";
    }

    bool uniqueName = true;
 for (auto __rangeIt38 = (pluginModules_).begin(); __rangeIt38 != (pluginModules_).end(); ++__rangeIt38) {
        const auto& module = *__rangeIt38;
        if (ToLower(module.name) == ToLower(pluginName)) {
            uniqueName = false;
            break;
        }
    }
    if (!uniqueName) {
        pluginName += L"_" + ToWStringCompat(nextPluginId_);
    }

    WdblHostApi hostApi = WdblHostApi();
    hostApi.size = sizeof(WdblHostApi);
    hostApi.apiVersion = WDBL_PLUGIN_API_VERSION;
    hostApi.context = this;
    hostApi.log = &Debugger::PluginHostLogThunk;
    hostApi.execute = &Debugger::PluginHostExecuteThunk;
    hostApi.getStopInfo = &Debugger::PluginHostGetStopInfoThunk;
    hostApi.subscribeEvents = &Debugger::PluginHostSubscribeEventsThunk;
    hostApi.debuggerApi = &debuggerApi_;

    PluginModule module = PluginModule();
    module.id = nextPluginId_++;
    module.module = handle;
    module.path = pluginPath;
    module.name = pluginName;
    module.version = TrimWhitespace(info.version);
    module.description = TrimWhitespace(info.description);
    module.execute = execute;
    module.shutdown = shutdown;
    module.onEvent = onEvent;
    module.enabled = true;
    module.subscribedEvents = true;
    pluginModules_.push_back(module);

    const size_t moduleIndex = pluginModules_.size() - 1;
    activePluginDispatchIndex_ = static_cast<int>(moduleIndex);
    void* pluginContext = nullptr;
    if (initialize(&hostApi, &pluginContext) == 0) {
        std::wcout << L"WdblPluginInitialize failed.\n";
        activePluginDispatchIndex_ = -1;
        if (pluginModules_[moduleIndex].module != nullptr) {
            FreeLibrary(pluginModules_[moduleIndex].module);
        }
        pluginModules_.erase(pluginModules_.begin() + static_cast<std::vector<PluginModule>::difference_type>(moduleIndex));
        return false;
    }
    activePluginDispatchIndex_ = -1;
    pluginModules_[moduleIndex].context = pluginContext;

    const PluginModule& loaded = pluginModules_[moduleIndex];
    std::wcout << L"Loaded plugin #" << loaded.id << L": " << loaded.name;
    if (!loaded.version.empty()) {
        std::wcout << L" v" << loaded.version;
    }
    std::wcout << L"\n";
    if (!loaded.description.empty()) {
        std::wcout << L"  " << loaded.description << L"\n";
    }
    return true;
}

bool Debugger::UnloadPluginModule(const std::wstring& token) {
    const std::wstring trimmed = TrimWhitespace(token);
    if (trimmed.empty()) {
        std::wcout << L"Usage: plugin unload <id|name|*>\n";
        return false;
    }
    if (trimmed == L"*") {
        if (activePluginDispatchIndex_ >= 0 &&
            activePluginDispatchIndex_ < static_cast<int>(pluginModules_.size())) {
            std::wcout << L"Cannot unload all plugins while a plugin callback is running.\n";
            return false;
        }
        UnloadAllPluginModules();
        return true;
    }

    PluginModule* module = FindPluginModule(trimmed);
    if (module == nullptr) {
        std::wcout << L"Plugin not found: " << trimmed << L"\n";
        return false;
    }
    const int removeId = module->id;

    auto it = std::find_if(pluginModules_.begin(), pluginModules_.end(), [&](const PluginModule& candidate) {
        return candidate.id == removeId;
    });
    if (it == pluginModules_.end()) {
        return false;
    }
    if (activePluginDispatchIndex_ >= 0 &&
        activePluginDispatchIndex_ < static_cast<int>(pluginModules_.size()) &&
        pluginModules_[static_cast<size_t>(activePluginDispatchIndex_)].id == it->id) {
        std::wcout << L"Cannot unload plugin while it is executing callbacks: " << it->name << L"\n";
        return false;
    }

    const std::wstring removedName = it->name;
    const size_t removeIndex = static_cast<size_t>(std::distance(pluginModules_.begin(), it));
    if (activePluginDispatchIndex_ == static_cast<int>(removeIndex)) {
        activePluginDispatchIndex_ = -1;
    }
    if (it->shutdown != nullptr) {
        it->shutdown(it->context);
    }
    if (it->module != nullptr) {
        FreeLibrary(it->module);
    }
    pluginModules_.erase(it);
    std::wcout << L"Unloaded plugin: " << removedName << L"\n";
    return true;
}

void Debugger::UnloadAllPluginModules() {
    activePluginDispatchIndex_ = -1;
    for (auto it = pluginModules_.rbegin(); it != pluginModules_.rend(); ++it) {
        if (it->shutdown != nullptr) {
            it->shutdown(it->context);
        }
        if (it->module != nullptr) {
            FreeLibrary(it->module);
        }
    }
    pluginModules_.clear();
}

void Debugger::ListPluginModules() const {
    std::wcout << L"--- Plugins ---\n";
    if (pluginModules_.empty()) {
        std::wcout << L"(none)\n";
        return;
    }
 for (auto __rangeIt39 = (pluginModules_).begin(); __rangeIt39 != (pluginModules_).end(); ++__rangeIt39) {
        const auto& module = *__rangeIt39;
        std::wcout << L"[#" << module.id << L"] " << module.name;
        if (!module.version.empty()) {
            std::wcout << L" v" << module.version;
        }
        std::wcout << L" enabled=" << (module.enabled ? L"yes" : L"no")
                   << L" events=" << (module.subscribedEvents ? L"yes" : L"no") << L"\n";
        if (!module.description.empty()) {
            std::wcout << L"  " << module.description << L"\n";
        }
        std::wcout << L"  Path: " << module.path << L"\n";
    }
}

bool Debugger::ExecutePluginModule(const std::wstring& token, const std::wstring& args) {
    PluginModule* module = FindPluginModule(token);
    if (module == nullptr) {
        std::wcout << L"Plugin not found: " << token << L"\n";
        return false;
    }
    if (!module->enabled) {
        std::wcout << L"Plugin is disabled: " << module->name << L"\n";
        return false;
    }
    if (module->execute == nullptr) {
        std::wcout << L"Plugin does not export WdblPluginExecute.\n";
        return false;
    }
    const int moduleId = module->id;
    const std::wstring moduleName = module->name;
    const size_t moduleIndex = static_cast<size_t>(module - pluginModules_.data());
    activePluginDispatchIndex_ = static_cast<int>(moduleIndex);
    const int32_t ok = module->execute(module->context, args.c_str());
    activePluginDispatchIndex_ = -1;
    if (ok == 0) {
        std::wcout << L"Plugin execution failed: " << moduleName << L"\n";
        return false;
    }
    (void)moduleId;
    return true;
}

bool Debugger::SetPluginModuleEnabled(const std::wstring& token, bool enabled) {
    PluginModule* module = FindPluginModule(token);
    if (module == nullptr) {
        std::wcout << L"Plugin not found: " << token << L"\n";
        return false;
    }
    module->enabled = enabled;
    std::wcout << L"Plugin #" << module->id << L" (" << module->name << L") "
               << (enabled ? L"enabled." : L"disabled.") << L"\n";
    return true;
}

void Debugger::AutoLoadPluginModules() {
    std::vector<std::wstring> pluginDirs;

    wchar_t currentDir[MAX_PATH] = {};
    const DWORD cwdLen = GetCurrentDirectoryW(MAX_PATH, currentDir);
    if (cwdLen > 0 && cwdLen < MAX_PATH) {
        pluginDirs.push_back(std::wstring(currentDir) + L"\\plugins");
    }

    wchar_t modulePath[MAX_PATH] = {};
    const DWORD moduleLen = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (moduleLen > 0 && moduleLen < MAX_PATH) {
        std::wstring exeDir(modulePath);
        const size_t slash = exeDir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            exeDir = exeDir.substr(0, slash);
            pluginDirs.push_back(exeDir + L"\\plugins");
        }
    }

    std::unordered_set<std::wstring> seenDirs;
 for (auto __rangeIt40 = (pluginDirs).begin(); __rangeIt40 != (pluginDirs).end(); ++__rangeIt40) {
        const auto& dir = *__rangeIt40;
        const std::wstring lowerDir = ToLower(dir);
        if (!seenDirs.insert(lowerDir).second) {
            continue;
        }
        if (!DirectoryExists(dir)) {
            continue;
        }

        WIN32_FIND_DATAW findData = WIN32_FIND_DATAW();
        const std::wstring pattern = JoinPath(dir, L"*");
        HANDLE findHandle = FindFirstFileW(pattern.c_str(), &findData);
        if (findHandle == INVALID_HANDLE_VALUE) {
            continue;
        }

        do {
            const std::wstring name = findData.cFileName;
            if (name == L"." || name == L"..") {
                continue;
            }
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                continue;
            }
            const std::wstring fullPath = JoinPath(dir, name);
            const std::wstring ext = ToLower(FileExtension(fullPath));
            if (ext != L".dll") {
                continue;
            }
            LoadPluginModule(fullPath);
        } while (FindNextFileW(findHandle, &findData));

        FindClose(findHandle);
    }
}

const wchar_t kWinDbgLiteMemDriverServiceName[] = L"WinDbgLiteMemDrv";
const wchar_t kWinDbgLiteMemDriverDisplayName[] = L"WinDbgLite Memory Driver";
const wchar_t kWinDbgLiteMemDriverFileName[] = L"WinDbgLiteMemDrv.sys";
const wchar_t kWinDbgLiteVehAgentFileName[] = L"Z0BDbgVehAgent.dll";

HANDLE g_wdblVehPipe = INVALID_HANDLE_VALUE;
HANDLE g_wdblVehReaderThread = nullptr;
DWORD g_wdblVehProcessId = 0;
DWORD g_wdblVehLastThreadId = 0;
bool g_wdblVehPreferred = false;
volatile LONG g_wdblVehReaderRunning = 0;
volatile LONG g_wdblVehNextRequestId = 1;
volatile LONG g_wdblVehBreakPending = 0;
bool g_wdblVehLastContextValid = false;
WdblVehContextResponse g_wdblVehLastContext = {};
int g_wdblVehStepOverBreakpointId = -1;
uint64_t g_wdblVehStepOverBreakpointAddress = 0;
uint64_t g_wdblVehAgentBase = 0;
bool g_wdblVehPendingStoppedContextValid = false;
WdblVehContextRequest g_wdblVehPendingStoppedContext = {};

struct WdblVehCachedModule {
    uint64_t baseAddress;
    uint32_t sizeOfImage;
    std::wstring fullName;
    std::wstring baseName;
};

std::map<uint64_t, WdblVehCachedModule> g_wdblVehModules;
std::unordered_set<DWORD> g_wdblVehThreads;

std::wstring BuildVehPipeName(DWORD processId) {
    std::wstringstream ss;
    ss << WDBL_VEH_PIPE_PREFIX << processId;
    return ss.str();
}

std::wstring GetCurrentExecutableDirectory() {
    wchar_t modulePath[MAX_PATH] = {};
    const DWORD moduleLen = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (moduleLen == 0 || moduleLen >= MAX_PATH) {
        return L"";
    }
    return ParentDirectoryPath(modulePath);
}

void AddVehAgentDllCandidate(
    const std::wstring& path,
    std::vector<std::wstring>* candidates,
    std::unordered_set<std::wstring>* seen) {
    if (path.empty() || candidates == nullptr || seen == nullptr) {
        return;
    }
    const std::wstring normalized = NormalizePathSeparators(path);
    const std::wstring key = ToLowerCopy(normalized);
    if (seen->insert(key).second) {
        candidates->push_back(normalized);
    }
}

void AddVehAgentDllCandidatesFromAnchor(
    const std::wstring& anchor,
    const std::wstring& platformDir,
    std::vector<std::wstring>* candidates,
    std::unordered_set<std::wstring>* seen) {
    std::wstring current = NormalizePathSeparators(anchor);
    for (int depth = 0; depth < 8 && !current.empty(); ++depth) {
        AddVehAgentDllCandidate(JoinPath(current, kWinDbgLiteVehAgentFileName), candidates, seen);
        AddVehAgentDllCandidate(JoinPath(JoinPath(current, L"VehAgent"), kWinDbgLiteVehAgentFileName), candidates, seen);
        AddVehAgentDllCandidate(
            JoinPath(JoinPath(JoinPath(JoinPath(current, L"BuildVS2010"), L"Build"), L"Bin"), platformDir) +
                L"\\" + kWinDbgLiteVehAgentFileName,
            candidates,
            seen);
        AddVehAgentDllCandidate(
            JoinPath(JoinPath(JoinPath(current, L"Build"), L"Bin"), L"Release") +
                L"\\" + platformDir + L"\\" + kWinDbgLiteVehAgentFileName,
            candidates,
            seen);

        const std::wstring parent = ParentDirectoryPath(current);
        if (parent.empty() || parent == current) {
            break;
        }
        current = parent;
    }
}

std::wstring FindVehAgentDllPath(const std::wstring& explicitPath, HANDLE targetProcess) {
    if (!explicitPath.empty()) {
        return explicitPath;
    }

    const bool wantX86 = targetProcess != nullptr && DetermineDisassemblyModeBits(targetProcess) == 32;
    const std::wstring platformDir = wantX86 ? L"x86" : L"x64";
    std::vector<std::wstring> candidates;
    std::unordered_set<std::wstring> seen;
    const std::wstring exeDir = GetCurrentExecutableDirectory();
    if (!exeDir.empty()) {
        AddVehAgentDllCandidate(JoinPath(JoinPath(exeDir, platformDir), kWinDbgLiteVehAgentFileName), &candidates, &seen);
        AddVehAgentDllCandidate(JoinPath(JoinPath(ParentDirectoryPath(exeDir), platformDir), kWinDbgLiteVehAgentFileName), &candidates, &seen);
        AddVehAgentDllCandidatesFromAnchor(exeDir, platformDir, &candidates, &seen);
        AddVehAgentDllCandidate(JoinPath(exeDir, kWinDbgLiteVehAgentFileName), &candidates, &seen);
    }

    wchar_t currentDir[MAX_PATH] = {};
    const DWORD cwdLen = GetCurrentDirectoryW(MAX_PATH, currentDir);
    if (cwdLen > 0 && cwdLen < MAX_PATH) {
        AddVehAgentDllCandidatesFromAnchor(currentDir, platformDir, &candidates, &seen);
    }

    for (size_t i = 0; i < candidates.size(); ++i) {
        if (PathExists(candidates[i])) {
            return candidates[i];
        }
    }
    return exeDir.empty() ? kWinDbgLiteVehAgentFileName : JoinPath(exeDir, kWinDbgLiteVehAgentFileName);
}

bool ReadExactPipe(HANDLE pipe, void* buffer, DWORD size) {
    BYTE* cursor = static_cast<BYTE*>(buffer);
    DWORD remaining = size;
    while (remaining != 0) {
        DWORD read = 0;
        if (!ReadFile(pipe, cursor, remaining, &read, nullptr) || read == 0) {
            return false;
        }
        cursor += read;
        remaining -= read;
    }
    return true;
}

bool WriteExactPipe(HANDLE pipe, const void* buffer, DWORD size) {
    const BYTE* cursor = static_cast<const BYTE*>(buffer);
    DWORD remaining = size;
    while (remaining != 0) {
        DWORD written = 0;
        if (!WriteFile(pipe, cursor, remaining, &written, nullptr) || written == 0) {
            return false;
        }
        cursor += written;
        remaining -= written;
    }
    return true;
}

const DWORD kVehLaunchWaitMs = 3000;

void SendVehContinue(HANDLE pipe, DWORD disposition);
bool StartVehSession(DWORD processId, const std::wstring& dllPath, std::wstring* detail);
struct PreparedRemoteLdrLoadDll;
bool StartVehSessionWithProcessHandle(DWORD processId, HANDLE processHandle, const PreparedRemoteLdrLoadDll* preparedLoad, const std::wstring& dllPath, std::wstring* detail);
bool AllocateRemoteDllPath(HANDLE process, const std::wstring& dllPath, LPVOID* remotePath, std::wstring* detail);
bool PrepareRemoteLdrLoadDllBlock(HANDLE process, const std::wstring& dllPath, PreparedRemoteLdrLoadDll* prepared, std::wstring* detail);
uint64_t WaitForRemoteModuleBaseWithProcessHandle(HANDLE process, DWORD processId, const std::wstring& moduleName, DWORD timeoutMilliseconds);

void CloseVehSession() {
    if (g_wdblVehPipe != INVALID_HANDLE_VALUE) {
        if (InterlockedCompareExchange(&g_wdblVehBreakPending, 0, 0) != 0) {
            SendVehContinue(g_wdblVehPipe, WDBL_VEH_CONTINUE_EXECUTION);
            InterlockedExchange(&g_wdblVehBreakPending, 0);
            Sleep(50);
        }
        WdblVehMessageHeader shutdown = {};
        shutdown.version = WDBL_VEH_PROTOCOL_VERSION;
        shutdown.type = WDBL_VEH_MSG_SHUTDOWN;
        shutdown.size = sizeof(shutdown);
        WriteExactPipe(g_wdblVehPipe, &shutdown, sizeof(shutdown));
    }
    InterlockedExchange(&g_wdblVehReaderRunning, 0);
    if (g_wdblVehPipe != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_wdblVehPipe);
        DisconnectNamedPipe(g_wdblVehPipe);
        CloseHandle(g_wdblVehPipe);
        g_wdblVehPipe = INVALID_HANDLE_VALUE;
    }
    if (g_wdblVehReaderThread != nullptr) {
        WaitForSingleObject(g_wdblVehReaderThread, 1000);
        CloseHandle(g_wdblVehReaderThread);
        g_wdblVehReaderThread = nullptr;
    }
    g_wdblVehProcessId = 0;
    g_wdblVehLastThreadId = 0;
    InterlockedExchange(&g_wdblVehBreakPending, 0);
    g_wdblVehLastContextValid = false;
    g_wdblVehLastContext = WdblVehContextResponse();
    g_wdblVehStepOverBreakpointId = -1;
    g_wdblVehStepOverBreakpointAddress = 0;
    g_wdblVehAgentBase = 0;
    g_wdblVehPendingStoppedContextValid = false;
    g_wdblVehPendingStoppedContext = WdblVehContextRequest();
    g_wdblVehModules.clear();
    g_wdblVehThreads.clear();
}

void SendVehContinue(HANDLE pipe, DWORD disposition) {
    WdblVehContinueMessage reply = {};
    reply.header.version = WDBL_VEH_PROTOCOL_VERSION;
    reply.header.type = WDBL_VEH_MSG_CONTINUE;
    reply.header.size = sizeof(reply);
    reply.disposition = disposition;
    if (g_wdblVehPendingStoppedContextValid) {
        reply.contextFlags = g_wdblVehPendingStoppedContext.contextFlags;
        reply.threadId = g_wdblVehPendingStoppedContext.threadId;
        reply.ip = g_wdblVehPendingStoppedContext.ip;
        reply.sp = g_wdblVehPendingStoppedContext.sp;
        reply.fp = g_wdblVehPendingStoppedContext.fp;
        reply.ax = g_wdblVehPendingStoppedContext.ax;
        reply.bx = g_wdblVehPendingStoppedContext.bx;
        reply.cx = g_wdblVehPendingStoppedContext.cx;
        reply.dx = g_wdblVehPendingStoppedContext.dx;
        reply.si = g_wdblVehPendingStoppedContext.si;
        reply.di = g_wdblVehPendingStoppedContext.di;
        reply.flags = g_wdblVehPendingStoppedContext.flags;
    }
    WriteExactPipe(pipe, &reply, sizeof(reply));
    g_wdblVehPendingStoppedContextValid = false;
    g_wdblVehPendingStoppedContext = WdblVehContextRequest();
}

bool CanSendVehRequest(std::wstring* detail) {
    if (g_wdblVehPipe == INVALID_HANDLE_VALUE) {
        if (detail != nullptr) {
            *detail = L"VEH agent is not active.";
        }
        return false;
    }
    if (InterlockedCompareExchange(&g_wdblVehBreakPending, 0, 0) != 0) {
        if (detail != nullptr) {
            *detail = L"VEH is stopped at an exception. Use g before sending agent requests.";
        }
        return false;
    }
    return true;
}

bool SendVehSoftwareBreakpointRequest(DWORD type, DWORD breakpointId, uint64_t address, std::wstring* detail) {
    DWORD flags = 0;
    if (!CanSendVehRequest(detail)) {
        return false;
    }

    WdblVehSoftwareBreakpointRequest request = {};
    request.header.version = WDBL_VEH_PROTOCOL_VERSION;
    request.header.type = type;
    request.header.size = sizeof(request);
    request.requestId = static_cast<DWORD>(InterlockedIncrement(&g_wdblVehNextRequestId));
    request.breakpointId = breakpointId;
    request.flags = flags;
    request.address = address;
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool SendVehSoftwareBreakpointRequestEx(DWORD type, DWORD breakpointId, uint64_t address, DWORD flags, std::wstring* detail) {
    if (!CanSendVehRequest(detail)) {
        return false;
    }

    WdblVehSoftwareBreakpointRequest request = {};
    request.header.version = WDBL_VEH_PROTOCOL_VERSION;
    request.header.type = type;
    request.header.size = sizeof(request);
    request.requestId = static_cast<DWORD>(InterlockedIncrement(&g_wdblVehNextRequestId));
    request.breakpointId = breakpointId;
    request.flags = flags;
    request.address = address;
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool SendVehMemoryRequest(DWORD type, uint64_t address, const std::vector<uint8_t>& data, DWORD size, std::wstring* detail) {
    if (!CanSendVehRequest(detail)) {
        return false;
    }
    if (size == 0 || size > WDBL_VEH_MAX_MEMORY_BYTES || data.size() > WDBL_VEH_MAX_MEMORY_BYTES) {
        if (detail != nullptr) {
            *detail = L"VEH memory request size must be 1..256.";
        }
        return false;
    }

    WdblVehMemoryRequest request = {};
    request.header.version = WDBL_VEH_PROTOCOL_VERSION;
    request.header.type = type;
    request.header.size = sizeof(request);
    request.requestId = static_cast<DWORD>(InterlockedIncrement(&g_wdblVehNextRequestId));
    request.address = address;
    request.size = size;
    for (size_t i = 0; i < data.size() && i < WDBL_VEH_MAX_MEMORY_BYTES; ++i) {
        request.data[i] = data[i];
    }
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH memory request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool SendVehHardwareBreakpointRequest(DWORD type, const HardwareBreakpoint& bp, std::wstring* detail) {
    if (!CanSendVehRequest(detail)) {
        return false;
    }

    WdblVehHardwareBreakpointRequest request = {};
    request.header.version = WDBL_VEH_PROTOCOL_VERSION;
    request.header.type = type;
    request.header.size = sizeof(request);
    request.requestId = static_cast<DWORD>(InterlockedIncrement(&g_wdblVehNextRequestId));
    request.breakpointId = static_cast<DWORD>(bp.id);
    request.slot = static_cast<DWORD>(bp.slot);
    request.access = static_cast<DWORD>(bp.access.value);
    request.length = static_cast<DWORD>(bp.length);
    request.threadId = bp.threadId;
    request.address = bp.address;
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH hardware breakpoint request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool SendVehMemoryBreakpointRequest(DWORD type, const MemoryBreakpoint& bp, std::wstring* detail) {
    if (!CanSendVehRequest(detail)) {
        return false;
    }

    WdblVehMemoryBreakpointRequest request = {};
    request.header.version = WDBL_VEH_PROTOCOL_VERSION;
    request.header.type = type;
    request.header.size = sizeof(request);
    request.requestId = static_cast<DWORD>(InterlockedIncrement(&g_wdblVehNextRequestId));
    request.breakpointId = static_cast<DWORD>(bp.id);
    request.access = static_cast<DWORD>(bp.access.value);
    request.address = bp.address;
    request.size = bp.size;
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH memory breakpoint request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool SendVehContextRequest(const WdblVehContextRequest& input, DWORD type, std::wstring* detail) {
    if (!CanSendVehRequest(detail)) {
        return false;
    }

    WdblVehContextRequest request = input;
    request.header.version = WDBL_VEH_PROTOCOL_VERSION;
    request.header.type = type;
    request.header.size = sizeof(request);
    request.requestId = static_cast<DWORD>(InterlockedIncrement(&g_wdblVehNextRequestId));
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH context request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool SendVehThreadControlRequest(DWORD type, DWORD threadId, std::wstring* detail) {
    if (!CanSendVehRequest(detail)) {
        return false;
    }

    WdblVehThreadControlRequest request = {};
    request.header.version = WDBL_VEH_PROTOCOL_VERSION;
    request.header.type = type;
    request.header.size = sizeof(request);
    request.requestId = static_cast<DWORD>(InterlockedIncrement(&g_wdblVehNextRequestId));
    request.threadId = threadId;
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH thread request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool SendVehExceptionPolicyRequest(DWORD policy, std::wstring* detail) {
    if (!CanSendVehRequest(detail)) {
        return false;
    }

    WdblVehExceptionPolicyRequest request = {};
    request.header.version = WDBL_VEH_PROTOCOL_VERSION;
    request.header.type = WDBL_VEH_MSG_REQ_SET_EXCEPTION_POLICY;
    request.header.size = sizeof(request);
    request.requestId = static_cast<DWORD>(InterlockedIncrement(&g_wdblVehNextRequestId));
    request.policy = policy;
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH exception policy request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool SendVehExceptionPolicyRequestEx(DWORD policy, DWORD exceptionCode, std::wstring* detail) {
    if (!CanSendVehRequest(detail)) {
        return false;
    }

    WdblVehExceptionPolicyRequest request = {};
    request.header.version = WDBL_VEH_PROTOCOL_VERSION;
    request.header.type = WDBL_VEH_MSG_REQ_SET_EXCEPTION_POLICY;
    request.header.size = sizeof(request);
    request.requestId = static_cast<DWORD>(InterlockedIncrement(&g_wdblVehNextRequestId));
    request.policy = policy;
    request.exceptionCode = exceptionCode;
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH exception policy request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool SendVehSimpleRequest(DWORD type, std::wstring* detail) {
    if (!CanSendVehRequest(detail)) {
        return false;
    }

    WdblVehMessageHeader request = {};
    request.version = WDBL_VEH_PROTOCOL_VERSION;
    request.type = type;
    request.size = sizeof(request);
    if (!WriteExactPipe(g_wdblVehPipe, &request, sizeof(request))) {
        if (detail != nullptr) {
            *detail = L"Write VEH request failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    return true;
}

bool ReadVehOutputDebugString(const WdblVehExceptionMessage& message, std::wstring* outText) {
    if (outText == nullptr) {
        return false;
    }
    outText->clear();
    if (message.parameterCount == 0 || message.parameters[0] == 0) {
        return false;
    }

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, message.processId);
    if (process == nullptr) {
        return false;
    }

    const bool wide = message.exceptionCode == WDBL_DBG_PRINTEXCEPTION_WIDE_C;
    const size_t maxChars = 4096;
    for (DWORD candidateIndex = 0; candidateIndex < message.parameterCount && candidateIndex < 2; ++candidateIndex) {
        const uint64_t stringAddress = message.parameters[candidateIndex];
        if (stringAddress == 0 || stringAddress < 0x10000) {
            continue;
        }
        if (wide) {
        std::wstring text;
        for (size_t i = 0; i < maxChars; ++i) {
            wchar_t ch = L'\0';
            SIZE_T read = 0;
            if (!ReadProcessMemory(
                    process,
                        reinterpret_cast<LPCVOID>(stringAddress + static_cast<uint64_t>(i * sizeof(wchar_t))),
                    &ch,
                    sizeof(ch),
                    &read) ||
                read != sizeof(ch)) {
                break;
            }
            if (ch == L'\0') {
                break;
            }
            text.push_back(ch);
        }
            if (!text.empty()) {
                *outText = text;
                CloseHandle(process);
                return true;
            }
        } else {
        std::string text;
        for (size_t i = 0; i < maxChars; ++i) {
            char ch = '\0';
            SIZE_T read = 0;
            if (!ReadProcessMemory(
                    process,
                        reinterpret_cast<LPCVOID>(stringAddress + static_cast<uint64_t>(i)),
                    &ch,
                    sizeof(ch),
                    &read) ||
                read != sizeof(ch)) {
                break;
            }
            if (ch == '\0') {
                break;
            }
            text.push_back(ch);
        }
            if (!text.empty()) {
                *outText = MultiByteToWide(text, CP_ACP, 0);
                CloseHandle(process);
                return !outText->empty();
            }
        }
    }
    CloseHandle(process);
    return false;
}

void PrintVehModules(const std::wstring& filter = L"") {
    std::wcout << L"--- VEH Modules ---\n";
    if (g_wdblVehModules.empty()) {
        std::wcout << L"(none)\n";
        return;
    }
    const std::wstring lowerFilter = ToLowerCopy(filter);
    for (auto it = g_wdblVehModules.begin(); it != g_wdblVehModules.end(); ++it) {
        const WdblVehCachedModule& module = it->second;
        if (!lowerFilter.empty()) {
            const std::wstring name = ToLowerCopy(module.baseName);
            const std::wstring path = ToLowerCopy(module.fullName);
            if (name.find(lowerFilter) == std::wstring::npos &&
                path.find(lowerFilter) == std::wstring::npos) {
                continue;
            }
        }
        std::wcout << ToHex(module.baseAddress) << L" size=0x" << std::hex << module.sizeOfImage << std::dec
                   << L" " << (module.baseName.empty() ? module.fullName : module.baseName) << L"\n";
    }
}

void PrintVehThreads() {
    std::wcout << L"--- VEH Threads ---\n";
    if (g_wdblVehThreads.empty()) {
        std::wcout << L"(none)\n";
        return;
    }
    for (auto it = g_wdblVehThreads.begin(); it != g_wdblVehThreads.end(); ++it) {
        std::wcout << L"tid=" << *it << L"\n";
    }
}

void PrintVehContext(const WdblVehContextResponse& message) {
    std::wcout << L"  ip=" << ToHex(message.ip)
               << L" sp=" << ToHex(message.sp)
               << L" fp=" << ToHex(message.fp)
               << L" flags=" << ToHex(message.flags) << L"\n";
    std::wcout << L"  ax=" << ToHex(message.ax)
               << L" bx=" << ToHex(message.bx)
               << L" cx=" << ToHex(message.cx)
               << L" dx=" << ToHex(message.dx)
               << L" si=" << ToHex(message.si)
               << L" di=" << ToHex(message.di) << L"\n";
}

bool IsVehAgentActive() {
    return g_wdblVehPreferred && g_wdblVehPipe != INVALID_HANDLE_VALUE;
}

bool IsVehBreakPending() {
    return IsVehAgentActive() && InterlockedCompareExchange(&g_wdblVehBreakPending, 0, 0) != 0;
}

DWORD GetDefaultVehThreadId() {
    if (g_wdblVehLastThreadId != 0) {
        return g_wdblVehLastThreadId;
    }
    if (!g_wdblVehThreads.empty()) {
        return *g_wdblVehThreads.begin();
    }
    return 0;
}

bool FillVehContextRegister(WdblVehContextRequest& request, const std::wstring& reg, uint64_t value) {
    const std::wstring name = ToLowerCopy(reg);
    if (name == L"ip" || name == L"rip" || name == L"eip") {
        request.contextFlags = WDBL_VEH_CONTEXT_IP;
        request.ip = value;
        return true;
    }
    if (name == L"sp" || name == L"rsp" || name == L"esp") {
        request.contextFlags = WDBL_VEH_CONTEXT_SP;
        request.sp = value;
        return true;
    }
    if (name == L"fp" || name == L"bp" || name == L"rbp" || name == L"ebp") {
        request.contextFlags = WDBL_VEH_CONTEXT_FP;
        request.fp = value;
        return true;
    }
    if (name == L"ax" || name == L"rax" || name == L"eax") {
        request.contextFlags = WDBL_VEH_CONTEXT_AX;
        request.ax = value;
        return true;
    }
    if (name == L"bx" || name == L"rbx" || name == L"ebx") {
        request.contextFlags = WDBL_VEH_CONTEXT_BX;
        request.bx = value;
        return true;
    }
    if (name == L"cx" || name == L"rcx" || name == L"ecx") {
        request.contextFlags = WDBL_VEH_CONTEXT_CX;
        request.cx = value;
        return true;
    }
    if (name == L"dx" || name == L"rdx" || name == L"edx") {
        request.contextFlags = WDBL_VEH_CONTEXT_DX;
        request.dx = value;
        return true;
    }
    if (name == L"si" || name == L"rsi" || name == L"esi") {
        request.contextFlags = WDBL_VEH_CONTEXT_SI;
        request.si = value;
        return true;
    }
    if (name == L"di" || name == L"rdi" || name == L"edi") {
        request.contextFlags = WDBL_VEH_CONTEXT_DI;
        request.di = value;
        return true;
    }
    if (name == L"flags" || name == L"eflags" || name == L"rflags") {
        request.contextFlags = WDBL_VEH_CONTEXT_FLAGS;
        request.flags = value;
        return true;
    }
    return false;
}

void ApplyVehContextToCachedStop(const WdblVehContextRequest& request) {
    if (!g_wdblVehLastContextValid) {
        return;
    }
    if ((request.contextFlags & WDBL_VEH_CONTEXT_IP) != 0) g_wdblVehLastContext.ip = request.ip;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_SP) != 0) g_wdblVehLastContext.sp = request.sp;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_FP) != 0) g_wdblVehLastContext.fp = request.fp;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_AX) != 0) g_wdblVehLastContext.ax = request.ax;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_BX) != 0) g_wdblVehLastContext.bx = request.bx;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_CX) != 0) g_wdblVehLastContext.cx = request.cx;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_DX) != 0) g_wdblVehLastContext.dx = request.dx;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_SI) != 0) g_wdblVehLastContext.si = request.si;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_DI) != 0) g_wdblVehLastContext.di = request.di;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_FLAGS) != 0) g_wdblVehLastContext.flags = request.flags;
}

void QueueVehStoppedContextUpdate(const WdblVehContextRequest& request) {
    if (!g_wdblVehPendingStoppedContextValid) {
        g_wdblVehPendingStoppedContext = WdblVehContextRequest();
        g_wdblVehPendingStoppedContext.threadId = request.threadId;
        g_wdblVehPendingStoppedContextValid = true;
    }
    g_wdblVehPendingStoppedContext.contextFlags |= request.contextFlags;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_IP) != 0) g_wdblVehPendingStoppedContext.ip = request.ip;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_SP) != 0) g_wdblVehPendingStoppedContext.sp = request.sp;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_FP) != 0) g_wdblVehPendingStoppedContext.fp = request.fp;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_AX) != 0) g_wdblVehPendingStoppedContext.ax = request.ax;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_BX) != 0) g_wdblVehPendingStoppedContext.bx = request.bx;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_CX) != 0) g_wdblVehPendingStoppedContext.cx = request.cx;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_DX) != 0) g_wdblVehPendingStoppedContext.dx = request.dx;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_SI) != 0) g_wdblVehPendingStoppedContext.si = request.si;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_DI) != 0) g_wdblVehPendingStoppedContext.di = request.di;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_FLAGS) != 0) g_wdblVehPendingStoppedContext.flags = request.flags;
    ApplyVehContextToCachedStop(request);
}

bool VehSingleStep() {
    if (!IsVehBreakPending()) {
        return false;
    }
    SendVehContinue(g_wdblVehPipe, WDBL_VEH_CONTINUE_STEP);
    InterlockedExchange(&g_wdblVehBreakPending, 0);
    std::wcout << L"VEH step requested.\n";
    return true;
}

bool VehStepOver(HANDLE processHandle) {
    if (!IsVehBreakPending()) {
        return false;
    }
    if (!g_wdblVehLastContextValid || g_wdblVehLastContext.ip == 0) {
        return VehSingleStep();
    }

    const uint64_t ip = g_wdblVehLastContext.ip;
    const uint8_t modeBits = processHandle != nullptr ? DetermineDisassemblyModeBits(processHandle) : 64;
    uint8_t codeBuf[16] = {};
    SIZE_T readBytes = 0;
    if (processHandle == nullptr ||
        !ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(ip), codeBuf, sizeof(codeBuf), &readBytes) ||
        readBytes == 0) {
        return VehSingleStep();
    }

    const DecodedInstruction decoded = DecodeInstruction(ip, codeBuf, readBytes, modeBits);
    const std::wstring mnemonic = ToLowerCopy(decoded.text);
    const size_t insnLen = decoded.length > 0 ? static_cast<size_t>(decoded.length) : 1;
    const uint64_t nextAddr = ip + insnLen;

    const bool isCall = (mnemonic.find(L"call") == 0);
    const bool isRepOrLoop = (mnemonic.find(L"rep") == 0 || mnemonic.find(L"loop") == 0);
    const bool isInt = (mnemonic.find(L"int") == 0);
    const bool overable = (isCall || isRepOrLoop || isInt) && nextAddr != 0;
    if (!overable) {
        return VehSingleStep();
    }

    if (g_wdblVehStepOverBreakpointId >= 0) {
        std::wstring detail;
        SendVehSoftwareBreakpointRequestEx(
            WDBL_VEH_MSG_REQ_REMOVE_SOFTWARE_BREAKPOINT,
            static_cast<DWORD>(g_wdblVehStepOverBreakpointId),
            g_wdblVehStepOverBreakpointAddress,
            WDBL_VEH_BREAKPOINT_FLAG_TEMPORARY,
            &detail);
        g_wdblVehStepOverBreakpointId = -1;
        g_wdblVehStepOverBreakpointAddress = 0;
    }

    const int tempId = static_cast<int>(InterlockedIncrement(&g_wdblVehNextRequestId)) | 0x40000000;
    std::wstring detail;
    if (!SendVehSoftwareBreakpointRequestEx(
            WDBL_VEH_MSG_REQ_SET_SOFTWARE_BREAKPOINT,
            static_cast<DWORD>(tempId),
            nextAddr,
            WDBL_VEH_BREAKPOINT_FLAG_TEMPORARY,
            &detail)) {
        std::wcout << L"VEH step-over temp breakpoint failed: " << detail << L"\n";
        return false;
    }
    g_wdblVehStepOverBreakpointId = tempId;
    g_wdblVehStepOverBreakpointAddress = nextAddr;
    SendVehContinue(g_wdblVehPipe, WDBL_VEH_CONTINUE_EXECUTION);
    InterlockedExchange(&g_wdblVehBreakPending, 0);
    std::wcout << L"VEH step-over temp breakpoint #" << tempId
               << L" set at " << ToHex(nextAddr) << L".\n";
    return true;
}

DWORD WINAPI VehReaderThreadProc(LPVOID param) {
    HANDLE pipe = reinterpret_cast<HANDLE>(param);
    while (InterlockedCompareExchange(&g_wdblVehReaderRunning, 1, 1) != 0) {
        WdblVehMessageHeader header = {};
        if (!ReadExactPipe(pipe, &header, sizeof(header))) {
            break;
        }
        if (header.version != WDBL_VEH_PROTOCOL_VERSION || header.size < sizeof(header)) {
            break;
        }

        if (header.type == WDBL_VEH_MSG_EXCEPTION && header.size == sizeof(WdblVehExceptionMessage)) {
            WdblVehExceptionMessage message = {};
            message.header = header;
            if (!ReadExactPipe(pipe, reinterpret_cast<BYTE*>(&message) + sizeof(header), sizeof(message) - sizeof(header))) {
                break;
            }
            g_wdblVehLastThreadId = message.threadId;
            g_wdblVehLastContext = WdblVehContextResponse();
            g_wdblVehLastContext.threadId = message.threadId;
            g_wdblVehLastContext.status = 1;
            g_wdblVehLastContext.ip = message.instructionPointer;
            g_wdblVehLastContext.sp = message.stackPointer;
            g_wdblVehLastContext.fp = message.framePointer;
            g_wdblVehLastContextValid = true;
            std::wcout << L"[VEH] exception pid=" << message.processId
                       << L" tid=" << message.threadId
                       << L" code=" << ToHex(message.exceptionCode, 8)
                       << L" ip=" << ToHex(message.instructionPointer);
            const bool stepComplete = (message.reserved & WDBL_VEH_EXCEPTION_FLAG_STEP_COMPLETE) != 0;
            const bool outputDebugString = (message.reserved & WDBL_VEH_EXCEPTION_FLAG_OUTPUT_DEBUG_STRING) != 0;
            const bool autoContinue = (message.reserved & WDBL_VEH_EXCEPTION_FLAG_CONTINUE_EXECUTION) != 0;
            const bool policyBreak = (message.reserved & WDBL_VEH_EXCEPTION_FLAG_POLICY_BREAK) != 0;
            const bool hardwareBreakpoint = (message.reserved & WDBL_VEH_EXCEPTION_FLAG_HARDWARE_BREAKPOINT) != 0;
            const bool memoryBreakpoint = (message.reserved & WDBL_VEH_EXCEPTION_FLAG_MEMORY_BREAKPOINT) != 0;
            if (message.breakpointId != 0) {
                std::wcout << L" bp=#" << message.breakpointId
                           << L" addr=" << ToHex(message.breakpointAddress);
                if (g_wdblVehStepOverBreakpointId == static_cast<int>(message.breakpointId)) {
                    g_wdblVehStepOverBreakpointId = -1;
                    g_wdblVehStepOverBreakpointAddress = 0;
                }
            }
            if (stepComplete) {
                std::wcout << L" step-complete";
            }
            if (policyBreak) {
                std::wcout << L" policy-break";
            }
            if (hardwareBreakpoint) {
                std::wcout << L" hw-bp";
            }
            if (memoryBreakpoint) {
                std::wcout << L" mem-bp";
            }
            if (outputDebugString) {
                std::wstring debugText;
                if (ReadVehOutputDebugString(message, &debugText)) {
                    std::wcout << L" output=\"" << debugText << L"\"";
                } else {
                    std::wcout << L" output=<unreadable>";
                }
            }
            std::wcout
                       << L"\n";
            if (outputDebugString || autoContinue) {
                SendVehContinue(pipe, WDBL_VEH_CONTINUE_EXECUTION);
            } else if (message.breakpointId != 0 || stepComplete || policyBreak) {
                InterlockedExchange(&g_wdblVehBreakPending, 1);
                std::wcout << L"[VEH] stopped. Use g to continue.\n";
            } else {
                SendVehContinue(pipe, WDBL_VEH_CONTINUE_SEARCH);
            }
            continue;
        }

        if ((header.type == WDBL_VEH_MSG_MODULE_LOAD || header.type == WDBL_VEH_MSG_MODULE_UNLOAD) &&
            header.size == sizeof(WdblVehModuleMessage)) {
            WdblVehModuleMessage message = {};
            message.header = header;
            if (!ReadExactPipe(pipe, reinterpret_cast<BYTE*>(&message) + sizeof(header), sizeof(message) - sizeof(header))) {
                break;
            }
            if (header.type == WDBL_VEH_MSG_MODULE_LOAD) {
                WdblVehCachedModule cached = {};
                cached.baseAddress = message.baseAddress;
                cached.sizeOfImage = message.sizeOfImage;
                cached.fullName = message.fullName;
                cached.baseName = message.baseName;
                g_wdblVehModules[message.baseAddress] = cached;
            } else {
                g_wdblVehModules.erase(message.baseAddress);
            }
            std::wcout << L"[VEH] module "
                       << (header.type == WDBL_VEH_MSG_MODULE_LOAD ? L"load" : L"unload")
                       << L" pid=" << message.processId
                       << L" tid=" << message.threadId
                       << L" base=" << ToHex(message.baseAddress)
                       << L" size=0x" << std::hex << message.sizeOfImage << std::dec
                       << L" name=" << (message.baseName[0] != L'\0' ? message.baseName : message.fullName)
                       << L"\n";
            continue;
        }

        if ((header.type == WDBL_VEH_MSG_THREAD_CREATE || header.type == WDBL_VEH_MSG_THREAD_EXIT) &&
            header.size == sizeof(WdblVehThreadMessage)) {
            WdblVehThreadMessage message = {};
            message.header = header;
            if (!ReadExactPipe(pipe, reinterpret_cast<BYTE*>(&message) + sizeof(header), sizeof(message) - sizeof(header))) {
                break;
            }
            if (header.type == WDBL_VEH_MSG_THREAD_CREATE) {
                g_wdblVehThreads.insert(message.threadId);
            } else {
                g_wdblVehThreads.erase(message.threadId);
            }
            std::wcout << L"[VEH] thread "
                       << (header.type == WDBL_VEH_MSG_THREAD_CREATE ? L"create" : L"exit")
                       << L" pid=" << message.processId
                       << L" tid=" << message.threadId
                       << L"\n";
            continue;
        }

        if (header.type == WDBL_VEH_MSG_RESPONSE && header.size == sizeof(WdblVehResponseMessage)) {
            WdblVehResponseMessage message = {};
            message.header = header;
            if (!ReadExactPipe(pipe, reinterpret_cast<BYTE*>(&message) + sizeof(header), sizeof(message) - sizeof(header))) {
                break;
            }
            std::wcout << L"[VEH] response req=" << message.requestId
                       << L" status=" << (message.status != 0 ? L"ok" : L"fail")
                       << L" value=" << message.value;
            if (message.errorCode != 0) {
                std::wcout << L" error=" << message.errorCode;
            }
            if (message.text[0] != L'\0') {
                std::wcout << L" " << message.text;
            }
            std::wcout << L"\n";
            continue;
        }

        if (header.type == WDBL_VEH_MSG_MEMORY_RESPONSE && header.size == sizeof(WdblVehMemoryResponse)) {
            WdblVehMemoryResponse message = {};
            message.header = header;
            if (!ReadExactPipe(pipe, reinterpret_cast<BYTE*>(&message) + sizeof(header), sizeof(message) - sizeof(header))) {
                break;
            }
            std::wcout << L"[VEH] memory req=" << message.requestId
                       << L" status=" << (message.status != 0 ? L"ok" : L"fail")
                       << L" addr=" << ToHex(message.address)
                       << L" bytes=" << message.bytesTransferred;
            if (message.errorCode != 0) {
                std::wcout << L" error=" << message.errorCode;
            }
            std::wcout << L"\n";
            if (message.status != 0 && message.bytesTransferred != 0) {
                std::wcout << L"  ";
                for (DWORD i = 0; i < message.bytesTransferred && i < WDBL_VEH_MAX_MEMORY_BYTES; ++i) {
                    std::wcout << ToHex(static_cast<uint64_t>(message.data[i]), 2) << L" ";
                }
                std::wcout << L"\n";
            }
            continue;
        }

        if (header.type == WDBL_VEH_MSG_CONTEXT_RESPONSE && header.size == sizeof(WdblVehContextResponse)) {
            WdblVehContextResponse message = {};
            message.header = header;
            if (!ReadExactPipe(pipe, reinterpret_cast<BYTE*>(&message) + sizeof(header), sizeof(message) - sizeof(header))) {
                break;
            }
            std::wcout << L"[VEH] context req=" << message.requestId
                       << L" status=" << (message.status != 0 ? L"ok" : L"fail")
                       << L" tid=" << message.threadId;
            if (message.errorCode != 0) {
                std::wcout << L" error=" << message.errorCode;
            }
            std::wcout << L"\n";
            if (message.status != 0) {
                g_wdblVehLastContext = message;
                g_wdblVehLastContextValid = true;
                PrintVehContext(message);
            }
            continue;
        }

        if (header.type == WDBL_VEH_MSG_PROCESS_EXIT && header.size == sizeof(WdblVehProcessExitMessage)) {
            WdblVehProcessExitMessage message = {};
            message.header = header;
            if (!ReadExactPipe(pipe, reinterpret_cast<BYTE*>(&message) + sizeof(header), sizeof(message) - sizeof(header))) {
                break;
            }
            std::wcout << L"[VEH] process exit pid=" << message.processId
                       << L" tid=" << message.threadId
                       << L" exit=" << message.exitCode << L"\n";
            break;
        }

        if (header.type == WDBL_VEH_MSG_SNAPSHOT_BEGIN || header.type == WDBL_VEH_MSG_SNAPSHOT_END) {
            if (header.type == WDBL_VEH_MSG_SNAPSHOT_BEGIN) {
                g_wdblVehModules.clear();
                g_wdblVehThreads.clear();
            }
            std::wcout << L"[VEH] snapshot "
                       << (header.type == WDBL_VEH_MSG_SNAPSHOT_BEGIN ? L"begin" : L"end")
                       << L"\n";
            continue;
        }

        if (header.type == WDBL_VEH_MSG_SHUTDOWN) {
            break;
        }

        const DWORD remaining = header.size - sizeof(header);
        std::vector<BYTE> discard(remaining);
        if (remaining != 0 && !ReadExactPipe(pipe, discard.data(), remaining)) {
            break;
        }
    }
    const LONG wasRunning = InterlockedExchange(&g_wdblVehReaderRunning, 0);
    if (wasRunning != 0 && g_wdblVehPipe == pipe) {
        CloseHandle(pipe);
        g_wdblVehPipe = INVALID_HANDLE_VALUE;
        g_wdblVehProcessId = 0;
        g_wdblVehLastThreadId = 0;
        InterlockedExchange(&g_wdblVehBreakPending, 0);
        g_wdblVehLastContextValid = false;
        g_wdblVehLastContext = WdblVehContextResponse();
        g_wdblVehStepOverBreakpointId = -1;
        g_wdblVehStepOverBreakpointAddress = 0;
        g_wdblVehAgentBase = 0;
        g_wdblVehPendingStoppedContextValid = false;
        g_wdblVehPendingStoppedContext = WdblVehContextRequest();
        g_wdblVehModules.clear();
        g_wdblVehThreads.clear();
        std::wcout << L"[VEH] agent disconnected.\n";
    }
    return 0;
}

uint64_t FindRemoteModuleBaseByHandle(HANDLE process, const std::wstring& moduleName) {
    if (process == nullptr) {
        return 0;
    }
    const std::wstring wanted = ToLowerCopy(moduleName);
    HMODULE modules[1024] = {};
    DWORD bytesNeeded = 0;
    DWORD filter = LIST_MODULES_ALL;
#if !defined(_M_X64)
    filter = LIST_MODULES_32BIT;
#endif
    if (!EnumProcessModulesEx(process, modules, sizeof(modules), &bytesNeeded, filter)) {
        return 0;
    }
    const DWORD count = std::min<DWORD>(
        bytesNeeded / sizeof(HMODULE),
        static_cast<DWORD>(sizeof(modules) / sizeof(modules[0])));
    for (DWORD i = 0; i < count; ++i) {
        wchar_t nameBuffer[MAX_PATH] = {};
        if (GetModuleBaseNameW(process, modules[i], nameBuffer, MAX_PATH) == 0) {
            continue;
        }
        if (ToLowerCopy(nameBuffer) == wanted) {
            return reinterpret_cast<uint64_t>(modules[i]);
        }
    }
    return 0;
}

uint64_t FindRemoteModuleBase(DWORD processId, const std::wstring& moduleName) {
    const std::wstring wanted = ToLowerCopy(moduleName);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me = MODULEENTRY32W();
        me.dwSize = sizeof(me);
        BOOL ok = Module32FirstW(snapshot, &me);
        while (ok) {
            const std::wstring name = ToLowerCopy(me.szModule);
            if (name == wanted) {
                const uint64_t base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                CloseHandle(snapshot);
                return base;
            }
            ok = Module32NextW(snapshot, &me);
        }
        CloseHandle(snapshot);
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (process == nullptr) {
        return 0;
    }

    const uint64_t base = FindRemoteModuleBaseByHandle(process, moduleName);
    CloseHandle(process);
    return base;
}

uint64_t WaitForRemoteModuleBase(DWORD processId, const std::wstring& moduleName, DWORD timeoutMilliseconds) {
    const DWORD start = GetTickCount();
    for (;;) {
        const uint64_t base = FindRemoteModuleBase(processId, moduleName);
        if (base != 0) {
            return base;
        }
        if (timeoutMilliseconds == 0 || GetTickCount() - start >= timeoutMilliseconds) {
            return 0;
        }
        Sleep(50);
    }
}

uint64_t WaitForRemoteModuleBaseWithProcessHandle(
    HANDLE process,
    DWORD processId,
    const std::wstring& moduleName,
    DWORD timeoutMilliseconds) {
    const DWORD start = GetTickCount();
    for (;;) {
        uint64_t base = FindRemoteModuleBaseByHandle(process, moduleName);
        if (base == 0) {
            base = FindRemoteModuleBase(processId, moduleName);
        }
        if (base != 0) {
            return base;
        }
        DWORD exitCode = 0;
        if (process != nullptr && GetExitCodeProcess(process, &exitCode) && exitCode != STILL_ACTIVE) {
            return 0;
        }
        if (timeoutMilliseconds == 0 || GetTickCount() - start >= timeoutMilliseconds) {
            return 0;
        }
        Sleep(50);
    }
}

uint64_t ResolveRemoteExportAddress(HANDLE process, uint64_t moduleBase, const char* exportName) {
    if (process == nullptr || moduleBase == 0 || exportName == nullptr) {
        return 0;
    }

    IMAGE_DOS_HEADER dos = IMAGE_DOS_HEADER();
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(moduleBase), &dos, sizeof(dos), &read) ||
        read != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0) {
        return 0;
    }

    const uint64_t ntAddress = moduleBase + static_cast<uint64_t>(dos.e_lfanew);
    IMAGE_NT_HEADERS64 nt64 = IMAGE_NT_HEADERS64();
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(ntAddress), &nt64, sizeof(nt64), &read) ||
        read < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) ||
        nt64.Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    DWORD exportRva = 0;
    DWORD exportSize = 0;
    if (nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        exportRva = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportSize = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        IMAGE_NT_HEADERS32 nt32 = IMAGE_NT_HEADERS32();
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(ntAddress), &nt32, sizeof(nt32), &read) ||
            read < sizeof(nt32) ||
            nt32.Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }
        exportRva = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportSize = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    if (exportRva == 0) {
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY exportDir = IMAGE_EXPORT_DIRECTORY();
    if (!ReadProcessMemory(
            process,
            reinterpret_cast<LPCVOID>(moduleBase + static_cast<uint64_t>(exportRva)),
            &exportDir,
            sizeof(exportDir),
            &read) ||
        read != sizeof(exportDir) ||
        exportDir.NumberOfNames == 0 ||
        exportDir.NumberOfFunctions == 0) {
        return 0;
    }

    std::vector<DWORD> nameRvas(exportDir.NumberOfNames);
    std::vector<WORD> ordinals(exportDir.NumberOfNames);
    std::vector<DWORD> functionRvas(exportDir.NumberOfFunctions);
    if (!ReadProcessMemory(
            process,
            reinterpret_cast<LPCVOID>(moduleBase + static_cast<uint64_t>(exportDir.AddressOfNames)),
            &nameRvas[0],
            static_cast<SIZE_T>(nameRvas.size() * sizeof(DWORD)),
            &read) ||
        read < sizeof(DWORD)) {
        return 0;
    }
    if (!ReadProcessMemory(
            process,
            reinterpret_cast<LPCVOID>(moduleBase + static_cast<uint64_t>(exportDir.AddressOfNameOrdinals)),
            &ordinals[0],
            static_cast<SIZE_T>(ordinals.size() * sizeof(WORD)),
            &read) ||
        read < sizeof(WORD)) {
        return 0;
    }
    if (!ReadProcessMemory(
            process,
            reinterpret_cast<LPCVOID>(moduleBase + static_cast<uint64_t>(exportDir.AddressOfFunctions)),
            &functionRvas[0],
            static_cast<SIZE_T>(functionRvas.size() * sizeof(DWORD)),
            &read) ||
        read < sizeof(DWORD)) {
        return 0;
    }

    for (size_t i = 0; i < nameRvas.size(); ++i) {
        std::string name;
        if (!ReadProcessAnsiCString(process, moduleBase + static_cast<uint64_t>(nameRvas[i]), name, 128)) {
            continue;
        }
        if (name != exportName) {
            continue;
        }
        const WORD ordinal = ordinals[i];
        if (ordinal >= functionRvas.size()) {
            return 0;
        }
        const DWORD rva = functionRvas[ordinal];
        if (exportSize != 0 && rva >= exportRva && rva < exportRva + exportSize) {
            return 0;
        }
        return moduleBase + static_cast<uint64_t>(rva);
    }
    return 0;
}

bool AllocateRemoteDllPath(HANDLE process, const std::wstring& dllPath, LPVOID* remotePath, std::wstring* detail) {
    if (process == nullptr) {
        if (detail != nullptr) {
            *detail = L"Invalid process handle.";
        }
        return false;
    }
    if (remotePath == nullptr) {
        if (detail != nullptr) {
            *detail = L"Invalid remote path output.";
        }
        return false;
    }
    *remotePath = nullptr;

    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID allocated = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocated == nullptr) {
        if (detail != nullptr) {
            *detail = L"VirtualAllocEx failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, allocated, dllPath.c_str(), bytes, &written) || written != bytes) {
        if (detail != nullptr) {
            *detail = L"WriteProcessMemory failed. LastError=" + ToWStringCompat(GetLastError());
        }
        VirtualFreeEx(process, allocated, 0, MEM_RELEASE);
        return false;
    }
    *remotePath = allocated;
    return true;
}

struct RemoteUnicodeString64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Reserved;
    ULONGLONG Buffer;
};

struct RemoteLdrLoadDllParameter64 {
    ULONGLONG LdrLoadDll;
    ULONGLONG UnicodeString;
    ULONGLONG ModuleHandle;
    LONG Status;
    ULONG Reserved;
    ULONGLONG Module;
};

typedef LONG (WINAPI* NtCreateThreadExFn)(
    PHANDLE,
    ACCESS_MASK,
    PVOID,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    SIZE_T,
    SIZE_T,
    SIZE_T,
    PVOID);

size_t AlignUpSize(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

NtCreateThreadExFn ResolveNtCreateThreadEx() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll != nullptr
        ? reinterpret_cast<NtCreateThreadExFn>(GetProcAddress(ntdll, "NtCreateThreadEx"))
        : nullptr;
}

bool StartRemoteThreadWithNtCreateThreadEx(
    HANDLE process,
    LPVOID startAddress,
    LPVOID parameter,
    HANDLE* thread,
    std::wstring* detail) {
    if (process == nullptr || startAddress == nullptr || thread == nullptr) {
        if (detail != nullptr) {
            *detail = L"Invalid NtCreateThreadEx state.";
        }
        return false;
    }

    NtCreateThreadExFn ntCreateThreadEx = ResolveNtCreateThreadEx();
    if (ntCreateThreadEx == nullptr) {
        if (detail != nullptr) {
            *detail = L"Cannot resolve local ntdll!NtCreateThreadEx.";
        }
        return false;
    }

    *thread = nullptr;
    const LONG status = ntCreateThreadEx(
        thread,
        THREAD_ALL_ACCESS,
        nullptr,
        process,
        startAddress,
        parameter,
        0,
        0,
        0,
        0,
        nullptr);
    if (status < 0 || *thread == nullptr) {
        if (detail != nullptr) {
            *detail = L"NtCreateThreadEx failed. status=" + ToHex(static_cast<uint32_t>(status), 8) +
                      L" thread=" + ToHex(reinterpret_cast<uint64_t>(*thread));
        }
        if (*thread != nullptr) {
            CloseHandle(*thread);
            *thread = nullptr;
        }
        return false;
    }
    return true;
}

void FreePreparedRemoteLdrLoadDllBlock(HANDLE process, const PreparedRemoteLdrLoadDll& prepared) {
    if (process != nullptr && prepared.block != nullptr) {
        VirtualFreeEx(process, prepared.block, 0, MEM_RELEASE);
    }
}

bool PrepareRemoteLdrLoadDllBlock(HANDLE process, const std::wstring& dllPath, PreparedRemoteLdrLoadDll* prepared, std::wstring* detail) {
#if !defined(_M_X64)
    UNREFERENCED_PARAMETER(process);
    UNREFERENCED_PARAMETER(dllPath);
    UNREFERENCED_PARAMETER(prepared);
    if (detail != nullptr) {
        *detail = L"LdrLoadDll VEH launch injection is only implemented for x64 CLI.";
    }
    return false;
#else
    if (process == nullptr || prepared == nullptr) {
        if (detail != nullptr) {
            *detail = L"Invalid LdrLoadDll preparation state.";
        }
        return false;
    }
    *prepared = PreparedRemoteLdrLoadDll();

    static const BYTE stub[] = {
        0x53,                               // push rbx
        0x48, 0x83, 0xEC, 0x20,             // sub rsp, 20h
        0x48, 0x8B, 0xD9,                   // mov rbx, rcx
        0x48, 0x8B, 0x03,                   // mov rax, [rbx]
        0x33, 0xC9,                         // xor ecx, ecx
        0x33, 0xD2,                         // xor edx, edx
        0x4C, 0x8B, 0x43, 0x08,             // mov r8, [rbx+8]
        0x4C, 0x8B, 0x4B, 0x10,             // mov r9, [rbx+10h]
        0xFF, 0xD0,                         // call rax
        0x89, 0x43, 0x18,                   // mov [rbx+18h], eax
        0x48, 0x8B, 0x43, 0x20,             // mov rax, [rbx+20h]
        0x48, 0x83, 0xC4, 0x20,             // add rsp, 20h
        0x5B,                               // pop rbx
        0xC3                                // ret
    };

    const size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    const size_t unicodeOffset = AlignUpSize(pathBytes, 8);
    const size_t parameterOffset = unicodeOffset + sizeof(RemoteUnicodeString64);
    const size_t stubOffset = AlignUpSize(parameterOffset + sizeof(RemoteLdrLoadDllParameter64), 16);
    const size_t totalBytes = stubOffset + sizeof(stub);

    BYTE* block = static_cast<BYTE*>(VirtualAllocEx(process, nullptr, totalBytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (block == nullptr) {
        if (detail != nullptr) {
            *detail = L"VirtualAllocEx Ldr block failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }

    RemoteUnicodeString64 unicodeString = RemoteUnicodeString64();
    unicodeString.Length = static_cast<USHORT>(dllPath.size() * sizeof(wchar_t));
    unicodeString.MaximumLength = static_cast<USHORT>(pathBytes);
    unicodeString.Buffer = reinterpret_cast<ULONGLONG>(block);

    RemoteLdrLoadDllParameter64 parameter = RemoteLdrLoadDllParameter64();
    parameter.UnicodeString = reinterpret_cast<ULONGLONG>(block + unicodeOffset);
    parameter.ModuleHandle = reinterpret_cast<ULONGLONG>(block + parameterOffset + 32);

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, block, dllPath.c_str(), pathBytes, &written) || written != pathBytes ||
        !WriteProcessMemory(process, block + unicodeOffset, &unicodeString, sizeof(unicodeString), &written) || written != sizeof(unicodeString) ||
        !WriteProcessMemory(process, block + parameterOffset, &parameter, sizeof(parameter), &written) || written != sizeof(parameter) ||
        !WriteProcessMemory(process, block + stubOffset, stub, sizeof(stub), &written) || written != sizeof(stub)) {
        const DWORD error = GetLastError();
        VirtualFreeEx(process, block, 0, MEM_RELEASE);
        if (detail != nullptr) {
            *detail = L"WriteProcessMemory Ldr block failed. LastError=" + ToWStringCompat(error);
        }
        return false;
    }

    prepared->block = block;
    prepared->parameter = block + parameterOffset;
    prepared->stub = block + stubOffset;
    return true;
#endif
}

bool RunRemoteLdrLoadDllBlock(
    HANDLE process,
    DWORD processId,
    const PreparedRemoteLdrLoadDll& prepared,
    bool freeRemoteBlock,
    std::wstring* detail) {
    if (process == nullptr || prepared.block == nullptr || prepared.parameter == nullptr || prepared.stub == nullptr) {
        if (detail != nullptr) {
            *detail = L"Invalid LdrLoadDll remote block.";
        }
        return false;
    }

    const uint64_t ntdllBase = WaitForRemoteModuleBaseWithProcessHandle(process, processId, L"ntdll.dll", 5000);
    const uint64_t ldrLoadDll = ResolveRemoteExportAddress(process, ntdllBase, "LdrLoadDll");
    if (ldrLoadDll == 0) {
        if (detail != nullptr) {
            *detail = L"Cannot resolve target ntdll!LdrLoadDll. ntdll=" + ToHex(ntdllBase);
        }
        if (freeRemoteBlock) {
            FreePreparedRemoteLdrLoadDllBlock(process, prepared);
        }
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, prepared.parameter, &ldrLoadDll, sizeof(ldrLoadDll), &written) ||
        written != sizeof(ldrLoadDll)) {
        if (detail != nullptr) {
            *detail = L"Write LdrLoadDll address failed. LastError=" + ToWStringCompat(GetLastError());
        }
        if (freeRemoteBlock) {
            FreePreparedRemoteLdrLoadDllBlock(process, prepared);
        }
        return false;
    }

    HANDLE thread = nullptr;
    if (!StartRemoteThreadWithNtCreateThreadEx(process, prepared.stub, prepared.parameter, &thread, detail)) {
        if (freeRemoteBlock) {
            FreePreparedRemoteLdrLoadDllBlock(process, prepared);
        }
        return false;
    }

    const DWORD waitResult = WaitForSingleObject(thread, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);
    CloseHandle(thread);

    RemoteLdrLoadDllParameter64 parameter = RemoteLdrLoadDllParameter64();
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, prepared.parameter, &parameter, sizeof(parameter), &read) ||
        read != sizeof(parameter)) {
        const DWORD error = GetLastError();
        if (freeRemoteBlock) {
            FreePreparedRemoteLdrLoadDllBlock(process, prepared);
        }
        if (detail != nullptr) {
            *detail = L"Read LdrLoadDll result failed. LastError=" + ToWStringCompat(error) +
                      L" read=" + ToWStringCompat(read) +
                      L" exit=" + ToWStringCompat(exitCode);
        }
        return false;
    }
    if (freeRemoteBlock) {
        FreePreparedRemoteLdrLoadDllBlock(process, prepared);
    }

    if (waitResult != WAIT_OBJECT_0) {
        if (detail != nullptr) {
            *detail = L"LdrLoadDll remote thread timeout. wait=" + ToWStringCompat(waitResult) +
                      L" exit=" + ToWStringCompat(exitCode);
        }
        return false;
    }
    if (parameter.Status < 0 || parameter.Module == 0) {
        if (detail != nullptr) {
            *detail = L"LdrLoadDll failed. status=" + ToHex(static_cast<uint32_t>(parameter.Status), 8) +
                      L" module=" + ToHex(parameter.Module);
        }
        return false;
    }
    return true;
}

bool InjectVehAgentDllWithProcessHandle(HANDLE process, DWORD processId, const std::wstring& dllPath, std::wstring* detail) {
    (void)processId;
    return InjectVehAgentDllCrossInject(process, dllPath, detail);
}

bool InjectVehAgentDll(DWORD processId, const std::wstring& dllPath, std::wstring* detail) {
    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        processId);
    if (process == nullptr) {
        if (detail != nullptr) {
            *detail = L"OpenProcess failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }

    const bool ok = InjectVehAgentDllWithProcessHandle(process, processId, dllPath, detail);
    CloseHandle(process);
    return ok;
}

bool CallRemoteKernel32Export(DWORD processId, const char* exportName, LPVOID parameter, DWORD waitMilliseconds, DWORD* exitCode, std::wstring* detail) {
    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ,
        FALSE,
        processId);
    if (process == nullptr) {
        if (detail != nullptr) {
            *detail = L"OpenProcess failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }

    const uint64_t kernel32Base = WaitForRemoteModuleBase(processId, L"kernel32.dll", 5000);
    const uint64_t remoteProc = ResolveRemoteExportAddress(process, kernel32Base, exportName);
    if (remoteProc == 0) {
        if (detail != nullptr) {
            *detail = L"Cannot resolve target kernel32 export. kernel32=" + ToHex(kernel32Base);
        }
        CloseHandle(process);
        return false;
    }

    HANDLE thread = nullptr;
    if (!StartRemoteThreadWithNtCreateThreadEx(
            process,
            reinterpret_cast<LPVOID>(remoteProc),
            parameter,
            &thread,
            detail)) {
        CloseHandle(process);
        return false;
    }

    DWORD waitResult = WaitForSingleObject(thread, waitMilliseconds);
    DWORD localExitCode = 0;
    GetExitCodeThread(thread, &localExitCode);
    if (exitCode != nullptr) {
        *exitCode = localExitCode;
    }
    CloseHandle(thread);
    CloseHandle(process);

    if (waitResult != WAIT_OBJECT_0 && waitMilliseconds != 0) {
        if (detail != nullptr) {
            *detail = L"Remote thread did not finish.";
        }
        return false;
    }
    return true;
}

bool BreakVehProcess(DWORD processId, std::wstring* detail) {
    DWORD exitCode = 0;
    return CallRemoteKernel32Export(processId, "DebugBreak", nullptr, 0, &exitCode, detail);
}

bool UnloadVehAgentDll(DWORD processId, uint64_t agentBase, std::wstring* detail) {
    if (processId == 0 || agentBase == 0) {
        if (detail != nullptr) {
            *detail = L"VEH agent base is not known.";
        }
        return false;
    }
    DWORD exitCode = 0;
    return CallRemoteKernel32Export(
        processId,
        "FreeLibrary",
        reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(agentBase)),
        5000,
        &exitCode,
        detail);
}

bool StartVehSessionWithProcessHandle(DWORD processId, HANDLE processHandle, const PreparedRemoteLdrLoadDll* preparedLoad, const std::wstring& dllPath, std::wstring* detail) {
    CloseVehSession();

    HANDLE targetProcess = processHandle != nullptr
        ? processHandle
        : OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    const std::wstring resolvedDll = FindVehAgentDllPath(dllPath, targetProcess);
    if (targetProcess != nullptr && targetProcess != processHandle) {
        CloseHandle(targetProcess);
    }
    if (!PathExists(resolvedDll)) {
        if (detail != nullptr) {
            *detail = L"Cannot find " + std::wstring(kWinDbgLiteVehAgentFileName) + L": " + resolvedDll;
        }
        return false;
    }

    const std::wstring pipeName = BuildVehPipeName(processId);
    HANDLE pipe = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
        1,
        4096,
        4096,
        0,
        nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        if (detail != nullptr) {
            *detail = L"CreateNamedPipeW failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }

    const bool injected = processHandle != nullptr
        ? InjectVehAgentDllWithProcessHandle(processHandle, processId, resolvedDll, detail)
        : InjectVehAgentDll(processId, resolvedDll, detail);
    if (!injected) {
        CloseHandle(pipe);
        return false;
    }

    bool pipeConnected = false;
    DWORD connectError = ERROR_SUCCESS;
    const DWORD connectStart = GetTickCount();
    while (GetTickCount() - connectStart < 10000) {
        if (ConnectNamedPipe(pipe, nullptr)) {
            pipeConnected = true;
            break;
        }
        connectError = GetLastError();
        if (connectError == ERROR_PIPE_CONNECTED) {
            pipeConnected = true;
            break;
        }
        if (connectError != ERROR_PIPE_LISTENING && connectError != ERROR_NO_DATA) {
            break;
        }
        Sleep(50);
    }
    if (!pipeConnected) {
        if (detail != nullptr) {
            *detail = L"VEH agent pipe connect failed. LastError=" + ToWStringCompat(connectError);
        }
        CloseHandle(pipe);
        return false;
    }
    DWORD pipeMode = PIPE_READMODE_BYTE | PIPE_WAIT;
    SetNamedPipeHandleState(pipe, &pipeMode, nullptr, nullptr);

    WdblVehMessageHeader header = {};
    if (!ReadExactPipe(pipe, &header, sizeof(header)) ||
        header.version != WDBL_VEH_PROTOCOL_VERSION ||
        header.type != WDBL_VEH_MSG_HELLO ||
        header.size != sizeof(WdblVehHelloMessage)) {
        if (detail != nullptr) {
            *detail = L"VEH agent hello failed.";
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return false;
    }

    WdblVehHelloMessage hello = {};
    hello.header = header;
    if (!ReadExactPipe(pipe, reinterpret_cast<BYTE*>(&hello) + sizeof(header), sizeof(hello) - sizeof(header))) {
        if (detail != nullptr) {
            *detail = L"VEH agent hello body read failed.";
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return false;
    }

    g_wdblVehPipe = pipe;
    g_wdblVehProcessId = processId;
    g_wdblVehAgentBase = hello.imageBase;
    InterlockedExchange(&g_wdblVehReaderRunning, 1);
    g_wdblVehReaderThread = CreateThread(nullptr, 0, VehReaderThreadProc, pipe, 0, nullptr);
    if (g_wdblVehReaderThread == nullptr) {
        InterlockedExchange(&g_wdblVehReaderRunning, 0);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        g_wdblVehPipe = INVALID_HANDLE_VALUE;
        g_wdblVehProcessId = 0;
        if (detail != nullptr) {
            *detail = L"Create VEH reader thread failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }
    if (detail != nullptr) {
        std::wstringstream ss;
        ss << L"VEH agent active. pid=" << hello.processId
           << L", tid=" << hello.threadId
           << L", imageBase=" << ToHex(hello.imageBase);
        *detail = ss.str();
    }
    return true;
}

bool StartVehSession(DWORD processId, const std::wstring& dllPath, std::wstring* detail) {
    return StartVehSessionWithProcessHandle(processId, nullptr, nullptr, dllPath, detail);
}

std::wstring GetSystemDriverPath() {
    wchar_t systemDir[MAX_PATH] = {};
    const UINT len = GetSystemDirectoryW(systemDir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return L"";
    }
    return JoinPath(JoinPath(systemDir, L"drivers"), kWinDbgLiteMemDriverFileName);
}

void AddDriverSourceCandidatesFromBase(
    const std::wstring& baseDir,
    std::vector<std::wstring>* candidates,
    std::unordered_set<std::wstring>* seen) {
    if (baseDir.empty() || candidates == nullptr || seen == nullptr) {
        return;
    }

    std::wstring current = NormalizePathSeparators(baseDir);
    for (int depth = 0; depth < 8 && !current.empty(); ++depth) {
        const std::wstring direct = JoinPath(current, kWinDbgLiteMemDriverFileName);
        const std::wstring directKey = ToLowerCopy(direct);
        if (seen->find(directKey) == seen->end()) {
            seen->insert(directKey);
            candidates->push_back(direct);
        }

        const std::wstring repoDriver = JoinPath(
            JoinPath(JoinPath(current, L"driver"), L"WinDbgLiteMemDrv"),
            kWinDbgLiteMemDriverFileName);
        const std::wstring repoDriverKey = ToLowerCopy(repoDriver);
        if (seen->find(repoDriverKey) == seen->end()) {
            seen->insert(repoDriverKey);
            candidates->push_back(repoDriver);
        }

        const std::wstring parent = ParentDirectoryPath(current);
        if (parent == current) {
            break;
        }
        current = parent;
    }
}

std::wstring FindPackagedDriverSysPath() {
    std::vector<std::wstring> candidates;
    std::unordered_set<std::wstring> seen;

    wchar_t modulePath[MAX_PATH] = {};
    const DWORD moduleLen = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (moduleLen > 0 && moduleLen < MAX_PATH) {
        AddDriverSourceCandidatesFromBase(ParentDirectoryPath(modulePath), &candidates, &seen);
    }

    wchar_t currentDir[MAX_PATH] = {};
    const DWORD cwdLen = GetCurrentDirectoryW(MAX_PATH, currentDir);
    if (cwdLen > 0 && cwdLen < MAX_PATH) {
        AddDriverSourceCandidatesFromBase(currentDir, &candidates, &seen);
    }

 for (auto __rangeItDriverPath = (candidates).begin(); __rangeItDriverPath != (candidates).end(); ++__rangeItDriverPath) {
        const std::wstring& path = *__rangeItDriverPath;
        if (PathExists(path)) {
            return path;
        }
    }
    return L"";
}

bool QueryServiceState(SC_HANDLE service, DWORD* outState) {
    if (outState == nullptr) {
        return false;
    }
    SERVICE_STATUS_PROCESS status = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytesNeeded)) {
        return false;
    }
    *outState = status.dwCurrentState;
    return true;
}

bool WaitForServiceState(SC_HANDLE service, DWORD targetState, DWORD timeoutMs) {
    const DWORD startTick = GetTickCount();
    for (;;) {
        DWORD state = 0;
        if (!QueryServiceState(service, &state)) {
            return false;
        }
        if (state == targetState) {
            return true;
        }
        if (GetTickCount() - startTick >= timeoutMs) {
            SetLastError(ERROR_TIMEOUT);
            return false;
        }
        Sleep(150);
    }
}

bool EnsureWinDbgLiteMemDriverInstalledAndStarted(std::wstring* detail) {
    const std::wstring installedPath = GetSystemDriverPath();
    if (installedPath.empty()) {
        if (detail != nullptr) {
            *detail = L"GetSystemDirectoryW failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return false;
    }

    const std::wstring sourcePath = FindPackagedDriverSysPath();
    if (!sourcePath.empty()) {
        if (!CopyFileW(sourcePath.c_str(), installedPath.c_str(), FALSE)) {
            const DWORD error = GetLastError();
            if (!PathExists(installedPath)) {
                if (detail != nullptr) {
                    *detail = L"Copy driver failed: " + sourcePath + L" -> " + installedPath +
                              L", LastError=" + ToWStringCompat(error);
                }
                return false;
            }
            if (error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED) {
                if (detail != nullptr) {
                    *detail = L"Copy driver failed: " + sourcePath + L" -> " + installedPath +
                              L", LastError=" + ToWStringCompat(error);
                }
                return false;
            }
        }
    } else if (!PathExists(installedPath)) {
        if (detail != nullptr) {
            *detail = L"Cannot find " + std::wstring(kWinDbgLiteMemDriverFileName) +
                      L". Put it beside Z0BDbgCli.exe or under driver\\WinDbgLiteMemDrv.";
        }
        return false;
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (scm == nullptr) {
        if (detail != nullptr) {
            *detail = L"OpenSCManager failed. Run CLI as Administrator. LastError=" +
                      ToWStringCompat(GetLastError());
        }
        return false;
    }

    SC_HANDLE service = CreateServiceW(
        scm,
        kWinDbgLiteMemDriverServiceName,
        kWinDbgLiteMemDriverDisplayName,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        installedPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);
    if (service == nullptr && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(
            scm,
            kWinDbgLiteMemDriverServiceName,
            SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
    }
    if (service == nullptr) {
        const DWORD error = GetLastError();
        CloseServiceHandle(scm);
        if (detail != nullptr) {
            *detail = L"Create/Open service failed. LastError=" + ToWStringCompat(error);
        }
        return false;
    }

    DWORD state = 0;
    if (QueryServiceState(service, &state) && state == SERVICE_RUNNING) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        if (detail != nullptr) {
            *detail = L"Driver service already running.";
        }
        return true;
    }

    if (!StartServiceW(service, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        const DWORD error = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        if (detail != nullptr) {
            *detail = L"Start service failed. LastError=" + ToWStringCompat(error);
        }
        return false;
    }

    const bool running = WaitForServiceState(service, SERVICE_RUNNING, 5000);
    const DWORD waitError = GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    if (!running) {
        if (detail != nullptr) {
            *detail = L"Service did not enter RUNNING state. LastError=" + ToWStringCompat(waitError);
        }
        return false;
    }
    if (detail != nullptr) {
        *detail = L"Driver service installed and started.";
    }
    return true;
}

bool StopAndUninstallWinDbgLiteMemDriver(std::wstring* detail) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        if (detail != nullptr) {
            *detail = L"OpenSCManager failed. Run CLI as Administrator. LastError=" +
                      ToWStringCompat(GetLastError());
        }
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        scm,
        kWinDbgLiteMemDriverServiceName,
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (service == nullptr) {
        const DWORD error = GetLastError();
        CloseServiceHandle(scm);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            if (detail != nullptr) {
                *detail = L"Driver service is not installed.";
            }
            return true;
        }
        if (detail != nullptr) {
            *detail = L"Open service failed. LastError=" + ToWStringCompat(error);
        }
        return false;
    }

    DWORD state = 0;
    if (QueryServiceState(service, &state) && state != SERVICE_STOPPED) {
        SERVICE_STATUS status = {};
        if (!ControlService(service, SERVICE_CONTROL_STOP, &status) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
            const DWORD error = GetLastError();
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            if (detail != nullptr) {
                *detail = L"Stop service failed. LastError=" + ToWStringCompat(error);
            }
            return false;
        }
        if (!WaitForServiceState(service, SERVICE_STOPPED, 5000)) {
            const DWORD error = GetLastError();
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            if (detail != nullptr) {
                *detail = L"Service did not stop. LastError=" + ToWStringCompat(error);
            }
            return false;
        }
    }

    if (!DeleteService(service)) {
        const DWORD error = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        if (detail != nullptr) {
            *detail = L"Delete service failed. LastError=" + ToWStringCompat(error);
        }
        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    const std::wstring installedPath = GetSystemDriverPath();
    if (!installedPath.empty() && PathExists(installedPath) && !DeleteFileW(installedPath.c_str())) {
        if (detail != nullptr) {
            *detail = L"Driver service uninstalled, but deleting " + installedPath +
                      L" failed. LastError=" + ToWStringCompat(GetLastError());
        }
        return true;
    }

    if (detail != nullptr) {
        *detail = L"Driver service stopped and uninstalled.";
    }
    return true;
}

bool Debugger::ExecuteCommand(const std::vector<std::wstring>& tokens, bool fromScript) {
    if (tokens.empty()) {
        return true;
    }
    const std::wstring cmd = ToLower(tokens[0]);
    logger_.Log((fromScript ? L"script-cmd: " : L"cmd: ") + JoinTokens(tokens, 0));

    if (cmd == L"help" || cmd == L"h" || cmd == L"?") {
        PrintHelp();
        return true;
    }
    if (cmd == L"veh") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: veh <on|off|detach|kill|status|launch|break|refresh|modules|threads|read|write|ctx|setreg|suspend|resume|ex> ...\n";
            return false;
        }

        const std::wstring action = ToLower(tokens[1]);
        if (action == L"launch") {
            if (tokens.size() < 3) {
                std::wcout << L"Usage: veh launch <exe> [args...]\n";
                return false;
            }
            return LaunchVeh(JoinTokens(tokens, 2), L"");
        }
        if (action == L"on") {
            DWORD pid = processId_;
            std::wstring dllPath;
            if (tokens.size() >= 3) {
                uint32_t parsedPid = 0;
                if (!ParseUInt32(tokens[2], parsedPid)) {
                    std::wcout << L"Invalid pid.\n";
                    return false;
                }
                pid = static_cast<DWORD>(parsedPid);
            }
            if (tokens.size() >= 4) {
                dllPath = tokens[3];
            }
            if (pid == 0) {
                g_wdblVehPreferred = true;
                std::wcout << L"VEH mode enabled. Attach or launch a process before starting the agent.\n";
                return true;
            }

            std::wstring detail;
            if (!StartVehSession(pid, dllPath, &detail)) {
                g_wdblVehPreferred = false;
                std::wcout << L"VEH mode failed: " << detail << L"\n";
                return false;
            }
            g_wdblVehPreferred = true;
            std::wcout << detail << L"\n";
            return true;
        }
        if (action == L"off") {
            const DWORD vehPid = g_wdblVehProcessId;
            const uint64_t agentBase = g_wdblVehAgentBase;
            CloseVehSession();
            if (vehPid != 0 && agentBase != 0) {
                std::wstring unloadDetail;
                if (!UnloadVehAgentDll(vehPid, agentBase, &unloadDetail) && !unloadDetail.empty()) {
                    std::wcout << L"VEH agent unload failed: " << unloadDetail << L"\n";
                }
            }
            g_wdblVehPreferred = false;
            std::wcout << L"VEH mode disabled.\n";
            return true;
        }
        if (action == L"detach") {
            const DWORD pid = g_wdblVehProcessId;
            CloseVehSession();
            if (processId_ == pid || pid == 0) {
                CleanupDebuggee();
            }
            g_wdblVehPreferred = false;
            std::wcout << L"VEH detached";
            if (pid != 0) {
                std::wcout << L" from pid=" << pid;
            }
            std::wcout << L".\n";
            return true;
        }
        if (action == L"kill") {
            DWORD pid = g_wdblVehProcessId != 0 ? g_wdblVehProcessId : processId_;
            HANDLE process = nullptr;
            bool closeProcess = false;
            if (processHandle_ != nullptr && processId_ == pid) {
                process = processHandle_;
            } else if (pid != 0) {
                process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pid);
                closeProcess = process != nullptr;
            }
            if (process == nullptr) {
                std::wcout << L"VEH target process is not available.\n";
                return false;
            }
            if (!TerminateProcess(process, 1)) {
                const DWORD error = GetLastError();
                if (closeProcess) {
                    CloseHandle(process);
                }
                std::wcout << L"TerminateProcess failed: " << error << L"\n";
                return false;
            }
            if (closeProcess) {
                CloseHandle(process);
            }
            CloseVehSession();
            CleanupDebuggee();
            g_wdblVehPreferred = false;
            std::wcout << L"VEH target killed";
            if (pid != 0) {
                std::wcout << L" pid=" << pid;
            }
            std::wcout << L".\n";
            return true;
        }
        if (action == L"status" || action == L"st") {
            std::wcout << L"VEH mode: " << (g_wdblVehPreferred ? L"on" : L"off")
                       << L", active: " << (g_wdblVehPipe != INVALID_HANDLE_VALUE ? L"yes" : L"no")
                       << L", pid=" << g_wdblVehProcessId
                       << L", agentBase=" << ToHex(g_wdblVehAgentBase) << L"\n";
            return true;
        }
        if (action == L"break" || action == L"pause") {
            if (!IsVehAgentActive() || g_wdblVehProcessId == 0) {
                std::wcout << L"VEH agent is not active.\n";
                return false;
            }
            std::wstring detail;
            if (!BreakVehProcess(g_wdblVehProcessId, &detail)) {
                std::wcout << L"VEH break failed: " << detail << L"\n";
                return false;
            }
            std::wcout << L"VEH break requested.\n";
            return true;
        }
        if (action == L"refresh" || action == L"snapshot") {
            std::wstring detail;
            if (!SendVehSimpleRequest(WDBL_VEH_MSG_REQ_REFRESH_SNAPSHOT, &detail)) {
                std::wcout << L"VEH refresh failed: " << detail << L"\n";
                return false;
            }
            std::wcout << L"VEH snapshot refresh requested.\n";
            return true;
        }
        if (action == L"modules" || action == L"lm") {
            PrintVehModules();
            return true;
        }
        if (action == L"threads" || action == L"tl") {
            PrintVehThreads();
            return true;
        }
        if (action == L"read" || action == L"db") {
            if (tokens.size() < 3 || tokens.size() > 4) {
                std::wcout << L"Usage: veh read <address> [size]\n";
                return false;
            }
            uint64_t address = 0;
            if (!ParseUInt64(tokens[2], address)) {
                std::wcout << L"Invalid address.\n";
                return false;
            }
            uint64_t size64 = 16;
            if (tokens.size() == 4 && (!ParseUInt64(tokens[3], size64) || size64 == 0 || size64 > WDBL_VEH_MAX_MEMORY_BYTES)) {
                std::wcout << L"Size must be 1..256.\n";
                return false;
            }
            std::wstring detail;
            if (!SendVehMemoryRequest(WDBL_VEH_MSG_REQ_READ_MEMORY, address, std::vector<uint8_t>(), static_cast<DWORD>(size64), &detail)) {
                std::wcout << L"VEH read failed: " << detail << L"\n";
                return false;
            }
            return true;
        }
        if (action == L"write" || action == L"eb") {
            if (tokens.size() < 4) {
                std::wcout << L"Usage: veh write <address> <byte> [byte...]\n";
                return false;
            }
            uint64_t address = 0;
            if (!ParseUInt64(tokens[2], address)) {
                std::wcout << L"Invalid address.\n";
                return false;
            }
            std::vector<uint8_t> bytes;
            for (size_t i = 3; i < tokens.size(); ++i) {
                uint64_t value = 0;
                if (!ParseUInt64(tokens[i], value) || value > 0xFF) {
                    std::wcout << L"Invalid byte: " << tokens[i] << L"\n";
                    return false;
                }
                bytes.push_back(static_cast<uint8_t>(value));
            }
            std::wstring detail;
            if (!SendVehMemoryRequest(WDBL_VEH_MSG_REQ_WRITE_MEMORY, address, bytes, static_cast<DWORD>(bytes.size()), &detail)) {
                std::wcout << L"VEH write failed: " << detail << L"\n";
                return false;
            }
            return true;
        }
        if (action == L"ctx" || action == L"r") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: veh ctx <tid>\n";
                return false;
            }
            uint32_t tid = 0;
            if (!ParseUInt32(tokens[2], tid)) {
                std::wcout << L"Invalid thread id.\n";
                return false;
            }
            if (IsVehBreakPending() && g_wdblVehLastContextValid && g_wdblVehLastContext.threadId == tid) {
                std::wcout << L"[VEH] context tid=" << g_wdblVehLastContext.threadId << L"\n";
                PrintVehContext(g_wdblVehLastContext);
                return true;
            }
            WdblVehContextRequest request = {};
            request.threadId = tid;
            std::wstring detail;
            if (!SendVehContextRequest(request, WDBL_VEH_MSG_REQ_GET_CONTEXT, &detail)) {
                std::wcout << L"VEH context failed: " << detail << L"\n";
                return false;
            }
            return true;
        }
        if (action == L"setreg") {
            if (tokens.size() != 5) {
                std::wcout << L"Usage: veh setreg <tid> <reg> <value>\n";
                return false;
            }
            uint32_t tid = 0;
            uint64_t value = 0;
            if (!ParseUInt32(tokens[2], tid) || !ParseUInt64(tokens[4], value)) {
                std::wcout << L"Invalid thread id or value.\n";
                return false;
            }
            WdblVehContextRequest request = {};
            request.threadId = tid;
            if (!FillVehContextRegister(request, tokens[3], value)) {
                std::wcout << L"Unknown register: " << tokens[3] << L"\n";
                return false;
            }
            if (IsVehBreakPending()) {
                if (!g_wdblVehLastContextValid || g_wdblVehLastContext.threadId != tid) {
                    std::wcout << L"Stopped VEH context is for a different thread.\n";
                    return false;
                }
                QueueVehStoppedContextUpdate(request);
                std::wcout << L"VEH stopped context updated. It will apply on continue.\n";
                return true;
            }
            std::wstring detail;
            if (!SendVehContextRequest(request, WDBL_VEH_MSG_REQ_SET_CONTEXT, &detail)) {
                std::wcout << L"VEH setreg failed: " << detail << L"\n";
                return false;
            }
            return true;
        }
        if (action == L"suspend" || action == L"resume") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: veh " << action << L" <tid>\n";
                return false;
            }
            uint32_t tid = 0;
            if (!ParseUInt32(tokens[2], tid)) {
                std::wcout << L"Invalid thread id.\n";
                return false;
            }
            std::wstring detail;
            const DWORD type = action == L"suspend" ? WDBL_VEH_MSG_REQ_SUSPEND_THREAD : WDBL_VEH_MSG_REQ_RESUME_THREAD;
            if (!SendVehThreadControlRequest(type, tid, &detail)) {
                std::wcout << L"VEH thread control failed: " << detail << L"\n";
                return false;
            }
            return true;
        }
        if (action == L"ex") {
            if (tokens.size() != 3 && tokens.size() != 4) {
                std::wcout << L"Usage: veh ex <bp|search|continue> [exception_code]\n";
                return false;
            }
            const std::wstring policyText = ToLower(tokens[2]);
            DWORD policy = WDBL_VEH_EXCEPTION_POLICY_BREAKPOINT_ONLY;
            if (policyText == L"search" || policyText == L"pass") {
                policy = WDBL_VEH_EXCEPTION_POLICY_SEARCH;
            } else if (policyText == L"continue" || policyText == L"handle") {
                policy = WDBL_VEH_EXCEPTION_POLICY_CONTINUE;
            } else if (policyText == L"bp" || policyText == L"breakpoint") {
                policy = WDBL_VEH_EXCEPTION_POLICY_BREAKPOINT_ONLY;
            } else {
                std::wcout << L"Usage: veh ex <bp|search|continue> [exception_code]\n";
                return false;
            }
            DWORD exceptionCode = 0;
            if (tokens.size() == 4 && !ParseExceptionCodeToken(tokens[3], exceptionCode)) {
                std::wcout << L"Invalid exception code.\n";
                return false;
            }
            std::wstring detail;
            if (!SendVehExceptionPolicyRequestEx(policy, exceptionCode, &detail)) {
                std::wcout << L"VEH exception policy failed: " << detail << L"\n";
                return false;
            }
            return true;
        }

        std::wcout << L"Usage: veh <on|off|detach|kill|status|launch|break|refresh|modules|threads|read|write|ctx|setreg|suspend|resume|ex> ...\n";
        return false;
    }
    if (cmd == L"drv" || cmd == L"driver") {
        if (tokens.size() < 2 || tokens.size() > 4) {
            std::wcout << L"Usage: drv <on|off|status|caps|antidebug|dr|handles|threadinfo|image|mitigations|events> [device_path|tid]\n";
            return false;
        }

        const std::wstring action = ToLower(tokens[1]);
        if (action == L"caps" || action == L"capabilities") {
            if (tokens.size() != 2) {
                std::wcout << L"Usage: drv caps\n";
                return false;
            }
            WDBL_DRIVER_CAPABILITIES_RESULT capabilities = WDBL_DRIVER_CAPABILITIES_RESULT();
            if (!wdbl::winapi::QueryDriverCapabilities(&capabilities)) {
                std::wcout << L"Driver capability query failed. LastError="
                           << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                return false;
            }
            std::wcout << L"Driver capabilities: version=" << capabilities.Version
                       << L", ioctl=" << capabilities.IoctlProtocolVersion
                       << L", mask=0x" << std::hex << capabilities.CapabilityMask
                       << L", debug_api=0x" << capabilities.DebugApiMask << std::dec << L"\n";
            return true;
        }
        if (action == L"antidebug" || action == L"ad") {
            if (tokens.size() != 2 || processId_ == 0) {
                std::wcout << L"Usage: drv antidebug\n";
                return false;
            }
            WDBL_ANTI_DEBUG_QUERY_RESULT result = WDBL_ANTI_DEBUG_QUERY_RESULT();
            if (!wdbl::winapi::QueryDriverAntiDebug(processId_, 0, &result)) {
                std::wcout << L"Driver anti-debug query failed. LastError="
                           << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                return false;
            }
            std::wcout << L"Anti-debug pid=" << result.ProcessId
                       << L", peb=0x" << std::hex << result.PebAddress
                       << L", wow64_peb=0x" << result.Wow64PebAddress << std::dec
                       << L", wow64=" << (result.IsWow64 ? L"yes" : L"no") << L"\n";
            std::wcout << L"BeingDebugged=" << result.BeingDebugged
                       << L", NtGlobalFlag=0x" << std::hex << result.NtGlobalFlag
                       << L", DebugPort=0x" << result.DebugPort
                       << L", DebugObject=0x" << result.DebugObjectHandle
                       << L", DebugFlags=0x" << result.DebugFlags << std::dec << L"\n";
            std::wcout << L"Status: peb=0x" << std::hex << static_cast<ULONG>(result.PebStatus)
                       << L", port=0x" << static_cast<ULONG>(result.DebugPortStatus)
                       << L", object=0x" << static_cast<ULONG>(result.DebugObjectStatus)
                       << L", flags=0x" << static_cast<ULONG>(result.DebugFlagsStatus)
                       << L", heap=0x" << static_cast<ULONG>(result.HeapStatus) << std::dec << L"\n";
            std::wcout << L"ProcessHeap=0x" << std::hex << result.ProcessHeap
                       << L" HeapFlags=0x" << result.HeapFlags
                       << L" HeapForceFlags=0x" << result.HeapForceFlags
                       << std::dec << L"\n";
            return true;
        }
        if (action == L"dr" || action == L"debugregs") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: drv dr <tid>\n";
                return false;
            }
            uint32_t threadId = 0;
            if (!ParseUInt32(tokens[2], threadId) || threadId == 0) {
                std::wcout << L"Invalid tid.\n";
                return false;
            }
            WDBL_DEBUG_REGISTERS_RESULT result = WDBL_DEBUG_REGISTERS_RESULT();
            if (!wdbl::winapi::DriverGetDebugRegisters(threadId, &result)) {
                std::wcout << L"Driver debug register query failed. LastError="
                           << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                return false;
            }
            std::wcout << L"DR0=0x" << std::hex << result.Dr0
                       << L" DR1=0x" << result.Dr1
                       << L" DR2=0x" << result.Dr2
                       << L" DR3=0x" << result.Dr3
                       << L" DR6=0x" << result.Dr6
                       << L" DR7=0x" << result.Dr7 << std::dec << L"\n";
            return true;
        }
        if (action == L"handles" || action == L"handlelist") {
            if (tokens.size() != 2 || processId_ == 0) {
                std::wcout << L"Usage: drv handles\n";
                return false;
            }
            std::vector<WDBL_HANDLE_ENUM_ENTRY> handles;
            if (!wdbl::winapi::QueryDriverHandleList(processId_, &handles)) {
                std::wcout << L"Driver handle query failed. LastError="
                           << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                return false;
            }
            std::wcout << L"Driver handles: " << handles.size() << L"\n";
            const size_t previewCount = handles.size() < 32 ? handles.size() : 32;
            for (size_t i = 0; i < previewCount; ++i) {
                std::wcout << L"  [" << i << L"] handle=0x" << std::hex
                           << handles[i].HandleValue
                           << L" object=0x" << handles[i].ObjectAddress
                           << L" type=" << handles[i].ObjectTypeIndex
                           << L" access=0x" << handles[i].GrantedAccess
                           << L" attr=0x" << handles[i].Attributes << std::dec;
                const std::wstring typeName =
                    QueryDuplicatedHandleTypeName(processId_, handles[i].HandleValue);
                if (!typeName.empty()) {
                    std::wcout << L" type_name=" << typeName;
                }
                if (handles[i].ObjectName[0] != L'\0') {
                    std::wcout << L" name=" << handles[i].ObjectName;
                }
                std::wcout << L"\n";
            }
            if (handles.size() > previewCount) {
                std::wcout << L"  ... " << (handles.size() - previewCount) << L" more\n";
            }
            return true;
        }
        if (action == L"threadinfo" || action == L"ti") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: drv threadinfo <tid>\n";
                return false;
            }
            uint32_t threadId = 0;
            if (!ParseUInt32(tokens[2], threadId) || threadId == 0) {
                std::wcout << L"Invalid tid.\n";
                return false;
            }
            WDBL_THREAD_INFO_RESULT result = WDBL_THREAD_INFO_RESULT();
            if (!wdbl::winapi::QueryDriverThreadInfo(threadId, &result)) {
                std::wcout << L"Driver thread info query failed. LastError="
                           << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                return false;
            }
            std::wcout << L"Thread " << result.ThreadId << L" process=" << result.ProcessId
                       << L" TEB=0x" << std::hex << result.TebBaseAddress
                       << L" start=0x" << result.StartAddress
                       << L" affinity=0x" << result.AffinityMask << std::dec << L"\n";
            std::wcout << L"Priority=" << result.Priority
                       << L" BasePriority=" << result.BasePriority
                       << L" ExitStatus=0x" << std::hex
                       << static_cast<ULONG>(result.ExitStatus)
                       << L" basic_status=0x" << static_cast<ULONG>(result.BasicInfoStatus)
                       << L" start_status=0x" << static_cast<ULONG>(result.StartAddressStatus)
                       << std::dec << L"\n";
            return true;
        }
        if (action == L"image" || action == L"imageinfo") {
            if (tokens.size() != 2 || processId_ == 0) {
                std::wcout << L"Usage: drv image\n";
                return false;
            }
            WDBL_IMAGE_INFO_RESULT result = WDBL_IMAGE_INFO_RESULT();
            if (!wdbl::winapi::QueryDriverImageInfo(processId_, &result)) {
                std::wcout << L"Driver image info query failed. LastError="
                           << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                return false;
            }
            std::wcout << L"Image base=0x" << std::hex << result.ImageBase
                       << L" entry=0x" << result.EntryPoint
                       << L" size=0x" << result.SizeOfImage
                       << L" headers=0x" << result.SizeOfHeaders
                       << L" machine=0x" << result.Machine
                       << L" chars=0x" << result.Characteristics
                       << L" subsystem=0x" << result.Subsystem
                       << L" timestamp=0x" << result.TimeDateStamp
                       << std::dec << L" sections=" << result.SectionCount << L"\n";
            std::wcout << L"Status: peb=0x" << std::hex
                       << static_cast<ULONG>(result.PebStatus)
                       << L" header=0x" << static_cast<ULONG>(result.HeaderStatus)
                       << std::dec << L"\n";
            return true;
        }
        if (action == L"mitigations" || action == L"mitigate") {
            if (tokens.size() != 2 || processId_ == 0) {
                std::wcout << L"Usage: drv mitigations\n";
                return false;
            }
            WDBL_PROCESS_MITIGATIONS_RESULT result = WDBL_PROCESS_MITIGATIONS_RESULT();
            if (!wdbl::winapi::QueryDriverProcessMitigations(processId_, &result)) {
                std::wcout << L"Driver mitigation query failed. LastError="
                           << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                return false;
            }
            std::wcout << L"ExecuteFlags=0x" << std::hex << result.ExecuteFlags
                       << L" ProtectionLevel=0x" << static_cast<unsigned>(result.ProtectionLevel)
                       << L" BreakOnTermination=" << result.BreakOnTermination
                       << L" Wow64=" << result.IsWow64 << std::dec << L"\n";
            std::wcout << L"Status: execute=0x" << std::hex
                       << static_cast<ULONG>(result.ExecuteFlagsStatus)
                       << L" protection=0x" << static_cast<ULONG>(result.ProtectionStatus)
                       << L" break=0x" << static_cast<ULONG>(result.BreakOnTerminationStatus)
                       << L" wow64=0x" << static_cast<ULONG>(result.Wow64Status)
                       << std::dec << L"\n";
            return true;
        }
        if (action == L"events" || action == L"timeline") {
            const bool follow = tokens.size() >= 3 && ToLower(tokens[2]) == L"follow";
            if ((!follow && tokens.size() > 3) || (follow && tokens.size() > 4)) {
                std::wcout << L"Usage: drv events [max] | drv events follow [interval_ms]\n";
                return false;
            }
            uint32_t maxEvents = 64;
            if (maxEvents > 256) {
                maxEvents = 256;
            }
            uint32_t intervalMs = 500;
            if (follow) {
                if (tokens.size() == 4 &&
                    (!ParseUInt32(tokens[3], intervalMs) || intervalMs == 0)) {
                    std::wcout << L"Invalid follow interval.\n";
                    return false;
                }
                if (intervalMs > 60000) {
                    intervalMs = 60000;
                }
            } else if (tokens.size() == 3 &&
                       (!ParseUInt32(tokens[2], maxEvents) || maxEvents == 0)) {
                std::wcout << L"Invalid max event count.\n";
                return false;
            }
            if (maxEvents > 256) {
                maxEvents = 256;
            }
            const auto printEvents = [](const std::vector<WDBL_DRIVER_EVENT_ENTRY>& events) {
                for (size_t i = 0; i < events.size(); ++i) {
                    const WDBL_DRIVER_EVENT_ENTRY& event = events[i];
                    const wchar_t* type = L"unknown";
                    if (event.Type == WDBL_DRIVER_EVENT_PROCESS) {
                        type = L"process";
                    } else if (event.Type == WDBL_DRIVER_EVENT_THREAD) {
                        type = L"thread";
                    } else if (event.Type == WDBL_DRIVER_EVENT_IMAGE) {
                        type = L"image";
                    } else if (event.Type == WDBL_DRIVER_EVENT_MEMORY_PROTECT) {
                        type = L"memory-protect";
                    } else if (event.Type == WDBL_DRIVER_EVENT_REMOTE_THREAD) {
                        type = L"remote-thread";
                    }
                    const wchar_t* action = event.Flags != 0 ? L"create/load" : L"exit";
                    if (event.Type == WDBL_DRIVER_EVENT_IMAGE) {
                        action = L"load";
                    } else if (event.Type == WDBL_DRIVER_EVENT_MEMORY_PROTECT) {
                        action = L"change";
                    } else if (event.Type == WDBL_DRIVER_EVENT_REMOTE_THREAD) {
                        action = L"create";
                    }
                    std::wcout << L"[" << i << L"] " << type
                               << L" " << action
                               << L" pid=" << event.ProcessId
                               << L" tid=" << event.ThreadId
                               << L" addr=0x" << std::hex << event.Address
                               << L" size=0x" << event.Size
                               << L" status=0x" << static_cast<ULONG>(event.Status)
                               << std::dec;
                    if (event.Type == WDBL_DRIVER_EVENT_MEMORY_PROTECT) {
                        std::wcout << L" new_protect=0x" << std::hex << event.Flags << std::dec;
                    } else if (event.Type == WDBL_DRIVER_EVENT_REMOTE_THREAD) {
                        std::wcout << L" create_flags=0x" << std::hex << event.Flags << std::dec;
                    }
                    if (event.Name[0] != L'\0') {
                        std::wcout << L" " << event.Name;
                    }
                    std::wcout << L"\n";
                }
            };
            if (follow) {
                std::wcout << L"Watching driver events; press Esc or q to stop.\n";
                std::wcout.flush();
            }
            do {
                std::vector<WDBL_DRIVER_EVENT_ENTRY> events;
                if (!wdbl::winapi::QueryDriverEvents(processId_, maxEvents, &events)) {
                    std::wcout << L"Driver event query failed. LastError="
                               << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                    return false;
                }
                printEvents(events);
                if (!follow) {
                    if (events.empty()) {
                        std::wcout << L"No driver events.\n";
                    }
                    break;
                }
                for (uint32_t waited = 0; waited < intervalMs; waited += 50) {
                    if (_kbhit()) {
                        const int key = _getch();
                        if (key == 27 || key == 'q' || key == 'Q') {
                            std::wcout << L"\nStopped event follow.\n";
                            return true;
                        }
                    }
                    Sleep(50);
                }
                DWORD exitCode = STILL_ACTIVE;
                if (processHandle_ == nullptr ||
                    !GetExitCodeProcess(processHandle_, &exitCode) ||
                    exitCode != STILL_ACTIVE) {
                    std::wcout << L"\nTarget process is no longer active.\n";
                    break;
                }
            } while (true);
            return true;
        }
        if (action == L"on") {
            const wchar_t* devicePath = tokens.size() == 3 ? tokens[2].c_str() : nullptr;
            wdbl::winapi::ConfigureProcessMemoryDriver(TRUE, devicePath);
            BOOL pingOk = wdbl::winapi::PingProcessMemoryDriver();
            if (!pingOk) {
                const DWORD firstError = wdbl::winapi::GetProcessMemoryDriverLastError();
                std::wstring detail;
                std::wcout << L"Driver is not active yet. Installing/starting service "
                           << kWinDbgLiteMemDriverServiceName
                           << L"... LastError=" << firstError << L"\n";
                if (!EnsureWinDbgLiteMemDriverInstalledAndStarted(&detail)) {
                    std::wcout << L"Driver install/start failed: " << detail << L"\n";
                    std::wcout << L"Driver mode remains enabled, but WinAPI fallback will be used when driver calls fail.\n";
                    return false;
                }
                if (!detail.empty()) {
                    std::wcout << detail << L"\n";
                }

                wdbl::winapi::ConfigureProcessMemoryDriver(TRUE, devicePath);
                pingOk = wdbl::winapi::PingProcessMemoryDriver();
            }
            if (pingOk) {
                std::wcout << L"Driver mode enabled and driver is active.\n";
            } else {
                const DWORD error = wdbl::winapi::GetProcessMemoryDriverLastError();
                std::wcout << L"Driver mode enabled, but driver is not active. LastError=" << error
                           << L". WinAPI fallback will be used when driver calls fail.\n";
            }
            return true;
        }
        if (action == L"off") {
            wdbl::winapi::ConfigureProcessMemoryDriver(FALSE, nullptr);
            std::wstring detail;
            if (!StopAndUninstallWinDbgLiteMemDriver(&detail)) {
                std::wcout << L"Driver mode disabled, but service uninstall failed: " << detail << L"\n";
                std::wcout << L"WinAPI memory/thread operations will be used.\n";
                return false;
            }
            std::wcout << L"Driver mode disabled. " << detail << L"\n";
            std::wcout << L"WinAPI memory/thread operations will be used.\n";
            return true;
        }
        if (action == L"status" || action == L"st") {
            const BOOL preferred = wdbl::winapi::IsProcessMemoryDriverPreferred();
            const BOOL active = wdbl::winapi::IsProcessMemoryDriverActive();
            const DWORD error = wdbl::winapi::GetProcessMemoryDriverLastError();
            std::wcout << L"Driver mode: " << (preferred ? L"on" : L"off")
                       << L", active: " << (active ? L"yes" : L"no")
                       << L", LastError=" << error << L"\n";
            if (preferred) {
                DWORD availableMask = 0;
                DWORD requiredMask = 0;
                if (wdbl::winapi::QueryDriverDebugApiSupport(&availableMask, &requiredMask)) {
                    std::wcout << L"Driver debug API support: available=0x" << std::hex << availableMask
                               << L", required=0x" << requiredMask << std::dec
                               << ((availableMask & requiredMask) == requiredMask ? L" (ready)" : L" (not ready)")
                               << L"\n";
                } else {
                    std::wcout << L"Driver debug API support: query failed, LastError="
                               << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                }

                DWORD imageNameOffset = 0;
                DWORD imageNameLength = 0;
                DWORD imageNameConfidence = 0;
                char imageName[16] = { 0 };
                if (wdbl::winapi::QueryDriverEprocessImageNameOffset(
                        &imageNameOffset,
                        &imageNameLength,
                        &imageNameConfidence,
                        imageName)) {
                    wchar_t imageNameWide[16] = { 0 };
                    DWORD i = 0;
                    for (i = 0; i < 15 && imageName[i] != '\0'; ++i) {
                        imageNameWide[i] = static_cast<unsigned char>(imageName[i]);
                    }
                    std::wcout << L"EPROCESS ImageFileName offset: 0x" << std::hex << imageNameOffset << std::dec
                               << L", name=" << imageNameWide
                               << L", length=" << imageNameLength
                               << L", confidence=" << imageNameConfidence << L"\n";
                } else {
                    std::wcout << L"EPROCESS ImageFileName offset: query failed, LastError="
                               << wdbl::winapi::GetProcessMemoryDriverLastError() << L"\n";
                }

                WDBL_DRIVER_CAPABILITIES_RESULT capabilities = WDBL_DRIVER_CAPABILITIES_RESULT();
                if (wdbl::winapi::QueryDriverCapabilities(&capabilities)) {
                    std::wcout << L"Driver capabilities: mask=0x" << std::hex
                               << capabilities.CapabilityMask
                               << L", debug_api=0x" << capabilities.DebugApiMask
                               << std::dec << L"\n";
                }
            }
            return true;
        }

        std::wcout << L"Usage: drv <on|off|status|caps|antidebug|dr|handles|threadinfo|image|mitigations|events> [device_path|tid]\n";
        return false;
    }
    if (cmd == L"launch") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: launch <exe> [args...]\n";
            return false;
        }
        return Launch(JoinTokens(tokens, 1));
    }
    if (!cmd.empty() && cmd[0] == L'~') {
        return ExecuteThreadCommand(tokens[0]);
    }
    if (cmd == L"attach" || cmd == L".attach") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: .attach <pid>\n";
            return false;
        }
        uint32_t pid = 0;
        if (!ParseUInt32(tokens[1], pid)) {
            std::wcout << L"Invalid pid.\n";
            return false;
        }
        return Attach(pid);
    }
    if (cmd == L"detach" || cmd == L".detach") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: .detach\n";
            return false;
        }
        return Detach();
    }
    if (cmd == L"run" || cmd == L"g" || cmd == L"go") {
        if (IsVehBreakPending()) {
            SendVehContinue(g_wdblVehPipe, WDBL_VEH_CONTINUE_EXECUTION);
            InterlockedExchange(&g_wdblVehBreakPending, 0);
            std::wcout << L"VEH continued.\n";
            return true;
        }
        return ContinueExecution();
    }
    if (cmd == L"step" || cmd == L"si" || cmd == L"t") {
        if (IsVehBreakPending()) {
            return VehSingleStep();
        }
        return SingleStep();
    }
    if (cmd == L"p" || cmd == L"stepover" || cmd == L"so") {
        if (IsVehBreakPending()) {
            return VehStepOver(processHandle_);
        }
        return StepOver();
    }
    if (cmd == L"gu") {
        return GoUp();
    }
    if (cmd == L"wt") {
        uint64_t maxSteps = 1000;
        if (tokens.size() > 2) {
            std::wcout << L"Usage: wt [max_steps]\n";
            return false;
        }
        if (tokens.size() == 2 && !ParseUInt64(tokens[1], maxSteps)) {
            std::wcout << L"Invalid wt step count.\n";
            return false;
        }
        return TraceWatch(maxSteps);
    }
    if (cmd == L"stepback" || cmd == L"reverse" || cmd == L"sbk" || cmd == L"debugback" || cmd == L"dbk") {
        uint64_t count = 1;
        if (tokens.size() > 2) {
            std::wcout << L"Usage: stepback [count]\n";
            return false;
        }
        if (tokens.size() == 2) {
            if (!ParseUInt64(tokens[1], count) || count == 0) {
                std::wcout << L"Invalid stepback count.\n";
                return false;
            }
        }
        for (uint64_t i = 0; i < count; ++i) {
            if (!StepBackToPreviousSnapshot()) {
                return i > 0;
            }
        }
        return true;
    }
    if (cmd == L"runtoentry" || cmd == L"rte") {
        return RunToEntryPoint();
    }
    if (cmd == L"snapshot" || cmd == L"snap") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: snapshot <save|restore|rerun|list|clear> [name]\n";
            return false;
        }
        const std::wstring action = ToLower(tokens[1]);
        if (action == L"list" || action == L"ls") {
            ListNamedSnapshots();
            return true;
        }
        if (action == L"clear") {
            if (tokens.size() == 2) {
                namedSnapshots_.clear();
                std::wcout << L"Cleared all named snapshots.\n";
                return true;
            }
            if (tokens.size() == 3) {
                const std::wstring key = NormalizeSnapshotKey(tokens[2]);
                if (namedSnapshots_.erase(key) == 0) {
                    std::wcout << L"Snapshot '" << key << L"' was not found.\n";
                    return false;
                }
                std::wcout << L"Cleared snapshot '" << key << L"'.\n";
                return true;
            }
            std::wcout << L"Usage: snapshot clear [name]\n";
            return false;
        }
        if (action == L"save") {
            if (tokens.size() > 3) {
                std::wcout << L"Usage: snapshot save [name]\n";
                return false;
            }
            const std::wstring name = tokens.size() == 3 ? tokens[2] : L"default";
            return SaveNamedSnapshot(name);
        }
        if (action == L"restore" || action == L"load") {
            if (tokens.size() > 3) {
                std::wcout << L"Usage: snapshot restore [name]\n";
                return false;
            }
            const std::wstring name = tokens.size() == 3 ? tokens[2] : L"default";
            return RestoreNamedSnapshot(name, false);
        }
        if (action == L"rerun" || action == L"run") {
            if (tokens.size() > 3) {
                std::wcout << L"Usage: snapshot rerun [name]\n";
                return false;
            }
            const std::wstring name = tokens.size() == 3 ? tokens[2] : L"default";
            return RestoreNamedSnapshot(name, true);
        }
        std::wcout << L"Unknown snapshot action.\n";
        return false;
    }
    if (cmd == L"savesnap" || cmd == L"snapsave") {
        if (tokens.size() > 2) {
            std::wcout << L"Usage: savesnap [name]\n";
            return false;
        }
        return SaveNamedSnapshot(tokens.size() == 2 ? tokens[1] : L"default");
    }
    if (cmd == L"rerunsnap" || cmd == L"snaprerun") {
        if (tokens.size() > 2) {
            std::wcout << L"Usage: rerunsnap [name]\n";
            return false;
        }
        return RestoreNamedSnapshot(tokens.size() == 2 ? tokens[1] : L"default", true);
    }
    if (cmd == L"flow" || cmd == L"cfg") {
        uint64_t address = 0;
        size_t maxBlocks = 24;
        if (tokens.size() >= 2) {
            if (!ParseUInt64(tokens[1], address)) {
                std::wcout << L"Invalid flow start address.\n";
                return false;
            }
        } else if (stopState_.valid) {
            address = GetInstructionPointer(stopState_.context);
        } else {
            std::wcout << L"Usage: flow [address] [max_blocks]\n";
            return false;
        }
        if (tokens.size() >= 3) {
            uint64_t value = 0;
            if (ParseUInt64(tokens[2], value)) {
                maxBlocks = static_cast<size_t>(value);
            }
        }
        PrintFlowGraph(address, maxBlocks);
        return true;
    }
    if (cmd == L"envsave" || cmd == L"savesettings" || cmd == L"settingssave") {
        if (tokens.size() > 2) {
            std::wcout << L"Usage: envsave [file_path]\n";
            return false;
        }
        std::wstring filePath = L"wdbl_environment_snapshot.txt";
        if (tokens.size() == 2) {
            filePath = tokens[1];
        }
        return SaveEnvironmentSnapshot(filePath);
    }
    if (cmd == L"envload" || cmd == L"loadsettings" || cmd == L"settingsload") {
        if (tokens.size() > 2) {
            std::wcout << L"Usage: envload [file_path]\n";
            return false;
        }
        std::wstring filePath = L"wdbl_environment_snapshot.txt";
        if (tokens.size() == 2) {
            filePath = tokens[1];
        }
        return LoadEnvironmentSnapshot(filePath);
    }
    if (cmd == L"stepuntil" || cmd == L"traceuntil" || cmd == L"tu") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: stepuntil <condition> [max_steps]\n";
            return false;
        }
        uint64_t maxSteps = 3000;
        size_t conditionEnd = tokens.size();
        if (tokens.size() >= 3) {
            uint64_t maybeMax = 0;
            if (ParseUInt64(tokens.back(), maybeMax)) {
                maxSteps = maybeMax;
                conditionEnd = tokens.size() - 1;
            }
        }
        if (conditionEnd <= 1) {
            std::wcout << L"Missing step-until condition.\n";
            return false;
        }
        const std::wstring condition = JoinTokens(std::vector<std::wstring>(tokens.begin(), tokens.begin() + conditionEnd), 1);
        return StepUntilCondition(condition, maxSteps);
    }
    if (cmd == L"rununtil" || cmd == L"pauseuntil" || cmd == L"ru") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: rununtil <condition> [max_pause_events]\n";
            return false;
        }
        uint64_t maxPauses = 1000;
        size_t conditionEnd = tokens.size();
        if (tokens.size() >= 3) {
            uint64_t maybeMax = 0;
            if (ParseUInt64(tokens.back(), maybeMax)) {
                maxPauses = maybeMax;
                conditionEnd = tokens.size() - 1;
            }
        }
        if (conditionEnd <= 1) {
            std::wcout << L"Missing run-until condition.\n";
            return false;
        }
        const std::wstring condition = JoinTokens(std::vector<std::wstring>(tokens.begin(), tokens.begin() + conditionEnd), 1);
        return RunUntilCondition(condition, maxPauses);
    }
    if (cmd == L"autostep" || cmd == L"astep") {
        if (tokens.size() < 2 || tokens.size() > 3) {
            std::wcout << L"Usage: autostep <count> [delay_ms]\n";
            return false;
        }
        uint64_t count = 0;
        if (!ParseUInt64(tokens[1], count)) {
            std::wcout << L"Invalid step count.\n";
            return false;
        }
        uint32_t delayMs = 0;
        if (tokens.size() == 3) {
            uint64_t tmp = 0;
            if (!ParseUInt64(tokens[2], tmp) || tmp > std::numeric_limits<uint32_t>::max()) {
                std::wcout << L"Invalid delay value.\n";
                return false;
            }
            delayMs = static_cast<uint32_t>(tmp);
        }
        return AutoStep(count, delayMs);
    }
    if (cmd == L"autorun" || cmd == L"arun") {
        if (tokens.size() < 2 || tokens.size() > 3) {
            std::wcout << L"Usage: autorun <pause_cycles> [delay_ms]\n";
            return false;
        }
        uint64_t cycles = 0;
        if (!ParseUInt64(tokens[1], cycles)) {
            std::wcout << L"Invalid cycle count.\n";
            return false;
        }
        uint32_t delayMs = 0;
        if (tokens.size() == 3) {
            uint64_t tmp = 0;
            if (!ParseUInt64(tokens[2], tmp) || tmp > std::numeric_limits<uint32_t>::max()) {
                std::wcout << L"Invalid delay value.\n";
                return false;
            }
            delayMs = static_cast<uint32_t>(tmp);
        }
        return AutoRun(cycles, delayMs);
    }
    if (cmd == L"break" || cmd == L"bp") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: break <address|api_name|module!api_name|module+offset>\n";
            std::wcout << L"Example: bp 0x7FF612341000\n";
            std::wcout << L"Example: bp CreateFileW\n";
            std::wcout << L"Example: bp kernel32!CreateFileW\n";
            std::wcout << L"Example: bp ntdll+0x1200\n";
            return false;
        }
        uint64_t address = 0;
        std::wstring resolvedText;
        if (!ResolveAddressExpression(tokens[1], address, resolvedText)) {
            std::wcout << L"Invalid breakpoint target: " << tokens[1] << L"\n";
            return false;
        }
        if (g_wdblVehPreferred && g_wdblVehPipe != INVALID_HANDLE_VALUE) {
            if (softwareBreakpointByAddress_.find(address) != softwareBreakpointByAddress_.end()) {
                std::wcout << L"Software breakpoint #" << softwareBreakpointByAddress_[address] << L" already exists.\n";
                return true;
            }
            SoftwareBreakpoint bp = SoftwareBreakpoint();
            bp.id = nextBreakpointId_++;
            bp.address = address;
            bp.enabled = true;
            softwareBreakpoints_[bp.id] = bp;
            softwareBreakpointByAddress_[address] = bp.id;
            std::wstring detail;
            if (!SendVehSoftwareBreakpointRequest(WDBL_VEH_MSG_REQ_SET_SOFTWARE_BREAKPOINT, static_cast<DWORD>(bp.id), address, &detail)) {
                softwareBreakpointByAddress_.erase(address);
                softwareBreakpoints_.erase(bp.id);
                std::wcout << L"VEH breakpoint request failed: " << detail << L"\n";
                return false;
            }
            std::wcout << L"VEH software breakpoint #" << bp.id << L" requested at " << ToHex(address);
            if (!resolvedText.empty()) {
                std::wcout << L" (" << resolvedText << L")";
            }
            std::wcout << L".\n";
            return true;
        }
        const int id = AddSoftwareBreakpoint(address);
        if (id >= 0) {
            uint64_t direct = 0;
            if (ParseUInt64(TrimWhitespace(tokens[1]), direct)) {
                std::wcout << L"Software breakpoint #" << id << L" set.\n";
            } else {
                std::wcout << L"Software breakpoint #" << id << L" set at " << ToHex(address);
                if (!resolvedText.empty()) {
                    std::wcout << L" (" << resolvedText << L")";
                }
                std::wcout << L".\n";
            }
            return true;
        }
        return false;
    }
    if (cmd == L"bu") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: bu <symbol|module!symbol|module+offset>\n";
            return false;
        }
        uint64_t address = 0;
        std::wstring resolvedText;
        if (ResolveAddressExpression(tokens[1], address, resolvedText)) {
            if (g_wdblVehPreferred && g_wdblVehPipe != INVALID_HANDLE_VALUE) {
                if (softwareBreakpointByAddress_.find(address) != softwareBreakpointByAddress_.end()) {
                    std::wcout << L"Software breakpoint #" << softwareBreakpointByAddress_[address] << L" already exists.\n";
                    return true;
                }
                SoftwareBreakpoint bp = SoftwareBreakpoint();
                bp.id = nextBreakpointId_++;
                bp.address = address;
                bp.enabled = true;
                softwareBreakpoints_[bp.id] = bp;
                softwareBreakpointByAddress_[address] = bp.id;
                std::wstring detail;
                if (!SendVehSoftwareBreakpointRequest(WDBL_VEH_MSG_REQ_SET_SOFTWARE_BREAKPOINT, static_cast<DWORD>(bp.id), address, &detail)) {
                    softwareBreakpointByAddress_.erase(address);
                    softwareBreakpoints_.erase(bp.id);
                    std::wcout << L"VEH breakpoint request failed: " << detail << L"\n";
                    return false;
                }
                std::wcout << L"VEH deferred breakpoint #" << bp.id << L" resolved immediately at " << ToHex(address);
                if (!resolvedText.empty()) {
                    std::wcout << L" (" << resolvedText << L")";
                }
                std::wcout << L".\n";
                return true;
            }
            const int id = AddSoftwareBreakpoint(address);
            if (id >= 0) {
                std::wcout << L"Deferred breakpoint #" << id << L" resolved immediately at " << ToHex(address);
                if (!resolvedText.empty()) {
                    std::wcout << L" (" << resolvedText << L")";
                }
                std::wcout << L".\n";
                return true;
            }
            return false;
        }
        pendingSoftwareBreakpoints_.push_back(JoinTokens(tokens, 1));
        std::wcout << L"Deferred breakpoint queued: " << JoinTokens(tokens, 1) << L"\n";
        return true;
    }
    if (cmd == L"hw" || cmd == L"hr" || cmd == L"he") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: " << cmd << L" <address|symbol|module+offset>\n";
            return false;
        }
        uint64_t address = 0;
        std::wstring resolvedText;
        if (!ResolveAddressExpression(tokens[1], address, resolvedText)) {
            std::wcout << L"Invalid hardware breakpoint target: " << tokens[1] << L"\n";
            return false;
        }

        HardwareAccessType access = HardwareAccessType::Write;
        int length = 1;
        if (cmd == L"hr") {
            access = HardwareAccessType::Access;
        } else if (cmd == L"he") {
            access = HardwareAccessType::Execute;
        }

        const int slot = FindFreeHardwareBreakpointSlot(0);
        if (slot < 0) {
            std::wcout << L"No free hardware breakpoint slot. Remove or disable one first.\n";
            ListBreakpoints();
            return false;
        }

        if (IsVehAgentActive()) {
            HardwareBreakpoint bp = HardwareBreakpoint();
            bp.id = nextBreakpointId_++;
            bp.slot = slot;
            bp.address = address;
            bp.access = access;
            bp.length = length;
            bp.threadId = 0;
            bp.enabled = true;
            hardwareBreakpoints_[bp.id] = bp;
            std::wstring detail;
            if (!SendVehHardwareBreakpointRequest(WDBL_VEH_MSG_REQ_SET_HARDWARE_BREAKPOINT, bp, &detail)) {
                hardwareBreakpoints_.erase(bp.id);
                std::wcout << L"VEH hardware breakpoint request failed: " << detail << L"\n";
                return false;
            }
            std::wcout << L"VEH hardware breakpoint #" << bp.id << L" requested at " << ToHex(address);
            if (!resolvedText.empty()) {
                std::wcout << L" (" << resolvedText << L")";
            }
            std::wcout << L".\n";
            return true;
        }

        const int id = AddHardwareBreakpoint(slot, address, access, length, 0);
        if (id < 0) {
            return false;
        }

        std::wcout << L"Hardware breakpoint #" << id << L" set at " << ToHex(address);
        if (!resolvedText.empty()) {
            std::wcout << L" (" << resolvedText << L")";
        }
        std::wcout << L".\n";
        ListBreakpoints();
        return true;
    }
    if (cmd == L"hbreak" || cmd == L"hbp") {
        if (tokens.size() < 5 || tokens.size() > 6) {
            std::wcout << L"Usage: hbreak <slot> <address> <exec|write|access> <1|2|4|8> [tid|all]\n";
            return false;
        }
        uint64_t slot64 = 0;
        uint64_t address = 0;
        uint64_t len64 = 0;
        if (!ParseUInt64(tokens[1], slot64) || !ParseUInt64(tokens[2], address) || !ParseUInt64(tokens[4], len64)) {
            std::wcout << L"Invalid numeric parameter.\n";
            return false;
        }
        if (slot64 > 3 || (len64 != 1 && len64 != 2 && len64 != 4 && len64 != 8)) {
            std::wcout << L"Invalid hardware slot or length.\n";
            return false;
        }
        const auto access = ParseHardwareAccess(tokens[3]);
        if (!access.has_value()) {
            std::wcout << L"Invalid hardware access mode.\n";
            return false;
        }
        DWORD tid = 0;
        if (tokens.size() == 6 && ToLower(tokens[5]) != L"all") {
            uint32_t tid32 = 0;
            if (!ParseUInt32(tokens[5], tid32)) {
                std::wcout << L"Invalid thread id.\n";
                return false;
            }
            tid = tid32;
        }
        if (IsVehAgentActive()) {
            HardwareBreakpoint bp = HardwareBreakpoint();
            bp.id = nextBreakpointId_++;
            bp.slot = static_cast<int>(slot64);
            bp.address = address;
            bp.access = *access;
            bp.length = static_cast<int>(len64);
            bp.threadId = tid;
            bp.enabled = true;
            hardwareBreakpoints_[bp.id] = bp;
            std::wstring detail;
            if (!SendVehHardwareBreakpointRequest(WDBL_VEH_MSG_REQ_SET_HARDWARE_BREAKPOINT, bp, &detail)) {
                hardwareBreakpoints_.erase(bp.id);
                std::wcout << L"VEH hardware breakpoint request failed: " << detail << L"\n";
                return false;
            }
            std::wcout << L"VEH hardware breakpoint #" << bp.id << L" requested.\n";
            return true;
        }
        const int id = AddHardwareBreakpoint(static_cast<int>(slot64), address, *access, static_cast<int>(len64), tid);
        if (id >= 0) {
            std::wcout << L"Hardware breakpoint #" << id << L" set.\n";
            return true;
        }
        return false;
    }
    if (cmd == L"mbreak" || cmd == L"mbp") {
        if (tokens.size() != 4) {
            std::wcout << L"Usage: mbreak <address> <size> <r|w|x|rw|rx|wx|rwx>\n";
            return false;
        }
        uint64_t address = 0;
        uint64_t size = 0;
        if (!ParseUInt64(tokens[1], address) || !ParseUInt64(tokens[2], size)) {
            std::wcout << L"Invalid address/size.\n";
            return false;
        }
        const auto access = ParseMemoryAccess(tokens[3]);
        if (!access.has_value()) {
            std::wcout << L"Invalid memory access mode.\n";
            return false;
        }
        if (IsVehAgentActive()) {
            MemoryBreakpoint bp = MemoryBreakpoint();
            bp.id = nextBreakpointId_++;
            bp.address = address;
            bp.size = static_cast<size_t>(size);
            bp.access = *access;
            bp.enabled = true;
            memoryBreakpoints_[bp.id] = bp;
            std::wstring detail;
            if (!SendVehMemoryBreakpointRequest(WDBL_VEH_MSG_REQ_SET_MEMORY_BREAKPOINT, bp, &detail)) {
                memoryBreakpoints_.erase(bp.id);
                std::wcout << L"VEH memory breakpoint request failed: " << detail << L"\n";
                return false;
            }
            std::wcout << L"VEH memory breakpoint #" << bp.id << L" requested.\n";
            return true;
        }
        const int id = AddMemoryBreakpoint(address, static_cast<size_t>(size), *access);
        if (id >= 0) {
            std::wcout << L"Memory breakpoint #" << id << L" set.\n";
            return true;
        }
        return false;
    }
    if (cmd == L"bl") {
        ListBreakpoints();
        return true;
    }
    if (cmd == L"hc" || cmd == L"hclear" || cmd == L"hbc") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: " << cmd << L" <hardware_breakpoint_id|*>\n";
            return false;
        }

        if (ToLower(tokens[1]) == L"*") {
            std::vector<int> ids;
            ids.reserve(hardwareBreakpoints_.size());
            for (auto it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
                ids.push_back(it->first);
            }

            size_t removed = 0;
            for (size_t i = 0; i < ids.size(); ++i) {
                if (IsVehAgentActive()) {
                    auto it = hardwareBreakpoints_.find(ids[i]);
                    if (it == hardwareBreakpoints_.end()) {
                        continue;
                    }
                    std::wstring detail;
                    if (SendVehHardwareBreakpointRequest(WDBL_VEH_MSG_REQ_REMOVE_HARDWARE_BREAKPOINT, it->second, &detail)) {
                        hardwareBreakpoints_.erase(it);
                        ++removed;
                    }
                } else {
                    if (RemoveBreakpoint(ids[i])) {
                        ++removed;
                    }
                }
            }
            std::wcout << L"Removed " << removed << L" hardware breakpoint(s).\n";
            ListBreakpoints();
            return true;
        }

        uint32_t id = 0;
        if (!ParseUInt32(tokens[1], id)) {
            std::wcout << L"Invalid hardware breakpoint id.\n";
            return false;
        }
        if (hardwareBreakpoints_.find(static_cast<int>(id)) == hardwareBreakpoints_.end()) {
            std::wcout << L"Hardware breakpoint #" << id << L" was not found.\n";
            return false;
        }
        if (IsVehAgentActive()) {
            auto hwIt = hardwareBreakpoints_.find(static_cast<int>(id));
            std::wstring detail;
            if (hwIt == hardwareBreakpoints_.end() ||
                !SendVehHardwareBreakpointRequest(WDBL_VEH_MSG_REQ_REMOVE_HARDWARE_BREAKPOINT, hwIt->second, &detail)) {
                std::wcout << L"Failed to remove VEH hardware breakpoint #" << id;
                if (!detail.empty()) {
                    std::wcout << L": " << detail;
                }
                std::wcout << L"\n";
                return false;
            }
            hardwareBreakpoints_.erase(hwIt);
        } else if (!RemoveBreakpoint(static_cast<int>(id))) {
            std::wcout << L"Failed to remove hardware breakpoint #" << id << L".\n";
            return false;
        }
        std::wcout << L"Removed hardware breakpoint #" << id << L".\n";
        ListBreakpoints();
        return true;
    }
    if (cmd == L"be" || cmd == L"bd" || cmd == L"bc") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: " << cmd << L" <breakpoint_id>\n";
            if (cmd == L"bc") {
                std::wcout << L"       bc *    (delete all breakpoints)\n";
                std::wcout << L"       bc <address>    (delete software breakpoint at address)\n";
            }
            return false;
        }
        if (cmd == L"bc" && ToLower(tokens[1]) == L"*") {
            if (g_wdblVehPreferred && g_wdblVehPipe != INVALID_HANDLE_VALUE) {
                std::vector<int> ids;
                ids.reserve(softwareBreakpoints_.size() + hardwareBreakpoints_.size() + memoryBreakpoints_.size());
                for (auto it = softwareBreakpoints_.begin(); it != softwareBreakpoints_.end(); ++it) {
                    ids.push_back(it->first);
                }
                for (auto it = hardwareBreakpoints_.begin(); it != hardwareBreakpoints_.end(); ++it) {
                    ids.push_back(it->first);
                }
                for (auto it = memoryBreakpoints_.begin(); it != memoryBreakpoints_.end(); ++it) {
                    ids.push_back(it->first);
                }
                size_t removed = 0;
                for (size_t i = 0; i < ids.size(); ++i) {
                    auto it = softwareBreakpoints_.find(ids[i]);
                    if (it != softwareBreakpoints_.end()) {
                        std::wstring detail;
                        if (SendVehSoftwareBreakpointRequest(
                                WDBL_VEH_MSG_REQ_REMOVE_SOFTWARE_BREAKPOINT,
                                static_cast<DWORD>(it->second.id),
                                it->second.address,
                                &detail)) {
                            softwareBreakpointByAddress_.erase(it->second.address);
                            softwareBreakpoints_.erase(it);
                            ++removed;
                        }
                        continue;
                    }
                    auto hwIt = hardwareBreakpoints_.find(ids[i]);
                    if (hwIt != hardwareBreakpoints_.end()) {
                        std::wstring detail;
                        if (SendVehHardwareBreakpointRequest(WDBL_VEH_MSG_REQ_REMOVE_HARDWARE_BREAKPOINT, hwIt->second, &detail)) {
                            hardwareBreakpoints_.erase(hwIt);
                            ++removed;
                        }
                        continue;
                    }
                    auto mbIt = memoryBreakpoints_.find(ids[i]);
                    if (mbIt != memoryBreakpoints_.end()) {
                        std::wstring detail;
                        if (SendVehMemoryBreakpointRequest(WDBL_VEH_MSG_REQ_REMOVE_MEMORY_BREAKPOINT, mbIt->second, &detail)) {
                            memoryBreakpoints_.erase(mbIt);
                            ++removed;
                        }
                        continue;
                    }
                }
                std::wcout << L"Requested removal of " << removed << L" VEH breakpoint(s).\n";
                return true;
            }
            const size_t removed = RemoveAllBreakpoints();
            std::wcout << L"Removed " << removed << L" breakpoint(s).\n";
            return true;
        }
        uint32_t id = 0;
        if (!ParseUInt32(tokens[1], id)) {
            if (cmd == L"bc") {
                uint64_t address = 0;
                if (ParseUInt64(tokens[1], address)) {
                    const auto swIt = softwareBreakpointByAddress_.find(address);
                    if (swIt != softwareBreakpointByAddress_.end()) {
                        if (g_wdblVehPreferred && g_wdblVehPipe != INVALID_HANDLE_VALUE) {
                            auto bpIt = softwareBreakpoints_.find(swIt->second);
                            if (bpIt != softwareBreakpoints_.end()) {
                                std::wstring detail;
                                if (!SendVehSoftwareBreakpointRequest(
                                        WDBL_VEH_MSG_REQ_REMOVE_SOFTWARE_BREAKPOINT,
                                        static_cast<DWORD>(bpIt->second.id),
                                        bpIt->second.address,
                                        &detail)) {
                                    std::wcout << L"VEH breakpoint remove failed: " << detail << L"\n";
                                    return false;
                                }
                                softwareBreakpoints_.erase(bpIt);
                            }
                            softwareBreakpointByAddress_.erase(swIt);
                            std::wcout << L"VEH software breakpoint removal requested at " << ToHex(address) << L".\n";
                            return true;
                        }
                        if (RemoveBreakpoint(swIt->second)) {
                            return true;
                        }
                    }
                    std::wcout << L"No software breakpoint at " << ToHex(address) << L".\n";
                    return false;
                }
            }
            std::wcout << L"Invalid breakpoint id.\n";
            return false;
        }
        bool ok = false;
        if (cmd == L"bc" && g_wdblVehPreferred && g_wdblVehPipe != INVALID_HANDLE_VALUE) {
            auto bpIt = softwareBreakpoints_.find(static_cast<int>(id));
            if (bpIt != softwareBreakpoints_.end()) {
                std::wstring detail;
                if (!SendVehSoftwareBreakpointRequest(
                        WDBL_VEH_MSG_REQ_REMOVE_SOFTWARE_BREAKPOINT,
                        static_cast<DWORD>(bpIt->second.id),
                        bpIt->second.address,
                        &detail)) {
                    std::wcout << L"VEH breakpoint remove failed: " << detail << L"\n";
                    return false;
                }
                softwareBreakpointByAddress_.erase(bpIt->second.address);
                softwareBreakpoints_.erase(bpIt);
                std::wcout << L"VEH software breakpoint #" << id << L" removal requested.\n";
                return true;
            }
            auto hwIt = hardwareBreakpoints_.find(static_cast<int>(id));
            if (hwIt != hardwareBreakpoints_.end()) {
                std::wstring detail;
                if (!SendVehHardwareBreakpointRequest(WDBL_VEH_MSG_REQ_REMOVE_HARDWARE_BREAKPOINT, hwIt->second, &detail)) {
                    std::wcout << L"VEH hardware breakpoint remove failed: " << detail << L"\n";
                    return false;
                }
                hardwareBreakpoints_.erase(hwIt);
                std::wcout << L"VEH hardware breakpoint #" << id << L" removal requested.\n";
                return true;
            }
            auto mbIt = memoryBreakpoints_.find(static_cast<int>(id));
            if (mbIt != memoryBreakpoints_.end()) {
                std::wstring detail;
                if (!SendVehMemoryBreakpointRequest(WDBL_VEH_MSG_REQ_REMOVE_MEMORY_BREAKPOINT, mbIt->second, &detail)) {
                    std::wcout << L"VEH memory breakpoint remove failed: " << detail << L"\n";
                    return false;
                }
                memoryBreakpoints_.erase(mbIt);
                std::wcout << L"VEH memory breakpoint #" << id << L" removal requested.\n";
                return true;
            }
        }
        if ((cmd == L"be" || cmd == L"bd") && IsVehAgentActive()) {
            const bool enable = cmd == L"be";
            auto hwIt = hardwareBreakpoints_.find(static_cast<int>(id));
            if (hwIt != hardwareBreakpoints_.end()) {
                std::wstring detail;
                DWORD type = enable ? WDBL_VEH_MSG_REQ_SET_HARDWARE_BREAKPOINT : WDBL_VEH_MSG_REQ_REMOVE_HARDWARE_BREAKPOINT;
                if (!SendVehHardwareBreakpointRequest(type, hwIt->second, &detail)) {
                    std::wcout << L"VEH hardware breakpoint update failed: " << detail << L"\n";
                    return false;
                }
                hwIt->second.enabled = enable;
                std::wcout << L"VEH hardware breakpoint #" << id << (enable ? L" enabled.\n" : L" disabled.\n");
                return true;
            }
            auto mbIt = memoryBreakpoints_.find(static_cast<int>(id));
            if (mbIt != memoryBreakpoints_.end()) {
                std::wstring detail;
                DWORD type = enable ? WDBL_VEH_MSG_REQ_SET_MEMORY_BREAKPOINT : WDBL_VEH_MSG_REQ_REMOVE_MEMORY_BREAKPOINT;
                if (!SendVehMemoryBreakpointRequest(type, mbIt->second, &detail)) {
                    std::wcout << L"VEH memory breakpoint update failed: " << detail << L"\n";
                    return false;
                }
                mbIt->second.enabled = enable;
                std::wcout << L"VEH memory breakpoint #" << id << (enable ? L" enabled.\n" : L" disabled.\n");
                return true;
            }
        }
        if (cmd == L"be") ok = EnableBreakpoint(static_cast<int>(id));
        if (cmd == L"bd") ok = DisableBreakpoint(static_cast<int>(id));
        if (cmd == L"bc") ok = RemoveBreakpoint(static_cast<int>(id));
        if (!ok) {
            std::wcout << L"Breakpoint operation failed.\n";
        }
        return ok;
    }
    if (cmd == L"bcond" || cmd == L"bcnd") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: bcond <breakpoint_id> <condition>\n";
            std::wcout << L"       bcond clear <breakpoint_id>\n";
            std::wcout << L"Condition vars: hit tid ip addr, operators: == != > >= < <=, combine with &&\n";
            return false;
        }
        const std::wstring action = ToLower(tokens[1]);
        if (action == L"list") {
            ListBreakpoints();
            return true;
        }
        if (action == L"clear") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: bcond clear <breakpoint_id>\n";
                return false;
            }
            uint32_t id = 0;
            if (!ParseUInt32(tokens[2], id)) {
                std::wcout << L"Invalid breakpoint id.\n";
                return false;
            }
            if (ClearBreakpointCondition(static_cast<int>(id))) {
                std::wcout << L"Breakpoint #" << id << L" condition cleared.\n";
                return true;
            }
            return false;
        }

        uint32_t id = 0;
        if (!ParseUInt32(tokens[1], id)) {
            std::wcout << L"Invalid breakpoint id.\n";
            return false;
        }
        if (tokens.size() < 3) {
            std::wcout << L"Usage: bcond <breakpoint_id> <condition>\n";
            return false;
        }
        const std::wstring condition = JoinTokens(tokens, 2);
        if (SetBreakpointCondition(static_cast<int>(id), condition)) {
            std::wcout << L"Breakpoint #" << id << L" condition set to: " << condition << L"\n";
            return true;
        }
        return false;
    }
    if (cmd == L"exshow" || cmd == L"excfg" || cmd == L"exceptioncfg") {
        ListExceptionSettings();
        return true;
    }
    if (cmd == L"exignore") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: exignore <list|all|add|del|clear> ...\n";
            return false;
        }
        const std::wstring action = ToLower(tokens[1]);
        if (action == L"list") {
            ListExceptionSettings();
            return true;
        }
        if (action == L"all") {
            if (tokens.size() != 4) {
                std::wcout << L"Usage: exignore all <debug|run|step> <on|off>\n";
                return false;
            }
            const auto scope = ParseExceptionScope(tokens[2]);
            if (!scope.has_value()) {
                std::wcout << L"Invalid exception scope.\n";
                return false;
            }
            const std::wstring toggle = ToLower(tokens[3]);
            if (toggle != L"on" && toggle != L"off") {
                std::wcout << L"Toggle must be on/off.\n";
                return false;
            }
            return ConfigureExceptionIgnoreAll(*scope, toggle == L"on");
        }
        if (action == L"add" || action == L"del" || action == L"remove") {
            if (tokens.size() != 4) {
                std::wcout << L"Usage: exignore " << action << L" <debug|run|step> <code>\n";
                return false;
            }
            const auto scope = ParseExceptionScope(tokens[2]);
            if (!scope.has_value()) {
                std::wcout << L"Invalid exception scope.\n";
                return false;
            }
            DWORD code = 0;
            if (!ParseExceptionCodeToken(tokens[3], code)) {
                std::wcout << L"Invalid exception code token.\n";
                return false;
            }
            if (action == L"add") {
                return AddIgnoredExceptionCode(*scope, code);
            }
            return RemoveIgnoredExceptionCode(*scope, code);
        }
        if (action == L"clear") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: exignore clear <debug|run|step>\n";
                return false;
            }
            const auto scope = ParseExceptionScope(tokens[2]);
            if (!scope.has_value()) {
                std::wcout << L"Invalid exception scope.\n";
                return false;
            }
            ClearIgnoredExceptionCodes(*scope);
            return true;
        }
        std::wcout << L"Unknown exignore action.\n";
        return false;
    }
    if (cmd == L"exstop" || cmd == L"exprstop") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: exstop <list|add|del|clear> ...\n";
            return false;
        }
        const std::wstring action = ToLower(tokens[1]);
        if (action == L"list") {
            ListRunStopExpressions();
            return true;
        }
        if (action == L"clear") {
            ClearRunStopExpressions();
            return true;
        }
        if (action == L"add") {
            if (tokens.size() < 3) {
                std::wcout << L"Usage: exstop add <expression>\n";
                return false;
            }
            return AddRunStopExpression(JoinTokens(tokens, 2));
        }
        if (action == L"del" || action == L"remove") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: exstop del <index>\n";
                return false;
            }
            uint64_t index = 0;
            if (!ParseUInt64(tokens[2], index)) {
                std::wcout << L"Invalid expression index.\n";
                return false;
            }
            return RemoveRunStopExpression(static_cast<size_t>(index));
        }
        std::wcout << L"Unknown exstop action.\n";
        return false;
    }
    if (cmd == L"eb" || cmd == L"ew" || cmd == L"ed" || cmd == L"eq") {
        if (tokens.size() != 3) {
            std::wcout << L"Usage: " << cmd << L" <address|symbol|module+offset> <value>\n";
            return false;
        }

        uint64_t address = 0;
        std::wstring resolvedText;
        if (!ResolveAddressExpression(tokens[1], address, resolvedText)) {
            std::wcout << L"Invalid write address.\n";
            return false;
        }

        uint64_t value = 0;
        if (!ParseUInt64(tokens[2], value)) {
            std::wstring prefixed = L"0x" + tokens[2];
            if (!ParseUInt64(prefixed, value)) {
                std::wcout << L"Invalid write value.\n";
                return false;
            }
        }

        size_t width = 1;
        if (cmd == L"ew") {
            width = 2;
        } else if (cmd == L"ed") {
            width = 4;
        } else if (cmd == L"eq") {
            width = 8;
        }

        const uint64_t maxValue = width == 8 ? std::numeric_limits<uint64_t>::max() : ((uint64_t(1) << (width * 8)) - 1);
        if (value > maxValue) {
            std::wcout << L"Value does not fit in " << width << L" byte(s).\n";
            return false;
        }

        std::vector<uint8_t> bytes(width, 0);
        for (size_t i = 0; i < width; ++i) {
            bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
        }
        if (IsVehAgentActive()) {
            std::wstring detail;
            if (!SendVehMemoryRequest(WDBL_VEH_MSG_REQ_WRITE_MEMORY, address, bytes, static_cast<DWORD>(bytes.size()), &detail)) {
                std::wcout << L"VEH write failed: " << detail << L"\n";
                return false;
            }
            return true;
        }
        return WriteMemoryPatch(address, bytes);
    }
    if (cmd == L"eza" || cmd == L"ezu") {
        if (tokens.size() < 3) {
            std::wcout << L"Usage: " << cmd << L" <address|symbol|module+offset> <string>\n";
            return false;
        }

        uint64_t address = 0;
        std::wstring resolvedText;
        if (!ResolveAddressExpression(tokens[1], address, resolvedText)) {
            std::wcout << L"Invalid write address.\n";
            return false;
        }

        std::wstring text;
        for (size_t i = 2; i < tokens.size(); ++i) {
            if (!text.empty()) {
                text.push_back(L' ');
            }
            text += tokens[i];
        }

        std::vector<uint8_t> bytes;
        if (cmd == L"eza") {
            bytes.reserve(text.size() + 1);
            for (auto it = text.begin(); it != text.end(); ++it) {
                const wchar_t ch = *it;
                if (ch > 0x7F) {
                    std::wcout << L"ASCII string must contain 7-bit characters only.\n";
                    return false;
                }
                bytes.push_back(static_cast<uint8_t>(ch));
            }
            bytes.push_back(0);
        } else {
            bytes.reserve((text.size() + 1) * sizeof(uint16_t));
            for (auto it = text.begin(); it != text.end(); ++it) {
                const uint16_t value = static_cast<uint16_t>(*it);
                bytes.push_back(static_cast<uint8_t>(value & 0xFF));
                bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            }
            bytes.push_back(0);
            bytes.push_back(0);
        }

        return WriteMemoryPatch(address, bytes);
    }
    if (cmd == L"patch" || cmd == L"poke") {
        if (cmd == L"patch" && tokens.size() >= 2) {
            const std::wstring action = ToLower(tokens[1]);
            if (action == L"list" || action == L"ls") {
                if (tokens.size() > 3) {
                    std::wcout << L"Usage: patch list [max_items]\n";
                    return false;
                }
                uint64_t maxItems = 32;
                if (tokens.size() == 3 && !ParseUInt64(tokens[2], maxItems)) {
                    std::wcout << L"Invalid max_items value.\n";
                    return false;
                }
                ListMemoryPatchHistory(static_cast<size_t>(maxItems));
                return true;
            }
            if (action == L"undo" || action == L"revert") {
                if (tokens.size() > 3) {
                    std::wcout << L"Usage: patch undo [count|*]\n";
                    return false;
                }
                size_t undoCount = 1;
                if (tokens.size() == 3) {
                    if (tokens[2] == L"*") {
                        undoCount = patchHistory_.size();
                        if (undoCount == 0) {
                            std::wcout << L"No memory patch history is available for undo.\n";
                            return false;
                        }
                    } else {
                        uint64_t parsed = 0;
                        if (!ParseUInt64(tokens[2], parsed) || parsed == 0) {
                            std::wcout << L"Invalid undo count.\n";
                            return false;
                        }
                        undoCount = static_cast<size_t>(parsed);
                    }
                }
                return UndoMemoryPatch(undoCount);
            }
        }
        if (tokens.size() < 3) {
            std::wcout << L"Usage: patch <address> <byte1> [byte2 ...]\n";
            return false;
        }
        uint64_t address = 0;
        if (!ParseUInt64(tokens[1], address)) {
            std::wcout << L"Invalid patch address.\n";
            return false;
        }
        std::wstring sequence;
        for (size_t i = 2; i < tokens.size(); ++i) {
            if (!sequence.empty()) {
                sequence.push_back(L' ');
            }
            sequence += tokens[i];
        }
        std::vector<uint8_t> bytes;
        std::wstring parseError;
        if (!ParseHexByteSequenceText(sequence, bytes, parseError)) {
            std::wcout << L"Invalid byte sequence: " << parseError << L"\n";
            return false;
        }
        return WriteMemoryPatch(address, bytes);
    }
    if (cmd == L"patchstr" || cmd == L"ps") {
        if (tokens.size() < 4) {
            std::wcout << L"Usage: patchstr <address> <ascii|utf16> <text>\n";
            return false;
        }
        uint64_t address = 0;
        if (!ParseUInt64(tokens[1], address)) {
            std::wcout << L"Invalid patch address.\n";
            return false;
        }
        std::wstring text;
        for (size_t i = 3; i < tokens.size(); ++i) {
            if (!text.empty()) {
                text.push_back(L' ');
            }
            text += tokens[i];
        }
        const std::wstring encoding = ToLower(tokens[2]);
        std::vector<uint8_t> bytes;
        if (encoding == L"ascii") {
 for (auto __rangeIt41 = (text).begin(); __rangeIt41 != (text).end(); ++__rangeIt41) {
                wchar_t ch = *__rangeIt41;
                if (ch > 0x7F) {
                    std::wcout << L"ASCII patch text must contain 7-bit characters only.\n";
                    return false;
                }
                bytes.push_back(static_cast<uint8_t>(ch));
            }
        } else if (encoding == L"utf16" || encoding == L"utf16le" || encoding == L"wide" || encoding == L"w") {
            bytes.reserve(text.size() * sizeof(wchar_t));
 for (auto __rangeIt42 = (text).begin(); __rangeIt42 != (text).end(); ++__rangeIt42) {
                wchar_t ch = *__rangeIt42;
                const uint16_t value = static_cast<uint16_t>(ch);
                bytes.push_back(static_cast<uint8_t>(value & 0xFF));
                bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            }
        } else {
            std::wcout << L"Unsupported patch string encoding. Use ascii or utf16.\n";
            return false;
        }
        return WriteMemoryPatch(address, bytes);
    }
    if (cmd == L"patchfile" || cmd == L"pf") {
        if (tokens.size() >= 3 && ToLower(tokens[1]) == L"preview") {
            if (tokens.size() < 3 || tokens.size() > 5) {
                std::wcout << L"Usage: patchfile preview <file_path> [offset] [size]\n";
                return false;
            }
            uint64_t offset = 0;
            if (tokens.size() >= 4 && !ParseUInt64(tokens[3], offset)) {
                std::wcout << L"Invalid file offset.\n";
                return false;
            }
            std::optional<uint64_t> sizeHint;
            if (tokens.size() >= 5) {
                uint64_t parsedSize = 0;
                if (!ParseUInt64(tokens[4], parsedSize)) {
                    std::wcout << L"Invalid file preview size.\n";
                    return false;
                }
                sizeHint = parsedSize;
            }

            std::vector<uint8_t> bytes;
            std::wstring readError;
            if (!ReadBinaryFileSlice(tokens[2], offset, sizeHint, bytes, readError)) {
                std::wcout << L"Unable to load preview bytes from file: " << readError << L"\n";
                return false;
            }
            std::wcout << L"Patch file preview | file=" << tokens[2]
                       << L" | offset=" << offset
                       << L" | size=" << bytes.size()
                       << L" | bytes=" << BytesToHexPreview(bytes, 64) << L"\n";
            return true;
        }

        if (tokens.size() < 3 || tokens.size() > 5) {
            std::wcout << L"Usage: patchfile <address> <file_path> [offset] [size]\n";
            return false;
        }
        uint64_t address = 0;
        if (!ParseUInt64(tokens[1], address)) {
            std::wcout << L"Invalid patch address.\n";
            return false;
        }
        uint64_t offset = 0;
        if (tokens.size() >= 4 && !ParseUInt64(tokens[3], offset)) {
            std::wcout << L"Invalid file offset.\n";
            return false;
        }
        std::optional<uint64_t> sizeHint;
        if (tokens.size() >= 5) {
            uint64_t parsedSize = 0;
            if (!ParseUInt64(tokens[4], parsedSize)) {
                std::wcout << L"Invalid file patch size.\n";
                return false;
            }
            sizeHint = parsedSize;
        }

        std::vector<uint8_t> bytes;
        std::wstring readError;
        if (!ReadBinaryFileSlice(tokens[2], offset, sizeHint, bytes, readError)) {
            std::wcout << L"Unable to load patch bytes from file: " << readError << L"\n";
            return false;
        }
        return WriteMemoryPatch(address, bytes);
    }
    if (cmd == L"nop") {
        if (tokens.size() != 3) {
            std::wcout << L"Usage: nop <address> <count>\n";
            return false;
        }
        uint64_t address = 0;
        uint64_t count = 0;
        if (!ParseUInt64(tokens[1], address) || !ParseUInt64(tokens[2], count) || count == 0) {
            std::wcout << L"Invalid nop address/count.\n";
            return false;
        }
        if (count > 4096) {
            std::wcout << L"NOP count too large (max 4096).\n";
            return false;
        }
        std::vector<uint8_t> bytes(static_cast<size_t>(count), 0x90);
        return WriteMemoryPatch(address, bytes);
    }
    if (cmd == L"plugin" || cmd == L"plug") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: plugin <load|unload|enable|disable|list|run|autoload> ...\n";
            return false;
        }
        const std::wstring action = ToLower(tokens[1]);
        if (action == L"list" || action == L"ls") {
            ListPluginModules();
            return true;
        }
        if (action == L"autoload") {
            AutoLoadPluginModules();
            return true;
        }
        if (action == L"load") {
            if (tokens.size() < 3) {
                std::wcout << L"Usage: plugin load <dll_path>\n";
                return false;
            }
            return LoadPluginModule(JoinTokens(tokens, 2));
        }
        if (action == L"enable" || action == L"disable") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: plugin " << action << L" <id|name>\n";
                return false;
            }
            return SetPluginModuleEnabled(tokens[2], action == L"enable");
        }
        if (action == L"unload" || action == L"remove" || action == L"rm") {
            if (tokens.size() != 3) {
                std::wcout << L"Usage: plugin unload <id|name|*>\n";
                return false;
            }
            return UnloadPluginModule(tokens[2]);
        }
        if (action == L"run" || action == L"exec") {
            if (tokens.size() < 3) {
                std::wcout << L"Usage: plugin run <id|name> [args...]\n";
                return false;
            }
            const std::wstring pluginToken = tokens[2];
            std::wstring args;
            if (tokens.size() > 3) {
                args = JoinTokens(tokens, 3);
            }
            return ExecutePluginModule(pluginToken, args);
        }
        std::wcout << L"Unknown plugin action.\n";
        return false;
    }
    if (cmd == L"process" || cmd == L"!process") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: !process\n";
            return false;
        }
        PrintProcessInfo();
        return true;
    }
    if (cmd == L"processes" || cmd == L"ps") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: processes\n";
            return false;
        }
        PrintProcessList();
        return true;
    }
    if (cmd == L"!thread") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: !thread\n";
            return false;
        }
        PrintCurrentThreadInfo();
        return true;
    }
    if (cmd == L"threads") {
        if (IsVehAgentActive()) {
            PrintVehThreads();
            return true;
        }
        PrintThreadInfo();
        return true;
    }
    if (cmd == L"!vm" || cmd == L"vm") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: !vm\n";
            return false;
        }
        PrintVirtualMemoryInfo();
        return true;
    }
    if (cmd == L"vmmap" || cmd == L"memmap") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: vmmap\n";
            return false;
        }
        PrintMemoryMapInfo();
        return true;
    }
    if (cmd == L"vad") {
        if (tokens.size() == 1) {
            PrintVadInfo();
            return true;
        }
        if (tokens.size() == 4 && ToLower(tokens[1]) == L"dump") {
            PrintVadDump(tokens[2], tokens[3]);
            return true;
        }
        {
            std::wcout << L"Usage: vad | vad dump <index|0xaddress> <file>\n";
            return false;
        }
    }
    if (cmd == L"modifycheck" || cmd == L"hookcheck" || cmd == L"patchcheck") {
        if (tokens.size() > 2) {
            std::wcout << L"Usage: modifycheck [module]\n";
            return false;
        }
        PrintModifyCheck(tokens.size() == 2 ? tokens[1] : L"ntdll.dll");
        return true;
    }
    if (cmd == L"iatcheck") {
        if (tokens.size() > 2) {
            std::wcout << L"Usage: iatcheck [module|all]\n";
            return false;
        }
        PrintIatCheck(tokens.size() == 2 ? tokens[1] : L"");
        return true;
    }
    if (cmd == L"syscallcheck") {
        if (tokens.size() > 2) {
            std::wcout << L"Usage: syscallcheck [module]\n";
            return false;
        }
        PrintSyscallCheck(tokens.size() == 2 ? tokens[1] : L"ntdll.dll");
        return true;
    }
    if (cmd == L"threadcheck") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: threadcheck\n";
            return false;
        }
        PrintThreadCheck();
        return true;
    }
    if (cmd == L"analysis") {
        if (tokens.size() != 2 || ToLower(tokens[1]) != L"report") {
            std::wcout << L"Usage: analysis report\n";
            return false;
        }
        PrintAnalysisReport();
        return true;
    }
    if (cmd == L"exceptioncheck" || cmd == L"excheck") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: exceptioncheck\n";
            return false;
        }
        PrintExceptionCheck();
        return true;
    }
    if (cmd == L"modulecheck" || cmd == L"modcheck") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: modulecheck\n";
            return false;
        }
        PrintModuleCheck();
        return true;
    }
    if (cmd == L"report") {
        if (tokens.size() < 2 || ToLower(tokens[1]) != L"export" ||
            tokens.size() > 4) {
            std::wcout << L"Usage: report export <file> [txt|json]\n";
            return false;
        }
        if (tokens.size() < 3) {
            std::wcout << L"Usage: report export <file> [txt|json]\n";
            return false;
        }
        return ExportAnalysisReport(
            tokens[2],
            tokens.size() == 4 ? tokens[3] : L"txt");
    }
    if (cmd == L"apitrace") {
        if (tokens.size() > 3) {
            std::wcout << L"Usage: apitrace [max] [filter]\n";
            return false;
        }
        size_t maxEvents = 256;
        std::wstring filter;
        if (tokens.size() >= 2) {
            uint64_t value = 0;
            if (ParseUInt64(tokens[1], value)) {
                maxEvents = static_cast<size_t>(value);
                if (tokens.size() == 3) {
                    filter = tokens[2];
                }
            } else {
                filter = tokens[1];
            }
        }
        PrintApiTrace(maxEvents, filter);
        return true;
    }
    if (cmd == L"timeline") {
        if (tokens.size() > 3) {
            std::wcout << L"Usage: timeline [max] | timeline follow [interval_ms]\n";
            return false;
        }
        const bool follow = tokens.size() >= 2 && ToLower(tokens[1]) == L"follow";
        if (!follow && tokens.size() == 3) {
            std::wcout << L"Usage: timeline [max] | timeline follow [interval_ms]\n";
            return false;
        }
        uint32_t maxEvents = 256;
        uint32_t intervalMs = 500;
        if (follow) {
            if (tokens.size() == 3 &&
                (!ParseUInt32(tokens[2], intervalMs) || intervalMs == 0)) {
                std::wcout << L"Invalid timeline interval.\n";
                return false;
            }
            intervalMs = std::min<uint32_t>(intervalMs, 60000);
            std::wcout << L"Watching timeline; press Esc or q to stop.\n";
        } else if (tokens.size() == 2 &&
                   (!ParseUInt32(tokens[1], maxEvents) || maxEvents == 0)) {
            std::wcout << L"Invalid timeline event count.\n";
            return false;
        }
        maxEvents = std::min<uint32_t>(maxEvents, 256);
        do {
            PrintTimeline(maxEvents);
            if (!follow) {
                break;
            }
            for (uint32_t waited = 0; waited < intervalMs; waited += 50) {
                if (_kbhit()) {
                    const int key = _getch();
                    if (key == 27 || key == 'q' || key == 'Q') {
                        std::wcout << L"\nStopped timeline follow.\n";
                        return true;
                    }
                }
                Sleep(50);
            }
            DWORD exitCode = STILL_ACTIVE;
            if (processHandle_ == nullptr ||
                !GetExitCodeProcess(processHandle_, &exitCode) ||
                exitCode != STILL_ACTIVE) {
                std::wcout << L"\nTarget process is no longer active.\n";
                break;
            }
        } while (true);
        return true;
    }
    if (cmd == L"modules") {
        if (IsVehAgentActive()) {
            PrintVehModules();
            return true;
        }
        PrintModuleInfo();
        return true;
    }
    if (cmd == L"lm") {
        if (tokens.size() == 1) {
            if (IsVehAgentActive()) {
                PrintVehModules();
                return true;
            }
            PrintModuleInfo();
            return true;
        }
        if (tokens.size() == 3 && ToLower(tokens[1]) == L"m") {
            if (IsVehAgentActive()) {
                PrintVehModules(tokens[2]);
                return true;
            }
            PrintModuleInfo(tokens[2]);
            return true;
        }
        std::wcout << L"Usage: lm [m <module-filter>]\n";
        return false;
    }
    if (cmd == L"sympath" || cmd == L".sympath") {
        if (tokens.size() == 1) {
            if (active_ && processHandle_ != nullptr && !InitializeSymbolEngine()) {
                std::wcout << L"Symbol engine is not initialized.\n";
                return false;
            }
            if (symbolSearchPath_.empty()) {
                ConfigureDefaultSymbolPath(false);
            }
            const std::wstring currentPath = GetSymbolSearchPath();
            std::wcout << L"Symbol path: " << (currentPath.empty() ? L"(empty)" : currentPath) << L"\n";
            return true;
        }

        if (!SetSymbolSearchPath(JoinTokens(tokens, 1))) {
            return false;
        }
        std::wcout << L"Symbol path updated.\n";
        return true;
    }
    if (cmd == L"symfix") {
        if (tokens.size() >= 2) {
            symbolCacheDirectory_ = tokens[1];
        }
        if (tokens.size() >= 3) {
            symbolServerUrl_ = tokens[2];
        }
        if (!ConfigureDefaultSymbolPath(true)) {
            return false;
        }

        std::wcout << L"Configured symbol server path: " << GetSymbolSearchPath() << L"\n";
        return true;
    }
    if (cmd == L"symreload" || cmd == L"reloadsym" || cmd == L".reload") {
        std::optional<std::wstring> filter = std::nullopt;
        if (tokens.size() >= 2) {
            filter = JoinTokens(tokens, 1);
        }
        return ReloadSymbols(false, filter);
    }
    if (cmd == L"symdownload" || cmd == L"symdl") {
        std::optional<std::wstring> filter = std::nullopt;
        if (tokens.size() >= 2) {
            filter = JoinTokens(tokens, 1);
        }
        return ReloadSymbols(true, filter);
    }
    if (cmd == L"srcroot" || cmd == L"sourceroot") {
        if (tokens.size() == 1 || ToLower(tokens[1]) == L"list") {
            ListSourceRoots();
            return true;
        }
        const std::wstring action = ToLower(tokens[1]);
        if (action == L"clear") {
            ClearSourceRoots();
            return true;
        }
        if (tokens.size() < 3) {
            std::wcout << L"Usage: srcroot <add|del|list|clear> [path]\n";
            return false;
        }
        if (action == L"add") {
            return AddSourceRoot(JoinTokens(tokens, 2));
        }
        if (action == L"del" || action == L"rm" || action == L"remove") {
            return RemoveSourceRoot(JoinTokens(tokens, 2));
        }
        std::wcout << L"Unknown srcroot action.\n";
        return false;
    }
    if (cmd == L"srcwhere") {
        if (!EnsurePaused()) {
            return false;
        }
        const uint64_t ip = GetInstructionPointer(stopState_.context);
        PrintSourceAtAddress(ip, 2);
        return true;
    }
    if (cmd == L"srcat") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: srcat <address> [context_lines]\n";
            return false;
        }
        uint64_t address = 0;
        if (!ParseUInt64(tokens[1], address)) {
            std::wcout << L"Invalid address.\n";
            return false;
        }
        size_t contextLines = 2;
        if (tokens.size() >= 3) {
            uint64_t value = 0;
            if (ParseUInt64(tokens[2], value)) {
                contextLines = static_cast<size_t>(std::min<uint64_t>(value, 50));
            }
        }
        PrintSourceAtAddress(address, contextLines);
        return true;
    }
    if (cmd == L"srcbp") {
        if (tokens.size() < 3) {
            std::wcout << L"Usage: srcbp <file> <line>\n";
            return false;
        }
        uint64_t line = 0;
        if (!ParseUInt64(tokens.back(), line) || line == 0 || line > std::numeric_limits<uint32_t>::max()) {
            std::wcout << L"Invalid line number.\n";
            return false;
        }
        std::wstringstream fileBuilder;
        for (size_t i = 1; i + 1 < tokens.size(); ++i) {
            if (i > 1) {
                fileBuilder << L' ';
            }
            fileBuilder << tokens[i];
        }
        return SetSourceBreakpoint(fileBuilder.str(), static_cast<uint32_t>(line));
    }
    if (cmd == L"srcresolve" || cmd == L"srcr") {
        if (tokens.size() < 3) {
            std::wcout << L"Usage: srcresolve <file> <line>\n";
            return false;
        }
        uint64_t line = 0;
        if (!ParseUInt64(tokens.back(), line) || line == 0 || line > std::numeric_limits<uint32_t>::max()) {
            std::wcout << L"Invalid line number.\n";
            return false;
        }
        std::wstringstream fileBuilder;
        for (size_t i = 1; i + 1 < tokens.size(); ++i) {
            if (i > 1) {
                fileBuilder << L' ';
            }
            fileBuilder << tokens[i];
        }

        uint64_t address = 0;
        std::wstring matchedFile;
        if (!ResolveSourceAddress(fileBuilder.str(), static_cast<uint32_t>(line), address, matchedFile)) {
            return false;
        }

        std::wcout << L"Resolved source location: " << matchedFile << L":" << line
                   << L" -> " << ToHex(address) << L" " << ResolveSymbol(address) << L"\n";
        return true;
    }
    if (cmd == L"scriptload" || cmd == L"sload") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: scriptload <file>\n";
            return false;
        }
        return LoadScriptFile(JoinTokens(tokens, 1));
    }
    if (cmd == L"scriptshow" || cmd == L"sshow") {
        ShowScript();
        return true;
    }
    if (cmd == L"scriptclear" || cmd == L"sclear") {
        ClearScriptState();
        std::wcout << L"Script state cleared.\n";
        return true;
    }
    if (cmd == L"scriptreset" || cmd == L"sreset") {
        if (!scriptLoaded_) {
            std::wcout << L"No script loaded.\n";
            return false;
        }
        scriptCursor_ = 0;
        scriptResumePastBreakpoint_ = false;
        std::wcout << L"Script cursor reset to first line.\n";
        return true;
    }
    if (cmd == L"scriptrun" || cmd == L"scriptstart" || cmd == L"srun") {
        if (fromScript) {
            std::wcout << L"Nested script execution is not supported.\n";
            return false;
        }
        return RunScript(false);
    }
    if (cmd == L"scriptstep" || cmd == L"sstep") {
        if (fromScript) {
            std::wcout << L"Nested script execution is not supported.\n";
            return false;
        }
        return RunScript(true);
    }
    if (cmd == L"scriptuntil" || cmd == L"srunto") {
        if (fromScript) {
            std::wcout << L"Nested script execution is not supported.\n";
            return false;
        }
        if (tokens.size() != 2) {
            std::wcout << L"Usage: scriptuntil <label>\n";
            return false;
        }
        return RunScriptUntilLabel(tokens[1]);
    }
    if (cmd == L"scriptbp" || cmd == L"sbp") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: scriptbp <line>\n";
            return false;
        }
        uint64_t line = 0;
        if (!ParseUInt64(tokens[1], line) || line == 0) {
            std::wcout << L"Invalid line number.\n";
            return false;
        }
        return SetScriptBreakpoint(static_cast<size_t>(line));
    }
    if (cmd == L"scriptbd" || cmd == L"sbd") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: scriptbd <line>\n";
            return false;
        }
        uint64_t line = 0;
        if (!ParseUInt64(tokens[1], line) || line == 0) {
            std::wcout << L"Invalid line number.\n";
            return false;
        }
        return RemoveScriptBreakpoint(static_cast<size_t>(line));
    }
    if (cmd == L"scriptbl" || cmd == L"sbl") {
        ListScriptBreakpoints();
        return true;
    }
    if (cmd == L"scriptset" || cmd == L"sset") {
        if (tokens.size() < 3) {
            std::wcout << L"Usage: scriptset <name> <value>\n";
            return false;
        }
        scriptVariables_[ToLower(tokens[1])] = JoinTokens(tokens, 2);
        return true;
    }
    if (cmd == L"scriptunset") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: scriptunset <name>\n";
            return false;
        }
        scriptVariables_.erase(ToLower(tokens[1]));
        return true;
    }
    if (cmd == L"scriptvars" || cmd == L"svars") {
        ShowScriptVariables();
        return true;
    }
    if (cmd == L"exception") {
        PrintExceptionInfo();
        return true;
    }
    if (cmd == L"r" || cmd == L"regs") {
        bool showUi = false;
        std::vector<std::wstring> args;
        args.push_back(tokens[0]);
        for (size_t i = 1; i < tokens.size(); ++i) {
            const std::wstring arg = ToLower(tokens[i]);
            if (arg == L"--ui" || arg == L"/ui") {
                showUi = true;
            } else {
                args.push_back(tokens[i]);
            }
        }
        if (args.size() > 2) {
            std::wcout << L"Usage: r [mmx|float|debug|reg=value] [--ui]\n";
            return false;
        }
        if (IsVehAgentActive() && !showUi) {
            if (args.size() == 1) {
                if (IsVehBreakPending()) {
                    if (!g_wdblVehLastContextValid) {
                        std::wcout << L"No VEH stop context is available.\n";
                        return false;
                    }
                    std::wcout << L"[VEH] context tid=" << g_wdblVehLastContext.threadId << L"\n";
                    PrintVehContext(g_wdblVehLastContext);
                    return true;
                }
                const DWORD tid = GetDefaultVehThreadId();
                if (tid == 0) {
                    std::wcout << L"No VEH thread is available.\n";
                    return false;
                }
                WdblVehContextRequest request = {};
                request.threadId = tid;
                std::wstring detail;
                if (!SendVehContextRequest(request, WDBL_VEH_MSG_REQ_GET_CONTEXT, &detail)) {
                    std::wcout << L"VEH context failed: " << detail << L"\n";
                    return false;
                }
                return true;
            }
            if (args.size() == 2 && args[1].find(L'=') != std::wstring::npos) {
                const size_t eq = args[1].find(L'=');
                const std::wstring reg = args[1].substr(0, eq);
                const std::wstring valueText = args[1].substr(eq + 1);
                uint64_t value = 0;
                if (!ParseUInt64(valueText, value)) {
                    std::wstring prefixed = L"0x" + valueText;
                    if (!ParseUInt64(prefixed, value)) {
                        std::wcout << L"Invalid register value.\n";
                        return false;
                    }
                }
                const DWORD tid = GetDefaultVehThreadId();
                if (tid == 0) {
                    std::wcout << L"No VEH thread is available.\n";
                    return false;
                }
                WdblVehContextRequest request = {};
                request.threadId = tid;
                if (!FillVehContextRegister(request, reg, value)) {
                    std::wcout << L"Unknown register: " << reg << L"\n";
                    return false;
                }
                if (IsVehBreakPending()) {
                    if (!g_wdblVehLastContextValid || g_wdblVehLastContext.threadId != tid) {
                        std::wcout << L"Stopped VEH context is for a different thread.\n";
                        return false;
                    }
                    QueueVehStoppedContextUpdate(request);
                    std::wcout << L"VEH stopped context updated. It will apply on continue.\n";
                    return true;
                }
                std::wstring detail;
                if (!SendVehContextRequest(request, WDBL_VEH_MSG_REQ_SET_CONTEXT, &detail)) {
                    std::wcout << L"VEH setreg failed: " << detail << L"\n";
                    return false;
                }
                return true;
            }
            if (args.size() == 2) {
                uint32_t tid = 0;
                if (ParseUInt32(args[1], tid)) {
                    if (IsVehBreakPending() && g_wdblVehLastContextValid && g_wdblVehLastContext.threadId == tid) {
                        std::wcout << L"[VEH] context tid=" << g_wdblVehLastContext.threadId << L"\n";
                        PrintVehContext(g_wdblVehLastContext);
                        return true;
                    }
                    WdblVehContextRequest request = {};
                    request.threadId = tid;
                    std::wstring detail;
                    if (!SendVehContextRequest(request, WDBL_VEH_MSG_REQ_GET_CONTEXT, &detail)) {
                        std::wcout << L"VEH context failed: " << detail << L"\n";
                        return false;
                    }
                    return true;
                }
            }
        }
        if (args.size() == 2) {
            if (args[1].find(L'=') != std::wstring::npos) {
                if (showUi) {
                    std::wcout << L"Usage: r [mmx|float|debug|reg=value] [--ui]\n";
                    return false;
                }
                return SetRegisterValue(args[1]);
            }
            const std::wstring view = ToLower(args[1]);
            if (showUi) {
                if (view == L"mmx" || view == L"float" || view == L"fpu" || view == L"debug" || view == L"dr") {
                    return ShowRegisterUi(view);
                }
                std::wcout << L"Usage: r [mmx|float|debug|reg=value] [--ui]\n";
                return false;
            }
            if (view == L"mmx") {
                PrintMmxRegisterInfo();
                return true;
            }
            if (view == L"float" || view == L"fpu") {
                PrintFloatRegisterInfo();
                return true;
            }
            if (view == L"debug" || view == L"dr") {
                PrintDebugRegisterInfo();
                return true;
            }
            std::wcout << L"Usage: r [mmx|float|debug|reg=value] [--ui]\n";
            return false;
        }
        if (showUi) {
            return ShowRegisterUi();
        }
        PrintRegisterInfo();
        return true;
    }
    if (cmd == L"k" || cmd == L"kb" || cmd == L"kv") {
        bool showUi = false;
        std::vector<std::wstring> args;
        args.push_back(tokens[0]);
        for (size_t i = 1; i < tokens.size(); ++i) {
            const std::wstring arg = ToLower(tokens[i]);
            if (arg == L"--ui" || arg == L"/ui") {
                showUi = true;
            } else {
                args.push_back(tokens[i]);
            }
        }
        size_t frames = 32;
        if (args.size() >= 2) {
            uint64_t tmp = 0;
            if (ParseUInt64(args[1], tmp)) {
                frames = static_cast<size_t>(tmp);
            } else {
                std::wcout << L"Usage: " << cmd << L" [max_frames] [--ui]\n";
                return false;
            }
        }
        if (args.size() > 2) {
            std::wcout << L"Usage: " << cmd << L" [max_frames] [--ui]\n";
            return false;
        }
        if (showUi) {
            return ShowStackUi(0, cmd);
        }
        PrintCallStack(frames, cmd == L"kb" || cmd == L"kv", cmd == L"kv");
        return true;
    }
    if (cmd == L"stack") {
        bool showUi = false;
        std::vector<std::wstring> args;
        args.push_back(tokens[0]);
        for (size_t i = 1; i < tokens.size(); ++i) {
            const std::wstring arg = ToLower(tokens[i]);
            if (arg == L"--ui" || arg == L"/ui") {
                showUi = true;
            } else {
                args.push_back(tokens[i]);
            }
        }
        size_t frames = 32;
        if (args.size() >= 2) {
            uint64_t tmp = 0;
            if (ParseUInt64(args[1], tmp)) {
                frames = static_cast<size_t>(tmp);
            } else {
                std::wcout << L"Usage: stack [max_frames] [--ui]\n";
                return false;
            }
        }
        if (args.size() > 2) {
            std::wcout << L"Usage: stack [max_frames] [--ui]\n";
            return false;
        }
        if (showUi) {
            return ShowStackUi(0, L"stack");
        }
        PrintStackInfo(frames);
        return true;
    }
    if (cmd == L"seh") {
        PrintSehChain();
        return true;
    }
    if (cmd == L"!peb" || cmd == L"peb") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: !peb\n";
            return false;
        }
        PrintPebInfo();
        return true;
    }
    if (cmd == L"!teb" || cmd == L"teb") {
        if (tokens.size() != 1) {
            std::wcout << L"Usage: !teb\n";
            return false;
        }
        PrintTebInfo();
        return true;
    }
    if (cmd == L"handles") {
        size_t limit = 200;
        if (tokens.size() > 2) {
            std::wcout << L"Usage: handles [max|all]\n";
            return false;
        }
        if (tokens.size() == 2) {
            if (ToLower(tokens[1]) == L"all" || tokens[1] == L"*") {
                limit = 0;
            } else {
                uint64_t tmp = 0;
                if (!ParseUInt64(tokens[1], tmp)) {
                    std::wcout << L"Invalid handle limit.\n";
                    return false;
                }
                limit = static_cast<size_t>(tmp);
            }
        }
        PrintHandleInfo(limit);
        return true;
    }
    if (cmd == L"memstr") {
        size_t minLen = 6;
        size_t maxMatches = 200;
        if (tokens.size() >= 2) {
            uint64_t tmp = 0;
            if (ParseUInt64(tokens[1], tmp)) {
                minLen = static_cast<size_t>(tmp);
            }
        }
        if (tokens.size() >= 3) {
            uint64_t tmp = 0;
            if (ParseUInt64(tokens[2], tmp)) {
                maxMatches = static_cast<size_t>(tmp);
            }
        }
        PrintMemoryStrings(minLen, maxMatches);
        return true;
    }
    if (cmd == L"s" || cmd == L"search") {
        return SearchMemory(tokens);
    }
    if (cmd == L"db" || cmd == L"dw" || cmd == L"dd" || cmd == L"dq") {
        bool showUi = false;
        std::vector<std::wstring> args;
        args.push_back(tokens[0]);
        for (size_t i = 1; i < tokens.size(); ++i) {
            const std::wstring arg = ToLower(tokens[i]);
            if (arg == L"--ui" || arg == L"/ui") {
                showUi = true;
            } else {
                args.push_back(tokens[i]);
            }
        }
        if (args.size() < 2 || args.size() > 4) {
            std::wcout << L"Usage: " << cmd << L" <address|symbol|module+offset> [byte_count] [items_per_line] [--ui]\n";
            return false;
        }

        uint64_t address = 0;
        std::wstring resolvedText;
        if (!ResolveAddressExpression(args[1], address, resolvedText)) {
            std::wcout << L"Invalid memory address.\n";
            return false;
        }

        uint64_t byteCount = 16 * 16;
        uint64_t itemsPerLine = 0;
        if (args.size() >= 3) {
            if (!ParseUInt64(args[2], byteCount) || byteCount == 0) {
                std::wcout << L"Invalid byte count.\n";
                return false;
            }
        }
        if (args.size() >= 4) {
            if (!ParseUInt64(args[3], itemsPerLine) || itemsPerLine == 0) {
                std::wcout << L"Invalid items-per-line value.\n";
                return false;
            }
        }

        size_t unitSize = 1;
        if (cmd == L"dw") {
            unitSize = 2;
        } else if (cmd == L"dd") {
            unitSize = 4;
        } else if (cmd == L"dq") {
            unitSize = 8;
        }
        if (itemsPerLine == 0) {
            if (unitSize == 2) {
                itemsPerLine = 8;
            } else if (unitSize == 4) {
                itemsPerLine = 4;
            } else if (unitSize == 8) {
                itemsPerLine = 2;
            } else {
                itemsPerLine = 16;
            }
        }
        if (showUi) {
            return ShowMemoryUi(address, static_cast<size_t>(byteCount), unitSize, static_cast<size_t>(itemsPerLine));
        }
        if (IsVehAgentActive()) {
            uint64_t remaining = byteCount;
            uint64_t current = address;
            while (remaining != 0) {
                const DWORD chunk = static_cast<DWORD>(std::min<uint64_t>(remaining, WDBL_VEH_MAX_MEMORY_BYTES));
                std::wstring detail;
                if (!SendVehMemoryRequest(WDBL_VEH_MSG_REQ_READ_MEMORY, current, std::vector<uint8_t>(), chunk, &detail)) {
                    std::wcout << L"VEH read failed: " << detail << L"\n";
                    return false;
                }
                current += chunk;
                remaining -= chunk;
            }
            return true;
        }
        PrintMemoryDump(address, static_cast<size_t>(byteCount), unitSize, static_cast<size_t>(itemsPerLine));
        return true;
    }
    if (cmd == L"da") {
        bool showUi = false;
        std::vector<std::wstring> args;
        args.push_back(tokens[0]);
        for (size_t i = 1; i < tokens.size(); ++i) {
            const std::wstring arg = ToLower(tokens[i]);
            if (arg == L"--ui" || arg == L"/ui") {
                showUi = true;
            } else {
                args.push_back(tokens[i]);
            }
        }
        if (args.size() < 2 || args.size() > 3) {
            std::wcout << L"Usage: da <address|symbol|module+offset> [byte_count] [--ui]\n";
            return false;
        }
        uint64_t address = 0;
        std::wstring resolvedText;
        if (!ResolveAddressExpression(args[1], address, resolvedText)) {
            std::wcout << L"Invalid ASCII memory address.\n";
            return false;
        }
        uint64_t byteCount = 256;
        if (args.size() == 3 && (!ParseUInt64(args[2], byteCount) || byteCount == 0)) {
            std::wcout << L"Invalid byte count.\n";
            return false;
        }
        if (showUi) {
            return ShowMemoryUi(address, static_cast<size_t>(byteCount), 1, 8, true);
        }
        PrintAsciiMemory(address, static_cast<size_t>(byteCount));
        return true;
    }
    if (cmd == L"dt") {
        if (tokens.size() < 3 || tokens.size() > 4) {
            std::wcout << L"Usage: dt <type|module!type> <address|symbol|module+offset> [depth]\n";
            return false;
        }
        uint64_t address = 0;
        std::wstring resolvedText;
        if (!ResolveAddressExpression(tokens[2], address, resolvedText)) {
            std::wcout << L"Invalid dt address.\n";
            return false;
        }
        size_t depth = 1;
        if (tokens.size() == 4) {
            uint64_t parsedDepth = 0;
            if (!ParseUInt64(tokens[3], parsedDepth) || parsedDepth == 0) {
                std::wcout << L"Invalid dt depth.\n";
                return false;
            }
            depth = static_cast<size_t>(parsedDepth);
        }
        return DisplayType(tokens[1], address, depth);
    }
    if (cmd == L".writemem" || cmd == L"writemem") {
        if (tokens.size() != 4) {
            std::wcout << L"Usage: .writemem <file_path> <address|symbol|module+offset> L<size>\n";
            return false;
        }

        uint64_t address = 0;
        std::wstring resolvedText;
        if (!ResolveAddressExpression(tokens[2], address, resolvedText)) {
            std::wcout << L"Invalid .writemem address.\n";
            return false;
        }

        std::wstring sizeToken = tokens[3];
        if (!sizeToken.empty() && (sizeToken[0] == L'L' || sizeToken[0] == L'l')) {
            sizeToken = sizeToken.substr(1);
        }
        uint64_t size = 0;
        if (!ParseUInt64(sizeToken, size) || size == 0) {
            std::wstring prefixed = L"0x" + sizeToken;
            if (!ParseUInt64(prefixed, size) || size == 0) {
                std::wcout << L"Invalid .writemem size.\n";
                return false;
            }
        }
        return WriteMemoryRangeToFile(tokens[1], address, static_cast<size_t>(size));
    }
    if (cmd == L"dump") {
        if (tokens.size() != 2 && tokens.size() != 4) {
            std::wcout << L"Usage: dump <file_path> [base_address length]\n";
            return false;
        }
        if (tokens.size() == 2) {
            return DumpCurrentImageToFile(tokens[1]);
        }

        uint64_t address = 0;
        uint64_t length = 0;
        if (!ParseUInt64(tokens[2], address) || address == 0) {
            std::wcout << L"Invalid dump base address.\n";
            return false;
        }
        if (!ParseUInt64(tokens[3], length) || length == 0) {
            std::wstring prefixed = L"0x" + tokens[3];
            if (!ParseUInt64(prefixed, length) || length == 0) {
                std::wcout << L"Invalid dump length.\n";
                return false;
            }
        }
        return DumpMemoryRangeToFile(tokens[1], address, static_cast<size_t>(length));
    }
    if (cmd == L".dvalloc" || cmd == L"dvalloc") {
        if (tokens.size() != 2) {
            std::wcout << L"Usage: .dvalloc <size>\n";
            return false;
        }
        uint64_t size = 0;
        if (!ParseUInt64(tokens[1], size) || size == 0) {
            std::wstring prefixed = L"0x" + tokens[1];
            if (!ParseUInt64(prefixed, size) || size == 0) {
                std::wcout << L"Invalid allocation size.\n";
                return false;
            }
        }
        return AllocateVirtualMemory(static_cast<size_t>(size));
    }
    if (cmd == L"membin" || cmd == L"mbin") {
        if (tokens.size() != 3) {
            std::wcout << L"Usage: membin <address> <size>\n";
            return false;
        }
        uint64_t address = 0;
        uint64_t size = 0;
        if (!ParseUInt64(tokens[1], address) || !ParseUInt64(tokens[2], size)) {
            std::wcout << L"Invalid address/size.\n";
            return false;
        }
        PrintMemoryBinary(address, static_cast<size_t>(size));
        return true;
    }
    if (cmd == L"asm" || cmd == L"disasmcolor" || cmd == L"ucolor") {
        std::wstring sub;
        if (tokens.size() >= 2) {
            sub = ToLower(tokens[1]);
        }
        if (sub == L"color" || sub.empty()) {
            // Toggle when no explicit state is given.
            if (tokens.size() >= 3) {
                const std::wstring state = ToLower(tokens[2]);
                if (state == L"on") {
                    disasmColorEnabled_ = true;
                } else if (state == L"off") {
                    disasmColorEnabled_ = false;
                } else {
                    std::wcout << L"Usage: asm color <on|off|status>\n";
                    return false;
                }
            } else {
                disasmColorEnabled_ = !disasmColorEnabled_;
            }
        } else if (sub == L"on") {
            disasmColorEnabled_ = true;
        } else if (sub == L"off") {
            disasmColorEnabled_ = false;
        } else if (sub == L"status") {
            std::wcout << L"Disassembly color: " << (disasmColorEnabled_ ? L"on" : L"off") << L"\n";
            return true;
        } else {
            std::wcout << L"Usage: asm color <on|off|status>\n";
            return false;
        }
        if (disasmColorEnabled_) {
            EnsureConsoleColorEnabled();
        }
        std::wcout << L"Disassembly color: " << (disasmColorEnabled_ ? L"on" : L"off") << L"\n";
        return true;
    }

    if (cmd == L"x") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: x <module!symbol-mask>\n";
            return false;
        }
        return ExamineSymbols(JoinTokens(tokens, 1));
    }

    if (cmd == L"disasm" || cmd == L"u" || cmd == L"uf") {
        bool showUi = false;
        std::vector<std::wstring> args;
        args.reserve(tokens.size());
        for (size_t i = 1; i < tokens.size(); ++i) {
            const std::wstring arg = ToLower(tokens[i]);
            if (arg == L"--ui" || arg == L"/ui") {
                showUi = true;
                continue;
            }
            args.push_back(tokens[i]);
        }

        uint64_t address = 0;
        size_t count = 16;
        if (!args.empty()) {
            std::wstring resolvedText;
            if (!ResolveAddressExpression(args[0], address, resolvedText)) {
                std::wcout << L"Invalid disassembly target.\n";
                return false;
            }
        } else if (stopState_.valid) {
            address = GetInstructionPointer(stopState_.context);
        } else {
            std::wcout << L"Usage: disasm <address|api|module!api|module+offset> [count] [--ui]\n";
            return false;
        }
        if (args.size() >= 2) {
            uint64_t tmp = 0;
            if (ParseUInt64(args[1], tmp)) {
                count = static_cast<size_t>(tmp);
            }
        }
        if (showUi) {
            return ShowDisassemblyUi(address);
        }
        PrintDisassembly(address, count);
        return true;
    }
    if (cmd == L"pc" || cmd == L"pseudoc" || cmd == L"decompile") {
        bool showUi = false;
        bool showFeatures = false;
        std::vector<std::wstring> args;
        args.reserve(tokens.size());
        for (size_t i = 1; i < tokens.size(); ++i) {
            const std::wstring arg = ToLower(tokens[i]);
            if (arg == L"--ui" || arg == L"/ui") {
                showUi = true;
                continue;
            }
            if (arg == L"--features" || arg == L"/features") {
                showFeatures = true;
                continue;
            }
            args.push_back(tokens[i]);
        }
        (void)showFeatures;

        uint64_t address = 0;
        size_t count = 128;
        if (!args.empty()) {
            std::wstring resolvedText;
            if (!ResolveAddressExpression(args[0], address, resolvedText)) {
                std::wcout << L"Invalid pseudo C target.\n";
                return false;
            }
        } else if (stopState_.valid) {
            address = GetInstructionPointer(stopState_.context);
        } else {
            std::wcout << L"Usage: pc [address|api|module!api|module+offset] [count] [--ui] [--features]\n";
            return false;
        }
        if (args.size() >= 2) {
            uint64_t tmp = 0;
            if (ParseUInt64(args[1], tmp)) {
                count = static_cast<size_t>(tmp);
            }
        }
        PrintPseudoC(address, count, showUi);
        return true;
    }
    if (cmd == L"s" || cmd == L"search") {
        size_t minLen = 6;
        size_t maxMatches = 200;
        if (tokens.size() >= 2) {
            uint64_t tmp = 0;
            if (ParseUInt64(tokens[1], tmp)) {
                minLen = static_cast<size_t>(tmp);
            }
        }
        if (tokens.size() >= 3) {
            uint64_t tmp = 0;
            if (ParseUInt64(tokens[2], tmp)) {
                maxMatches = static_cast<size_t>(tmp);
            }
        }
        PrintMemoryStrings(minLen, maxMatches);
        return true;
    }
    if (cmd == L"comment" || cmd == L"cmt") {
        if (tokens.size() < 2) {
            std::wcout << L"Usage: comment <add|set|del|clear|show|list> [address] [text]\n";
            return false;
        }
        const std::wstring action = ToLower(tokens[1]);
        if (action == L"list" || action == L"ls") {
            ListInstructionComments();
            return true;
        }
        if (action == L"show") {
            uint64_t address = 0;
            if (tokens.size() == 2) {
                if (!EnsurePaused()) {
                    return false;
                }
                address = GetInstructionPointer(stopState_.context);
            } else if (tokens.size() == 3 && ParseUInt64(tokens[2], address)) {
                // parsed
            } else {
                std::wcout << L"Usage: comment show [address]\n";
                return false;
            }
            const auto it = instructionComments_.find(address);
            if (it == instructionComments_.end()) {
                std::wcout << L"No comment at " << ToHex(address) << L".\n";
                return false;
            }
            std::wcout << ToHex(address) << L" : " << it->second << L"\n";
            return true;
        }
        if (action == L"del" || action == L"remove" || action == L"clear") {
            uint64_t address = 0;
            if (tokens.size() == 3 && ParseUInt64(tokens[2], address)) {
                return RemoveInstructionComment(address);
            }
            if (tokens.size() == 2) {
                if (!EnsurePaused()) {
                    return false;
                }
                address = GetInstructionPointer(stopState_.context);
                return RemoveInstructionComment(address);
            }
            std::wcout << L"Usage: comment del [address]\n";
            return false;
        }
        if (action == L"add" || action == L"set") {
            uint64_t address = 0;
            size_t textStart = 2;
            if (tokens.size() >= 3 && ParseUInt64(tokens[2], address)) {
                textStart = 3;
            } else {
                if (!EnsurePaused()) {
                    return false;
                }
                address = GetInstructionPointer(stopState_.context);
            }
            if (tokens.size() <= textStart) {
                std::wcout << L"Usage: comment set [address] <text>\n";
                return false;
            }
            return SetInstructionComment(address, JoinTokens(tokens, textStart));
        }
        std::wcout << L"Unknown comment action.\n";
        return false;
    }
    if (cmd == L"context" || cmd == L"ctx") {
        PrintProcessInfo();
        PrintThreadInfo();
        PrintExceptionInfo();
        PrintRegisterInfo();
        PrintStackInfo(16);
        PrintModuleInfo();
        return true;
    }

    std::wcout << L"Unknown command. Use 'help'.\n";
    return false;
}

void Debugger::PrintHelp() const {
    std::wcout << L"Commands:\n";
    std::wcout << L"  z0dbgcli --py <file>                    Run a Python script after GUI init\n";
    std::wcout << L"  z0dbgcli --pyexec <code>                Run inline Python after GUI init\n";
    std::wcout << L"  launch <exe> [args...]                  Launch and break at main-module entry point\n";
    std::wcout << L"  .attach|attach <pid>                    Attach debugger to process\n";
    std::wcout << L"  .detach|detach                          Detach debugger from attached process\n";
    std::wcout << L"  drv <on|off|status|caps|antidebug|dr|handles|threadinfo|image|mitigations|events|events follow>\n";
    std::wcout << L"  veh <on|off|detach|kill|status> [pid]   Control VEH agent framework\n";
    std::wcout << L"  veh launch <exe> [args...]              Launch a process under VEH agent mode\n";
    std::wcout << L"  veh break                               Interrupt the VEH target process\n";
    std::wcout << L"  veh refresh                             Refresh VEH module/thread snapshot\n";
    std::wcout << L"  veh modules|threads                     Show VEH-synced module/thread cache\n";
    std::wcout << L"  veh read <addr> [size]                  Read memory through VEH agent\n";
    std::wcout << L"  veh write <addr> <byte...>              Write memory through VEH agent\n";
    std::wcout << L"  veh ctx <tid> | setreg <tid> <reg> <v>  Get/set thread context through VEH agent\n";
    std::wcout << L"  veh suspend|resume <tid>                Suspend/resume thread through VEH agent\n";
    std::wcout << L"  veh ex <bp|search|continue> [code]      Set VEH exception forwarding policy\n";
    std::wcout << L"  run | g                                 Continue execution\n";
    std::wcout << L"  step | si | t                           Single instruction step (step into)\n";
    std::wcout << L"  p | stepover | so                       Step over call/rep/loop/int\n";
    std::wcout << L"  gu                                      Go up until current function returns\n";
    std::wcout << L"  wt [max_steps]                          Trace/watch execution timing\n";
    std::wcout << L"  stepback|reverse|sbk [count]            Restore previous paused snapshot(s)\n";
    std::wcout << L"  debugback|dbk [count]                   Alias for stepback\n";
    std::wcout << L"  runtoentry|rte                          Run and break at main-module entry point\n";
    std::wcout << L"  snapshot|snap <save|restore|rerun|list|clear> [name]\n";
    std::wcout << L"  savesnap|snapsave [name]                Save current paused snapshot by name\n";
    std::wcout << L"  rerunsnap|snaprerun [name]              Restore snapshot and continue execution\n";
    std::wcout << L"  flow|cfg [address] [max_blocks]         Show textual control-flow graph\n";
    std::wcout << L"  stepuntil|traceuntil|tu <cond> [max]    Step until condition is met\n";
    std::wcout << L"  rununtil|pauseuntil|ru <cond> [max]     Continue/pause until condition is met\n";
    std::wcout << L"  autostep|astep <count> [delay_ms]       Automatic repeated single-step\n";
    std::wcout << L"  autorun|arun <cycles> [delay_ms]        Automatic repeated continue-to-pause\n";
    std::wcout << L"  break|bp <address|api|module!api|module+offset>\n";
    std::wcout << L"  bu <symbol|module!symbol|module+offset>  Set deferred software breakpoint\n";
    std::wcout << L"  hw|hr|he <addr>                         Set hardware write/read-access/execute breakpoint\n";
    std::wcout << L"  hbreak|hbp <slot> <addr> <type> <len> [tid|all]\n";
    std::wcout << L"                                           type: exec|write|access, len: 1|2|4|8\n";
    std::wcout << L"  hc|hclear <id|*>                        Delete hardware breakpoint(s)\n";
    std::wcout << L"  mbreak|mbp <addr> <size> <access>       Set memory guard breakpoint\n";
    std::wcout << L"                                           access: r|w|x|rw|rx|wx|rwx\n";
    std::wcout << L"  bl                                      List breakpoints\n";
    std::wcout << L"  be <id> | bd <id> | bc <id|*>           Enable/disable/delete breakpoint(s)\n";
    std::wcout << L"  bcond <id> <condition>                  Set breakpoint condition expression\n";
    std::wcout << L"  bcond clear <id>                        Clear breakpoint condition\n";
    std::wcout << L"                                           vars: hit tid ip addr; ops: == != > >= < <=; use &&\n";
    std::wcout << L"  excfg|exshow                            Show exception ignore/run-stop settings\n";
    std::wcout << L"  exignore all <scope> <on|off>           Toggle ignore-all exceptions in scope\n";
    std::wcout << L"  exignore add|del <scope> <code>         Manage ignored exception codes\n";
    std::wcout << L"  exignore clear <scope>                  Clear ignored exception code list\n";
    std::wcout << L"                                           scope: debug|run|step; code: hex or aliases (av,bp,ss,guard)\n";
    std::wcout << L"  exstop add|del|list|clear               Manage run-stop expression breakpoints\n";
    std::wcout << L"  eb|ew|ed|eq <addr> <value>              Write byte/word/dword/qword memory value\n";
    std::wcout << L"  eza|ezu <addr> <string>                 Write null-terminated ASCII/Unicode string\n";
    std::wcout << L"  patch|poke <addr> <byte...>             Patch target process memory bytes\n";
    std::wcout << L"  patch list [max_items]                  Show patch history (latest first)\n";
    std::wcout << L"  patch undo [count|*]                    Revert recent patch operations\n";
    std::wcout << L"  patchstr|ps <addr> <ascii|utf16> <txt>  Patch text bytes into target memory\n";
    std::wcout << L"  patchfile|pf <addr> <file> [off] [sz]   Patch bytes loaded from a file slice\n";
    std::wcout << L"  patchfile|pf preview <file> [off] [sz]  Preview bytes from a file slice\n";
    std::wcout << L"  nop <addr> <count>                      Patch count bytes with 0x90 NOP\n";
    std::wcout << L"  plugin|plug list                        List loaded plugin modules\n";
    std::wcout << L"  plugin|plug autoload                    Load all plugin DLLs from default plugin folders\n";
    std::wcout << L"  plugin|plug load <dll_path>             Load plugin module DLL\n";
    std::wcout << L"  plugin|plug enable <id|name>            Enable a loaded plugin module\n";
    std::wcout << L"  plugin|plug disable <id|name>           Disable a loaded plugin module\n";
    std::wcout << L"  plugin|plug unload <id|name|*>          Unload plugin module(s)\n";
    std::wcout << L"  plugin|plug run <id|name> [args...]     Execute a loaded plugin module\n";
    std::wcout << L"  !process|process                        Show process information\n";
    std::wcout << L"  processes|ps                            List processes\n";
    std::wcout << L"  !thread                                 Show current thread information and stack\n";
    std::wcout << L"  threads                                 Show thread information\n";
    std::wcout << L"  ~ | ~* | ~*s | ~*k | ~<index>s         List/switch threads, show all stacks\n";
    std::wcout << L"  !vm                                     Show virtual memory status\n";
    std::wcout << L"  vmmap|memmap                            Show process memory regions\n";
    std::wcout << L"  vad                                     Scan suspicious VAD-like regions\n";
    std::wcout << L"  vad dump <index|0xaddress> <file>       Dump one committed memory region\n";
    std::wcout << L"  iatcheck [module|all]                   Check imported function pointers\n";
    std::wcout << L"  modifycheck [module|all]                Compare selected module/API bytes\n";
    std::wcout << L"  syscallcheck [module]                   Check ntdll syscall stubs against disk\n";
    std::wcout << L"  threadcheck                             Check thread start/current addresses\n";
    std::wcout << L"  analysis report                         Summarize anti-debug/VAD/thread checks\n";
    std::wcout << L"  timeline [max]                          Show driver events and debugger stop\n";
    std::wcout << L"  timeline follow [interval_ms]           Follow the unified event timeline\n";
    std::wcout << L"  exceptioncheck                          Check SEH and exception dispatcher integrity\n";
    std::wcout << L"  modulecheck                             Check loaded module headers and mappings\n";
    std::wcout << L"  report export <file> [txt|json]         Export an analysis summary\n";
    std::wcout << L"  apitrace [max] [filter]                 Show driver-backed API behavior events\n";
    std::wcout << L"  modules | lm [m <filter>]               Show loaded modules\n";
    std::wcout << L"  .sympath|sympath [path]                 Show/set symbol search path\n";
    std::wcout << L"  symfix [cache_dir] [server_url]         Configure symbol server path\n";
    std::wcout << L"  .reload|symreload [*|module|address]    Reload symbols from path\n";
    std::wcout << L"  symdownload|symdl [*|module|address]    Download and load PDB symbols\n";
    std::wcout << L"  x <module!symbol-mask>                  Examine symbols\n";
    std::wcout << L"  srcroot <add|del|list|clear> [path]     Manage source localization roots\n";
    std::wcout << L"  srcwhere                                Show current IP source location\n";
    std::wcout << L"  srcat <address> [context_lines]         Show source around address\n";
    std::wcout << L"  srcbp <file> <line>                     Set source-level breakpoint\n";
    std::wcout << L"  srcresolve|srcr <file> <line>           Resolve source location to address\n";
    std::wcout << L"  scriptload|sload <file>                 Load custom debugger script\n";
    std::wcout << L"  scriptshow|sshow                         Show script with cursor/breakpoints\n";
    std::wcout << L"  scriptrun|scriptstart|srun              Run script until end/breakpoint\n";
    std::wcout << L"  scriptstep|sstep                         Execute one script line\n";
    std::wcout << L"  scriptuntil|srunto <label>               Run script until label is reached\n";
    std::wcout << L"  scriptbp|sbp <line>                      Set script breakpoint on source line\n";
    std::wcout << L"  scriptbd|sbd <line>                      Remove script breakpoint\n";
    std::wcout << L"  scriptbl|sbl                             List script breakpoints\n";
    std::wcout << L"  scriptset|sset <name> <value>            Set script variable\n";
    std::wcout << L"  scriptunset <name>                       Remove script variable\n";
    std::wcout << L"  scriptvars|svars                         Show script variables\n";
    std::wcout << L"  scriptreset|sreset                       Reset script cursor to start\n";
    std::wcout << L"  scriptclear|sclear                       Clear loaded script state\n";
    std::wcout << L"  envsave|savesettings [file_path]         Save current runtime environment snapshot\n";
    std::wcout << L"  envload|loadsettings [file_path]         Load runtime environment snapshot\n";
    std::wcout << L"  exception                               Show exception information\n";
    std::wcout << L"  r [mmx|float|debug|reg=value] [--ui]    Show or modify CPU registers\n";
    std::wcout << L"  regs                                    Alias for r\n";
    std::wcout << L"  asm color <on|off|status>               Toggle disassembly color output\n";
    std::wcout << L"  disasm|u|uf [address|api|module!api|module+offset] [count]\n";
    std::wcout << L"  pc|pseudoc|decompile [address|symbol] [count] [--ui] [--features]  Minimal pseudo C\n";
    std::wcout << L"  comment|cmt <add|set|del|show|list> ... Manage instruction comments\n";
    std::wcout << L"  k|kb|kv [max_frames] [--ui]             Show stack trace\n";
    std::wcout << L"  stack [max_frames] [--ui]               Show stack contents\n";
    std::wcout << L"  !peb|peb                                Show process environment block details\n";
    std::wcout << L"  !teb|teb                                Show current thread environment block details\n";
    std::wcout << L"  seh                                     Show SEH/exception chain details\n";
    std::wcout << L"  handles [max|all]                       Show process handle information\n";
    std::wcout << L"  memstr [min_len] [max]                  Scan memory strings\n";
    std::wcout << L"  s -a|-u <text> | -b <byte...> | -d <value> | -q <value>\n";
    std::wcout << L"  search                                  Alias for s\n";
    std::wcout << L"  db|dw|dd|dq <addr> [bytes] [per_line] [--ui] Dump memory as byte/word/dword/qword\n";
    std::wcout << L"  da <addr> [bytes] [--ui]                Display ASCII memory\n";
    std::wcout << L"  dt <type|module!type> <addr> [depth]    Display structure fields and values\n";
    std::wcout << L"  dump <file> [base_address length]       Dump current exe or a custom memory range to file\n";
    std::wcout << L"  .writemem <file> <addr> L<size>         Save target memory range to file\n";
    std::wcout << L"  .dvalloc <size>                         Allocate virtual memory in target process\n";
    std::wcout << L"  membin|mbin <address> <size>            Show memory as binary bytes\n";
    std::wcout << L"  context|ctx                             Show key debug context views\n";
    std::wcout << L"  py help                                 Show Python bridge help\n";
    std::wcout << L"  py run <file>                           Run a Python script file\n";
    std::wcout << L"  py exec <code>                          Execute Python code\n";
    std::wcout << L"  help                                    Show this help\n";
    std::wcout << L"  quit|exit                               Exit debugger\n";
}

std::wstring Debugger::ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

std::wstring Debugger::JoinTokens(const std::vector<std::wstring>& tokens, size_t startIndex) {
    std::wstringstream ss;
    for (size_t i = startIndex; i < tokens.size(); ++i) {
        if (i != startIndex) {
            ss << L' ';
        }
        const bool needsQuotes = tokens[i].find(L' ') != std::wstring::npos;
        if (needsQuotes) {
            ss << L'"' << tokens[i] << L'"';
        } else {
            ss << tokens[i];
        }
    }
    return ss.str();
}

std::wstring Debugger::GetModuleNameFromPath(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return path;
    }
    if (slash + 1 >= path.size()) {
        return L"";
    }
    return path.substr(slash + 1);
}

bool Debugger::IsScriptComment(const std::wstring& text) {
    const std::wstring trimmed = TrimWhitespace(text);
    if (trimmed.empty()) {
        return true;
    }
    return trimmed.rfind(L"#", 0) == 0 ||
           trimmed.rfind(L";", 0) == 0 ||
           trimmed.rfind(L"//", 0) == 0;
}

bool Debugger::ParseUInt64(const std::wstring& text, uint64_t& value) {
    try {
        size_t idx = 0;
        const int base = (text.rfind(L"0x", 0) == 0 || text.rfind(L"0X", 0) == 0) ? 16 : 10;
        value = std::stoull(text, &idx, base);
        return idx == text.size();
    } catch (...) {
        return false;
    }
}

bool Debugger::ParseUInt32(const std::wstring& text, uint32_t& value) {
    uint64_t temp = 0;
    if (!ParseUInt64(text, temp) || temp > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    value = static_cast<uint32_t>(temp);
    return true;
}

bool Debugger::ResolveAddressExpression(const std::wstring& expression, uint64_t& address, std::wstring& resolvedText) const {
    address = 0;
    resolvedText.clear();

    const std::wstring spec = TrimWhitespace(expression);
    if (spec.empty()) {
        return false;
    }

    if (ParseUInt64(spec, address)) {
        resolvedText = ToHex(address);
        return true;
    }
    {
        bool allHex = !spec.empty();
        bool hasHexLetter = false;
        for (size_t i = 0; i < spec.size(); ++i) {
            const wchar_t ch = spec[i];
            if (!std::iswxdigit(ch)) {
                allHex = false;
                break;
            }
            if ((ch >= L'a' && ch <= L'f') || (ch >= L'A' && ch <= L'F')) {
                hasHexLetter = true;
            }
        }
        if (allHex && hasHexLetter) {
            try {
                size_t idx = 0;
                address = std::stoull(spec, &idx, 16);
                if (idx == spec.size()) {
                    resolvedText = ToHex(address);
                    return true;
                }
            } catch (...) {
            }
        }
    }

    if (!EnsureDebuggee()) {
        return false;
    }

    std::vector<ModuleRecord> modules;
    if (!CollectModuleRecords(modules) || modules.empty()) {
        return false;
    }

    const auto normalizeModuleKey = [&](const std::wstring& text) -> std::wstring {
        std::wstring key = ToLower(TrimWhitespace(text));
        if (key.empty()) {
            return key;
        }
        const std::wstring fileName = ToLower(GetModuleNameFromPath(key));
        if (!fileName.empty()) {
            key = fileName;
        }
        if (key.size() > 4 && key.substr(key.size() - 4) == L".dll") {
            key = key.substr(0, key.size() - 4);
        }
        return key;
    };

    const auto findModuleByToken = [&](const std::wstring& moduleToken) -> const ModuleRecord* {
        const std::wstring wanted = normalizeModuleKey(moduleToken);
        if (wanted.empty()) {
            return nullptr;
        }
        for (size_t i = 0; i < modules.size(); ++i) {
            const ModuleRecord& module = modules[i];
            const std::wstring nameKey = normalizeModuleKey(module.moduleName);
            const std::wstring pathKey = normalizeModuleKey(module.imagePath);
            if ((!nameKey.empty() && nameKey == wanted) || (!pathKey.empty() && pathKey == wanted)) {
                return &module;
            }
        }
        return nullptr;
    };

    // module+offset / module-offset
    size_t plusPos = spec.find_last_of(L'+');
    size_t minusPos = spec.find_last_of(L'-');
    size_t splitPos = std::wstring::npos;
    wchar_t splitOp = L'\0';
    if (plusPos != std::wstring::npos && plusPos > 0 && plusPos + 1 < spec.size()) {
        splitPos = plusPos;
        splitOp = L'+';
    }
    if (minusPos != std::wstring::npos && minusPos > 0 && minusPos + 1 < spec.size() &&
        (splitPos == std::wstring::npos || minusPos > splitPos)) {
        splitPos = minusPos;
        splitOp = L'-';
    }
    if (splitPos != std::wstring::npos) {
        const std::wstring moduleToken = TrimWhitespace(spec.substr(0, splitPos));
        const std::wstring offsetToken = TrimWhitespace(spec.substr(splitPos + 1));
        uint64_t offset = 0;
        if (!moduleToken.empty() && ParseUInt64(offsetToken, offset)) {
            const ModuleRecord* module = findModuleByToken(moduleToken);
            if (module != nullptr) {
                if (splitOp == L'+') {
                    address = module->baseAddress + offset;
                } else {
                    if (module->baseAddress < offset) {
                        return false;
                    }
                    address = module->baseAddress - offset;
                }
                const std::wstring moduleName = module->moduleName.empty()
                    ? GetModuleNameFromPath(module->imagePath)
                    : module->moduleName;
                resolvedText = moduleName + std::wstring(1, splitOp) + ToHex(offset);
                return true;
            }
        }
    }

    // plain module name -> module base
    {
        const ModuleRecord* module = findModuleByToken(spec);
        if (module != nullptr) {
            address = module->baseAddress;
            resolvedText = module->moduleName.empty() ? GetModuleNameFromPath(module->imagePath) : module->moduleName;
            return true;
        }
    }

    // module!api / api
    std::wstring moduleHint;
    std::wstring apiName = spec;
    const size_t bangPos = spec.find(L'!');
    if (bangPos != std::wstring::npos) {
        moduleHint = TrimWhitespace(spec.substr(0, bangPos));
        apiName = TrimWhitespace(spec.substr(bangPos + 1));
    }
    if (apiName.empty()) {
        return false;
    }

    std::vector<size_t> candidateIndices;
    if (!moduleHint.empty()) {
        const ModuleRecord* module = findModuleByToken(moduleHint);
        if (module == nullptr) {
            return false;
        }
        for (size_t i = 0; i < modules.size(); ++i) {
            if (&modules[i] == module) {
                candidateIndices.push_back(i);
                break;
            }
        }
    } else {
        static const wchar_t* kPreferredModules[] = {
            L"kernelbase",
            L"kernel32",
            L"ntdll",
            L"user32",
            L"advapi32",
            L"gdi32"
        };
        for (size_t p = 0; p < sizeof(kPreferredModules) / sizeof(kPreferredModules[0]); ++p) {
            const std::wstring preferred(kPreferredModules[p]);
            for (size_t i = 0; i < modules.size(); ++i) {
                const ModuleRecord& m = modules[i];
                const std::wstring nameKey = normalizeModuleKey(m.moduleName);
                const std::wstring pathKey = normalizeModuleKey(m.imagePath);
                if ((!nameKey.empty() && nameKey == preferred) ||
                    (!pathKey.empty() && pathKey == preferred)) {
                    candidateIndices.push_back(i);
                }
            }
        }
        if (candidateIndices.empty()) {
            for (size_t i = 0; i < modules.size(); ++i) {
                candidateIndices.push_back(i);
            }
        }
    }

    const std::string apiNameAnsi = WideToAnsi(apiName);
    if (apiNameAnsi.empty()) {
        return false;
    }

    for (size_t c = 0; c < candidateIndices.size(); ++c) {
        const ModuleRecord& targetModule = modules[candidateIndices[c]];
        if (targetModule.imagePath.empty() || targetModule.baseAddress == 0) {
            continue;
        }

        HMODULE localModule = LoadLibraryExW(
            targetModule.imagePath.c_str(),
            nullptr,
            DONT_RESOLVE_DLL_REFERENCES);
        bool unloadLocalModule = false;
        if (localModule != nullptr) {
            unloadLocalModule = true;
        } else {
            const std::wstring moduleBaseName = targetModule.moduleName.empty()
                ? GetModuleNameFromPath(targetModule.imagePath)
                : targetModule.moduleName;
            if (!moduleBaseName.empty()) {
                localModule = GetModuleHandleW(moduleBaseName.c_str());
            }
        }
        if (localModule == nullptr) {
            continue;
        }

        FARPROC localProc = GetProcAddress(localModule, apiNameAnsi.c_str());
        if (localProc != nullptr) {
            const uint64_t localBase = reinterpret_cast<uint64_t>(localModule);
            const uint64_t localAddress = reinterpret_cast<uint64_t>(localProc);
            if (localAddress >= localBase) {
                const uint64_t rva = localAddress - localBase;
                address = targetModule.baseAddress + rva;
                if (unloadLocalModule) {
                    FreeLibrary(localModule);
                }
                const std::wstring moduleName = targetModule.moduleName.empty()
                    ? GetModuleNameFromPath(targetModule.imagePath)
                    : targetModule.moduleName;
                resolvedText = moduleName + L"!" + apiName;
                return true;
            }
        }

        if (unloadLocalModule) {
            FreeLibrary(localModule);
        }
    }

    return false;
}

std::wstring Debugger::ExceptionCodeToString(DWORD code) {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION: return L"EXCEPTION_ACCESS_VIOLATION";
        case EXCEPTION_BREAKPOINT: return L"EXCEPTION_BREAKPOINT";
        case EXCEPTION_SINGLE_STEP: return L"EXCEPTION_SINGLE_STEP";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return L"EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_DATATYPE_MISALIGNMENT: return L"EXCEPTION_DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: return L"EXCEPTION_FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return L"EXCEPTION_ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR: return L"EXCEPTION_IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO: return L"EXCEPTION_INT_DIVIDE_BY_ZERO";
        case EXCEPTION_STACK_OVERFLOW: return L"EXCEPTION_STACK_OVERFLOW";
        case STATUS_GUARD_PAGE_VIOLATION_VALUE: return L"STATUS_GUARD_PAGE_VIOLATION";
        default: return L"0x" + ToHex(code, 8).substr(2);
    }
}

std::wstring Debugger::EventCodeToString(DWORD eventCode) {
    switch (eventCode) {
        case EXCEPTION_DEBUG_EVENT: return L"EXCEPTION_DEBUG_EVENT";
        case CREATE_THREAD_DEBUG_EVENT: return L"CREATE_THREAD_DEBUG_EVENT";
        case CREATE_PROCESS_DEBUG_EVENT: return L"CREATE_PROCESS_DEBUG_EVENT";
        case EXIT_THREAD_DEBUG_EVENT: return L"EXIT_THREAD_DEBUG_EVENT";
        case EXIT_PROCESS_DEBUG_EVENT: return L"EXIT_PROCESS_DEBUG_EVENT";
        case LOAD_DLL_DEBUG_EVENT: return L"LOAD_DLL_DEBUG_EVENT";
        case UNLOAD_DLL_DEBUG_EVENT: return L"UNLOAD_DLL_DEBUG_EVENT";
        case OUTPUT_DEBUG_STRING_EVENT: return L"OUTPUT_DEBUG_STRING_EVENT";
        case RIP_EVENT: return L"RIP_EVENT";
        default: return L"UNKNOWN_EVENT";
    }
}

std::wstring Debugger::MemoryAccessToString(MemoryAccessType access) {
    std::wstring out;
    if (HasMemoryAccess(access, MemoryAccessType::Read)) out += L"r";
    if (HasMemoryAccess(access, MemoryAccessType::Write)) out += L"w";
    if (HasMemoryAccess(access, MemoryAccessType::Execute)) out += L"x";
    if (out.empty()) out = L"-";
    return out;
}

std::optional<MemoryAccessType> Debugger::ParseMemoryAccess(const std::wstring& value) {
    const std::wstring v = ToLower(value);
    MemoryAccessType access = MemoryAccessType::Read;
    bool hasAny = false;
 for (auto __rangeIt43 = (v).begin(); __rangeIt43 != (v).end(); ++__rangeIt43) {
        wchar_t c = *__rangeIt43;
        if (c == L'r') {
            access = hasAny ? (access | MemoryAccessType(MemoryAccessType::Read)) : MemoryAccessType(MemoryAccessType::Read);
            hasAny = true;
        } else if (c == L'w') {
            access = hasAny ? (access | MemoryAccessType(MemoryAccessType::Write)) : MemoryAccessType(MemoryAccessType::Write);
            hasAny = true;
        } else if (c == L'x') {
            access = hasAny ? (access | MemoryAccessType(MemoryAccessType::Execute)) : MemoryAccessType(MemoryAccessType::Execute);
            hasAny = true;
        }
        else return std::nullopt;
    }
    if (!hasAny || static_cast<uint32_t>(access) == 0) {
        return std::nullopt;
    }
    return access;
}

std::optional<HardwareAccessType> Debugger::ParseHardwareAccess(const std::wstring& value) {
    const std::wstring v = ToLower(value);
    if (v == L"exec" || v == L"execute" || v == L"x") return HardwareAccessType::Execute;
    if (v == L"write" || v == L"w") return HardwareAccessType::Write;
    if (v == L"access" || v == L"rw") return HardwareAccessType::Access;
    return std::nullopt;
}

std::optional<ExceptionScope> Debugger::ParseExceptionScope(const std::wstring& text) {
    const std::wstring v = ToLower(text);
    if (v == L"debug" || v == L"dbg" || v == L"debugging") {
        return ExceptionScope::Debugging;
    }
    if (v == L"run" || v == L"runtime") {
        return ExceptionScope::Runtime;
    }
    if (v == L"step" || v == L"stepping") {
        return ExceptionScope::Stepping;
    }
    return std::nullopt;
}

std::wstring Debugger::ExceptionScopeToString(ExceptionScope scope) {
    switch (scope) {
    case ExceptionScope::Debugging:
        return L"debugging";
    case ExceptionScope::Runtime:
        return L"runtime";
    case ExceptionScope::Stepping:
        return L"stepping";
    default:
        return L"unknown";
    }
}

bool Debugger::ParseExceptionCodeToken(const std::wstring& text, DWORD& code) {
    const std::wstring v = ToLower(text);
    if (v == L"exception_access_violation") {
        code = EXCEPTION_ACCESS_VIOLATION;
        return true;
    }
    if (v == L"exception_breakpoint") {
        code = EXCEPTION_BREAKPOINT;
        return true;
    }
    if (v == L"exception_single_step") {
        code = EXCEPTION_SINGLE_STEP;
        return true;
    }
    if (v == L"exception_array_bounds_exceeded") {
        code = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
        return true;
    }
    if (v == L"exception_datatype_misalignment") {
        code = EXCEPTION_DATATYPE_MISALIGNMENT;
        return true;
    }
    if (v == L"exception_flt_divide_by_zero") {
        code = EXCEPTION_FLT_DIVIDE_BY_ZERO;
        return true;
    }
    if (v == L"exception_in_page_error") {
        code = EXCEPTION_IN_PAGE_ERROR;
        return true;
    }
    if (v == L"exception_int_divide_by_zero") {
        code = EXCEPTION_INT_DIVIDE_BY_ZERO;
        return true;
    }
    if (v == L"exception_stack_overflow") {
        code = EXCEPTION_STACK_OVERFLOW;
        return true;
    }
    if (v == L"status_guard_page_violation") {
        code = STATUS_GUARD_PAGE_VIOLATION_VALUE;
        return true;
    }
    if (v == L"av" || v == L"access_violation") {
        code = EXCEPTION_ACCESS_VIOLATION;
        return true;
    }
    if (v == L"bp" || v == L"breakpoint") {
        code = EXCEPTION_BREAKPOINT;
        return true;
    }
    if (v == L"single_step" || v == L"ss") {
        code = EXCEPTION_SINGLE_STEP;
        return true;
    }
    if (v == L"intdiv0" || v == L"int_divide_by_zero") {
        code = EXCEPTION_INT_DIVIDE_BY_ZERO;
        return true;
    }
    if (v == L"illegal" || v == L"illegal_instruction") {
        code = EXCEPTION_ILLEGAL_INSTRUCTION;
        return true;
    }
    if (v == L"guard" || v == L"guard_page") {
        code = STATUS_GUARD_PAGE_VIOLATION_VALUE;
        return true;
    }
    uint64_t raw = 0;
    if (!ParseUInt64(text, raw) || raw > std::numeric_limits<DWORD>::max()) {
        return false;
    }
    code = static_cast<DWORD>(raw);
    return true;
}

std::vector<std::wstring> Tokenize(const std::wstring& line) {
    std::vector<std::wstring> tokens;
    std::wstring current;
    bool inQuotes = false;
    wchar_t quoteChar = L'"';

    for (size_t i = 0; i < line.size(); ++i) {
        const wchar_t ch = line[i];
        if (!inQuotes && (ch == L'"' || ch == L'\'')) {
            inQuotes = true;
            quoteChar = ch;
            continue;
        }
        if (inQuotes && ch == quoteChar) {
            inQuotes = false;
            continue;
        }
        if (!inQuotes && std::iswspace(ch)) {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) {
        tokens.push_back(current);
    }
    return tokens;
}
