#include "CliConsole.h"

#include <Windows.h>

#include <cstdint>
#include <sstream>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef DISABLE_NEWLINE_AUTO_RETURN
#define DISABLE_NEWLINE_AUTO_RETURN 0x0008
#endif

namespace {

bool IsChineseUserInterface() {
    const LANGID lang = GetUserDefaultUILanguage();
    return PRIMARYLANGID(lang) == LANG_CHINESE;
}

void TryUseDefaultConsoleFont(HANDLE output) {
    if (output == INVALID_HANDLE_VALUE || output == NULL) {
        return;
    }

    typedef BOOL(WINAPI* GetCurrentConsoleFontExFn)(HANDLE, BOOL, PCONSOLE_FONT_INFOEX);
    typedef BOOL(WINAPI* SetCurrentConsoleFontExFn)(HANDLE, BOOL, PCONSOLE_FONT_INFOEX);

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == NULL) {
        return;
    }

    GetCurrentConsoleFontExFn getFont =
        reinterpret_cast<GetCurrentConsoleFontExFn>(GetProcAddress(kernel32, "GetCurrentConsoleFontEx"));
    SetCurrentConsoleFontExFn setFont =
        reinterpret_cast<SetCurrentConsoleFontExFn>(GetProcAddress(kernel32, "SetCurrentConsoleFontEx"));
    if (getFont == NULL || setFont == NULL) {
        return;
    }

    CONSOLE_FONT_INFOEX font = CONSOLE_FONT_INFOEX();
    font.cbSize = sizeof(font);
    if (!getFont(output, FALSE, &font)) {
        return;
    }

    font.dwFontSize.Y = 8;
    font.dwFontSize.X = 0;
    const wchar_t chineseFaceName[] = {
        static_cast<wchar_t>(0x65B0),
        static_cast<wchar_t>(0x5B8B),
        static_cast<wchar_t>(0x4F53),
        L'\0'
    };
    wcsncpy_s(
        font.FaceName,
        LF_FACESIZE,
        IsChineseUserInterface() ? chineseFaceName : L"Consolas",
        _TRUNCATE);

    setFont(output, FALSE, &font);
}

}  // namespace

CliConsole::CliConsole()
    : output_(GetStdHandle(STD_OUTPUT_HANDLE)),
      vtEnabled_(false) {
}

CliConsole::~CliConsole() {
}

bool CliConsole::Initialize() {
    if (output_ == INVALID_HANDLE_VALUE) {
        return false;
    }

    SetConsoleOutputCP(CP_UTF8);
    TryUseDefaultConsoleFont(output_);

    DWORD mode = 0;
    if (GetConsoleMode(output_, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        mode |= DISABLE_NEWLINE_AUTO_RETURN;
        if (SetConsoleMode(output_, mode)) {
            vtEnabled_ = true;
        }
    }

    // Reveal the window title so multiple sessions are easy to tell apart.
    SetConsoleTitleW(L"WinDbgLite CLI");
    return true;
}

std::wstring CliConsole::AnsiColor(Color color) const {
    if (!vtEnabled_) {
        return std::wstring();
    }
    switch (color) {
        case ColorBlack:   return L"\x1b[30m";
        case ColorRed:     return L"\x1b[31m";
        case ColorGreen:   return L"\x1b[32m";
        case ColorYellow:  return L"\x1b[33m";
        case ColorBlue:    return L"\x1b[34m";
        case ColorMagenta: return L"\x1b[35m";
        case ColorCyan:    return L"\x1b[36m";
        case ColorWhite:   return L"\x1b[37m";
        case ColorGray:    return L"\x1b[90m";
        default:           return std::wstring();
    }
}

void CliConsole::Write(const std::wstring& text) const {
    if (output_ == INVALID_HANDLE_VALUE || output_ == NULL) {
        return;
    }
    DWORD written = 0;
    WriteConsoleW(output_, text.c_str(), static_cast<DWORD>(text.size()), &written, NULL);
}

void CliConsole::WriteColored(const std::wstring& text, Color color) const {
    if (color != ColorDefault) {
        Write(AnsiColor(color));
    }
    Write(text);
    if (color != ColorDefault && vtEnabled_) {
        Write(L"\x1b[0m");
    }
}

void CliConsole::WriteLine(const std::wstring& text, Color color) const {
    WriteColored(text, color);
    Write(L"\n");
}

void CliConsole::CarriageReturn() const {
    Write(L"\r");
}

void CliConsole::ClearScreen() const {
    if (vtEnabled_) {
        Write(L"\x1b[2J\x1b[H");
    } else {
        // Best-effort fallback: newline spam.
        for (int i = 0; i < 40; ++i) {
            Write(L"\n");
        }
    }
}



void CliConsole::PrintBanner() const {
    const std::wstring banner =
        L"  _____     ___      ____      ____        ____             ____\r\n"
        L" |__  /    / _ \\    |  _ \\    |  __ \\     |  _ \\      / ____ \\\r\n"
        L"   / /    | | | |   | |_) |   | |  \\ |    | |_) |       | /    _ \r\n" 
        L"  / /     | | | |   |  _ <    | |   ||    |  _ <         | |  /_  \\\r\n" 
        L" / / _    | |_| |   | |_) |   | |__/ |    | |_) |        | |  __| |\r\n"   
        L"/_____|    \\___/    |____/    |____ /    |____/         \\_____/ \r\n";
    WriteColored(banner, ColorCyan);
    WriteColored(L"  user-mode Windows debugger  -  CLI\r\n", ColorGray);
    WriteColored(L"  powered by the Windows Debug API. Type 'help' for commands, 'quit' to exit.\r\n\n", ColorGray);
}
