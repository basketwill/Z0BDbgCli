#include <Windows.h>
#include <windowsx.h>
#include <CommCtrl.h>
#include <CommDlg.h>
#include <shellapi.h>
#include <Richedit.h>
#include "WinDbgLiteCliResource.h"
#include "Debugger.h"
#include "PythonBridge.h"

#include <algorithm>
#include "StdCompat.h"
#include <cstring>
#include <deque>
#include <iostream>
#include <cwctype>
#include <sstream>
#include <streambuf>
#include <string>
#include <vector>

#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(lib, "Comdlg32.lib")

namespace {

const UINT WM_APP_OUTPUT_READY = WM_APP + 1;
const UINT WM_APP_SUBMIT_INPUT = WM_APP + 2;
const UINT WM_APP_PAINT_TITLE_TAB = WM_APP + 3;
const UINT WM_APP_PAINT_OUTPUT_SELECTION = WM_APP + 4;
const UINT WM_APP_RUN_STARTUP_PY = WM_APP + 5;
const UINT WM_APP_SHOW_DISASM_UI = WM_APP + 6;
const UINT WM_APP_GOTO_COMPLETE = WM_APP + 7;
const UINT WM_APP_DISASM_PAGE_READY = WM_APP + 8;
const UINT WM_APP_SHOW_MEMORY_UI = WM_APP + 9;
const UINT WM_APP_SHOW_REGISTER_UI = WM_APP + 10;
const UINT WM_APP_SHOW_STACK_UI = WM_APP + 11;
const UINT WM_APP_SHOW_PSEUDOC_UI = WM_APP + 12;
const UINT_PTR kOutputSelectionAutoScrollTimer = 1;
const UINT_PTR kTitleTabRepaintTimer = 2;
const UINT_PTR kDisasmPageLoadTimer = 3;

const int kPadding = 8;
const int kPromptWidth = 48;
const int kPromptTextWidth = 48;
const int kInputHeight = 24;
const int kInitialWindowWidth = 980;
const int kInitialWindowHeight = 620;
const int kHistoryLimit = 1000;
const int kCustomTitleHeight = 34;
const int kTitleButtonWidth = 46;
const int kTitleTabRadius = 10;
const int kTitleTabMinWidth = 190;
const int kTitleLeftIconX = 10;
const int kTitleLeftSlotWidth = 33;
const int kTitleTabIconX = 8;
const int kTitleActionWidth = 52;
const int kTitleActionHeight = 21;
const int kTitleActionGap = 3;
const int kTitleActionSeparatorX = 25;
const int kTitleActionVWidth = 8;
const int kTitleActionVHeight = 8;
const int kTitleActionVLeftOffset = 37;
const int kSelectionAutoScrollIntervalMs = 45;
const COLORREF kBackground = RGB(0, 0, 0);
const COLORREF kForeground = RGB(255, 255, 255);
const COLORREF kPromptColor = RGB(0, 255, 0);
const COLORREF kErrorColor = RGB(255, 80, 80);
const COLORREF kGrayColor = RGB(160, 160, 160);
const COLORREF kTitleBarColor = RGB(46, 46, 46);
const wchar_t kMainClassName[] = L"Windows.UI.Composition.DesktopWindowContentBridge";
const wchar_t kOutputClassName[] = L"Windows.UI.Input.InputSite.WindowClass";
const wchar_t kTitleMenuClassName[] = L"Z0BDbgCli.TitleMenu";
const wchar_t kGotoDialogClassName[] = L"Z0BDbgCli.GotoDialog";
const wchar_t kSystemWindowTitle[] = L"";
const wchar_t kWindowTitle[] = L"Z0BDBG";
const wchar_t kRichEditClassMsft[] = L"RICHEDIT50W";

HCURSOR ArrowCursor() {
    return LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(32512)));
}

HCURSOR IBeamCursor() {
    return LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(32513)));
}

HCURSOR SizeWeCursor() {
    return LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(32644)));
}

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif
#ifndef DWMWA_TEXT_COLOR
#define DWMWA_TEXT_COLOR 36
#endif
#ifndef DWMWA_BORDER_COLOR
#define DWMWA_BORDER_COLOR 34
#endif
#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef WM_UAHDRAWCAPTION
#define WM_UAHDRAWCAPTION 0x00AE
#endif
#ifndef WM_UAHDRAWFRAME
#define WM_UAHDRAWFRAME 0x00AF
#endif

enum {
    ID_TITLE_MENU_SETTINGS = 1001,
    ID_TITLE_MENU_COMMAND_PANEL = 1002,
    ID_TITLE_MENU_ABOUT = 1003,
    ID_GOTO_EDIT = 1101,
    ID_GOTO_OK = 1102,
    ID_GOTO_CANCEL = 1103,
    ID_DISASM_FOLLOW = 1200,
    ID_DISASM_COPY_CLIPBOARD = 1201,
    ID_DISASM_COPY_FILE = 1202,
    ID_VIEW_COPY_CLIPBOARD = 1210,
    ID_VIEW_COPY_FILE = 1211
};

const wchar_t* TitleMenuText(UINT id, bool zh) {
    switch (id) {
        case ID_TITLE_MENU_SETTINGS:
            return zh ? L"设置" : L"Settings";
        case ID_TITLE_MENU_COMMAND_PANEL:
            return zh ? L"命令面板" : L"Command Panel";
        case ID_TITLE_MENU_ABOUT:
            return zh ? L"关于" : L"About";
        default:
            return L"";
    }
}

bool IsChineseUserInterface() {
    return PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE;
}

typedef HRESULT(WINAPI* DwmSetWindowAttributeFn)(HWND, DWORD, LPCVOID, DWORD);

enum DwmWindowCornerPreferenceCompat {
    DWMWCP_DEFAULT_COMPAT = 0,
    DWMWCP_DONOTROUND_COMPAT = 1,
    DWMWCP_ROUND_COMPAT = 2,
    DWMWCP_ROUNDSMALL_COMPAT = 3
};

void ApplyConsoleLikeChrome(HWND hwnd) {
    if (hwnd == nullptr) {
        return;
    }

    HMODULE dwmapi = LoadLibraryW(L"dwmapi.dll");
    if (dwmapi == nullptr) {
        return;
    }

    DwmSetWindowAttributeFn setAttr = reinterpret_cast<DwmSetWindowAttributeFn>(
        GetProcAddress(dwmapi, "DwmSetWindowAttribute"));
    if (setAttr == nullptr) {
        FreeLibrary(dwmapi);
        return;
    }

    const BOOL dark = TRUE;
    const COLORREF caption = kTitleBarColor;
    const COLORREF text = RGB(255, 255, 255);
    const COLORREF border = kTitleBarColor;

    setAttr(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    setAttr(hwnd, DWMWA_CAPTION_COLOR, &caption, sizeof(caption));
    setAttr(hwnd, DWMWA_TEXT_COLOR, &text, sizeof(text));
    setAttr(hwnd, DWMWA_BORDER_COLOR, &border, sizeof(border));

    FreeLibrary(dwmapi);
}

void ApplySmoothSmallWindowCorners(HWND hwnd, bool enabled) {
    if (hwnd == nullptr) {
        return;
    }

    HMODULE dwmapi = LoadLibraryW(L"dwmapi.dll");
    if (dwmapi == nullptr) {
        return;
    }

    DwmSetWindowAttributeFn setAttr = reinterpret_cast<DwmSetWindowAttributeFn>(
        GetProcAddress(dwmapi, "DwmSetWindowAttribute"));
    if (setAttr != nullptr) {
        const int preference = enabled ? DWMWCP_ROUNDSMALL_COMPAT : DWMWCP_DONOTROUND_COMPAT;
        setAttr(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &preference, sizeof(preference));
    }

    FreeLibrary(dwmapi);
}

void ApplyConsoleLikeIcon(HWND hwnd, HINSTANCE instance) {
    if (hwnd == nullptr || !IsWindow(hwnd)) {
        return;
    }

    HINSTANCE iconInstance = instance != nullptr ? instance : GetModuleHandleW(nullptr);
    if (iconInstance == nullptr) {
        return;
    }

    HICON smallIcon = static_cast<HICON>(LoadImageW(
        iconInstance,
        MAKEINTRESOURCEW(IDI_APP_ICON),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON),
        LR_DEFAULTCOLOR));
    HICON bigIcon = static_cast<HICON>(LoadImageW(
        iconInstance,
        MAKEINTRESOURCEW(IDI_APP_ICON),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXICON),
        GetSystemMetrics(SM_CYICON),
        LR_DEFAULTCOLOR));

    if (smallIcon == nullptr || bigIcon == nullptr) {
        if (smallIcon == nullptr) {
            smallIcon = static_cast<HICON>(LoadImageW(
                nullptr,
                MAKEINTRESOURCEW(IDI_APPLICATION),
                IMAGE_ICON,
                GetSystemMetrics(SM_CXSMICON),
                GetSystemMetrics(SM_CYSMICON),
                LR_SHARED));
        }
        if (bigIcon == nullptr) {
            bigIcon = static_cast<HICON>(LoadImageW(
                nullptr,
                MAKEINTRESOURCEW(IDI_APPLICATION),
                IMAGE_ICON,
                GetSystemMetrics(SM_CXICON),
                GetSystemMetrics(SM_CYICON),
                LR_SHARED));
        }
    }

    if (smallIcon != nullptr) {
        SetClassLongPtrW(hwnd, GCLP_HICONSM, reinterpret_cast<LONG_PTR>(smallIcon));
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallIcon));
        SendMessageW(hwnd, WM_SETICON, static_cast<WPARAM>(2), reinterpret_cast<LPARAM>(smallIcon));
    }
    if (bigIcon != nullptr) {
        SetClassLongPtrW(hwnd, GCLP_HICON, reinterpret_cast<LONG_PTR>(bigIcon));
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(bigIcon));
    }
}

bool SetClipboardUnicodeText(HWND owner, const std::wstring& text) {
    if (text.empty() || !OpenClipboard(owner)) {
        return false;
    }
    EmptyClipboard();

    const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory == nullptr) {
        CloseClipboard();
        return false;
    }

    void* data = GlobalLock(memory);
    if (data == nullptr) {
        GlobalFree(memory);
        CloseClipboard();
        return false;
    }
    memcpy(data, text.c_str(), bytes);
    GlobalUnlock(memory);

    if (SetClipboardData(CF_UNICODETEXT, memory) == nullptr) {
        GlobalFree(memory);
        CloseClipboard();
        return false;
    }
    CloseClipboard();
    return true;
}

bool GetClipboardUnicodeText(HWND owner, std::wstring& text) {
    text.clear();
    if (!OpenClipboard(owner)) {
        return false;
    }

    HGLOBAL memory = GetClipboardData(CF_UNICODETEXT);
    if (memory == nullptr) {
        CloseClipboard();
        return false;
    }

    const wchar_t* data = static_cast<const wchar_t*>(GlobalLock(memory));
    if (data == nullptr) {
        CloseClipboard();
        return false;
    }
    text = data;
    GlobalUnlock(memory);
    CloseClipboard();
    return !text.empty();
}

std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

std::wstring Trim(const std::wstring& value) {
    const size_t start = value.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) {
        return L"";
    }
    const size_t end = value.find_last_not_of(L" \t\r\n");
    return value.substr(start, end - start + 1);
}

std::wstring JoinTokens(const std::vector<std::wstring>& tokens, size_t startIndex) {
    std::wstringstream ss;
    for (size_t i = startIndex; i < tokens.size(); ++i) {
        if (i != startIndex) {
            ss << L' ';
        }
        ss << tokens[i];
    }
    return ss.str();
}

std::wstring QuoteCommandToken(const std::wstring& value) {
    if (value.empty()) {
        return L"\"\"";
    }

    bool needsQuotes = false;
    for (size_t i = 0; i < value.size(); ++i) {
        const wchar_t ch = value[i];
        if (std::iswspace(ch) || ch == L'"') {
            needsQuotes = true;
            break;
        }
    }
    if (!needsQuotes) {
        return value;
    }

    std::wstring quoted;
    quoted.reserve(value.size() + 2);
    quoted.push_back(L'"');
    for (size_t i = 0; i < value.size(); ++i) {
        const wchar_t ch = value[i];
        if (ch == L'"') {
            quoted.push_back(L'\\');
        }
        quoted.push_back(ch);
    }
    quoted.push_back(L'"');
    return quoted;
}

std::wstring AnsiToWide(const char* text) {
    if (text == nullptr || *text == '\0') {
        return L"";
    }
    const int chars = MultiByteToWideChar(CP_ACP, 0, text, -1, nullptr, 0);
    if (chars <= 0) {
        return L"";
    }
    std::wstring out;
    out.resize(static_cast<size_t>(chars - 1));
    MultiByteToWideChar(CP_ACP, 0, text, -1, &out[0], chars);
    return out;
}

std::wstring MakeRuntimeClassName() {
    LARGE_INTEGER counter = {};
    QueryPerformanceCounter(&counter);
    const uint64_t seed =
        (static_cast<uint64_t>(GetCurrentProcessId()) << 32) ^
        static_cast<uint64_t>(GetCurrentThreadId()) ^
        GetTickCount64() ^
        static_cast<uint64_t>(counter.QuadPart);
    std::wstring text = L"W";
    uint64_t value = seed;
    const wchar_t alphabet[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < 31; ++i) {
        value = value * 6364136223846793005ULL + 1442695040888963407ULL;
        text.push_back(alphabet[(value >> 24) % 62]);
    }
    text.push_back(L'_');
    std::wstringstream ss;
    ss << std::hex << std::uppercase
       << GetCurrentProcessId() << L"_"
       << static_cast<unsigned long long>(counter.QuadPart);
    text += ss.str();
    return text;
}

std::wstring FormatHexAddress(uint64_t value) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::uppercase << value;
    return ss.str();
}

enum StartupPythonMode {
    STARTUP_PYTHON_MODE_NONE,
    STARTUP_PYTHON_MODE_FILE,
    STARTUP_PYTHON_MODE_EXEC
};

struct StartupPythonRequest {
    StartupPythonMode mode;
    std::wstring payload;
    std::vector<std::wstring> args;

    StartupPythonRequest() : mode(STARTUP_PYTHON_MODE_NONE), payload(), args() {}
};

bool ParseStartupPythonRequest(StartupPythonRequest& request) {
    request = StartupPythonRequest();

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) {
        return false;
    }

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = ToLower(argv[i]);
        if ((arg == L"--py" || arg == L"/py") && i + 1 < argc) {
            request.mode = STARTUP_PYTHON_MODE_FILE;
            request.payload = argv[++i];
            for (int j = i + 1; j < argc; ++j) {
                request.args.push_back(argv[j]);
            }
            break;
        }
        if ((arg == L"--pyexec" || arg == L"--pycode" || arg == L"/pyexec") && i + 1 < argc) {
            request.mode = STARTUP_PYTHON_MODE_EXEC;
            std::wstringstream code;
            for (int j = i + 1; j < argc; ++j) {
                if (j != i + 1) {
                    code << L' ';
                }
                code << argv[j];
            }
            request.payload = code.str();
            break;
        }
    }

    LocalFree(argv);
    return true;
}

struct TextStyle {
    COLORREF fg;
    COLORREF bg;
    bool hasBg;
    TextStyle() : fg(kForeground), bg(kBackground), hasBg(false) {}
};

struct StyledRun {
    std::wstring text;
    TextStyle style;
};

struct LineBuffer {
    std::vector<StyledRun> runs;
};

struct GotoResult {
    bool ok;
    std::wstring error;
    GotoResult() : ok(false) {}
};

struct DisasmPageResult {
    bool ok;
    LONG generation;
    uint64_t targetAddress;
    uint64_t regionBase;
    uint64_t regionEnd;
    int keepTopRow;
    size_t exactPlacementStart;
    std::vector<DisassemblyUiRow> rows;
    DisasmPageResult() : ok(false), generation(0), targetAddress(0), regionBase(0), regionEnd(0), keepTopRow(0), exactPlacementStart(static_cast<size_t>(-1)) {}
};

class OutputStreamBuf;

class GuiTerminalApp {
public:
    GuiTerminalApp();
    ~GuiTerminalApp();

    int Run();

    void QueueOutput(const std::wstring& text);
    void HandleOutputReady();
    void SubmitInput();
    void MoveHistory(int direction);
    void ClearInputHistoryState();

private:
    friend class OutputStreamBuf;

    static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK OutputWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK InputWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK DisasmToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK DisasmViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MemoryToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MemoryViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK RegisterToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK RegisterViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK StackToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK StackViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK PseudoCToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK PseudoCViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK TitleMenuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK GotoDialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    bool RegisterClasses();
    bool CreateMainWindow();
    bool CreateChildControls();
    void QueueDisassemblyUi(const std::vector<DisassemblyUiRow>& rows, uint64_t targetAddress, uint64_t regionBase, uint64_t regionEnd);
    void ShowPendingDisassemblyUi();
    void CreateOrUpdateDisassemblyTool(const std::vector<DisassemblyUiRow>& rows, uint64_t targetAddress, uint64_t regionBase, uint64_t regionEnd);
    void QueueMemoryUi(const std::vector<MemoryUiRow>& rows, uint64_t targetAddress, uint64_t baseAddress, size_t byteCount, size_t unitSize, size_t unitsPerLine);
    void ShowPendingMemoryUi();
    void CreateOrUpdateMemoryTool(const std::vector<MemoryUiRow>& rows, uint64_t targetAddress, uint64_t baseAddress, size_t byteCount, size_t unitSize, size_t unitsPerLine);
    void LayoutMemoryTool();
    void UpdateMemoryMetrics();
    void UpdateMemoryScrollInfo();
    void PaintMemoryView(HDC targetDc, const RECT& clip);
    int HitTestMemoryColumnSeparator(int x) const;
    void QueueRegisterUi(const std::vector<RegisterUiRow>& rows, const std::wstring& view);
    void ShowPendingRegisterUi();
    void CreateOrUpdateRegisterTool(const std::vector<RegisterUiRow>& rows, const std::wstring& view);
    void LayoutRegisterTool();
    void UpdateRegisterMetrics();
    void UpdateRegisterScrollInfo();
    void PaintRegisterView(HDC targetDc, const RECT& clip);
    int HitTestRegisterColumnSeparator(int x) const;
    void QueueStackUi(const std::vector<StackUiRow>& rows, const std::wstring& view, uint64_t stackPointer);
    void ShowPendingStackUi();
    void CreateOrUpdateStackTool(const std::vector<StackUiRow>& rows, const std::wstring& view, uint64_t stackPointer);
    void LayoutStackTool();
    void UpdateStackMetrics();
    void UpdateStackScrollInfo();
    void PaintStackView(HDC targetDc, const RECT& clip);
    int HitTestStackColumnSeparator(int x) const;
    void QueuePseudoCUi(const std::wstring& text, uint64_t address);
    void ShowPendingPseudoCUi();
    void CreateOrUpdatePseudoCTool(const std::wstring& text, uint64_t address);
    void LayoutPseudoCTool();
    void UpdatePseudoCMetrics();
    void UpdatePseudoCScrollInfo();
    void PaintPseudoCView(HDC targetDc, const RECT& clip);
    void LayoutDisassemblyTool();
    void UpdateDisassemblyMetrics();
    void UpdateDisassemblyScrollInfo();
    void PaintDisassemblyView(HDC targetDc, const RECT& clip);
    void ScrollDisassemblyToAddress(uint64_t address);
    bool DisassemblyVisibleRangeHasInstruction() const;
    bool DisassemblyVisibleRangeHasEmptyInstruction() const;
    int HitTestDisassemblyColumnSeparator(int x) const;
    int DisassemblyRowFromPoint(int y) const;
    void DestroyChildControls();
    void ApplyWindowIcon();
    void CreateTitleTabWindow();
    void DestroyTitleTabWindow();
    void UpdateTitleTabWindow();
    void ShowTitleMenu(POINT pt);
    void HideTitleMenu();
    void ShowGotoDialog();
    void HideGotoDialog();
    bool SubmitGotoDialog();
    void SetGotoDialogError(const std::wstring& text);
    void AddGotoHistory(const std::wstring& text);
    void SetGotoDialogBusy(bool busy);
    void CompleteGotoDialog(GotoResult* result);
    void StartDisassemblyJumpAsync(const std::wstring& target, bool reportToGotoDialog);
    void RefreshDisassemblyPageIfNeeded();
    void CompleteDisassemblyPageRefresh(DisasmPageResult* result);
    bool TryGetSelectedDisassemblyJumpTarget(std::wstring& target) const;
    bool JumpSelectedDisassemblyTarget();
    std::wstring BuildDisassemblySelectionText() const;
    bool CopyDisassemblySelectionToClipboard();
    bool SaveDisassemblySelectionToFile();
    int MemoryRowFromPoint(int y) const;
    int RegisterRowFromPoint(int y) const;
    int StackRowFromPoint(int y) const;
    std::wstring BuildMemorySelectionText() const;
    std::wstring BuildRegisterSelectionText() const;
    std::wstring BuildStackSelectionText() const;
    bool CopyMemorySelectionToClipboard();
    bool CopyRegisterSelectionToClipboard();
    bool CopyStackSelectionToClipboard();
    bool CopyPseudoCToClipboard();
    bool SaveMemorySelectionToFile();
    bool SaveRegisterSelectionToFile();
    bool SaveStackSelectionToFile();
    bool SavePseudoCToFile();
    std::wstring BuildPseudoCText() const;
    bool SaveTextToFile(const std::wstring& text, HWND owner, const wchar_t* defaultName);
    void PaintTitleBarTab();
    void PaintTitleBarTab(HDC targetDc, int width);
    void PaintTitleMenu(HDC targetDc, const RECT& rc);
    void PaintCommandLinePrompt(HDC targetDc);
    void SetFonts();
    void Layout(int width, int height);
    void AppendText(const std::wstring& text);
    void AppendPlainLine(const std::wstring& text, COLORREF fg);
    void AppendPromptedCommand(const std::wstring& command);
    void AppendHistory();
    void AddHistory(const std::wstring& command);
    void StartWorker();
    void StopWorker();
    void WorkerLoop();
    void RedirectStreams();
    void RestoreStreams();
    void RunStartupPython();
    bool HandlePythonCommand(const std::wstring& command);
    std::vector<std::wstring> DrainPendingOutputs();
    void AppendStyledText(const std::wstring& text);
    void AppendStyledRun(const std::wstring& text, const TextStyle& style);
    void AppendOutputRunSegment(const std::wstring& text, const TextStyle& style);
    void FinalizeOutputLine();
    void BeginOutputBatch();
    void EndOutputBatch(bool scrollToEnd);
    void ApplyOutputParagraphFormat();
    void ResetOutputTextIndex();
    void AppendOutputTextIndex(const std::wstring& text);
    POINT GetOutputTextOrigin() const;
    LONG OutputCharFromPoint(const POINTL& pt) const;
    size_t OutputLineFromChar(LONG charIndex) const;
    bool GetOutputLineTextSpan(size_t line, LONG* start, LONG* end) const;
    void SetOutputSelectionEnd();
    void ScrollOutputToEnd();
    void InvalidateOutputRange(LONG start, LONG end);
    bool GetOutputRangeBounds(LONG start, LONG end, RECT* bounds);
    bool GetOutputSelectionBounds(RECT* bounds);
    void PaintOutputSelectionRangeToDc(HDC targetDc, const RECT& clip, LONG start, LONG end);
    void PaintOutputSelectionRange(LONG start, LONG end);
    void PaintOutputSelectionToDc(HDC targetDc, const RECT& clip);
    void PaintOutputContentToDc(HDC targetDc, const RECT& clip);
    void PaintOutputSelection();
    void RefreshOutputSelection();
    void ClearOutputSelection();
    void UpdateOutputMetrics();
    void UpdateOutputScrollInfo();
    void QueueOutputSelectionPaint();
    void RedrawCommandLineArea();
    void UpdateInputText(const std::wstring& text);
    std::wstring ReadInputText() const;
    bool CopyOutputSelectionToClipboard();
    bool PasteClipboardToInput();
    void HandleRightClickPasteOrCopy();

    static bool IsQuitCommand(const std::wstring& text);
    static bool IsClearCommand(const std::wstring& text);
    static bool IsHistoryCommand(const std::wstring& text);

    HINSTANCE instance_;
    std::wstring disasmToolClassName_;
    std::wstring disasmViewClassName_;
    std::wstring memoryToolClassName_;
    std::wstring memoryViewClassName_;
    std::wstring registerToolClassName_;
    std::wstring registerViewClassName_;
    std::wstring stackToolClassName_;
    std::wstring stackViewClassName_;
    std::wstring pseudoCToolClassName_;
    std::wstring pseudoCViewClassName_;
    HWND hwnd_;
    HWND outputWnd_;
    HWND inputWnd_;
    HWND disasmToolWnd_;
    HWND disasmViewWnd_;
    HWND memoryToolWnd_;
    HWND memoryViewWnd_;
    HWND registerToolWnd_;
    HWND registerViewWnd_;
    HWND stackToolWnd_;
    HWND stackViewWnd_;
    HWND pseudoCToolWnd_;
    HWND pseudoCViewWnd_;
    HWND titleMenuWnd_;
    HWND gotoDialogWnd_;
    HWND gotoEditWnd_;
    HWND gotoErrorWnd_;
    bool gotoBusy_;
    COLORREF gotoStatusColor_;
    std::vector<std::wstring> gotoHistory_;
    HFONT font_;
    HFONT disasmFont_;
    bool ownsFont_;
    int titleButtonHover_;
    int titleButtonPressed_;
    bool titleMouseTracking_;
    int titleActionHover_;
    int titleActionPressed_;
    int titleMenuHover_;
    HMODULE richEditModule_;
    WNDPROC outputOrigProc_;
    WNDPROC inputOrigProc_;

    Debugger debugger_;
    PythonBridge pythonBridge_;
    class OutputStreamBuf* sink_;
    std::wstreambuf* oldCoutBuf_;
    std::wstreambuf* oldCerrBuf_;

    std::mutex outputMutex_;
    std::deque<std::wstring> pendingOutputs_;
    std::mutex disasmUiMutex_;
    std::vector<DisassemblyUiRow> pendingDisasmRows_;
    uint64_t pendingDisasmTarget_;
    uint64_t pendingDisasmRegionBase_;
    uint64_t pendingDisasmRegionEnd_;
    bool hasPendingDisasmUi_;
    std::vector<MemoryUiRow> pendingMemoryRows_;
    uint64_t pendingMemoryTarget_;
    uint64_t pendingMemoryBase_;
    size_t pendingMemoryByteCount_;
    size_t pendingMemoryUnitSize_;
    size_t pendingMemoryUnitsPerLine_;
    bool hasPendingMemoryUi_;
    std::vector<RegisterUiRow> pendingRegisterRows_;
    std::wstring pendingRegisterView_;
    bool hasPendingRegisterUi_;
    std::vector<StackUiRow> pendingStackRows_;
    std::wstring pendingStackView_;
    uint64_t pendingStackPointer_;
    bool hasPendingStackUi_;
    std::wstring pendingPseudoCText_;
    uint64_t pendingPseudoCAddress_;
    bool hasPendingPseudoCUi_;
    std::vector<DisassemblyUiRow> disasmRows_;
    uint64_t disasmTarget_;
    uint64_t disasmRegionBase_;
    uint64_t disasmRegionEnd_;
    bool disasmPageLoadPending_;
    uint64_t disasmPageLoadAddress_;
    LONG disasmPageLoadGeneration_;
    int disasmTopRow_;
    int disasmVisibleRows_;
    int disasmRowHeight_;
    int disasmCharWidth_;
    int disasmColAddrW_;
    int disasmColHexW_;
    int disasmColAsmW_;
    int disasmColCmtW_;
    int disasmDragCol_;
    int disasmDragStartX_;
    int disasmDragStartW_;
    bool disasmSelecting_;
    int disasmSelectionAnchor_;
    int disasmSelectionEnd_;
    std::vector<MemoryUiRow> memoryRows_;
    uint64_t memoryTarget_;
    uint64_t memoryBase_;
    size_t memoryByteCount_;
    size_t memoryUnitSize_;
    size_t memoryUnitsPerLine_;
    int memoryTopRow_;
    int memoryVisibleRows_;
    int memoryRowHeight_;
    int memoryCharWidth_;
    int memoryColAddrW_;
    int memoryColHexW_;
    int memoryDragCol_;
    int memoryDragStartX_;
    int memoryDragStartW_;
    bool memorySelecting_;
    int memorySelectionAnchor_;
    int memorySelectionEnd_;
    std::vector<RegisterUiRow> registerRows_;
    std::wstring registerViewName_;
    int registerTopRow_;
    int registerVisibleRows_;
    int registerRowHeight_;
    int registerCharWidth_;
    int registerColNameW_;
    int registerColValueW_;
    int registerDragCol_;
    int registerDragStartX_;
    int registerDragStartW_;
    bool registerSelecting_;
    int registerSelectionAnchor_;
    int registerSelectionEnd_;
    std::vector<StackUiRow> stackRows_;
    std::wstring stackViewName_;
    uint64_t stackPointer_;
    int stackTopRow_;
    int stackVisibleRows_;
    int stackRowHeight_;
    int stackCharWidth_;
    int stackColIndexW_;
    int stackColAddressW_;
    int stackColValueW_;
    int stackDragCol_;
    int stackDragStartX_;
    int stackDragStartW_;
    bool stackSelecting_;
    int stackSelectionAnchor_;
    int stackSelectionEnd_;
    std::vector<std::wstring> pseudoCLines_;
    uint64_t pseudoCAddress_;
    int pseudoCTopLine_;
    int pseudoCVisibleRows_;
    int pseudoCLineHeight_;
    int pseudoCCharWidth_;
    std::vector<LineBuffer> outputLines_;
    LineBuffer outputCurrentLine_;
    std::wstring outputText_;
    std::vector<LONG> outputLineStarts_;

    std::mutex commandMutex_;
    std::condition_variable commandCv_;
    std::deque<std::wstring> commandQueue_;
    std::mutex debuggerCommandMutex_;
    bool stopWorker_;
    std::thread worker_;

    std::vector<std::wstring> history_;
    bool historyActive_;
    int historyIndex_;
    std::wstring historyDraft_;
    bool outputSelectionPaintPending_;
    bool outputBatching_;
    LONG outputBatchStartLength_;
    bool outputSelecting_;
    int outputSelectionAutoScrollDirection_;
    POINTL outputSelectionLastPoint_;
    LONG outputSelectionAnchor_;
    LONG outputSelectionStart_;
    LONG outputSelectionEnd_;
    bool hasOutputSelection_;
    LONG outputPaintedSelectionStart_;
    LONG outputPaintedSelectionEnd_;
    bool hasOutputPaintedSelection_;
    RECT outputSelectionDirty_;
    bool hasOutputSelectionDirty_;

    int charWidth_;
    int lineHeight_;
    int visibleRows_;
    int topLine_;
    bool followTail_;
    StartupPythonRequest startupPythonRequest_;
};

class OutputStreamBuf : public std::wstreambuf {
public:
    explicit OutputStreamBuf(GuiTerminalApp* app) : app_(app) {}

protected:
    int_type overflow(int_type ch) override {
        if (traits_type::eq_int_type(ch, traits_type::eof())) {
            return traits_type::not_eof(ch);
        }
        const wchar_t wc = static_cast<wchar_t>(ch);
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.push_back(wc);
        if (wc == L'\n') {
            FlushLocked();
        }
        return ch;
    }

    int sync() override {
        std::lock_guard<std::mutex> lock(mutex_);
        FlushLocked();
        return 0;
    }

private:
    void FlushLocked() {
        if (app_ != nullptr && !pending_.empty()) {
            app_->QueueOutput(pending_);
        }
        pending_.clear();
    }

    GuiTerminalApp* app_;
    std::mutex mutex_;
    std::wstring pending_;
};

bool GuiTerminalApp::IsQuitCommand(const std::wstring& text) {
    const std::wstring lower = ToLower(Trim(text));
    return lower == L"quit" || lower == L"exit" || lower == L"q";
}

bool GuiTerminalApp::IsClearCommand(const std::wstring& text) {
    const std::wstring lower = ToLower(Trim(text));
    return lower == L"clear" || lower == L"cls";
}

bool GuiTerminalApp::IsHistoryCommand(const std::wstring& text) {
    return ToLower(Trim(text)) == L"history";
}

GuiTerminalApp::GuiTerminalApp()
    : instance_(GetModuleHandleW(nullptr)),
      disasmToolClassName_(MakeRuntimeClassName()),
      disasmViewClassName_(MakeRuntimeClassName()),
      memoryToolClassName_(MakeRuntimeClassName()),
      memoryViewClassName_(MakeRuntimeClassName()),
      registerToolClassName_(MakeRuntimeClassName()),
      registerViewClassName_(MakeRuntimeClassName()),
      stackToolClassName_(MakeRuntimeClassName()),
      stackViewClassName_(MakeRuntimeClassName()),
      pseudoCToolClassName_(MakeRuntimeClassName()),
      pseudoCViewClassName_(MakeRuntimeClassName()),
      hwnd_(nullptr),
      outputWnd_(nullptr),
      inputWnd_(nullptr),
      disasmToolWnd_(nullptr),
      disasmViewWnd_(nullptr),
      memoryToolWnd_(nullptr),
      memoryViewWnd_(nullptr),
      registerToolWnd_(nullptr),
      registerViewWnd_(nullptr),
      stackToolWnd_(nullptr),
      stackViewWnd_(nullptr),
      pseudoCToolWnd_(nullptr),
      pseudoCViewWnd_(nullptr),
      titleMenuWnd_(nullptr),
      gotoDialogWnd_(nullptr),
      gotoEditWnd_(nullptr),
      gotoErrorWnd_(nullptr),
      gotoBusy_(false),
      gotoStatusColor_(kErrorColor),
      font_(nullptr),
      disasmFont_(nullptr),
      ownsFont_(false),
      titleButtonHover_(-1),
      titleButtonPressed_(-1),
      titleMouseTracking_(false),
      titleActionHover_(-1),
      titleActionPressed_(-1),
      titleMenuHover_(-1),
      richEditModule_(nullptr),
      outputOrigProc_(nullptr),
      inputOrigProc_(nullptr),
      debugger_(L"trace.log"),
      pythonBridge_(),
      sink_(nullptr),
      oldCoutBuf_(nullptr),
      oldCerrBuf_(nullptr),
      pendingDisasmTarget_(0),
      pendingDisasmRegionBase_(0),
      pendingDisasmRegionEnd_(0),
      hasPendingDisasmUi_(false),
      pendingMemoryTarget_(0),
      pendingMemoryBase_(0),
      pendingMemoryByteCount_(0),
      pendingMemoryUnitSize_(1),
      pendingMemoryUnitsPerLine_(16),
      hasPendingMemoryUi_(false),
      pendingRegisterView_(),
      hasPendingRegisterUi_(false),
      pendingStackView_(),
      pendingStackPointer_(0),
      hasPendingStackUi_(false),
      pendingPseudoCAddress_(0),
      hasPendingPseudoCUi_(false),
      disasmTarget_(0),
      disasmRegionBase_(0),
      disasmRegionEnd_(0),
      disasmPageLoadPending_(false),
      disasmPageLoadAddress_(0),
      disasmPageLoadGeneration_(0),
      disasmTopRow_(0),
      disasmVisibleRows_(1),
      disasmRowHeight_(16),
      disasmCharWidth_(8),
      disasmColAddrW_(150),
      disasmColHexW_(230),
      disasmColAsmW_(360),
      disasmColCmtW_(220),
      disasmDragCol_(-1),
      disasmDragStartX_(0),
      disasmDragStartW_(0),
      disasmSelecting_(false),
      disasmSelectionAnchor_(-1),
      disasmSelectionEnd_(-1),
      memoryTarget_(0),
      memoryBase_(0),
      memoryByteCount_(0),
      memoryUnitSize_(1),
      memoryUnitsPerLine_(16),
      memoryTopRow_(0),
      memoryVisibleRows_(1),
      memoryRowHeight_(16),
      memoryCharWidth_(8),
      memoryColAddrW_(150),
      memoryColHexW_(520),
      memoryDragCol_(-1),
      memoryDragStartX_(0),
      memoryDragStartW_(0),
      memorySelecting_(false),
      memorySelectionAnchor_(-1),
      memorySelectionEnd_(-1),
      registerViewName_(),
      registerTopRow_(0),
      registerVisibleRows_(1),
      registerRowHeight_(16),
      registerCharWidth_(8),
      registerColNameW_(130),
      registerColValueW_(230),
      registerDragCol_(-1),
      registerDragStartX_(0),
      registerDragStartW_(0),
      registerSelecting_(false),
      registerSelectionAnchor_(-1),
      registerSelectionEnd_(-1),
      stackViewName_(),
      stackPointer_(0),
      stackTopRow_(0),
      stackVisibleRows_(1),
      stackRowHeight_(16),
      stackCharWidth_(8),
      stackColIndexW_(70),
      stackColAddressW_(180),
      stackColValueW_(190),
      stackDragCol_(-1),
      stackDragStartX_(0),
      stackDragStartW_(0),
      stackSelecting_(false),
      stackSelectionAnchor_(-1),
      stackSelectionEnd_(-1),
      pseudoCAddress_(0),
      pseudoCTopLine_(0),
      pseudoCVisibleRows_(1),
      pseudoCLineHeight_(16),
      pseudoCCharWidth_(8),
      stopWorker_(false),
      historyActive_(false),
      historyIndex_(0),
      outputSelectionPaintPending_(false),
      outputBatching_(false),
      outputBatchStartLength_(0),
      outputSelecting_(false),
      outputSelectionAutoScrollDirection_(0),
      outputSelectionLastPoint_(),
      outputSelectionAnchor_(0),
      outputSelectionStart_(0),
      outputSelectionEnd_(0),
      hasOutputSelection_(false),
      outputPaintedSelectionStart_(0),
      outputPaintedSelectionEnd_(0),
      hasOutputPaintedSelection_(false),
      outputSelectionDirty_(),
      hasOutputSelectionDirty_(false),
      charWidth_(8),
      lineHeight_(13),
      visibleRows_(1),
      topLine_(0),
      followTail_(true) {
    outputLineStarts_.push_back(0);
    sink_ = new OutputStreamBuf(this);
    pythonBridge_.SetOutputCallback([this](const std::wstring& text) {
        QueueOutput(text);
    });
    debugger_.SetDisassemblyUiCallback([this](const std::vector<DisassemblyUiRow>& rows, uint64_t targetAddress, uint64_t regionBase, uint64_t regionEnd) {
        QueueDisassemblyUi(rows, targetAddress, regionBase, regionEnd);
    });
    debugger_.SetMemoryUiCallback([this](const std::vector<MemoryUiRow>& rows, uint64_t targetAddress, uint64_t baseAddress, size_t byteCount, size_t unitSize, size_t unitsPerLine) {
        QueueMemoryUi(rows, targetAddress, baseAddress, byteCount, unitSize, unitsPerLine);
    });
    debugger_.SetRegisterUiCallback([this](const std::vector<RegisterUiRow>& rows, const std::wstring& view) {
        QueueRegisterUi(rows, view);
    });
    debugger_.SetStackUiCallback([this](const std::vector<StackUiRow>& rows, const std::wstring& view, uint64_t stackPointer) {
        QueueStackUi(rows, view, stackPointer);
    });
    debugger_.SetPseudoCUiCallback([this](const std::wstring& text, uint64_t address) {
        QueuePseudoCUi(text, address);
    });
}

GuiTerminalApp::~GuiTerminalApp() {
    pythonBridge_.Shutdown();
    StopWorker();
    RestoreStreams();
    DestroyTitleTabWindow();
    DestroyChildControls();
    if (disasmFont_ != nullptr) {
        DeleteObject(disasmFont_);
        disasmFont_ = nullptr;
    }
    if (font_ != nullptr) {
        if (ownsFont_) {
            DeleteObject(font_);
        }
        font_ = nullptr;
        ownsFont_ = false;
    }
    if (richEditModule_ != nullptr) {
        FreeLibrary(richEditModule_);
        richEditModule_ = nullptr;
    }
    delete sink_;
    sink_ = nullptr;
}

bool GuiTerminalApp::RegisterClasses() {
    WNDCLASSW wc = {};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = &GuiTerminalApp::MainWndProc;
    wc.hInstance = instance_;
    wc.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hCursor = ArrowCursor();
    wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    wc.lpszClassName = kMainClassName;
    if (RegisterClassW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW out = {};
    out.style = CS_HREDRAW | CS_VREDRAW;
    out.lpfnWndProc = &GuiTerminalApp::OutputWndProc;
    out.hInstance = instance_;
    out.hCursor = ArrowCursor();
    out.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    out.lpszClassName = kOutputClassName;
    if (RegisterClassW(&out) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW disasmTool = {};
    disasmTool.style = CS_HREDRAW | CS_VREDRAW;
    disasmTool.lpfnWndProc = &GuiTerminalApp::DisasmToolWndProc;
    disasmTool.hInstance = instance_;
    disasmTool.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_APP_ICON));
    disasmTool.hCursor = ArrowCursor();
    disasmTool.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    disasmTool.lpszClassName = disasmToolClassName_.c_str();
    if (RegisterClassW(&disasmTool) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW disasmView = {};
    disasmView.style = CS_HREDRAW | CS_VREDRAW;
    disasmView.lpfnWndProc = &GuiTerminalApp::DisasmViewWndProc;
    disasmView.hInstance = instance_;
    disasmView.hCursor = ArrowCursor();
    disasmView.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    disasmView.lpszClassName = disasmViewClassName_.c_str();
    if (RegisterClassW(&disasmView) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW memoryTool = {};
    memoryTool.style = CS_HREDRAW | CS_VREDRAW;
    memoryTool.lpfnWndProc = &GuiTerminalApp::MemoryToolWndProc;
    memoryTool.hInstance = instance_;
    memoryTool.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_APP_ICON));
    memoryTool.hCursor = ArrowCursor();
    memoryTool.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    memoryTool.lpszClassName = memoryToolClassName_.c_str();
    if (RegisterClassW(&memoryTool) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW memoryView = {};
    memoryView.style = CS_HREDRAW | CS_VREDRAW;
    memoryView.lpfnWndProc = &GuiTerminalApp::MemoryViewWndProc;
    memoryView.hInstance = instance_;
    memoryView.hCursor = ArrowCursor();
    memoryView.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    memoryView.lpszClassName = memoryViewClassName_.c_str();
    if (RegisterClassW(&memoryView) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW registerTool = {};
    registerTool.style = CS_HREDRAW | CS_VREDRAW;
    registerTool.lpfnWndProc = &GuiTerminalApp::RegisterToolWndProc;
    registerTool.hInstance = instance_;
    registerTool.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_APP_ICON));
    registerTool.hCursor = ArrowCursor();
    registerTool.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    registerTool.lpszClassName = registerToolClassName_.c_str();
    if (RegisterClassW(&registerTool) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW registerView = {};
    registerView.style = CS_HREDRAW | CS_VREDRAW;
    registerView.lpfnWndProc = &GuiTerminalApp::RegisterViewWndProc;
    registerView.hInstance = instance_;
    registerView.hCursor = ArrowCursor();
    registerView.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    registerView.lpszClassName = registerViewClassName_.c_str();
    if (RegisterClassW(&registerView) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW stackTool = {};
    stackTool.style = CS_HREDRAW | CS_VREDRAW;
    stackTool.lpfnWndProc = &GuiTerminalApp::StackToolWndProc;
    stackTool.hInstance = instance_;
    stackTool.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_APP_ICON));
    stackTool.hCursor = ArrowCursor();
    stackTool.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    stackTool.lpszClassName = stackToolClassName_.c_str();
    if (RegisterClassW(&stackTool) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW stackView = {};
    stackView.style = CS_HREDRAW | CS_VREDRAW;
    stackView.lpfnWndProc = &GuiTerminalApp::StackViewWndProc;
    stackView.hInstance = instance_;
    stackView.hCursor = ArrowCursor();
    stackView.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    stackView.lpszClassName = stackViewClassName_.c_str();
    if (RegisterClassW(&stackView) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW pseudoCTool = {};
    pseudoCTool.style = CS_HREDRAW | CS_VREDRAW;
    pseudoCTool.lpfnWndProc = &GuiTerminalApp::PseudoCToolWndProc;
    pseudoCTool.hInstance = instance_;
    pseudoCTool.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_APP_ICON));
    pseudoCTool.hCursor = ArrowCursor();
    pseudoCTool.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    pseudoCTool.lpszClassName = pseudoCToolClassName_.c_str();
    if (RegisterClassW(&pseudoCTool) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW pseudoCView = {};
    pseudoCView.style = CS_HREDRAW | CS_VREDRAW;
    pseudoCView.lpfnWndProc = &GuiTerminalApp::PseudoCViewWndProc;
    pseudoCView.hInstance = instance_;
    pseudoCView.hCursor = IBeamCursor();
    pseudoCView.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    pseudoCView.lpszClassName = pseudoCViewClassName_.c_str();
    if (RegisterClassW(&pseudoCView) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW titleMenu = {};
    titleMenu.style = CS_HREDRAW | CS_VREDRAW;
    titleMenu.lpfnWndProc = &GuiTerminalApp::TitleMenuWndProc;
    titleMenu.hInstance = instance_;
    titleMenu.hCursor = ArrowCursor();
    titleMenu.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    titleMenu.lpszClassName = kTitleMenuClassName;
    if (RegisterClassW(&titleMenu) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW gotoDialog = {};
    gotoDialog.style = CS_HREDRAW | CS_VREDRAW;
    gotoDialog.lpfnWndProc = &GuiTerminalApp::GotoDialogWndProc;
    gotoDialog.hInstance = instance_;
    gotoDialog.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_APP_ICON));
    gotoDialog.hCursor = ArrowCursor();
    gotoDialog.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    gotoDialog.lpszClassName = kGotoDialogClassName;
    if (RegisterClassW(&gotoDialog) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }
    return true;
}

bool GuiTerminalApp::CreateMainWindow() {
    RECT workArea = {};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
    const int workWidth = std::max<int>(1, workArea.right - workArea.left);
    const int workHeight = std::max<int>(1, workArea.bottom - workArea.top);
    const int windowX = workArea.left + std::max<int>(0, (workWidth - kInitialWindowWidth) / 2);
    const int windowY = workArea.top + std::max<int>(0, (workHeight - kInitialWindowHeight) / 2);

    hwnd_ = CreateWindowExW(
        0,
        kMainClassName,
        kSystemWindowTitle,
        WS_POPUP | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_VISIBLE | WS_CLIPCHILDREN,
        windowX,
        windowY,
        kInitialWindowWidth,
        kInitialWindowHeight,
        nullptr,
        nullptr,
        instance_,
        this);
    if (hwnd_ != nullptr) {
        ApplySmoothSmallWindowCorners(hwnd_, true);
    }
    return hwnd_ != nullptr;
}

bool GuiTerminalApp::CreateChildControls() {
    outputWnd_ = CreateWindowExW(
        0,
        kOutputClassName,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_VSCROLL,
        0, 0, 0, 0,
        hwnd_,
        nullptr,
        instance_,
        nullptr);

    inputWnd_ = CreateWindowExW(
        0,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | ES_AUTOHSCROLL | ES_NOHIDESEL,
        0, 0, 0, 0,
        hwnd_,
        nullptr,
        instance_,
        nullptr);

    if (outputWnd_ == nullptr || inputWnd_ == nullptr) {
        return false;
    }

    SetWindowLongPtrW(inputWnd_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    SetWindowLongPtrW(outputWnd_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    inputOrigProc_ = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(inputWnd_, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&GuiTerminalApp::InputWndProc)));

    SetFonts();
    UpdateOutputMetrics();
    Layout(kInitialWindowWidth, kInitialWindowHeight);
    SetFocus(inputWnd_);
    return true;
}

void GuiTerminalApp::ApplyWindowIcon() {
    if (hwnd_ == nullptr || !IsWindow(hwnd_)) {
        return;
    }
    ApplyConsoleLikeIcon(hwnd_, instance_);
}

void GuiTerminalApp::CreateTitleTabWindow() {
    UpdateTitleTabWindow();
}

void GuiTerminalApp::DestroyTitleTabWindow() {
    HideTitleMenu();
}

void GuiTerminalApp::UpdateTitleTabWindow() {
    if (hwnd_ == nullptr || !IsWindow(hwnd_) || IsIconic(hwnd_) || !IsWindowVisible(hwnd_)) {
        return;
    }
    RECT rc = {};
    GetClientRect(hwnd_, &rc);
    rc.bottom = std::min<LONG>(rc.bottom, kCustomTitleHeight);
    InvalidateRect(hwnd_, &rc, FALSE);
}

void GuiTerminalApp::HideTitleMenu() {
    titleMenuHover_ = -1;
    if (titleMenuWnd_ != nullptr && IsWindow(titleMenuWnd_)) {
        DestroyWindow(titleMenuWnd_);
    }
    titleMenuWnd_ = nullptr;
}

void GuiTerminalApp::ShowTitleMenu(POINT pt) {
    HideTitleMenu();

    const int itemWidth = 280;
    const int itemHeight = 34;
    const int margin = 6;
    const int width = itemWidth + margin * 2;
    const int height = itemHeight * 3 + margin * 2;

    titleMenuWnd_ = CreateWindowExW(
        WS_EX_TOOLWINDOW,
        kTitleMenuClassName,
        L"",
        WS_POPUP,
        pt.x,
        pt.y,
        width,
        height,
        hwnd_,
        nullptr,
        instance_,
        this);
    if (titleMenuWnd_ == nullptr) {
        return;
    }
    SetWindowRgn(titleMenuWnd_, CreateRoundRectRgn(0, 0, width + 1, height + 1, 16, 16), TRUE);
    SetWindowPos(titleMenuWnd_, HWND_TOP, pt.x, pt.y, width, height, SWP_NOACTIVATE);
    ShowWindow(titleMenuWnd_, SW_SHOWNOACTIVATE);
    UpdateWindow(titleMenuWnd_);
}

void GuiTerminalApp::SetGotoDialogError(const std::wstring& text) {
    gotoStatusColor_ = kErrorColor;
    if (gotoErrorWnd_ != nullptr && IsWindow(gotoErrorWnd_)) {
        SetWindowTextW(gotoErrorWnd_, text.c_str());
        InvalidateRect(gotoErrorWnd_, nullptr, TRUE);
    }
}

void GuiTerminalApp::AddGotoHistory(const std::wstring& text) {
    const std::wstring value = Trim(text);
    if (value.empty()) {
        return;
    }
    for (size_t i = 0; i < gotoHistory_.size(); ++i) {
        if (ToLower(gotoHistory_[i]) == ToLower(value)) {
            gotoHistory_.erase(gotoHistory_.begin() + i);
            break;
        }
    }
    gotoHistory_.insert(gotoHistory_.begin(), value);
    if (gotoHistory_.size() > 32) {
        gotoHistory_.resize(32);
    }
    if (gotoEditWnd_ != nullptr && IsWindow(gotoEditWnd_)) {
        SendMessageW(gotoEditWnd_, CB_RESETCONTENT, 0, 0);
        for (size_t i = 0; i < gotoHistory_.size(); ++i) {
            SendMessageW(gotoEditWnd_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(gotoHistory_[i].c_str()));
        }
        SetWindowTextW(gotoEditWnd_, value.c_str());
    }
}

void GuiTerminalApp::SetGotoDialogBusy(bool busy) {
    gotoBusy_ = busy;
    if (gotoDialogWnd_ != nullptr && IsWindow(gotoDialogWnd_)) {
        HWND ok = GetDlgItem(gotoDialogWnd_, ID_GOTO_OK);
        if (ok != nullptr) {
            EnableWindow(ok, busy ? FALSE : TRUE);
        }
        if (gotoEditWnd_ != nullptr) {
            EnableWindow(gotoEditWnd_, busy ? FALSE : TRUE);
        }
    }
}

void GuiTerminalApp::CompleteGotoDialog(GotoResult* result) {
    if (result == nullptr) {
        SetGotoDialogBusy(false);
        return;
    }
    const bool ok = result->ok;
    const std::wstring error = result->error;
    delete result;

    SetGotoDialogBusy(false);
    if (ok) {
        HideGotoDialog();
        if (disasmViewWnd_ != nullptr && IsWindow(disasmViewWnd_)) {
            SetFocus(disasmViewWnd_);
        }
        return;
    }

    SetGotoDialogError(error.empty()
        ? (IsChineseUserInterface() ? L"无法跳转：地址不可达。" : L"Cannot jump: target is unreachable.")
        : error);
    if (gotoEditWnd_ != nullptr && IsWindow(gotoEditWnd_)) {
        SendMessageW(gotoEditWnd_, CB_SETEDITSEL, 0, MAKELPARAM(0, -1));
        SetFocus(gotoEditWnd_);
    }
}

void GuiTerminalApp::StartDisassemblyJumpAsync(const std::wstring& target, bool reportToGotoDialog) {
    const std::wstring jumpTarget = Trim(target);
    if (jumpTarget.empty()) {
        return;
    }
    HWND notifyWnd = hwnd_;
    if (reportToGotoDialog) {
        gotoStatusColor_ = RGB(210, 210, 210);
        if (gotoErrorWnd_ != nullptr && IsWindow(gotoErrorWnd_)) {
            SetWindowTextW(gotoErrorWnd_, IsChineseUserInterface() ? L"正在跳转..." : L"Jumping...");
            InvalidateRect(gotoErrorWnd_, nullptr, TRUE);
        }
        SetGotoDialogBusy(true);
    }
    std::thread([this, notifyWnd, jumpTarget, reportToGotoDialog]() {
        std::vector<std::wstring> tokens;
        tokens.push_back(L"u");
        tokens.push_back(jumpTarget);
        tokens.push_back(L"--ui");
        bool ok = false;
        {
            std::lock_guard<std::mutex> lock(debuggerCommandMutex_);
            ok = debugger_.ExecuteCommand(tokens);
        }
        if (reportToGotoDialog && notifyWnd != nullptr && IsWindow(notifyWnd)) {
            GotoResult* result = new GotoResult();
            result->ok = ok;
            if (!ok) {
                result->error = IsChineseUserInterface()
                    ? L"无法跳转：地址/符号不可解析，或目标内存不可执行/不可读。"
                    : L"Cannot jump: unresolved target, or memory is not executable/readable.";
            }
            PostMessageW(notifyWnd, WM_APP_GOTO_COMPLETE, 0, reinterpret_cast<LPARAM>(result));
        }
    }).detach();
}

void GuiTerminalApp::RefreshDisassemblyPageIfNeeded() {
    if (disasmRows_.empty() || disasmRegionBase_ == 0 || disasmRegionEnd_ <= disasmRegionBase_) {
        return;
    }
    const int maxRows = static_cast<int>(disasmRows_.size());
    const int firstVisible = std::clamp<int>(disasmTopRow_, 0, std::max<int>(0, maxRows - 1));
    const int lastVisible = std::min<int>(maxRows, firstVisible + std::max<int>(1, disasmVisibleRows_));
    bool needsRefresh = false;
    int refreshRow = firstVisible;
    for (int i = firstVisible; i < lastVisible; ++i) {
        if (disasmRows_[i].instruction.empty()) {
            needsRefresh = true;
            refreshRow = i;
            break;
        }
    }
    if (!needsRefresh) {
        return;
    }
    const int rowIndex = refreshRow;
    const DisassemblyUiRow& row = disasmRows_[rowIndex];
    uint64_t address = row.address;
    if (address == 0) {
        address = disasmRegionBase_ + static_cast<uint64_t>(std::max<int>(0, rowIndex)) * 2;
    }
    if (address < disasmRegionBase_) {
        address = disasmRegionBase_;
    }
    if (address >= disasmRegionEnd_) {
        address = disasmRegionEnd_ - 1;
    }
    if (disasmPageLoadPending_ && disasmPageLoadAddress_ == address) {
        return;
    }
    disasmPageLoadPending_ = true;
    disasmPageLoadAddress_ = address;
    const int keepTopRow = disasmTopRow_;
    const size_t preciseBytes = static_cast<size_t>(std::max<int>(0x800, disasmVisibleRows_ * 48));
    const LONG generation = InterlockedIncrement(&disasmPageLoadGeneration_);
    HWND notifyWnd = hwnd_;
    std::thread([this, notifyWnd, address, keepTopRow, rowIndex, preciseBytes, generation]() {
        if (InterlockedCompareExchange(&disasmPageLoadGeneration_, 0, 0) != generation) {
            return;
        }
        DisasmPageResult* result = new DisasmPageResult();
        result->generation = generation;
        result->targetAddress = address;
        result->keepTopRow = keepTopRow;
        {
            std::lock_guard<std::mutex> lock(debuggerCommandMutex_);
            if (InterlockedCompareExchange(&disasmPageLoadGeneration_, 0, 0) != generation) {
                delete result;
                return;
            }
            result->ok = debugger_.CollectDisassemblyUiRows(
                address,
                result->rows,
                result->regionBase,
                result->regionEnd,
                static_cast<size_t>(std::max<int>(0, rowIndex)),
                preciseBytes,
                &result->exactPlacementStart);
        }
        if (notifyWnd != nullptr && IsWindow(notifyWnd)) {
            PostMessageW(notifyWnd, WM_APP_DISASM_PAGE_READY, 0, reinterpret_cast<LPARAM>(result));
        } else {
            delete result;
        }
    }).detach();
}

void GuiTerminalApp::CompleteDisassemblyPageRefresh(DisasmPageResult* result) {
    if (result == nullptr) {
        disasmPageLoadPending_ = false;
        disasmPageLoadAddress_ = 0;
        return;
    }
    if (InterlockedCompareExchange(&disasmPageLoadGeneration_, 0, 0) != result->generation) {
        delete result;
        return;
    }

    const bool ok = result->ok;
    const uint64_t targetAddress = result->targetAddress;
    const uint64_t regionBase = result->regionBase;
    const uint64_t regionEnd = result->regionEnd;
    const int keepTopRow = result->keepTopRow;
    const size_t exactPlacementStart = result->exactPlacementStart;
    std::vector<DisassemblyUiRow> rows;
    rows.swap(result->rows);
    delete result;

    disasmPageLoadPending_ = false;
    disasmPageLoadAddress_ = 0;
    if (!ok || rows.empty()) {
        return;
    }
    if (regionBase != disasmRegionBase_ || regionEnd != disasmRegionEnd_) {
        return;
    }
    if (targetAddress < disasmRegionBase_ || targetAddress >= disasmRegionEnd_) {
        return;
    }
    if (exactPlacementStart != static_cast<size_t>(-1) && exactPlacementStart < disasmRows_.size()) {
        for (size_t i = 0; i < rows.size() && exactPlacementStart + i < disasmRows_.size(); ++i) {
            if (!rows[i].instruction.empty()) {
                disasmRows_[exactPlacementStart + i] = rows[i];
            }
        }
    } else if (rows.size() == disasmRows_.size()) {
        for (size_t i = 0; i < rows.size(); ++i) {
            if (!rows[i].instruction.empty()) {
                disasmRows_[i] = rows[i];
            } else {
                disasmRows_[i].currentIp = rows[i].currentIp;
                disasmRows_[i].breakpoint = rows[i].breakpoint;
            }
        }
    } else {
        disasmRows_.swap(rows);
    }
    const int maxTop = std::max<int>(0, static_cast<int>(disasmRows_.size()) - disasmVisibleRows_);
    disasmTopRow_ = std::clamp<int>(disasmTopRow_, 0, maxTop);
    UpdateDisassemblyScrollInfo();
    if (disasmViewWnd_ != nullptr && IsWindow(disasmViewWnd_)) {
        const bool visibleHasInstruction = DisassemblyVisibleRangeHasInstruction();
        const bool visibleStillEmpty = DisassemblyVisibleRangeHasEmptyInstruction();
        if (visibleHasInstruction) {
            InvalidateRect(disasmViewWnd_, nullptr, FALSE);
        }
        if (keepTopRow != disasmTopRow_ || visibleStillEmpty) {
            KillTimer(disasmViewWnd_, kDisasmPageLoadTimer);
            SetTimer(disasmViewWnd_, kDisasmPageLoadTimer, 20, nullptr);
        }
    }
}

void GuiTerminalApp::HideGotoDialog() {
    if (gotoDialogWnd_ != nullptr && IsWindow(gotoDialogWnd_)) {
        DestroyWindow(gotoDialogWnd_);
    }
    gotoDialogWnd_ = nullptr;
    gotoEditWnd_ = nullptr;
    gotoErrorWnd_ = nullptr;
    gotoBusy_ = false;
}

bool GuiTerminalApp::SubmitGotoDialog() {
    if (gotoBusy_) {
        return false;
    }
    if (gotoEditWnd_ == nullptr || !IsWindow(gotoEditWnd_)) {
        return false;
    }

    wchar_t buffer[512] = {};
    GetWindowTextW(gotoEditWnd_, buffer, static_cast<int>(sizeof(buffer) / sizeof(buffer[0])));
    const std::wstring target = Trim(buffer);
    if (target.empty()) {
        SetGotoDialogError(IsChineseUserInterface() ? L"请输入地址或符号。" : L"Enter an address or symbol.");
        return false;
    }

    AddGotoHistory(target);
    StartDisassemblyJumpAsync(target, true);
    return true;
}

bool GuiTerminalApp::TryGetSelectedDisassemblyJumpTarget(std::wstring& target) const {
    target.clear();
    if (disasmRows_.empty() || disasmSelectionAnchor_ < 0) {
        return false;
    }

    const int rowIndex = (disasmSelectionEnd_ >= 0) ? disasmSelectionEnd_ : disasmSelectionAnchor_;
    if (rowIndex < 0 || rowIndex >= static_cast<int>(disasmRows_.size())) {
        return false;
    }

    const std::wstring instruction = Trim(disasmRows_[rowIndex].instruction);
    if (instruction.empty()) {
        return false;
    }

    const size_t mnemonicEnd = instruction.find_first_of(L" \t");
    const std::wstring mnemonic = ToLower(mnemonicEnd == std::wstring::npos ? instruction : instruction.substr(0, mnemonicEnd));
    const bool isJump =
        mnemonic == L"call" ||
        mnemonic == L"jmp" ||
        mnemonic == L"loop" ||
        mnemonic == L"loope" ||
        mnemonic == L"loopne" ||
        mnemonic == L"jcxz" ||
        mnemonic == L"jecxz" ||
        mnemonic == L"jrcxz" ||
        (mnemonic.size() >= 2 && mnemonic[0] == L'j');
    if (!isJump || mnemonicEnd == std::wstring::npos) {
        return false;
    }

    std::wstring operand = Trim(instruction.substr(mnemonicEnd + 1));
    const size_t comma = operand.find(L',');
    if (comma != std::wstring::npos) {
        operand = Trim(operand.substr(0, comma));
    }

    const wchar_t* prefixes[] = {
        L"SHORT ",
        L"NEAR ",
        L"FAR ",
        L"BYTE ",
        L"WORD ",
        L"DWORD ",
        L"QWORD ",
        L"TBYTE ",
        L"PTR "
    };
    bool stripped = true;
    while (stripped) {
        stripped = false;
        const std::wstring upper = ToLower(operand);
        for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
            const std::wstring prefix = ToLower(prefixes[i]);
            if (upper.rfind(prefix, 0) == 0) {
                operand = Trim(operand.substr(prefix.size()));
                stripped = true;
                break;
            }
        }
    }

    if (operand.empty() || operand.find(L'[') != std::wstring::npos || operand.find(L']') != std::wstring::npos) {
        return false;
    }

    bool bareHex = operand.size() >= 8;
    for (size_t i = 0; i < operand.size() && bareHex; ++i) {
        bareHex = std::iswxdigit(operand[i]) != 0;
    }
    if (bareHex && operand.rfind(L"0x", 0) != 0 && operand.rfind(L"0X", 0) != 0) {
        operand = L"0x" + operand;
    }

    target = operand;
    return !target.empty();
}

bool GuiTerminalApp::JumpSelectedDisassemblyTarget() {
    std::wstring target;
    if (!TryGetSelectedDisassemblyJumpTarget(target)) {
        return false;
    }

    StartDisassemblyJumpAsync(target, false);
    return true;
}

std::wstring GuiTerminalApp::BuildDisassemblySelectionText() const {
    if (disasmRows_.empty() || disasmSelectionAnchor_ < 0 || disasmSelectionEnd_ < 0) {
        return L"";
    }

    const int selStart = std::max<int>(0, std::min<int>(disasmSelectionAnchor_, disasmSelectionEnd_));
    const int selEnd = std::min<int>(
        static_cast<int>(disasmRows_.size()) - 1,
        std::max<int>(disasmSelectionAnchor_, disasmSelectionEnd_));
    if (selStart > selEnd) {
        return L"";
    }

    std::wstringstream out;
    for (int i = selStart; i <= selEnd; ++i) {
        const DisassemblyUiRow& row = disasmRows_[i];
        std::wstring compactHex;
        compactHex.reserve(row.hexBytes.size());
        for (size_t j = 0; j < row.hexBytes.size(); ++j) {
            const wchar_t ch = row.hexBytes[j];
            if (ch != L' ' && ch != L'\t') {
                compactHex.push_back(ch);
            }
        }

        out << row.addressText << L"\t"
            << compactHex << L"\t"
            << row.instruction;
        if (!row.comment.empty()) {
            out << L"\t" << row.comment;
        }
        out << L"\r\n";
    }
    return out.str();
}

bool GuiTerminalApp::CopyDisassemblySelectionToClipboard() {
    const std::wstring text = BuildDisassemblySelectionText();
    return !text.empty() && SetClipboardUnicodeText(disasmViewWnd_ != nullptr ? disasmViewWnd_ : hwnd_, text);
}

bool GuiTerminalApp::SaveDisassemblySelectionToFile() {
    const std::wstring text = BuildDisassemblySelectionText();
    return SaveTextToFile(text, disasmToolWnd_ != nullptr ? disasmToolWnd_ : hwnd_, L"disassembly.txt");
}

bool GuiTerminalApp::SaveTextToFile(const std::wstring& text, HWND owner, const wchar_t* defaultName) {
    if (text.empty()) {
        return false;
    }

    wchar_t filePath[MAX_PATH] = {};
    if (defaultName != nullptr && defaultName[0] != L'\0') {
        wcsncpy_s(filePath, defaultName, _TRUNCATE);
    } else {
        wcsncpy_s(filePath, L"selection.txt", _TRUNCATE);
    }
    const wchar_t filter[] = L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner != nullptr ? owner : hwnd_;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = static_cast<DWORD>(sizeof(filePath) / sizeof(filePath[0]));
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (!GetSaveFileNameW(&ofn)) {
        return false;
    }

    HANDLE file = CreateFileW(
        filePath,
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    const wchar_t bom = 0xFEFF;
    DWORD written = 0;
    BOOL ok = WriteFile(file, &bom, sizeof(bom), &written, nullptr);
    if (ok) {
        const DWORD bytes = static_cast<DWORD>(text.size() * sizeof(wchar_t));
        ok = WriteFile(file, text.c_str(), bytes, &written, nullptr);
    }
    CloseHandle(file);
    return ok != FALSE;
}

int GuiTerminalApp::MemoryRowFromPoint(int y) const {
    if (y < memoryRowHeight_ || memoryRowHeight_ <= 0 || memoryRows_.empty()) {
        return -1;
    }
    const int row = memoryTopRow_ + ((y - memoryRowHeight_) / memoryRowHeight_);
    return (row >= 0 && row < static_cast<int>(memoryRows_.size())) ? row : -1;
}

int GuiTerminalApp::RegisterRowFromPoint(int y) const {
    if (y < registerRowHeight_ || registerRowHeight_ <= 0 || registerRows_.empty()) {
        return -1;
    }
    const int row = registerTopRow_ + ((y - registerRowHeight_) / registerRowHeight_);
    return (row >= 0 && row < static_cast<int>(registerRows_.size())) ? row : -1;
}

int GuiTerminalApp::StackRowFromPoint(int y) const {
    if (y < stackRowHeight_ || stackRowHeight_ <= 0 || stackRows_.empty()) {
        return -1;
    }
    const int row = stackTopRow_ + ((y - stackRowHeight_) / stackRowHeight_);
    return (row >= 0 && row < static_cast<int>(stackRows_.size())) ? row : -1;
}

std::wstring GuiTerminalApp::BuildMemorySelectionText() const {
    if (memoryRows_.empty() || memorySelectionAnchor_ < 0 || memorySelectionEnd_ < 0) {
        return L"";
    }
    const int selStart = std::max<int>(0, std::min<int>(memorySelectionAnchor_, memorySelectionEnd_));
    const int selEnd = std::min<int>(static_cast<int>(memoryRows_.size()) - 1, std::max<int>(memorySelectionAnchor_, memorySelectionEnd_));
    std::wstringstream out;
    for (int i = selStart; i <= selEnd; ++i) {
        const MemoryUiRow& row = memoryRows_[i];
        out << row.addressText << L"\t" << row.hexText << L"\t" << row.ansiText << L"\r\n";
    }
    return out.str();
}

std::wstring GuiTerminalApp::BuildRegisterSelectionText() const {
    if (registerRows_.empty() || registerSelectionAnchor_ < 0 || registerSelectionEnd_ < 0) {
        return L"";
    }
    const int selStart = std::max<int>(0, std::min<int>(registerSelectionAnchor_, registerSelectionEnd_));
    const int selEnd = std::min<int>(static_cast<int>(registerRows_.size()) - 1, std::max<int>(registerSelectionAnchor_, registerSelectionEnd_));
    std::wstringstream out;
    for (int i = selStart; i <= selEnd; ++i) {
        const RegisterUiRow& row = registerRows_[i];
        out << row.name << L"\t" << row.value;
        if (!row.info.empty()) {
            out << L"\t" << row.info;
        }
        out << L"\r\n";
    }
    return out.str();
}

std::wstring GuiTerminalApp::BuildStackSelectionText() const {
    if (stackRows_.empty() || stackSelectionAnchor_ < 0 || stackSelectionEnd_ < 0) {
        return L"";
    }
    const int selStart = std::max<int>(0, std::min<int>(stackSelectionAnchor_, stackSelectionEnd_));
    const int selEnd = std::min<int>(static_cast<int>(stackRows_.size()) - 1, std::max<int>(stackSelectionAnchor_, stackSelectionEnd_));
    std::wstringstream out;
    for (int i = selStart; i <= selEnd; ++i) {
        const StackUiRow& row = stackRows_[i];
        out << row.address << L"\t" << row.value;
        if (!row.symbol.empty()) {
            out << L"\t" << row.symbol;
        }
        out << L"\r\n";
    }
    return out.str();
}

bool GuiTerminalApp::CopyMemorySelectionToClipboard() {
    const std::wstring text = BuildMemorySelectionText();
    return !text.empty() && SetClipboardUnicodeText(memoryViewWnd_ != nullptr ? memoryViewWnd_ : hwnd_, text);
}

bool GuiTerminalApp::CopyRegisterSelectionToClipboard() {
    const std::wstring text = BuildRegisterSelectionText();
    return !text.empty() && SetClipboardUnicodeText(registerViewWnd_ != nullptr ? registerViewWnd_ : hwnd_, text);
}

bool GuiTerminalApp::CopyStackSelectionToClipboard() {
    const std::wstring text = BuildStackSelectionText();
    return !text.empty() && SetClipboardUnicodeText(stackViewWnd_ != nullptr ? stackViewWnd_ : hwnd_, text);
}

std::wstring GuiTerminalApp::BuildPseudoCText() const {
    if (pseudoCLines_.empty()) {
        return L"";
    }
    std::wstringstream out;
    for (size_t i = 0; i < pseudoCLines_.size(); ++i) {
        out << pseudoCLines_[i] << L"\r\n";
    }
    return out.str();
}

bool GuiTerminalApp::CopyPseudoCToClipboard() {
    const std::wstring text = BuildPseudoCText();
    return !text.empty() && SetClipboardUnicodeText(pseudoCViewWnd_ != nullptr ? pseudoCViewWnd_ : hwnd_, text);
}

bool GuiTerminalApp::SaveMemorySelectionToFile() {
    return SaveTextToFile(BuildMemorySelectionText(), memoryToolWnd_ != nullptr ? memoryToolWnd_ : hwnd_, L"memory.txt");
}

bool GuiTerminalApp::SaveRegisterSelectionToFile() {
    return SaveTextToFile(BuildRegisterSelectionText(), registerToolWnd_ != nullptr ? registerToolWnd_ : hwnd_, L"registers.txt");
}

bool GuiTerminalApp::SaveStackSelectionToFile() {
    return SaveTextToFile(BuildStackSelectionText(), stackToolWnd_ != nullptr ? stackToolWnd_ : hwnd_, L"stack.txt");
}

bool GuiTerminalApp::SavePseudoCToFile() {
    return SaveTextToFile(BuildPseudoCText(), pseudoCToolWnd_ != nullptr ? pseudoCToolWnd_ : hwnd_, L"pseudoc.txt");
}

void GuiTerminalApp::ShowGotoDialog() {
    HideTitleMenu();
    if (gotoDialogWnd_ != nullptr && IsWindow(gotoDialogWnd_)) {
        ShowWindow(gotoDialogWnd_, SW_SHOWNORMAL);
        SetForegroundWindow(gotoDialogWnd_);
        if (gotoEditWnd_ != nullptr) {
            SetFocus(gotoEditWnd_);
            SendMessageW(gotoEditWnd_, CB_SETEDITSEL, 0, MAKELPARAM(0, -1));
        }
        return;
    }

    const bool zh = IsChineseUserInterface();
    const int width = 420;
    const int height = 168;
    RECT ownerRc = {};
    HWND owner = (disasmToolWnd_ != nullptr && IsWindow(disasmToolWnd_)) ? disasmToolWnd_ : hwnd_;
    GetWindowRect(owner, &ownerRc);
    const int x = ownerRc.left + std::max<int>(0, ((ownerRc.right - ownerRc.left) - width) / 2);
    const int y = ownerRc.top + std::max<int>(0, ((ownerRc.bottom - ownerRc.top) - height) / 2);

    gotoDialogWnd_ = CreateWindowExW(
        WS_EX_TOOLWINDOW,
        kGotoDialogClassName,
        zh ? L"转到地址" : L"Go To Address",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        x,
        y,
        width,
        height,
        owner,
        nullptr,
        instance_,
        this);
    if (gotoDialogWnd_ == nullptr) {
        return;
    }
    ApplyConsoleLikeChrome(gotoDialogWnd_);
    ApplyConsoleLikeIcon(gotoDialogWnd_, instance_);
    ShowWindow(gotoDialogWnd_, SW_SHOWNORMAL);
    UpdateWindow(gotoDialogWnd_);
    if (gotoEditWnd_ != nullptr) {
        SetFocus(gotoEditWnd_);
    }
}

void GuiTerminalApp::PaintTitleBarTab() {
    if (hwnd_ == nullptr || !IsWindow(hwnd_) || IsIconic(hwnd_)) {
        return;
    }

    HDC dc = GetDC(hwnd_);
    if (dc == nullptr) {
        return;
    }

    RECT rc = {};
    GetClientRect(hwnd_, &rc);
    const int width = std::max<int>(1, rc.right - rc.left);
    HDC memDc = CreateCompatibleDC(dc);
    HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, width, kCustomTitleHeight) : nullptr;
    if (memDc != nullptr && memBitmap != nullptr) {
        HGDIOBJ oldBitmap = SelectObject(memDc, memBitmap);
        PaintTitleBarTab(memDc, width);
        BitBlt(dc, 0, 0, width, kCustomTitleHeight, memDc, 0, 0, SRCCOPY);
        SelectObject(memDc, oldBitmap);
    } else {
        PaintTitleBarTab(dc, width);
    }
    if (memBitmap != nullptr) {
        DeleteObject(memBitmap);
    }
    if (memDc != nullptr) {
        DeleteDC(memDc);
    }
    ReleaseDC(hwnd_, dc);
}

void GuiTerminalApp::PaintTitleMenu(HDC targetDc, const RECT& rc) {
    if (targetDc == nullptr) {
        return;
    }
    const bool zh = IsChineseUserInterface();
    const int margin = 6;
    const int itemHeight = 34;
    const int itemLeft = rc.left + margin;
    const int itemRight = rc.right - margin;
    const wchar_t* items[] = {
        TitleMenuText(ID_TITLE_MENU_SETTINGS, zh),
        TitleMenuText(ID_TITLE_MENU_COMMAND_PANEL, zh),
        TitleMenuText(ID_TITLE_MENU_ABOUT, zh)
    };
    for (int i = 0; i < 3; ++i) {
        const int top = rc.top + margin + i * itemHeight;
        RECT itemRc = {itemLeft, top, itemRight, top + itemHeight - 4};
        const bool hover = (i == titleMenuHover_);
        HBRUSH brush = CreateSolidBrush(hover ? RGB(58, 58, 58) : RGB(24, 24, 24));
        HRGN clipRgn = CreateRoundRectRgn(itemRc.left, itemRc.top, itemRc.right, itemRc.bottom, 14, 14);
        if (clipRgn != nullptr) {
            SelectClipRgn(targetDc, clipRgn);
        }
        FillRect(targetDc, &itemRc, brush);
        if (clipRgn != nullptr) {
            SelectClipRgn(targetDc, nullptr);
            DeleteObject(clipRgn);
        }
        DeleteObject(brush);

        SetBkMode(targetDc, TRANSPARENT);
        SetTextColor(targetDc, RGB(255, 255, 255));
        HGDIOBJ oldFont = nullptr;
        if (font_ != nullptr) {
            oldFont = SelectObject(targetDc, font_);
        }
        RECT textRc = itemRc;
        textRc.left += 14;
        DrawTextW(targetDc, items[i], -1, &textRc, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
        if (oldFont != nullptr) {
            SelectObject(targetDc, oldFont);
        }
    }
}

LRESULT CALLBACK GuiTerminalApp::TitleMenuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->titleMenuWnd_ = hwnd;
            app->titleMenuHover_ = -1;
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    if (app->titleMenuWnd_ != nullptr && IsWindow(app->titleMenuWnd_)) {
        switch (msg) {
            case WM_LBUTTONDOWN:
            case WM_LBUTTONDBLCLK:
            case WM_RBUTTONDOWN:
            case WM_RBUTTONDBLCLK:
            case WM_MBUTTONDOWN:
            case WM_MBUTTONDBLCLK:
            case WM_XBUTTONDOWN:
            case WM_KEYDOWN:
            case WM_SYSKEYDOWN:
            case WM_NCLBUTTONDOWN:
            case WM_NCRBUTTONDOWN:
            case WM_NCMBUTTONDOWN:
            case WM_ACTIVATEAPP:
                if (msg == WM_ACTIVATEAPP && wParam != FALSE) {
                    break;
                }
                app->HideTitleMenu();
                break;
            default:
                break;
        }
    }

    switch (msg) {
        case WM_ERASEBKGND:
            return 1;
        case WM_NCPAINT:
            return 0;
        case WM_ACTIVATE:
            if (LOWORD(wParam) == WA_INACTIVE) {
                app->HideTitleMenu();
            }
            return 0;
        case WM_MOUSEMOVE: {
            const int y = GET_Y_LPARAM(lParam);
            const int margin = 6;
            const int itemHeight = 34;
            int hover = -1;
            if (y >= margin && y < margin + itemHeight * 3) {
                hover = std::min<int>(2, std::max<int>(0, (y - margin) / itemHeight));
            }
            if (hover != app->titleMenuHover_) {
                app->titleMenuHover_ = hover;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_LBUTTONDOWN: {
            app->HideTitleMenu();
            const int y = GET_Y_LPARAM(lParam);
            const int margin = 6;
            const int itemHeight = 34;
            if (y >= margin && y < margin + itemHeight * 3) {
                const int index = std::min<int>(2, std::max<int>(0, (y - margin) / itemHeight));
                const UINT cmd = ID_TITLE_MENU_SETTINGS + index;
                app->HideTitleMenu();
                PostMessageW(app->hwnd_, WM_COMMAND, cmd, 0);
                return 0;
            }
            return 0;
        }
        case WM_KILLFOCUS:
        case WM_CAPTURECHANGED:
            app->HideTitleMenu();
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            if (dc == nullptr) {
                EndPaint(hwnd, &ps);
                return 0;
            }
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            HDC memDc = CreateCompatibleDC(dc);
            HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, rc.right - rc.left, rc.bottom - rc.top) : nullptr;
            if (memDc != nullptr && memBitmap != nullptr) {
                HGDIOBJ oldBmp = SelectObject(memDc, memBitmap);
                HBRUSH bg = CreateSolidBrush(RGB(24, 24, 24));
                FillRect(memDc, &rc, bg);
                DeleteObject(bg);
                app->PaintTitleMenu(memDc, rc);
                BitBlt(dc, 0, 0, rc.right - rc.left, rc.bottom - rc.top, memDc, 0, 0, SRCCOPY);
                SelectObject(memDc, oldBmp);
            } else {
                app->PaintTitleMenu(dc, rc);
            }
            if (memBitmap != nullptr) {
                DeleteObject(memBitmap);
            }
            if (memDc != nullptr) {
                DeleteDC(memDc);
            }
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_DESTROY:
            if (app->titleMenuWnd_ == hwnd) {
                app->titleMenuWnd_ = nullptr;
                app->titleMenuHover_ = -1;
            }
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void GuiTerminalApp::PaintTitleBarTab(HDC targetDc, int width) {
    if (targetDc == nullptr || width <= 0) {
        return;
    }

    RECT titleRc = {0, 0, width, kCustomTitleHeight};
    HBRUSH titleBrush = CreateSolidBrush(kTitleBarColor);
    FillRect(targetDc, &titleRc, titleBrush);
    DeleteObject(titleBrush);

    const int buttonLeft = std::max<int>(0, width - kTitleButtonWidth * 3);
    RECT buttonBack = {buttonLeft, 0, width, kCustomTitleHeight};
    HBRUSH buttonBrush = CreateSolidBrush(kTitleBarColor);
    FillRect(targetDc, &buttonBack, buttonBrush);
    DeleteObject(buttonBrush);

    const int activeButton = titleButtonPressed_ >= 0 ? titleButtonPressed_ : titleButtonHover_;
    if (activeButton >= 0 && activeButton <= 2) {
        const int activeLeft = width - kTitleButtonWidth * (3 - activeButton);
        RECT activeRc = {activeLeft, 0, activeLeft + kTitleButtonWidth, kCustomTitleHeight};
        HBRUSH activeBrush = CreateSolidBrush(titleButtonPressed_ >= 0 ? RGB(196, 43, 28) : RGB(58, 58, 58));
        FillRect(targetDc, &activeRc, activeBrush);
        DeleteObject(activeBrush);
    }

    HPEN glyphPen = CreatePen(PS_SOLID, 1, RGB(235, 235, 235));
    HGDIOBJ oldGlyphPen = SelectObject(targetDc, glyphPen);
    const int glyphY = kCustomTitleHeight / 2;
    const int minCenterX = width - kTitleButtonWidth * 3 + kTitleButtonWidth / 2;
    MoveToEx(targetDc, minCenterX - 5, glyphY + 5, nullptr);
    LineTo(targetDc, minCenterX + 6, glyphY + 5);

    const int maxCenterX = width - kTitleButtonWidth * 2 + kTitleButtonWidth / 2;
    if (IsZoomed(hwnd_)) {
        MoveToEx(targetDc, maxCenterX - 3, glyphY - 6, nullptr);
        LineTo(targetDc, maxCenterX + 6, glyphY - 6);
        LineTo(targetDc, maxCenterX + 6, glyphY + 3);
        MoveToEx(targetDc, maxCenterX - 6, glyphY - 3, nullptr);
        LineTo(targetDc, maxCenterX + 3, glyphY - 3);
        LineTo(targetDc, maxCenterX + 3, glyphY + 6);
        LineTo(targetDc, maxCenterX - 6, glyphY + 6);
        LineTo(targetDc, maxCenterX - 6, glyphY - 3);
    } else {
        MoveToEx(targetDc, maxCenterX - 5, glyphY - 5, nullptr);
        LineTo(targetDc, maxCenterX + 6, glyphY - 5);
        LineTo(targetDc, maxCenterX + 6, glyphY + 6);
        LineTo(targetDc, maxCenterX - 5, glyphY + 6);
        LineTo(targetDc, maxCenterX - 5, glyphY - 5);
    }

    const int closeCenterX = width - kTitleButtonWidth + kTitleButtonWidth / 2;
    MoveToEx(targetDc, closeCenterX - 5, glyphY - 5, nullptr);
    LineTo(targetDc, closeCenterX + 6, glyphY + 6);
    MoveToEx(targetDc, closeCenterX + 5, glyphY - 5, nullptr);
    LineTo(targetDc, closeCenterX - 6, glyphY + 6);
    SelectObject(targetDc, oldGlyphPen);
    DeleteObject(glyphPen);

    SetBkMode(targetDc, TRANSPARENT);
    SetTextColor(targetDc, kForeground);
    HFONT oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = static_cast<HFONT>(SelectObject(targetDc, font_));
    } else {
        oldFont = static_cast<HFONT>(SelectObject(targetDc, GetStockObject(DEFAULT_GUI_FONT)));
    }

    const int titleIconWidth = 16;
    const int titleIconHeight = 18;
    const int titleIconY = std::max<int>(0, (kCustomTitleHeight - titleIconHeight) / 2 + 2);
    HICON titleIcon = static_cast<HICON>(LoadImageW(
        instance_,
        MAKEINTRESOURCEW(IDI_LEFT_ICON),
        IMAGE_ICON,
        titleIconWidth,
        titleIconHeight,
        LR_DEFAULTCOLOR));
    if (titleIcon != nullptr) {
        DrawIconEx(targetDc, kTitleLeftIconX, titleIconY, titleIcon, titleIconWidth, titleIconHeight, 0, nullptr, DI_NORMAL);
        DestroyIcon(titleIcon);
    }

    const int tabLeft = kTitleLeftSlotWidth;
    const int tabTop = 3;
    const int tabHeight = kCustomTitleHeight - tabTop;
    const int iconSize = GetSystemMetrics(SM_CXSMICON);
    const int iconX = kTitleTabIconX;
    const int iconY = std::max<int>(0, (tabHeight - iconSize) / 2);
    const int textX = iconX + iconSize + 11;
    const int tabWidth = std::min<int>(
        std::max<int>(kTitleTabMinWidth, textX + 120),
        std::max<int>(1, buttonLeft - tabLeft - 8));

    TEXTMETRICW tm = {};
    GetTextMetricsW(targetDc, &tm);
    const int textHeight = tm.tmHeight > 0 ? tm.tmHeight : tabHeight;
    const int textTop = std::max<int>(0, (tabHeight - textHeight) / 2 - 1);

    HBRUSH tabBrush = CreateSolidBrush(RGB(0, 0, 0));
    HPEN tabPen = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
    HGDIOBJ oldBrush = SelectObject(targetDc, tabBrush);
    HGDIOBJ oldPen = SelectObject(targetDc, tabPen);
    RoundRect(
        targetDc,
        tabLeft,
        tabTop,
        tabLeft + tabWidth,
        tabTop + tabHeight + kTitleTabRadius,
        kTitleTabRadius,
        kTitleTabRadius);
    RECT tabBottom = {tabLeft, tabTop + tabHeight - kTitleTabRadius, tabLeft + tabWidth, tabTop + tabHeight};
    FillRect(targetDc, &tabBottom, tabBrush);
    SelectObject(targetDc, oldPen);
    SelectObject(targetDc, oldBrush);
    DeleteObject(tabPen);
    DeleteObject(tabBrush);

    HICON smallIcon = static_cast<HICON>(LoadImageW(
        instance_,
        MAKEINTRESOURCEW(IDI_APP_ICON),
        IMAGE_ICON,
        iconSize,
        iconSize,
        LR_DEFAULTCOLOR));
    if (smallIcon != nullptr) {
        DrawIconEx(targetDc, tabLeft + iconX, tabTop + iconY, smallIcon, iconSize, iconSize, 0, nullptr, DI_NORMAL);
        DestroyIcon(smallIcon);
    }

    RECT textRect = {tabLeft + textX, tabTop + textTop, tabLeft + tabWidth - 8, tabTop + textTop + textHeight};
    DrawTextW(targetDc, kWindowTitle, -1, &textRect, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);

    const int actionX = tabLeft + tabWidth + 3;
    if (actionX + kTitleActionWidth < buttonLeft) {
        const int actionTop = (kCustomTitleHeight - kTitleActionHeight) / 2;
        const int actionLeft = actionX;
        const int actionRight = actionLeft + kTitleActionWidth;
        const int actionBottom = actionTop + kTitleActionHeight;
        const int activeAction = titleActionPressed_ >= 0 ? titleActionPressed_ : titleActionHover_;
        if (activeAction >= 0 && activeAction <= 1) {
            const COLORREF actionColor = titleActionPressed_ >= 0 ? RGB(66, 66, 66) : RGB(58, 58, 58);
            const int activeInset = 1;
            HBRUSH activeBrush = CreateSolidBrush(actionColor);
            HPEN activePen = CreatePen(PS_SOLID, 1, actionColor);
            HGDIOBJ oldActiveBrush = SelectObject(targetDc, activeBrush);
            HGDIOBJ oldActivePen = SelectObject(targetDc, activePen);
            RoundRect(
                targetDc,
                actionLeft + activeInset,
                actionTop + activeInset,
                actionRight - activeInset,
                actionBottom - activeInset,
                8,
                8);
            SelectObject(targetDc, oldActivePen);
            SelectObject(targetDc, oldActiveBrush);
            DeleteObject(activePen);
            DeleteObject(activeBrush);
            HPEN separatorPen = CreatePen(PS_SOLID, 1, RGB(85, 85, 85));
            HGDIOBJ oldSeparatorPen = SelectObject(targetDc, separatorPen);
            MoveToEx(targetDc, actionLeft + kTitleActionSeparatorX, actionTop + 3, nullptr);
            LineTo(targetDc, actionLeft + kTitleActionSeparatorX, actionBottom - 3);
            SelectObject(targetDc, oldSeparatorPen);
            DeleteObject(separatorPen);
        }

        HPEN actionPen = CreatePen(PS_SOLID, 1, RGB(235, 235, 235));
        HGDIOBJ oldActionPen = SelectObject(targetDc, actionPen);
        const int actionY = kCustomTitleHeight / 2;
        const int plusCenterX = actionLeft + 10;
        MoveToEx(targetDc, plusCenterX - 4, actionY, nullptr);
        LineTo(targetDc, plusCenterX + 5, actionY);
        MoveToEx(targetDc, plusCenterX, actionY - 4, nullptr);
        LineTo(targetDc, plusCenterX, actionY + 5);

        const int vLeft = actionLeft + kTitleActionVLeftOffset;
        const int vTop = actionY - 3;
        const int vWidth = kTitleActionVWidth;
        const int vHeight = kTitleActionVHeight;
        const int scale = 4;
        HDC vMemDc = CreateCompatibleDC(targetDc);
        HBITMAP vBmp = vMemDc != nullptr ? CreateCompatibleBitmap(targetDc, vWidth * scale, vHeight * scale) : nullptr;
        if (vMemDc != nullptr && vBmp != nullptr) {
            HGDIOBJ oldVBmp = SelectObject(vMemDc, vBmp);
            HBRUSH clearBrush = CreateSolidBrush(RGB(46, 46, 46));
            RECT clearRc = {0, 0, vWidth * scale, vHeight * scale};
            FillRect(vMemDc, &clearRc, clearBrush);
            DeleteObject(clearBrush);

            HPEN vPen = CreatePen(PS_SOLID, scale, RGB(235, 235, 235));
            HGDIOBJ oldVPen = SelectObject(vMemDc, vPen);
            SetBkMode(vMemDc, TRANSPARENT);
            POINT vPts[] = {
                {0 * scale, 0 * scale},
                {4 * scale, 5 * scale},
                {8 * scale, 0 * scale}
            };
            Polyline(vMemDc, vPts, 3);

            SetStretchBltMode(targetDc, HALFTONE);
            StretchBlt(targetDc, vLeft, vTop, vWidth, vHeight, vMemDc, 0, 0, vWidth * scale, vHeight * scale, SRCCOPY);

            SelectObject(vMemDc, oldVPen);
            DeleteObject(vPen);
            SelectObject(vMemDc, oldVBmp);
            DeleteObject(vBmp);
            DeleteDC(vMemDc);
        }
        SelectObject(targetDc, oldActionPen);
        DeleteObject(actionPen);
    }

    if (oldFont != nullptr) {
        SelectObject(targetDc, oldFont);
    }
}

void GuiTerminalApp::PaintCommandLinePrompt(HDC targetDc) {
    if (targetDc == nullptr || hwnd_ == nullptr || inputWnd_ == nullptr || !IsWindow(hwnd_) || !IsWindow(inputWnd_)) {
        return;
    }

    RECT input = {};
    GetWindowRect(inputWnd_, &input);
    MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&input), 2);

    const int promptWidth = std::max<int>(kPromptWidth, kPromptTextWidth);
    RECT prompt = {
        kPadding,
        input.top,
        kPadding + promptWidth,
        input.bottom
    };

    HFONT oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = static_cast<HFONT>(SelectObject(targetDc, font_));
    }
    const int oldBkMode = SetBkMode(targetDc, OPAQUE);
    const COLORREF oldBkColor = SetBkColor(targetDc, kBackground);
    const COLORREF oldTextColor = SetTextColor(targetDc, kPromptColor);

    TEXTMETRICW tm = {};
    if (targetDc != nullptr) {
        GetTextMetricsW(targetDc, &tm);
    }
    const int textHeight = tm.tmHeight > 0 ? tm.tmHeight : std::max<int>(1, input.bottom - input.top);
    const int textTop = input.top + std::max<int>(0, (input.bottom - input.top - textHeight) / 2 - 3);

    HBRUSH brush = CreateSolidBrush(kBackground);
    FillRect(targetDc, &prompt, brush);
    DeleteObject(brush);

    RECT textRect = prompt;
    textRect.left += 2;
    textRect.top = textTop;
    textRect.bottom = textTop + textHeight;
    DrawTextW(targetDc, L"z0dbg> ", -1, &textRect, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);

    SetTextColor(targetDc, oldTextColor);
    SetBkColor(targetDc, oldBkColor);
    SetBkMode(targetDc, oldBkMode);
    if (oldFont != nullptr) {
        SelectObject(targetDc, oldFont);
    }
}

void GuiTerminalApp::DestroyChildControls() {
    HideGotoDialog();
    if (disasmToolWnd_ != nullptr && IsWindow(disasmToolWnd_)) {
        DestroyWindow(disasmToolWnd_);
    }
    disasmToolWnd_ = nullptr;
    disasmViewWnd_ = nullptr;
    if (memoryToolWnd_ != nullptr && IsWindow(memoryToolWnd_)) {
        DestroyWindow(memoryToolWnd_);
    }
    memoryToolWnd_ = nullptr;
    memoryViewWnd_ = nullptr;
    if (registerToolWnd_ != nullptr && IsWindow(registerToolWnd_)) {
        DestroyWindow(registerToolWnd_);
    }
    registerToolWnd_ = nullptr;
    registerViewWnd_ = nullptr;
    if (stackToolWnd_ != nullptr && IsWindow(stackToolWnd_)) {
        DestroyWindow(stackToolWnd_);
    }
    stackToolWnd_ = nullptr;
    stackViewWnd_ = nullptr;
    if (pseudoCToolWnd_ != nullptr && IsWindow(pseudoCToolWnd_)) {
        DestroyWindow(pseudoCToolWnd_);
    }
    pseudoCToolWnd_ = nullptr;
    pseudoCViewWnd_ = nullptr;
    if (inputWnd_ != nullptr && IsWindow(inputWnd_)) {
        SetWindowLongPtrW(inputWnd_, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(inputOrigProc_));
        inputOrigProc_ = nullptr;
        DestroyWindow(inputWnd_);
    }
    inputWnd_ = nullptr;
    if (outputWnd_ != nullptr && IsWindow(outputWnd_)) {
        SetWindowLongPtrW(outputWnd_, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(outputOrigProc_));
        outputOrigProc_ = nullptr;
        DestroyWindow(outputWnd_);
    }
    outputWnd_ = nullptr;
}

void GuiTerminalApp::SetFonts() {
    if (font_ != nullptr) {
        if (ownsFont_) {
            DeleteObject(font_);
        }
        font_ = nullptr;
        ownsFont_ = false;
    }
    const wchar_t chineseFace[] = {
        static_cast<wchar_t>(0x65B0),
        static_cast<wchar_t>(0x5B8B),
        static_cast<wchar_t>(0x4F53),
        L'\0'
    };
    const wchar_t* face = IsChineseUserInterface() ? chineseFace : L"Consolas";
    font_ = CreateFontW(
        -12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        FIXED_PITCH | FF_MODERN, face);
    if (font_ == nullptr) {
        font_ = static_cast<HFONT>(GetStockObject(ANSI_FIXED_FONT));
        ownsFont_ = false;
    } else {
        ownsFont_ = true;
    }

    if (outputWnd_ != nullptr) {
        SendMessageW(outputWnd_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    }
    if (inputWnd_ != nullptr) {
        SendMessageW(inputWnd_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    }
}

void GuiTerminalApp::Layout(int width, int height) {
    if (outputWnd_ == nullptr || inputWnd_ == nullptr) {
        return;
    }
    const int clientWidth = std::max<int>(1, width - (2 * kPadding));
    const int contentTop = kCustomTitleHeight + kPadding;
    const int clientHeight = std::max<int>(1, height - contentTop - kPadding);
    const int inputY = contentTop + clientHeight - kInputHeight;
    const int outputHeight = std::max<int>(1, inputY - contentTop - 6);

    MoveWindow(outputWnd_, kPadding, contentTop, clientWidth, outputHeight, TRUE);
    MoveWindow(inputWnd_, kPadding + kPromptWidth, inputY, std::max(20, clientWidth - kPromptWidth), kInputHeight, TRUE);
}

void GuiTerminalApp::UpdateOutputMetrics() {
    if (outputWnd_ == nullptr || font_ == nullptr) {
        return;
    }
    HDC dc = GetDC(outputWnd_);
    if (dc == nullptr) {
        return;
    }
    HGDIOBJ old = SelectObject(dc, font_);
    TEXTMETRICW tm = {};
    if (GetTextMetricsW(dc, &tm)) {
        charWidth_ = std::max<int>(6, static_cast<int>(tm.tmAveCharWidth));
        lineHeight_ = std::max<int>(1, static_cast<int>(tm.tmHeight));
    }
    SelectObject(dc, old);
    ReleaseDC(outputWnd_, dc);
    UpdateOutputScrollInfo();
    InvalidateRect(outputWnd_, nullptr, FALSE);
}

void GuiTerminalApp::ApplyOutputParagraphFormat() {
}

void GuiTerminalApp::ResetOutputTextIndex() {
    outputText_.clear();
    outputLineStarts_.clear();
    outputLineStarts_.push_back(0);
    outputLines_.clear();
    outputCurrentLine_ = LineBuffer();
    hasOutputSelection_ = false;
    hasOutputPaintedSelection_ = false;
    hasOutputSelectionDirty_ = false;
    outputSelectionAnchor_ = 0;
    outputSelectionStart_ = 0;
    outputSelectionEnd_ = 0;
}

void GuiTerminalApp::AppendOutputTextIndex(const std::wstring& text) {
    if (text.empty()) {
        return;
    }
    const size_t base = outputText_.size();
    outputText_.append(text);
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == L'\n') {
            const size_t next = base + i + 1;
            outputLineStarts_.push_back(static_cast<LONG>(std::min<size_t>(next, LONG_MAX)));
        }
    }
    if (outputLineStarts_.empty()) {
        outputLineStarts_.push_back(0);
    }
}

void GuiTerminalApp::AppendOutputRunSegment(const std::wstring& text, const TextStyle& style) {
    if (text.empty()) {
        return;
    }

    if (!outputCurrentLine_.runs.empty() && outputCurrentLine_.runs.back().style.fg == style.fg &&
        outputCurrentLine_.runs.back().style.bg == style.bg && outputCurrentLine_.runs.back().style.hasBg == style.hasBg) {
        outputCurrentLine_.runs.back().text += text;
    } else {
        StyledRun run;
        run.text = text;
        run.style = style;
        outputCurrentLine_.runs.push_back(std::move(run));
    }
}

void GuiTerminalApp::FinalizeOutputLine() {
    outputLines_.push_back(std::move(outputCurrentLine_));
    outputCurrentLine_ = LineBuffer();
}

size_t GuiTerminalApp::OutputLineFromChar(LONG charIndex) const {
    if (outputLineStarts_.empty()) {
        return 0;
    }
    const LONG clamped = std::max<LONG>(0, std::min<LONG>(charIndex, static_cast<LONG>(outputText_.size())));
    auto it = std::upper_bound(outputLineStarts_.begin(), outputLineStarts_.end(), clamped);
    if (it == outputLineStarts_.begin()) {
        return 0;
    }
    return static_cast<size_t>((it - outputLineStarts_.begin()) - 1);
}

bool GuiTerminalApp::GetOutputLineTextSpan(size_t line, LONG* start, LONG* end) const {
    if (start == nullptr || end == nullptr || outputLineStarts_.empty() || line >= outputLineStarts_.size()) {
        return false;
    }

    const LONG lineStart = outputLineStarts_[line];
    LONG lineEnd = line + 1 < outputLineStarts_.size()
        ? outputLineStarts_[line + 1]
        : static_cast<LONG>(outputText_.size());
    while (lineEnd > lineStart) {
        const wchar_t ch = outputText_[static_cast<size_t>(lineEnd - 1)];
        if (ch != L'\r' && ch != L'\n') {
            break;
        }
        --lineEnd;
    }

    *start = lineStart;
    *end = lineEnd;
    return true;
}

POINT GuiTerminalApp::GetOutputTextOrigin() const {
    POINT pt; pt.x = 0; pt.y = 0; return pt;
}

LONG GuiTerminalApp::OutputCharFromPoint(const POINTL& pt) const {
    if (outputText_.empty() || outputLineStarts_.empty()) {
        return 0;
    }

    const int safeCharWidth = std::max<int>(1, charWidth_);
    const int safeLineHeight = std::max<int>(1, lineHeight_);
    const POINT origin = GetOutputTextOrigin();
    LONG line = static_cast<LONG>(std::max<LONG>(0, topLine_)) +
        std::max<LONG>(0, pt.y - origin.y) / safeLineHeight;
    const LONG maxLine = static_cast<LONG>(outputLineStarts_.size() - 1);
    line = std::max<LONG>(0, std::min<LONG>(line, maxLine));

    LONG lineStart = 0;
    LONG lineEnd = 0;
    if (!GetOutputLineTextSpan(static_cast<size_t>(line), &lineStart, &lineEnd)) {
        return static_cast<LONG>(outputText_.size());
    }

    const LONG column = std::max<LONG>(0, (pt.x - origin.x) / safeCharWidth);
    return std::max<LONG>(0, std::min<LONG>(lineStart + column, lineEnd));
}

void GuiTerminalApp::UpdateOutputScrollInfo() {
    if (outputWnd_ == nullptr) {
        return;
    }
    RECT rc = {};
    GetClientRect(outputWnd_, &rc);
    const int height = std::max<int>(1, static_cast<int>(rc.bottom - rc.top));
    visibleRows_ = std::max<int>(1, height / std::max<int>(1, lineHeight_));
    const LONG lineCount = static_cast<LONG>(outputLineStarts_.size());

    SCROLLINFO vsi = {};
    vsi.cbSize = sizeof(vsi);
    vsi.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    vsi.nMin = 0;
    vsi.nMax = std::max<LONG>(0, lineCount - 1);
    vsi.nPage = static_cast<UINT>(visibleRows_);
    vsi.nPos = std::max<LONG>(0, std::min<LONG>(topLine_, std::max<LONG>(0, lineCount - 1)));
    SetScrollInfo(outputWnd_, SB_VERT, &vsi, TRUE);

}

void GuiTerminalApp::RedirectStreams() {
    oldCoutBuf_ = std::wcout.rdbuf(sink_);
    oldCerrBuf_ = std::wcerr.rdbuf(sink_);
}

void GuiTerminalApp::RestoreStreams() {
    if (oldCoutBuf_ != nullptr) {
        std::wcout.rdbuf(oldCoutBuf_);
        oldCoutBuf_ = nullptr;
    }
    if (oldCerrBuf_ != nullptr) {
        std::wcerr.rdbuf(oldCerrBuf_);
        oldCerrBuf_ = nullptr;
    }
}

void GuiTerminalApp::StartWorker() {
    stopWorker_ = false;
    worker_ = std::thread(&GuiTerminalApp::WorkerLoop, this);
}

void GuiTerminalApp::StopWorker() {
    {
        std::lock_guard<std::mutex> lock(commandMutex_);
        stopWorker_ = true;
    }
    commandCv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void GuiTerminalApp::QueueOutput(const std::wstring& text) {
    {
        std::lock_guard<std::mutex> lock(outputMutex_);
        pendingOutputs_.push_back(text);
    }
    if (hwnd_ != nullptr && IsWindow(hwnd_)) {
        PostMessageW(hwnd_, WM_APP_OUTPUT_READY, 0, 0);
    }
}

std::vector<std::wstring> GuiTerminalApp::DrainPendingOutputs() {
    std::vector<std::wstring> out;
    std::lock_guard<std::mutex> lock(outputMutex_);
    while (!pendingOutputs_.empty()) {
        out.push_back(std::move(pendingOutputs_.front()));
        pendingOutputs_.pop_front();
    }
    return out;
}

void GuiTerminalApp::SetOutputSelectionEnd() {
    hasOutputSelectionDirty_ = false;
}

void GuiTerminalApp::ScrollOutputToEnd() {
    const LONG lineCount = static_cast<LONG>(outputLineStarts_.size());
    topLine_ = std::max<LONG>(0, lineCount - visibleRows_);
    UpdateOutputScrollInfo();
    InvalidateRect(outputWnd_, nullptr, FALSE);
    UpdateWindow(outputWnd_);
}

void GuiTerminalApp::InvalidateOutputRange(LONG start, LONG end) {
    if (outputWnd_ == nullptr || !IsWindow(outputWnd_) || end <= start) {
        return;
    }

    RECT rc = {};
    if (!GetOutputRangeBounds(start, end, &rc)) {
        RECT client = {};
        GetClientRect(outputWnd_, &client);
        const int strip = std::max<int>(lineHeight_ * 3, 1);
        rc = client;
        rc.top = std::max<LONG>(client.top, client.bottom - strip);
    }
    InvalidateRect(outputWnd_, &rc, FALSE);
}

bool GuiTerminalApp::GetOutputRangeBounds(LONG rangeStart, LONG rangeEnd, RECT* bounds) {
    if (bounds == nullptr || outputWnd_ == nullptr || !IsWindow(outputWnd_)) {
        return false;
    }

    const LONG textLength = static_cast<LONG>(outputText_.size());
    rangeStart = std::max<LONG>(0, std::min<LONG>(rangeStart, textLength));
    rangeEnd = std::max<LONG>(0, std::min<LONG>(rangeEnd, textLength));
    if (rangeEnd <= rangeStart || outputLineStarts_.empty()) {
        return false;
    }

    RECT total = {LONG_MAX, LONG_MAX, LONG_MIN, LONG_MIN};
    const size_t firstLine = OutputLineFromChar(rangeStart);
    const size_t lastLine = OutputLineFromChar(rangeEnd - 1);
    const int rowHeight = std::max<int>(1, lineHeight_);
    const int colWidth = std::max<int>(1, charWidth_);
    RECT client = {};
    GetClientRect(outputWnd_, &client);
    const POINT origin = GetOutputTextOrigin();

    for (size_t line = firstLine; line <= lastLine; ++line) {
        LONG lineStart = 0;
        LONG lineEnd = 0;
        if (!GetOutputLineTextSpan(line, &lineStart, &lineEnd)) {
            continue;
        }
        const LONG start = std::max<LONG>(rangeStart, lineStart);
        const LONG end = std::min<LONG>(rangeEnd, lineEnd);
        if (end <= start) {
            continue;
        }

        const LONG visualLine = static_cast<LONG>(line) - static_cast<LONG>(topLine_);
        const LONG row = visualLine;
        const LONG startX = static_cast<LONG>(origin.x + (start - lineStart) * colWidth);
        const LONG endX = static_cast<LONG>(origin.x + (end - lineStart) * colWidth);
        const LONG y = origin.y + row * rowHeight;
        if (y >= client.bottom || y + rowHeight <= client.top) {
            continue;
        }

        total.left = std::min<LONG>(total.left, std::max<LONG>(client.left, startX));
        total.top = std::min<LONG>(total.top, std::max<LONG>(client.top, y));
        total.right = std::max<LONG>(total.right, std::min<LONG>(client.right, std::max<LONG>(endX, startX + colWidth)));
        total.bottom = std::max<LONG>(total.bottom, std::min<LONG>(client.bottom, y + rowHeight));
    }

    if (total.left == LONG_MAX || total.right <= total.left || total.bottom <= total.top) {
        return false;
    }

    InflateRect(&total, 2, 1);
    *bounds = total;
    return true;
}

bool GuiTerminalApp::GetOutputSelectionBounds(RECT* bounds) {
    if (outputWnd_ == nullptr || !IsWindow(outputWnd_)) {
        return false;
    }

    CHARRANGE sel = {};
    if (hasOutputSelection_) {
        sel.cpMin = outputSelectionStart_;
        sel.cpMax = outputSelectionEnd_;
    } else {
        SendMessageW(outputWnd_, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
    }
    if (sel.cpMin < 0 || sel.cpMax <= sel.cpMin) {
        return false;
    }
    return GetOutputRangeBounds(sel.cpMin, sel.cpMax, bounds);
}

void GuiTerminalApp::PaintOutputContentToDc(HDC targetDc, const RECT& clip) {
    if (targetDc == nullptr || outputWnd_ == nullptr || !IsWindow(outputWnd_)) {
        return;
    }

    HFONT oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = static_cast<HFONT>(SelectObject(targetDc, font_));
    }
    const int oldBkMode = SetBkMode(targetDc, TRANSPARENT);

    const int rowHeight = std::max<int>(1, lineHeight_);
    const int colWidth = std::max<int>(1, charWidth_);
    const POINT origin = GetOutputTextOrigin();
    const LONG lineCount = static_cast<LONG>(outputLineStarts_.size());
    const LONG startLine = std::max<LONG>(0, topLine_);
    const LONG endLine = std::min<LONG>(lineCount, startLine + visibleRows_ + 1);

    RECT client = {};
    GetClientRect(outputWnd_, &client);

    for (LONG line = startLine; line < endLine; ++line) {
        const LONG row = line - startLine;
        const LONG y = origin.y + row * rowHeight;
        if (y >= clip.bottom || y + rowHeight <= clip.top) {
            continue;
        }

        const LineBuffer* buffer = nullptr;
        if (line < static_cast<LONG>(outputLines_.size())) {
            buffer = &outputLines_[static_cast<size_t>(line)];
        } else {
            buffer = &outputCurrentLine_;
        }

        LONG x = origin.x;
        if (buffer != nullptr) {
            for (size_t runIdx = 0; runIdx < buffer->runs.size(); ++runIdx) {
                const StyledRun& run = buffer->runs[runIdx];
                if (run.text.empty()) {
                    continue;
                }

                const LONG width = static_cast<LONG>(run.text.size()) * colWidth;
                if (run.style.hasBg) {
                    RECT fill = {x, y, x + width, y + rowHeight};
                    HBRUSH brush = CreateSolidBrush(run.style.bg);
                    FillRect(targetDc, &fill, brush);
                    DeleteObject(brush);
                }

                SetTextColor(targetDc, run.style.fg);
                RECT textRect = {x, y, x + width, y + rowHeight};
                DrawTextW(targetDc, run.text.c_str(), static_cast<int>(run.text.size()), &textRect,
                          DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP);
                x += width;
            }
        }
    }

    SetBkMode(targetDc, oldBkMode);
    if (oldFont != nullptr) {
        SelectObject(targetDc, oldFont);
    }
}

void GuiTerminalApp::PaintOutputSelectionRangeToDc(HDC targetDc, const RECT& clip, LONG rangeStart, LONG rangeEnd) {
    if (targetDc == nullptr || outputWnd_ == nullptr || !IsWindow(outputWnd_) || rangeEnd <= rangeStart) {
        return;
    }
    const LONG textLength = static_cast<LONG>(outputText_.size());
    rangeStart = std::max<LONG>(0, std::min<LONG>(rangeStart, textLength));
    rangeEnd = std::max<LONG>(0, std::min<LONG>(rangeEnd, textLength));
    if (rangeEnd <= rangeStart) {
        return;
    }

    HFONT oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = static_cast<HFONT>(SelectObject(targetDc, font_));
    }
    const int oldBkMode = SetBkMode(targetDc, OPAQUE);
    const COLORREF oldBkColor = SetBkColor(targetDc, RGB(186, 186, 186));
    const COLORREF oldTextColor = SetTextColor(targetDc, RGB(0, 0, 0));

    const size_t firstLine = OutputLineFromChar(rangeStart);
    const size_t lastLine = OutputLineFromChar(rangeEnd - 1);
    const int rowHeight = std::max<int>(1, lineHeight_);
    const int colWidth = std::max<int>(1, charWidth_);
    const POINT origin = GetOutputTextOrigin();

    for (size_t line = firstLine; line <= lastLine; ++line) {
        LONG lineStart = 0;
        LONG lineEnd = 0;
        if (!GetOutputLineTextSpan(line, &lineStart, &lineEnd)) {
            continue;
        }
        const LONG start = std::max<LONG>(rangeStart, lineStart);
        const LONG end = std::min<LONG>(rangeEnd, lineEnd);
        if (end <= start) {
            continue;
        }

        const LONG visualLine = static_cast<LONG>(line) - static_cast<LONG>(topLine_);
        const LONG row = visualLine;
        const LONG startX = static_cast<LONG>(origin.x + (start - lineStart) * colWidth);
        const LONG endX = static_cast<LONG>(origin.x + (end - lineStart) * colWidth);
        const LONG y = origin.y + row * rowHeight;

        RECT selectionRect = {
            static_cast<LONG>(startX - clip.left),
            static_cast<LONG>(y - clip.top),
            static_cast<LONG>(std::max<LONG>(endX, startX + colWidth) - clip.left),
            static_cast<LONG>(y + rowHeight - clip.top)
        };
        HBRUSH selectionBrush = CreateSolidBrush(RGB(186, 186, 186));
        FillRect(targetDc, &selectionRect, selectionBrush);
        DeleteObject(selectionBrush);

        if (end > start && static_cast<size_t>(end) <= outputText_.size()) {
            std::wstring text = outputText_.substr(static_cast<size_t>(start), static_cast<size_t>(end - start));
            RECT textRect = {
                static_cast<LONG>(startX - clip.left),
                static_cast<LONG>(y - clip.top),
                static_cast<LONG>(endX - clip.left + colWidth),
                static_cast<LONG>(y + rowHeight - clip.top)
            };
            DrawTextW(targetDc, text.c_str(), static_cast<int>(text.size()), &textRect,
                      DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP);
        }
    }

    SetTextColor(targetDc, oldTextColor);
    SetBkColor(targetDc, oldBkColor);
    SetBkMode(targetDc, oldBkMode);
    if (oldFont != nullptr) {
        SelectObject(targetDc, oldFont);
    }
}

void GuiTerminalApp::PaintOutputSelectionRange(LONG rangeStart, LONG rangeEnd) {
    if (outputWnd_ == nullptr || !IsWindow(outputWnd_) || rangeEnd <= rangeStart) {
        return;
    }
    const LONG textLength = static_cast<LONG>(outputText_.size());
    rangeStart = std::max<LONG>(0, std::min<LONG>(rangeStart, textLength));
    rangeEnd = std::max<LONG>(0, std::min<LONG>(rangeEnd, textLength));
    if (rangeEnd <= rangeStart) {
        return;
    }
    HDC dc = GetDC(outputWnd_);
    if (dc == nullptr) {
        return;
    }

    RECT clip = {};
    if (!GetOutputRangeBounds(rangeStart, rangeEnd, &clip)) {
        ReleaseDC(outputWnd_, dc);
        return;
    }
    const int clipWidth = std::max<int>(1, clip.right - clip.left);
    const int clipHeight = std::max<int>(1, clip.bottom - clip.top);

    HDC memDc = CreateCompatibleDC(dc);
    HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, clipWidth, clipHeight) : nullptr;
    if (memDc == nullptr || memBitmap == nullptr) {
        if (memBitmap != nullptr) {
            DeleteObject(memBitmap);
        }
        if (memDc != nullptr) {
            DeleteDC(memDc);
        }
        ReleaseDC(outputWnd_, dc);
        return;
    }
    HGDIOBJ oldBitmap = SelectObject(memDc, memBitmap);
    BitBlt(memDc, 0, 0, clipWidth, clipHeight, dc, clip.left, clip.top, SRCCOPY);
    PaintOutputSelectionRangeToDc(memDc, clip, rangeStart, rangeEnd);

    BitBlt(dc, clip.left, clip.top, clipWidth, clipHeight, memDc, 0, 0, SRCCOPY);

    SelectObject(memDc, oldBitmap);
    DeleteObject(memBitmap);
    DeleteDC(memDc);
    ReleaseDC(outputWnd_, dc);
}

void GuiTerminalApp::PaintOutputSelectionToDc(HDC targetDc, const RECT& clip) {
    CHARRANGE sel = {};
    if (hasOutputSelection_) {
        sel.cpMin = outputSelectionStart_;
        sel.cpMax = outputSelectionEnd_;
    } else if (outputWnd_ != nullptr) {
        SendMessageW(outputWnd_, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
    }
    if (sel.cpMax <= sel.cpMin) {
        hasOutputSelectionDirty_ = false;
        hasOutputPaintedSelection_ = false;
        return;
    }

    PaintOutputSelectionRangeToDc(targetDc, clip, sel.cpMin, sel.cpMax);
    outputSelectionDirty_ = clip;
    hasOutputSelectionDirty_ = true;
    outputPaintedSelectionStart_ = sel.cpMin;
    outputPaintedSelectionEnd_ = sel.cpMax;
    hasOutputPaintedSelection_ = true;
}

void GuiTerminalApp::PaintOutputSelection() {
    CHARRANGE sel = {};
    if (hasOutputSelection_) {
        sel.cpMin = outputSelectionStart_;
        sel.cpMax = outputSelectionEnd_;
    } else if (outputWnd_ != nullptr) {
        SendMessageW(outputWnd_, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
    }
    if (sel.cpMax <= sel.cpMin) {
        hasOutputSelectionDirty_ = false;
        hasOutputPaintedSelection_ = false;
        return;
    }

    RECT clip = {};
    if (GetOutputRangeBounds(sel.cpMin, sel.cpMax, &clip)) {
        outputSelectionDirty_ = clip;
        hasOutputSelectionDirty_ = true;
    }
    PaintOutputSelectionRange(sel.cpMin, sel.cpMax);
    outputPaintedSelectionStart_ = sel.cpMin;
    outputPaintedSelectionEnd_ = sel.cpMax;
    hasOutputPaintedSelection_ = true;
}

void GuiTerminalApp::RefreshOutputSelection() {
    if (outputWnd_ == nullptr || !IsWindow(outputWnd_)) {
        return;
    }

    const bool hasNew = hasOutputSelection_ && outputSelectionEnd_ > outputSelectionStart_;
    const LONG newStart = hasNew ? outputSelectionStart_ : 0;
    const LONG newEnd = hasNew ? outputSelectionEnd_ : 0;
    const bool hasOld = hasOutputPaintedSelection_ && outputPaintedSelectionEnd_ > outputPaintedSelectionStart_;
    const LONG oldStart = hasOld ? outputPaintedSelectionStart_ : 0;
    const LONG oldEnd = hasOld ? outputPaintedSelectionEnd_ : 0;

    auto invalidateRange = [&](LONG start, LONG end) {
        RECT rc = {};
        if (end > start && GetOutputRangeBounds(start, end, &rc)) {
            InvalidateRect(outputWnd_, &rc, FALSE);
        }
    };
    auto paintRange = [&](LONG start, LONG end) {
        if (end > start) {
            PaintOutputSelectionRange(start, end);
        }
    };

    if (hasOld) {
        invalidateRange(oldStart, std::min<LONG>(oldEnd, newStart));
        invalidateRange(std::max<LONG>(oldStart, newEnd), oldEnd);
    }
    UpdateWindow(outputWnd_);

    if (hasNew) {
        if (hasOld) {
            paintRange(newStart, std::min<LONG>(newEnd, oldStart));
            paintRange(std::max<LONG>(newStart, oldEnd), newEnd);
        } else {
            paintRange(newStart, newEnd);
        }

        RECT newDirty = {};
        if (GetOutputRangeBounds(newStart, newEnd, &newDirty)) {
            outputSelectionDirty_ = newDirty;
            hasOutputSelectionDirty_ = true;
        }
        outputPaintedSelectionStart_ = newStart;
        outputPaintedSelectionEnd_ = newEnd;
        hasOutputPaintedSelection_ = true;
    } else {
        hasOutputSelectionDirty_ = false;
        hasOutputPaintedSelection_ = false;
    }
}

void GuiTerminalApp::ClearOutputSelection() {
    if (outputWnd_ == nullptr || !IsWindow(outputWnd_)) {
        return;
    }

    LONG caret = outputSelectionEnd_;
    if (caret < 0) {
        caret = 0;
    }

    hasOutputSelection_ = false;
    RefreshOutputSelection();
}

void GuiTerminalApp::QueueOutputSelectionPaint() {
    if (hwnd_ == nullptr || !IsWindow(hwnd_) || outputSelectionPaintPending_) {
        return;
    }
    outputSelectionPaintPending_ = true;
    PostMessageW(hwnd_, WM_APP_PAINT_OUTPUT_SELECTION, 0, 0);
}

void GuiTerminalApp::BeginOutputBatch() {
    if (outputWnd_ == nullptr || !IsWindow(outputWnd_) || outputBatching_) {
        return;
    }
    outputBatching_ = true;
}

void GuiTerminalApp::EndOutputBatch(bool scrollToEnd) {
    if (outputWnd_ == nullptr || !IsWindow(outputWnd_) || !outputBatching_) {
        return;
    }
    outputBatching_ = false;
    if (scrollToEnd) {
        ScrollOutputToEnd();
    }
    InvalidateRect(outputWnd_, nullptr, FALSE);
    UpdateWindow(outputWnd_);
}

void GuiTerminalApp::AppendStyledRun(const std::wstring& text, const TextStyle& style) {
    if (outputWnd_ == nullptr || text.empty()) {
        return;
    }

    AppendOutputTextIndex(text);
    std::wstring segment;
    for (size_t i = 0; i < text.size(); ++i) {
        const wchar_t ch = text[i];
        if (ch == L'\r') {
            continue;
        }
        if (ch == L'\n') {
            AppendOutputRunSegment(segment, style);
            segment.clear();
            FinalizeOutputLine();
            continue;
        }
        segment.push_back(ch);
    }
    AppendOutputRunSegment(segment, style);

    int currentColumns = 0;
    for (size_t runIdx = 0; runIdx < outputCurrentLine_.runs.size(); ++runIdx) {
        const StyledRun& run = outputCurrentLine_.runs[runIdx];
        currentColumns += static_cast<int>(run.text.size());
    }
    if (!outputBatching_) {
        if (followTail_) {
            ScrollOutputToEnd();
        } else {
            UpdateOutputScrollInfo();
            InvalidateRect(outputWnd_, nullptr, FALSE);
        }
    }
}

void GuiTerminalApp::AppendPlainLine(const std::wstring& text, COLORREF fg) {
    TextStyle style;
    style.fg = fg;
    AppendStyledRun(text + L"\r\n", style);
}

void GuiTerminalApp::AppendText(const std::wstring& text) {
    if (outputWnd_ == nullptr || text.empty()) {
        return;
    }

    TextStyle style;
    TextStyle lineBgStyle;
    bool lineHasBg = false;
    size_t lineVisibleColumns = 0;
    std::wstring plain;
    plain.reserve(text.size());

    const auto getTargetColumns = [&]() -> size_t {
        RECT rc = {};
        if (GetClientRect(outputWnd_, &rc)) {
            const int width = std::max<int>(1, static_cast<int>(rc.right - rc.left));
            return static_cast<size_t>(std::max<int>(1, width / std::max<int>(1, charWidth_)));
        }
        return static_cast<size_t>(120);
    };

    auto flushPlain = [&]() {
        if (!plain.empty()) {
            AppendStyledRun(plain, style);
            lineVisibleColumns += plain.size();
            plain.clear();
        }
    };

    auto fillBackgroundToEdge = [&]() {
        if (!lineHasBg) {
            return;
        }
        const size_t targetColumns = getTargetColumns();
        if (lineVisibleColumns >= targetColumns) {
            return;
        }
        AppendStyledRun(std::wstring(targetColumns - lineVisibleColumns, L' '), lineBgStyle);
        lineVisibleColumns = targetColumns;
    };

    for (size_t i = 0; i < text.size(); ++i) {
        const wchar_t ch = text[i];
        if (ch == L'\r') {
            continue;
        }
        if (ch == L'\n') {
            flushPlain();
            fillBackgroundToEdge();
            AppendStyledRun(L"\r\n", style);
            style = TextStyle();
            lineBgStyle = TextStyle();
            lineHasBg = false;
            lineVisibleColumns = 0;
            continue;
        }
        if (ch == L'\x1b' && i + 1 < text.size() && text[i + 1] == L'[') {
            flushPlain();
            size_t j = i + 2;
            while (j < text.size() && text[j] != L'm') {
                ++j;
            }
            if (j < text.size()) {
                std::wstring args = text.substr(i + 2, j - (i + 2));
                std::vector<int> params;
                std::wstring token;
                for (size_t k = 0; k <= args.size(); ++k) {
                    const wchar_t a = k < args.size() ? args[k] : L';';
                    if (a == L';') {
                        params.push_back(token.empty() ? 0 : _wtoi(token.c_str()));
                        token.clear();
                    } else {
                        token.push_back(a);
                    }
                }
                if (params.empty()) {
                    params.push_back(0);
                }
                for (size_t k = 0; k < params.size(); ++k) {
                    const int p = params[k];
                    if (p == 0) {
                        style = TextStyle();
                    } else if (p == 39) {
                        style.fg = kForeground;
                    } else if (p == 49) {
                        style.bg = kBackground;
                        style.hasBg = false;
                    } else if ((p >= 30 && p <= 37) || p == 90) {
                        static const COLORREF colors[] = {
                            RGB(0, 0, 0), RGB(205, 49, 49), RGB(13, 188, 121), RGB(229, 229, 16),
                            RGB(36, 114, 200), RGB(188, 63, 188), RGB(17, 168, 205), RGB(229, 229, 229)
                        };
                        const int idx = (p == 90) ? 7 : (p - 30);
                        if (idx >= 0 && idx < 8) {
                            style.fg = colors[idx];
                        }
                    } else if ((p >= 40 && p <= 47) || (p >= 100 && p <= 107)) {
                        static const COLORREF colors[] = {
                            RGB(0, 0, 0), RGB(205, 49, 49), RGB(13, 188, 121), RGB(229, 229, 16),
                            RGB(36, 114, 200), RGB(188, 63, 188), RGB(17, 168, 205), RGB(229, 229, 229)
                        };
                        const int idx = (p >= 100) ? (p - 100) : (p - 40);
                        if (idx >= 0 && idx < 8) {
                            style.bg = colors[idx];
                            style.hasBg = true;
                        }
                    } else if ((p == 38 || p == 48) && k + 4 < params.size() && params[k + 1] == 2) {
                        const COLORREF c = RGB(
                            std::clamp(params[k + 2], 0, 255),
                            std::clamp(params[k + 3], 0, 255),
                            std::clamp(params[k + 4], 0, 255));
                        if (p == 38) {
                            style.fg = c;
                        } else {
                            style.bg = c;
                            style.hasBg = true;
                            lineBgStyle = style;
                            lineHasBg = true;
                        }
                        k += 4;
                    }
                }
                i = j;
                continue;
            }
        }
        plain.push_back(ch);
    }

    flushPlain();
    fillBackgroundToEdge();
    if (!outputBatching_) {
        ScrollOutputToEnd();
    }
}

void GuiTerminalApp::AppendPromptedCommand(const std::wstring& command) {
    TextStyle prompt;
    prompt.fg = kPromptColor;
    AppendStyledRun(L"z0dbg> ", prompt);
    TextStyle body;
    body.fg = kForeground;
    AppendStyledRun(command + L"\r\n", body);
}

void GuiTerminalApp::AppendHistory() {
    if (history_.empty()) {
        AppendPlainLine(L"(history is empty)", kGrayColor);
        return;
    }
    for (size_t i = 0; i < history_.size(); ++i) {
        std::wstringstream ss;
        ss << (i + 1) << L"  " << history_[i];
        AppendPlainLine(ss.str(), kForeground);
    }
}

void GuiTerminalApp::HandleOutputReady() {
    const std::vector<std::wstring> chunks = DrainPendingOutputs();
    BeginOutputBatch();
    for (size_t i = 0; i < chunks.size(); ++i) {
        AppendText(chunks[i]);
    }
    EndOutputBatch(true);
}

void GuiTerminalApp::AddHistory(const std::wstring& command) {
    if (command.empty()) {
        return;
    }
    if (!history_.empty() && history_.back() == command) {
        historyIndex_ = static_cast<int>(history_.size());
        return;
    }
    history_.push_back(command);
    if (history_.size() > kHistoryLimit) {
        history_.erase(history_.begin());
    }
    historyIndex_ = static_cast<int>(history_.size());
    historyActive_ = false;
    historyDraft_.clear();
}

void GuiTerminalApp::MoveHistory(int direction) {
    if (inputWnd_ == nullptr || history_.empty()) {
        return;
    }

    const int total = static_cast<int>(history_.size());
    if (!historyActive_) {
        historyDraft_ = ReadInputText();
        historyIndex_ = total;
        historyActive_ = true;
    }

    historyIndex_ = std::clamp(historyIndex_ + direction, 0, total);
    if (historyIndex_ == total) {
        UpdateInputText(historyDraft_);
    } else {
        UpdateInputText(history_[static_cast<size_t>(historyIndex_)]);
    }
}

void GuiTerminalApp::ClearInputHistoryState() {
    historyActive_ = false;
    historyDraft_.clear();
    historyIndex_ = static_cast<int>(history_.size());
}

void GuiTerminalApp::UpdateInputText(const std::wstring& text) {
    if (inputWnd_ == nullptr) {
        return;
    }
    SetWindowTextW(inputWnd_, text.c_str());
    SendMessageW(inputWnd_, EM_SETSEL, static_cast<WPARAM>(text.size()), static_cast<LPARAM>(text.size()));
}

void GuiTerminalApp::RedrawCommandLineArea() {
    if (hwnd_ == nullptr || inputWnd_ == nullptr || !IsWindow(hwnd_) || !IsWindow(inputWnd_)) {
        return;
    }

    RECT input = {};
    GetWindowRect(inputWnd_, &input);
    MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&input), 2);

    const int promptWidth = std::max<int>(kPromptWidth, kPromptTextWidth);
    RECT commandLine = {
        kPadding,
        input.top,
        input.left + (input.right - input.left),
        input.bottom
    };
    commandLine.right = std::max<LONG>(commandLine.right, kPadding + promptWidth + (input.right - input.left));
    InflateRect(&commandLine, 2, 2);

    HDC dc = GetDC(hwnd_);
    if (dc != nullptr) {
        HBRUSH brush = CreateSolidBrush(kBackground);
        FillRect(dc, &commandLine, brush);
        DeleteObject(brush);
        PaintCommandLinePrompt(dc);
        ReleaseDC(hwnd_, dc);
    }

    RedrawWindow(inputWnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW);
}

std::wstring GuiTerminalApp::ReadInputText() const {
    if (inputWnd_ == nullptr) {
        return L"";
    }
    const int len = GetWindowTextLengthW(inputWnd_);
    if (len <= 0) {
        return L"";
    }
    std::wstring text(static_cast<size_t>(len) + 1, L'\0');
    GetWindowTextW(inputWnd_, &text[0], len + 1);
    text.resize(static_cast<size_t>(len));
    return text;
}

bool GuiTerminalApp::CopyOutputSelectionToClipboard() {
    if (outputWnd_ == nullptr || !IsWindow(outputWnd_)) {
        return false;
    }

    CHARRANGE sel = {};
    if (hasOutputSelection_) {
        sel.cpMin = outputSelectionStart_;
        sel.cpMax = outputSelectionEnd_;
    }

    sel.cpMin = std::max<LONG>(0, std::min<LONG>(sel.cpMin, static_cast<LONG>(outputText_.size())));
    sel.cpMax = std::max<LONG>(0, std::min<LONG>(sel.cpMax, static_cast<LONG>(outputText_.size())));
    if (sel.cpMax <= sel.cpMin) {
        return false;
    }
    std::wstring text = outputText_.substr(static_cast<size_t>(sel.cpMin), static_cast<size_t>(sel.cpMax - sel.cpMin));
    return SetClipboardUnicodeText(hwnd_, text);
}

bool GuiTerminalApp::PasteClipboardToInput() {
    if (inputWnd_ == nullptr || !IsWindow(inputWnd_)) {
        return false;
    }

    std::wstring text;
    if (!GetClipboardUnicodeText(hwnd_, text)) {
        return false;
    }

    SetFocus(inputWnd_);
    SendMessageW(inputWnd_, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(text.c_str()));
    RedrawCommandLineArea();
    return true;
}

void GuiTerminalApp::HandleRightClickPasteOrCopy() {
    HideTitleMenu();
    if (CopyOutputSelectionToClipboard()) {
        ClearOutputSelection();
        if (inputWnd_ != nullptr) {
            SetFocus(inputWnd_);
        }
        return;
    }
    PasteClipboardToInput();
}

void GuiTerminalApp::QueueDisassemblyUi(const std::vector<DisassemblyUiRow>& rows, uint64_t targetAddress, uint64_t regionBase, uint64_t regionEnd) {
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        pendingDisasmRows_ = rows;
        pendingDisasmTarget_ = targetAddress;
        pendingDisasmRegionBase_ = regionBase;
        pendingDisasmRegionEnd_ = regionEnd;
        hasPendingDisasmUi_ = true;
    }
    if (hwnd_ != nullptr) {
        PostMessageW(hwnd_, WM_APP_SHOW_DISASM_UI, 0, 0);
    }
}

void GuiTerminalApp::ShowPendingDisassemblyUi() {
    std::vector<DisassemblyUiRow> rows;
    uint64_t target = 0;
    uint64_t regionBase = 0;
    uint64_t regionEnd = 0;
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        if (!hasPendingDisasmUi_) {
            return;
        }
        rows.swap(pendingDisasmRows_);
        target = pendingDisasmTarget_;
        regionBase = pendingDisasmRegionBase_;
        regionEnd = pendingDisasmRegionEnd_;
        hasPendingDisasmUi_ = false;
    }
    CreateOrUpdateDisassemblyTool(rows, target, regionBase, regionEnd);
}

void GuiTerminalApp::QueueMemoryUi(const std::vector<MemoryUiRow>& rows, uint64_t targetAddress, uint64_t baseAddress, size_t byteCount, size_t unitSize, size_t unitsPerLine) {
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        pendingMemoryRows_ = rows;
        pendingMemoryTarget_ = targetAddress;
        pendingMemoryBase_ = baseAddress;
        pendingMemoryByteCount_ = byteCount;
        pendingMemoryUnitSize_ = unitSize;
        pendingMemoryUnitsPerLine_ = unitsPerLine;
        hasPendingMemoryUi_ = true;
    }
    if (hwnd_ != nullptr) {
        PostMessageW(hwnd_, WM_APP_SHOW_MEMORY_UI, 0, 0);
    }
}

void GuiTerminalApp::ShowPendingMemoryUi() {
    std::vector<MemoryUiRow> rows;
    uint64_t targetAddress = 0;
    uint64_t baseAddress = 0;
    size_t byteCount = 0;
    size_t unitSize = 1;
    size_t unitsPerLine = 16;
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        if (!hasPendingMemoryUi_) {
            return;
        }
        rows.swap(pendingMemoryRows_);
        targetAddress = pendingMemoryTarget_;
        baseAddress = pendingMemoryBase_;
        byteCount = pendingMemoryByteCount_;
        unitSize = pendingMemoryUnitSize_;
        unitsPerLine = pendingMemoryUnitsPerLine_;
        hasPendingMemoryUi_ = false;
    }
    CreateOrUpdateMemoryTool(rows, targetAddress, baseAddress, byteCount, unitSize, unitsPerLine);
}

void GuiTerminalApp::CreateOrUpdateMemoryTool(const std::vector<MemoryUiRow>& rows, uint64_t targetAddress, uint64_t baseAddress, size_t byteCount, size_t unitSize, size_t unitsPerLine) {
    memoryRows_ = rows;
    memoryTarget_ = targetAddress;
    memoryBase_ = baseAddress;
    memoryByteCount_ = byteCount;
    memoryUnitSize_ = unitSize;
    memoryUnitsPerLine_ = unitsPerLine;
    memorySelecting_ = false;
    memorySelectionAnchor_ = -1;
    memorySelectionEnd_ = -1;
    const size_t bytesPerLine = std::max<size_t>(unitSize, unitSize * unitsPerLine);
    memoryTopRow_ = 0;
    if (targetAddress >= baseAddress && bytesPerLine != 0) {
        memoryTopRow_ = static_cast<int>((targetAddress - baseAddress) / bytesPerLine);
    }

    if (memoryToolWnd_ == nullptr || !IsWindow(memoryToolWnd_)) {
        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
        const int width = 940;
        const int height = 560;
        const int x = workArea.left + std::max<int>(0, ((workArea.right - workArea.left) - width) / 2);
        const int y = workArea.top + std::max<int>(0, ((workArea.bottom - workArea.top) - height) / 2);
        memoryToolWnd_ = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            memoryToolClassName_.c_str(),
            L"Memory",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            x, y, width, height,
            nullptr,
            nullptr,
            instance_,
            this);
        if (memoryToolWnd_ == nullptr) {
            QueueOutput(L"Failed to create memory tool window.\r\n");
            return;
        }
        memoryViewWnd_ = CreateWindowExW(
            0,
            memoryViewClassName_.c_str(),
            L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPSIBLINGS,
            0, 0, 0, 0,
            memoryToolWnd_,
            nullptr,
            instance_,
            this);
        if (memoryViewWnd_ == nullptr) {
            DestroyWindow(memoryToolWnd_);
            memoryToolWnd_ = nullptr;
            QueueOutput(L"Failed to create memory view.\r\n");
            return;
        }
        ShowWindow(memoryToolWnd_, SW_SHOW);
    } else {
        ShowWindow(memoryToolWnd_, SW_SHOW);
    }

    std::wstringstream title;
    title << L"Memory - " << FormatHexAddress(baseAddress) << L" : " << FormatHexAddress(targetAddress);
    SetWindowTextW(memoryToolWnd_, title.str().c_str());
    UpdateMemoryMetrics();
    LayoutMemoryTool();
    if (targetAddress >= baseAddress && bytesPerLine != 0) {
        memoryTopRow_ = std::max<int>(0, static_cast<int>((targetAddress - baseAddress) / bytesPerLine) - std::max<int>(1, memoryVisibleRows_ / 3));
    }
    UpdateMemoryScrollInfo();
    InvalidateRect(memoryViewWnd_, nullptr, FALSE);
}

void GuiTerminalApp::LayoutMemoryTool() {
    if (memoryToolWnd_ == nullptr || memoryViewWnd_ == nullptr) {
        return;
    }
    RECT rc = {};
    GetClientRect(memoryToolWnd_, &rc);
    MoveWindow(memoryViewWnd_, 0, 0, std::max<int>(1, rc.right - rc.left), std::max<int>(1, rc.bottom - rc.top), TRUE);
    UpdateMemoryMetrics();
    UpdateMemoryScrollInfo();
}

void GuiTerminalApp::UpdateMemoryMetrics() {
    if (memoryViewWnd_ == nullptr) {
        return;
    }
    HDC dc = GetDC(memoryViewWnd_);
    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(dc, font_);
    }
    TEXTMETRICW tm = {};
    GetTextMetricsW(dc, &tm);
    memoryRowHeight_ = std::max<int>(1, tm.tmHeight - tm.tmInternalLeading);
    memoryCharWidth_ = std::max<int>(1, tm.tmAveCharWidth);
    if (oldFont != nullptr) {
        SelectObject(dc, oldFont);
    }
    ReleaseDC(memoryViewWnd_, dc);

    RECT rc = {};
    GetClientRect(memoryViewWnd_, &rc);
    memoryVisibleRows_ = std::max<int>(1, ((rc.bottom - rc.top) / memoryRowHeight_) - 1);
}

void GuiTerminalApp::UpdateMemoryScrollInfo() {
    if (memoryViewWnd_ == nullptr) {
        return;
    }
    const int maxTop = std::max<int>(0, static_cast<int>(memoryRows_.size()) - memoryVisibleRows_);
    memoryTopRow_ = std::clamp<int>(memoryTopRow_, 0, maxTop);
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = std::max<int>(0, static_cast<int>(memoryRows_.size()) - 1);
    si.nPage = static_cast<UINT>(std::max<int>(1, memoryVisibleRows_));
    si.nPos = memoryTopRow_;
    SetScrollInfo(memoryViewWnd_, SB_VERT, &si, TRUE);
}

int GuiTerminalApp::HitTestMemoryColumnSeparator(int x) const {
    const int padX = 8;
    const int gapX = 1;
    const int addrW = std::max<int>(100, memoryColAddrW_);
    const int hexW = std::max<int>(180, memoryColHexW_);
    const int xAddr = padX;
    const int xHex = xAddr + addrW + gapX;
    const int xAnsi = xHex + hexW + gapX;
    const int hitPad = 6;
    if (std::abs(x - (xHex - gapX)) <= hitPad) {
        return 0;
    }
    if (std::abs(x - (xAnsi - gapX)) <= hitPad) {
        return 1;
    }
    return -1;
}

void GuiTerminalApp::QueueRegisterUi(const std::vector<RegisterUiRow>& rows, const std::wstring& view) {
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        pendingRegisterRows_ = rows;
        pendingRegisterView_ = view;
        hasPendingRegisterUi_ = true;
    }
    if (hwnd_ != nullptr) {
        PostMessageW(hwnd_, WM_APP_SHOW_REGISTER_UI, 0, 0);
    }
}

void GuiTerminalApp::ShowPendingRegisterUi() {
    std::vector<RegisterUiRow> rows;
    std::wstring view;
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        if (!hasPendingRegisterUi_) {
            return;
        }
        rows.swap(pendingRegisterRows_);
        view.swap(pendingRegisterView_);
        hasPendingRegisterUi_ = false;
    }
    CreateOrUpdateRegisterTool(rows, view);
}

void GuiTerminalApp::CreateOrUpdateRegisterTool(const std::vector<RegisterUiRow>& rows, const std::wstring& view) {
    registerRows_ = rows;
    registerViewName_ = view;
    registerTopRow_ = 0;
    registerSelecting_ = false;
    registerSelectionAnchor_ = -1;
    registerSelectionEnd_ = -1;

    if (registerToolWnd_ == nullptr || !IsWindow(registerToolWnd_)) {
        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
        const int width = 760;
        const int height = 520;
        const int x = workArea.left + std::max<int>(0, ((workArea.right - workArea.left) - width) / 2);
        const int y = workArea.top + std::max<int>(0, ((workArea.bottom - workArea.top) - height) / 2);
        registerToolWnd_ = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            registerToolClassName_.c_str(),
            L"Registers",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            x, y, width, height,
            nullptr,
            nullptr,
            instance_,
            this);
        if (registerToolWnd_ == nullptr) {
            QueueOutput(L"Failed to create register tool window.\r\n");
            return;
        }
        registerViewWnd_ = CreateWindowExW(
            0,
            registerViewClassName_.c_str(),
            L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPSIBLINGS,
            0, 0, 0, 0,
            registerToolWnd_,
            nullptr,
            instance_,
            this);
        if (registerViewWnd_ == nullptr) {
            DestroyWindow(registerToolWnd_);
            registerToolWnd_ = nullptr;
            QueueOutput(L"Failed to create register view.\r\n");
            return;
        }
        ShowWindow(registerToolWnd_, SW_SHOW);
    } else {
        ShowWindow(registerToolWnd_, SW_SHOW);
    }

    std::wstring title = L"Registers";
    if (!view.empty()) {
        title += L" - " + view;
    }
    const std::wstring imagePath = debugger_.GetDebuggeeImagePath();
    if (!imagePath.empty()) {
        title += L" - " + imagePath;
    }
    SetWindowTextW(registerToolWnd_, title.c_str());
    UpdateRegisterMetrics();
    LayoutRegisterTool();
    UpdateRegisterScrollInfo();
    InvalidateRect(registerViewWnd_, nullptr, FALSE);
}

void GuiTerminalApp::LayoutRegisterTool() {
    if (registerToolWnd_ == nullptr || registerViewWnd_ == nullptr) {
        return;
    }
    RECT rc = {};
    GetClientRect(registerToolWnd_, &rc);
    MoveWindow(registerViewWnd_, 0, 0, std::max<int>(1, rc.right - rc.left), std::max<int>(1, rc.bottom - rc.top), TRUE);
    UpdateRegisterMetrics();
    UpdateRegisterScrollInfo();
}

void GuiTerminalApp::UpdateRegisterMetrics() {
    if (registerViewWnd_ == nullptr) {
        return;
    }
    HDC dc = GetDC(registerViewWnd_);
    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(dc, font_);
    }
    TEXTMETRICW tm = {};
    GetTextMetricsW(dc, &tm);
    registerRowHeight_ = std::max<int>(1, tm.tmHeight - tm.tmInternalLeading);
    registerCharWidth_ = std::max<int>(1, tm.tmAveCharWidth);
    if (oldFont != nullptr) {
        SelectObject(dc, oldFont);
    }
    ReleaseDC(registerViewWnd_, dc);

    RECT rc = {};
    GetClientRect(registerViewWnd_, &rc);
    registerVisibleRows_ = std::max<int>(1, ((rc.bottom - rc.top) / registerRowHeight_) - 1);
}

void GuiTerminalApp::UpdateRegisterScrollInfo() {
    if (registerViewWnd_ == nullptr) {
        return;
    }
    const int maxTop = std::max<int>(0, static_cast<int>(registerRows_.size()) - registerVisibleRows_);
    registerTopRow_ = std::clamp<int>(registerTopRow_, 0, maxTop);
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = std::max<int>(0, static_cast<int>(registerRows_.size()) - 1);
    si.nPage = static_cast<UINT>(std::max<int>(1, registerVisibleRows_));
    si.nPos = registerTopRow_;
    SetScrollInfo(registerViewWnd_, SB_VERT, &si, TRUE);
}

int GuiTerminalApp::HitTestRegisterColumnSeparator(int x) const {
    const int padX = 8;
    const int gapX = 1;
    const int nameW = std::max<int>(90, registerColNameW_);
    const int valueW = std::max<int>(140, registerColValueW_);
    const int xName = padX;
    const int xValue = xName + nameW + gapX;
    const int xInfo = xValue + valueW + gapX;
    const int hitPad = 6;
    if (std::abs(x - (xValue - gapX)) <= hitPad) {
        return 0;
    }
    if (std::abs(x - (xInfo - gapX)) <= hitPad) {
        return 1;
    }
    return -1;
}

void GuiTerminalApp::PaintRegisterView(HDC targetDc, const RECT& clip) {
    RECT rc = {};
    GetClientRect(registerViewWnd_, &rc);
    HBRUSH bg = CreateSolidBrush(RGB(18, 18, 18));
    FillRect(targetDc, &rc, bg);
    DeleteObject(bg);

    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(targetDc, font_);
    }
    SetBkMode(targetDc, TRANSPARENT);

    const int padX = 8;
    const int gapX = 1;
    const int textInsetX = 4;
    const int headerH = registerRowHeight_;
    const int nameW = std::max<int>(90, registerColNameW_);
    const int valueW = std::max<int>(140, registerColValueW_);
    const int xName = padX;
    const int xValue = xName + nameW + gapX;
    const int xInfo = xValue + valueW + gapX;
    const int infoW = std::max<int>(80, rc.right - xInfo - padX);
    const COLORREF dataBg = RGB(255, 251, 241);

    auto drawCell = [&](const std::wstring& text, int x, int y, int w, COLORREF color) {
        RECT r = {x + textInsetX, y, x + w, y + registerRowHeight_};
        if (r.bottom <= clip.top || r.top >= clip.bottom) {
            return;
        }
        SetTextColor(targetDc, color);
        DrawTextW(targetDc, text.c_str(), static_cast<int>(text.size()), &r, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    };

    RECT header = {0, 0, rc.right, headerH};
    HBRUSH headerBrush = CreateSolidBrush(RGB(34, 34, 34));
    FillRect(targetDc, &header, headerBrush);
    DeleteObject(headerBrush);
    drawCell(L"Register", xName, 0, nameW, RGB(210, 210, 210));
    drawCell(L"Value", xValue, 0, valueW, RGB(210, 210, 210));
    drawCell(L"Info", xInfo, 0, infoW, RGB(210, 210, 210));

    const int maxRows = static_cast<int>(registerRows_.size());
    const int last = std::min<int>(maxRows, registerTopRow_ + registerVisibleRows_ + 1);
    const int selStart = (registerSelectionAnchor_ >= 0 && registerSelectionEnd_ >= 0)
        ? std::min<int>(registerSelectionAnchor_, registerSelectionEnd_)
        : -1;
    const int selEnd = (registerSelectionAnchor_ >= 0 && registerSelectionEnd_ >= 0)
        ? std::max<int>(registerSelectionAnchor_, registerSelectionEnd_)
        : -1;
    for (int rowIndex = registerTopRow_; rowIndex < last; ++rowIndex) {
        const int y = headerH + (rowIndex - registerTopRow_) * registerRowHeight_;
        RECT rowBgRc = {0, y, rc.right, y + registerRowHeight_};
        HBRUSH rowBrush = CreateSolidBrush(dataBg);
        FillRect(targetDc, &rowBgRc, rowBrush);
        DeleteObject(rowBrush);
        const RegisterUiRow& row = registerRows_[rowIndex];
        drawCell(row.name, xName, y, nameW, RGB(20, 95, 175));
        drawCell(row.value, xValue, y, valueW, RGB(0, 0, 0));
        drawCell(row.info, xInfo, y, infoW, RGB(0, 0, 0));
    }
    if (selStart >= 0) {
        HBRUSH selectionBrush = CreateSolidBrush(RGB(186, 186, 186));
        for (int rowIndex = std::max<int>(registerTopRow_, selStart); rowIndex <= selEnd && rowIndex < last; ++rowIndex) {
            const int y = headerH + (rowIndex - registerTopRow_) * registerRowHeight_;
            RECT lineRc = {0, y, rc.right, y + registerRowHeight_};
            FillRect(targetDc, &lineRc, selectionBrush);
            const RegisterUiRow& row = registerRows_[rowIndex];
            drawCell(row.name, xName, y, nameW, RGB(0, 0, 0));
            drawCell(row.value, xValue, y, valueW, RGB(0, 0, 0));
            drawCell(row.info, xInfo, y, infoW, RGB(0, 0, 0));
        }
        DeleteObject(selectionBrush);
    }

    HBRUSH sepBrush = CreateSolidBrush(RGB(86, 86, 86));
    RECT sep1 = {xValue - gapX, 0, xValue - gapX + 1, rc.bottom};
    RECT sep2 = {xInfo - gapX, 0, xInfo - gapX + 1, rc.bottom};
    FillRect(targetDc, &sep1, sepBrush);
    FillRect(targetDc, &sep2, sepBrush);
    DeleteObject(sepBrush);

    if (oldFont != nullptr) {
        SelectObject(targetDc, oldFont);
    }
}

void GuiTerminalApp::QueueStackUi(const std::vector<StackUiRow>& rows, const std::wstring& view, uint64_t stackPointer) {
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        pendingStackRows_ = rows;
        pendingStackView_ = view;
        pendingStackPointer_ = stackPointer;
        hasPendingStackUi_ = true;
    }
    if (hwnd_ != nullptr) {
        PostMessageW(hwnd_, WM_APP_SHOW_STACK_UI, 0, 0);
    }
}

void GuiTerminalApp::ShowPendingStackUi() {
    std::vector<StackUiRow> rows;
    std::wstring view;
    uint64_t stackPointer = 0;
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        if (!hasPendingStackUi_) {
            return;
        }
        rows.swap(pendingStackRows_);
        view.swap(pendingStackView_);
        stackPointer = pendingStackPointer_;
        hasPendingStackUi_ = false;
    }
    CreateOrUpdateStackTool(rows, view, stackPointer);
}

void GuiTerminalApp::QueuePseudoCUi(const std::wstring& text, uint64_t address) {
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        pendingPseudoCText_ = text;
        pendingPseudoCAddress_ = address;
        hasPendingPseudoCUi_ = true;
    }
    if (hwnd_ != nullptr) {
        PostMessageW(hwnd_, WM_APP_SHOW_PSEUDOC_UI, 0, 0);
    }
}

void GuiTerminalApp::ShowPendingPseudoCUi() {
    std::wstring text;
    uint64_t address = 0;
    {
        std::lock_guard<std::mutex> lock(disasmUiMutex_);
        if (!hasPendingPseudoCUi_) {
            return;
        }
        text.swap(pendingPseudoCText_);
        address = pendingPseudoCAddress_;
        hasPendingPseudoCUi_ = false;
    }
    CreateOrUpdatePseudoCTool(text, address);
}

void GuiTerminalApp::CreateOrUpdatePseudoCTool(const std::wstring& text, uint64_t address) {
    pseudoCLines_.clear();
    pseudoCAddress_ = address;
    pseudoCTopLine_ = 0;

    std::wstring current;
    for (size_t i = 0; i < text.size(); ++i) {
        const wchar_t ch = text[i];
        if (ch == L'\r') {
            continue;
        }
        if (ch == L'\n') {
            pseudoCLines_.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    if (!current.empty() || pseudoCLines_.empty()) {
        pseudoCLines_.push_back(current);
    }

    if (pseudoCToolWnd_ == nullptr || !IsWindow(pseudoCToolWnd_)) {
        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
        const int width = 920;
        const int height = 620;
        const int x = workArea.left + std::max<int>(0, ((workArea.right - workArea.left) - width) / 2);
        const int y = workArea.top + std::max<int>(0, ((workArea.bottom - workArea.top) - height) / 2);
        pseudoCToolWnd_ = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            pseudoCToolClassName_.c_str(),
            L"Pseudo C",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            x, y, width, height,
            nullptr,
            nullptr,
            instance_,
            this);
        if (pseudoCToolWnd_ == nullptr) {
            QueueOutput(L"Failed to create pseudo C tool window.\r\n");
            return;
        }
        pseudoCViewWnd_ = CreateWindowExW(
            0,
            pseudoCViewClassName_.c_str(),
            L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPSIBLINGS,
            0, 0, 0, 0,
            pseudoCToolWnd_,
            nullptr,
            instance_,
            this);
        if (pseudoCViewWnd_ == nullptr) {
            DestroyWindow(pseudoCToolWnd_);
            pseudoCToolWnd_ = nullptr;
            QueueOutput(L"Failed to create pseudo C view.\r\n");
            return;
        }
        ShowWindow(pseudoCToolWnd_, SW_SHOW);
    } else {
        ShowWindow(pseudoCToolWnd_, SW_SHOW);
    }

    if (pseudoCToolWnd_ != nullptr) {
        std::wstringstream title;
        title << L"Pseudo C - 0x" << std::uppercase << std::hex << address;
        SetWindowTextW(pseudoCToolWnd_, title.str().c_str());
    }

    UpdatePseudoCMetrics();
    LayoutPseudoCTool();
    UpdatePseudoCScrollInfo();
    if (pseudoCViewWnd_ != nullptr) {
        InvalidateRect(pseudoCViewWnd_, nullptr, FALSE);
    }
}

void GuiTerminalApp::LayoutPseudoCTool() {
    if (pseudoCToolWnd_ == nullptr || pseudoCViewWnd_ == nullptr) {
        return;
    }
    RECT rc = {};
    GetClientRect(pseudoCToolWnd_, &rc);
    MoveWindow(pseudoCViewWnd_, 0, 0, std::max<int>(1, rc.right - rc.left), std::max<int>(1, rc.bottom - rc.top), TRUE);
    UpdatePseudoCMetrics();
    UpdatePseudoCScrollInfo();
}

void GuiTerminalApp::UpdatePseudoCMetrics() {
    if (pseudoCViewWnd_ == nullptr) {
        return;
    }
    HDC dc = GetDC(pseudoCViewWnd_);
    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(dc, font_);
    }
    TEXTMETRICW tm = {};
    GetTextMetricsW(dc, &tm);
    pseudoCLineHeight_ = std::max<int>(1, tm.tmHeight - tm.tmInternalLeading);
    pseudoCCharWidth_ = std::max<int>(1, tm.tmAveCharWidth);
    if (oldFont != nullptr) {
        SelectObject(dc, oldFont);
    }
    ReleaseDC(pseudoCViewWnd_, dc);

    RECT rc = {};
    GetClientRect(pseudoCViewWnd_, &rc);
    pseudoCVisibleRows_ = std::max<int>(1, (rc.bottom - rc.top) / pseudoCLineHeight_);
}

void GuiTerminalApp::UpdatePseudoCScrollInfo() {
    if (pseudoCViewWnd_ == nullptr) {
        return;
    }
    const int maxTop = std::max<int>(0, static_cast<int>(pseudoCLines_.size()) - pseudoCVisibleRows_);
    pseudoCTopLine_ = std::max<int>(0, std::min<int>(pseudoCTopLine_, maxTop));

    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = std::max<int>(0, static_cast<int>(pseudoCLines_.size()) - 1);
    si.nPage = static_cast<UINT>(std::max<int>(1, pseudoCVisibleRows_));
    si.nPos = pseudoCTopLine_;
    SetScrollInfo(pseudoCViewWnd_, SB_VERT, &si, TRUE);
}

void GuiTerminalApp::PaintPseudoCView(HDC targetDc, const RECT& clip) {
    RECT rc = {};
    GetClientRect(pseudoCViewWnd_, &rc);
    HBRUSH bg = CreateSolidBrush(RGB(248, 248, 248));
    FillRect(targetDc, &rc, bg);
    DeleteObject(bg);

    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(targetDc, font_);
    }
    SetBkMode(targetDc, TRANSPARENT);
    const int gutterWidth = std::max<int>(48, pseudoCCharWidth_ * 5);
    HBRUSH gutterBrush = CreateSolidBrush(RGB(232, 236, 242));
    RECT gutter = {0, 0, gutterWidth, rc.bottom};
    FillRect(targetDc, &gutter, gutterBrush);
    DeleteObject(gutterBrush);

    HPEN sepPen = CreatePen(PS_SOLID, 1, RGB(198, 205, 214));
    HGDIOBJ oldPen = SelectObject(targetDc, sepPen);
    MoveToEx(targetDc, gutterWidth, 0, nullptr);
    LineTo(targetDc, gutterWidth, rc.bottom);
    SelectObject(targetDc, oldPen);
    DeleteObject(sepPen);

    const int first = std::max<int>(0, pseudoCTopLine_);
    const int last = std::min<int>(static_cast<int>(pseudoCLines_.size()), first + pseudoCVisibleRows_ + 1);
    for (int i = first; i < last; ++i) {
        const int y = (i - first) * pseudoCLineHeight_;
        if (y + pseudoCLineHeight_ < clip.top || y > clip.bottom) {
            continue;
        }
        std::wstringstream num;
        num << (i + 1);
        RECT numRc = {0, y, gutterWidth - 8, y + pseudoCLineHeight_};
        SetTextColor(targetDc, RGB(102, 112, 128));
        const std::wstring numText = num.str();
        DrawTextW(targetDc, numText.c_str(), static_cast<int>(numText.size()), &numRc, DT_RIGHT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);

        const std::wstring& line = pseudoCLines_[i];
        RECT textRc = {gutterWidth + 10, y, rc.right - 8, y + pseudoCLineHeight_};
        const size_t commentPos = line.find(L"//");
        if (commentPos == std::wstring::npos) {
            SetTextColor(targetDc, RGB(24, 29, 35));
            DrawTextW(targetDc, line.c_str(), static_cast<int>(line.size()), &textRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | DT_END_ELLIPSIS);
        } else {
            const std::wstring codeText = line.substr(0, commentPos);
            const std::wstring commentText = line.substr(commentPos);
            if (!codeText.empty()) {
                SetTextColor(targetDc, RGB(24, 29, 35));
                DrawTextW(targetDc, codeText.c_str(), static_cast<int>(codeText.size()), &textRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
            }
            SIZE codeSize = {};
            if (!codeText.empty()) {
                GetTextExtentPoint32W(targetDc, codeText.c_str(), static_cast<int>(codeText.size()), &codeSize);
            }
            RECT commentRc = textRc;
            commentRc.left += codeSize.cx;
            SetTextColor(targetDc, RGB(0, 128, 0));
            DrawTextW(targetDc, commentText.c_str(), static_cast<int>(commentText.size()), &commentRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | DT_END_ELLIPSIS);
        }
    }

    if (oldFont != nullptr) {
        SelectObject(targetDc, oldFont);
    }
}

void GuiTerminalApp::CreateOrUpdateStackTool(const std::vector<StackUiRow>& rows, const std::wstring& view, uint64_t stackPointer) {
    stackRows_ = rows;
    stackViewName_ = view;
    stackPointer_ = stackPointer;
    stackTopRow_ = 0;
    stackSelecting_ = false;
    stackSelectionAnchor_ = -1;
    stackSelectionEnd_ = -1;

    if (stackToolWnd_ == nullptr || !IsWindow(stackToolWnd_)) {
        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
        const int width = 880;
        const int height = 560;
        const int x = workArea.left + std::max<int>(0, ((workArea.right - workArea.left) - width) / 2);
        const int y = workArea.top + std::max<int>(0, ((workArea.bottom - workArea.top) - height) / 2);
        stackToolWnd_ = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            stackToolClassName_.c_str(),
            L"Stack",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            x, y, width, height,
            nullptr,
            nullptr,
            instance_,
            this);
        if (stackToolWnd_ == nullptr) {
            QueueOutput(L"Failed to create stack tool window.\r\n");
            return;
        }
        stackViewWnd_ = CreateWindowExW(
            0,
            stackViewClassName_.c_str(),
            L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPSIBLINGS,
            0, 0, 0, 0,
            stackToolWnd_,
            nullptr,
            instance_,
            this);
        if (stackViewWnd_ == nullptr) {
            DestroyWindow(stackToolWnd_);
            stackToolWnd_ = nullptr;
            QueueOutput(L"Failed to create stack view.\r\n");
            return;
        }
        ShowWindow(stackToolWnd_, SW_SHOW);
    } else {
        ShowWindow(stackToolWnd_, SW_SHOW);
    }

    std::wstring title = L"Stack";
    if (!view.empty()) {
        title += L" - " + view;
    }
    const std::wstring imagePath = debugger_.GetDebuggeeImagePath();
    if (!imagePath.empty()) {
        title += L" - " + imagePath;
    }
    SetWindowTextW(stackToolWnd_, title.c_str());
    UpdateStackMetrics();
    LayoutStackTool();
    if (stackPointer_ != 0) {
        for (size_t i = 0; i < stackRows_.size(); ++i) {
            if (stackRows_[i].addressValue == stackPointer_) {
                stackTopRow_ = static_cast<int>(i);
                break;
            }
        }
    }
    UpdateStackScrollInfo();
    InvalidateRect(stackViewWnd_, nullptr, FALSE);
}

void GuiTerminalApp::LayoutStackTool() {
    if (stackToolWnd_ == nullptr || stackViewWnd_ == nullptr) {
        return;
    }
    RECT rc = {};
    GetClientRect(stackToolWnd_, &rc);
    MoveWindow(stackViewWnd_, 0, 0, std::max<int>(1, rc.right - rc.left), std::max<int>(1, rc.bottom - rc.top), TRUE);
    UpdateStackMetrics();
    UpdateStackScrollInfo();
}

void GuiTerminalApp::UpdateStackMetrics() {
    if (stackViewWnd_ == nullptr) {
        return;
    }
    HDC dc = GetDC(stackViewWnd_);
    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(dc, font_);
    }
    TEXTMETRICW tm = {};
    GetTextMetricsW(dc, &tm);
    stackRowHeight_ = std::max<int>(1, tm.tmHeight - tm.tmInternalLeading);
    stackCharWidth_ = std::max<int>(1, tm.tmAveCharWidth);
    if (oldFont != nullptr) {
        SelectObject(dc, oldFont);
    }
    ReleaseDC(stackViewWnd_, dc);

    RECT rc = {};
    GetClientRect(stackViewWnd_, &rc);
    stackVisibleRows_ = std::max<int>(1, ((rc.bottom - rc.top) / stackRowHeight_) - 1);
}

void GuiTerminalApp::UpdateStackScrollInfo() {
    if (stackViewWnd_ == nullptr) {
        return;
    }
    const int maxTop = std::max<int>(0, static_cast<int>(stackRows_.size()) - stackVisibleRows_);
    stackTopRow_ = std::clamp<int>(stackTopRow_, 0, maxTop);
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = std::max<int>(0, static_cast<int>(stackRows_.size()) - 1);
    si.nPage = static_cast<UINT>(std::max<int>(1, stackVisibleRows_));
    si.nPos = stackTopRow_;
    SetScrollInfo(stackViewWnd_, SB_VERT, &si, TRUE);
}

int GuiTerminalApp::HitTestStackColumnSeparator(int x) const {
    const int padX = 8;
    const int gapX = 1;
    const int addressW = std::max<int>(120, stackColAddressW_);
    const int valueW = std::max<int>(120, stackColValueW_);
    const int xAddress = padX;
    const int xValue = xAddress + addressW + gapX;
    const int xSymbol = xValue + valueW + gapX;
    const int hitPad = 6;
    if (std::abs(x - (xValue - gapX)) <= hitPad) {
        return 0;
    }
    if (std::abs(x - (xSymbol - gapX)) <= hitPad) {
        return 1;
    }
    return -1;
}

void GuiTerminalApp::PaintStackView(HDC targetDc, const RECT& clip) {
    RECT rc = {};
    GetClientRect(stackViewWnd_, &rc);
    HBRUSH bg = CreateSolidBrush(RGB(18, 18, 18));
    FillRect(targetDc, &rc, bg);
    DeleteObject(bg);

    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(targetDc, font_);
    }
    SetBkMode(targetDc, TRANSPARENT);

    const int padX = 8;
    const int gapX = 1;
    const int textInsetX = 4;
    const int headerH = stackRowHeight_;
    const int addressW = std::max<int>(120, stackColAddressW_);
    const int valueW = std::max<int>(120, stackColValueW_);
    const int xAddress = padX;
    const int xValue = xAddress + addressW + gapX;
    const int xSymbol = xValue + valueW + gapX;
    const int symbolW = std::max<int>(80, rc.right - xSymbol - padX);
    const COLORREF dataBg = RGB(255, 251, 241);

    auto drawCell = [&](const std::wstring& text, int x, int y, int w, COLORREF color) {
        RECT r = {x + textInsetX, y, x + w, y + stackRowHeight_};
        if (r.bottom <= clip.top || r.top >= clip.bottom) {
            return;
        }
        SetTextColor(targetDc, color);
        DrawTextW(targetDc, text.c_str(), static_cast<int>(text.size()), &r, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    };

    RECT header = {0, 0, rc.right, headerH};
    HBRUSH headerBrush = CreateSolidBrush(RGB(34, 34, 34));
    FillRect(targetDc, &header, headerBrush);
    DeleteObject(headerBrush);
    drawCell(L"Address", xAddress, 0, addressW, RGB(210, 210, 210));
    drawCell(L"Value", xValue, 0, valueW, RGB(210, 210, 210));
    drawCell(L"Symbol", xSymbol, 0, symbolW, RGB(210, 210, 210));

    const int maxRows = static_cast<int>(stackRows_.size());
    const int last = std::min<int>(maxRows, stackTopRow_ + stackVisibleRows_ + 1);
    const int selStart = (stackSelectionAnchor_ >= 0 && stackSelectionEnd_ >= 0)
        ? std::min<int>(stackSelectionAnchor_, stackSelectionEnd_)
        : -1;
    const int selEnd = (stackSelectionAnchor_ >= 0 && stackSelectionEnd_ >= 0)
        ? std::max<int>(stackSelectionAnchor_, stackSelectionEnd_)
        : -1;
    for (int rowIndex = stackTopRow_; rowIndex < last; ++rowIndex) {
        const int y = headerH + (rowIndex - stackTopRow_) * stackRowHeight_;
        RECT rowBgRc = {0, y, rc.right, y + stackRowHeight_};
        const StackUiRow& row = stackRows_[rowIndex];
        const bool isStackPointerRow = stackPointer_ != 0 && row.addressValue == stackPointer_;
        HBRUSH rowBrush = CreateSolidBrush(isStackPointerRow ? RGB(255, 0, 0) : dataBg);
        FillRect(targetDc, &rowBgRc, rowBrush);
        DeleteObject(rowBrush);
        drawCell(row.address, xAddress, y, addressW, isStackPointerRow ? RGB(0, 0, 0) : RGB(20, 95, 175));
        drawCell(row.value, xValue, y, valueW, RGB(0, 0, 0));
        drawCell(row.symbol, xSymbol, y, symbolW, RGB(0, 0, 0));
    }
    if (selStart >= 0) {
        HBRUSH selectionBrush = CreateSolidBrush(RGB(186, 186, 186));
        for (int rowIndex = std::max<int>(stackTopRow_, selStart); rowIndex <= selEnd && rowIndex < last; ++rowIndex) {
            const int y = headerH + (rowIndex - stackTopRow_) * stackRowHeight_;
            RECT lineRc = {0, y, rc.right, y + stackRowHeight_};
            FillRect(targetDc, &lineRc, selectionBrush);
            const StackUiRow& row = stackRows_[rowIndex];
            drawCell(row.address, xAddress, y, addressW, RGB(0, 0, 0));
            drawCell(row.value, xValue, y, valueW, RGB(0, 0, 0));
            drawCell(row.symbol, xSymbol, y, symbolW, RGB(0, 0, 0));
        }
        DeleteObject(selectionBrush);
    }

    HBRUSH sepBrush = CreateSolidBrush(RGB(86, 86, 86));
    RECT sep1 = {xValue - gapX, 0, xValue - gapX + 1, rc.bottom};
    RECT sep2 = {xSymbol - gapX, 0, xSymbol - gapX + 1, rc.bottom};
    FillRect(targetDc, &sep1, sepBrush);
    FillRect(targetDc, &sep2, sepBrush);
    DeleteObject(sepBrush);

    if (oldFont != nullptr) {
        SelectObject(targetDc, oldFont);
    }
}

void GuiTerminalApp::CreateOrUpdateDisassemblyTool(const std::vector<DisassemblyUiRow>& rows, uint64_t targetAddress, uint64_t regionBase, uint64_t regionEnd) {
    disasmRows_ = rows;
    disasmTarget_ = targetAddress;
    disasmRegionBase_ = regionBase;
    disasmRegionEnd_ = regionEnd;
    disasmPageLoadPending_ = false;
    disasmPageLoadAddress_ = 0;
    InterlockedIncrement(&disasmPageLoadGeneration_);
    disasmSelecting_ = false;
    disasmSelectionAnchor_ = -1;
    disasmSelectionEnd_ = -1;

    if (disasmToolWnd_ == nullptr || !IsWindow(disasmToolWnd_)) {
        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
        const int width = 1120;
        const int height = 680;
        const int x = workArea.left + std::max<int>(0, ((workArea.right - workArea.left) - width) / 2);
        const int y = workArea.top + std::max<int>(0, ((workArea.bottom - workArea.top) - height) / 2);
        disasmToolWnd_ = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            disasmToolClassName_.c_str(),
            L"Disassembly",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            x, y, width, height,
            nullptr,
            nullptr,
            instance_,
            this);
        if (disasmToolWnd_ == nullptr) {
            QueueOutput(L"Failed to create disassembly tool window.\r\n");
            return;
        }
        disasmViewWnd_ = CreateWindowExW(
            0,
            disasmViewClassName_.c_str(),
            L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPSIBLINGS,
            0, 0, 0, 0,
            disasmToolWnd_,
            nullptr,
            instance_,
            this);
        if (disasmViewWnd_ == nullptr) {
            DestroyWindow(disasmToolWnd_);
            disasmToolWnd_ = nullptr;
            QueueOutput(L"Failed to create disassembly view.\r\n");
            return;
        }
        ShowWindow(disasmToolWnd_, SW_SHOW);
    } else {
        ShowWindow(disasmToolWnd_, SW_SHOW);
    }

    if (disasmToolWnd_ != nullptr) {
        const std::wstring imagePath = debugger_.GetDebuggeeImagePath();
        const std::wstring title = imagePath.empty() ? L"Disassembly" : (L"Disassembly - " + imagePath);
        SetWindowTextW(disasmToolWnd_, title.c_str());
    }

    UpdateDisassemblyMetrics();
    LayoutDisassemblyTool();
    ScrollDisassemblyToAddress(targetAddress);
    UpdateDisassemblyScrollInfo();
    InvalidateRect(disasmViewWnd_, nullptr, FALSE);
}

void GuiTerminalApp::LayoutDisassemblyTool() {
    if (disasmToolWnd_ == nullptr || disasmViewWnd_ == nullptr) {
        return;
    }
    RECT rc = {};
    GetClientRect(disasmToolWnd_, &rc);
    MoveWindow(disasmViewWnd_, 0, 0, std::max<int>(1, rc.right - rc.left), std::max<int>(1, rc.bottom - rc.top), TRUE);
    UpdateDisassemblyMetrics();
    UpdateDisassemblyScrollInfo();
}

void GuiTerminalApp::UpdateDisassemblyMetrics() {
    if (disasmViewWnd_ == nullptr) {
        return;
    }
    HDC dc = GetDC(disasmViewWnd_);
    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(dc, font_);
    }
    TEXTMETRICW tm = {};
    GetTextMetricsW(dc, &tm);
    disasmRowHeight_ = std::max<int>(1, tm.tmHeight - tm.tmInternalLeading);
    disasmCharWidth_ = std::max<int>(1, tm.tmAveCharWidth);
    if (oldFont != nullptr) {
        SelectObject(dc, oldFont);
    }
    ReleaseDC(disasmViewWnd_, dc);

    RECT rc = {};
    GetClientRect(disasmViewWnd_, &rc);
    const int headerRows = 1;
    disasmVisibleRows_ = std::max<int>(1, ((rc.bottom - rc.top) / disasmRowHeight_) - headerRows);
}

void GuiTerminalApp::UpdateDisassemblyScrollInfo() {
    if (disasmViewWnd_ == nullptr) {
        return;
    }
    const int maxTop = std::max<int>(0, static_cast<int>(disasmRows_.size()) - disasmVisibleRows_);
    disasmTopRow_ = std::clamp<int>(disasmTopRow_, 0, maxTop);
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = std::max<int>(0, static_cast<int>(disasmRows_.size()) - 1);
    si.nPage = static_cast<UINT>(std::max<int>(1, disasmVisibleRows_));
    si.nPos = disasmTopRow_;
    SetScrollInfo(disasmViewWnd_, SB_VERT, &si, TRUE);
    SetScrollPos(disasmViewWnd_, SB_VERT, disasmTopRow_, TRUE);
}

void GuiTerminalApp::ScrollDisassemblyToAddress(uint64_t address) {
    int targetRow = 0;
    bool foundExact = false;
    for (size_t i = 0; i < disasmRows_.size(); ++i) {
        const DisassemblyUiRow& row = disasmRows_[i];
        if (!row.instruction.empty() && (row.currentIp || row.address == address)) {
            targetRow = static_cast<int>(i);
            foundExact = true;
            break;
        }
    }
    if (!foundExact) {
        for (size_t i = 0; i < disasmRows_.size(); ++i) {
            uint64_t rowAddress = disasmRows_[i].address;
            if (rowAddress == 0 && disasmRegionBase_ != 0) {
                rowAddress = disasmRegionBase_ + static_cast<uint64_t>(i) * 2;
            }
            if (disasmRows_[i].currentIp || rowAddress >= address) {
                targetRow = static_cast<int>(i);
                break;
            }
            targetRow = static_cast<int>(i);
        }
    }
    disasmTopRow_ = std::max<int>(0, targetRow - std::max<int>(1, disasmVisibleRows_ / 3));
}

bool GuiTerminalApp::DisassemblyVisibleRangeHasInstruction() const {
    if (disasmRows_.empty()) {
        return false;
    }
    const int maxRows = static_cast<int>(disasmRows_.size());
    const int firstVisible = std::clamp<int>(disasmTopRow_, 0, std::max<int>(0, maxRows - 1));
    const int lastVisible = std::min<int>(maxRows, firstVisible + std::max<int>(1, disasmVisibleRows_));
    for (int i = firstVisible; i < lastVisible; ++i) {
        if (!disasmRows_[i].instruction.empty()) {
            return true;
        }
    }
    return false;
}

bool GuiTerminalApp::DisassemblyVisibleRangeHasEmptyInstruction() const {
    if (disasmRows_.empty()) {
        return false;
    }
    const int maxRows = static_cast<int>(disasmRows_.size());
    const int firstVisible = std::clamp<int>(disasmTopRow_, 0, std::max<int>(0, maxRows - 1));
    const int lastVisible = std::min<int>(maxRows, firstVisible + std::max<int>(1, disasmVisibleRows_));
    for (int i = firstVisible; i < lastVisible; ++i) {
        if (disasmRows_[i].instruction.empty()) {
            return true;
        }
    }
    return false;
}

int GuiTerminalApp::HitTestDisassemblyColumnSeparator(int x) const {
    const int padX = 8;
    const int gapX = 1;
    const int textInsetX = 4;
    const int xAddr = padX;
    const int xHex = xAddr + disasmColAddrW_ + gapX;
    const int xAsm = xHex + disasmColHexW_ + gapX;
    const int xCmt = xAsm + disasmColAsmW_ + gapX;
    const int hitPad = 4;
    if (std::abs(x - (xHex - gapX)) <= hitPad) {
        return 0;
    }
    if (std::abs(x - (xAsm - gapX)) <= hitPad) {
        return 1;
    }
    if (std::abs(x - (xCmt - gapX)) <= hitPad) {
        return 2;
    }
    return -1;
}

int GuiTerminalApp::DisassemblyRowFromPoint(int y) const {
    if (y < disasmRowHeight_ || disasmRowHeight_ <= 0 || disasmRows_.empty()) {
        return -1;
    }
    const int row = disasmTopRow_ + ((y - disasmRowHeight_) / disasmRowHeight_);
    if (row < 0 || row >= static_cast<int>(disasmRows_.size())) {
        return -1;
    }
    return row;
}

void GuiTerminalApp::PaintDisassemblyView(HDC targetDc, const RECT& clip) {
    RECT rc = {};
    GetClientRect(disasmViewWnd_, &rc);
    HBRUSH bg = CreateSolidBrush(RGB(18, 18, 18));
    FillRect(targetDc, &rc, bg);
    DeleteObject(bg);

    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(targetDc, font_);
    }
    SetBkMode(targetDc, TRANSPARENT);

    const int padX = 8;
    const int gapX = 1;
    const int textInsetX = 4;
    const int headerH = disasmRowHeight_;
    const int addrW = std::max<int>(80, disasmColAddrW_);
    const int hexW = std::max<int>(80, disasmColHexW_);
    const int asmW = std::max<int>(120, disasmColAsmW_);
    const int xAddr = padX;
    const int xHex = xAddr + addrW + gapX;
    const int xAsm = xHex + hexW + gapX;
    const int xCmt = xAsm + asmW + gapX;
    const int cmtW = std::max<int>(60, rc.right - xCmt - padX);

    auto drawText = [&](const std::wstring& text, RECT r, COLORREF color, UINT flags) {
        SetTextColor(targetDc, color);
        DrawTextW(targetDc, text.c_str(), static_cast<int>(text.size()), &r, flags | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    };
    auto drawCell = [&](const std::wstring& text, int x, int y, int w, COLORREF color) {
        RECT r = {x + textInsetX, y, x + w, y + disasmRowHeight_};
        if (r.bottom <= clip.top || r.top >= clip.bottom) {
            return;
        }
        drawText(text, r, color, DT_LEFT);
    };
    const COLORREF disasmDataBg = RGB(255, 251, 241);
    auto drawSegments = [&](const std::vector<DisasmTextSegment>& segments, const std::wstring& fallback, int x, int y, int w) {
        RECT r = {x, y, x + w, y + disasmRowHeight_};
        if (r.bottom <= clip.top || r.top >= clip.bottom) {
            return;
        }
        if (segments.empty()) {
            drawText(fallback, r, RGB(0, 0, 0), DT_LEFT);
            return;
        }
        HBRUSH fillBrush = CreateSolidBrush(disasmDataBg);
        FillRect(targetDc, &r, fillBrush);
        DeleteObject(fillBrush);

        std::wstring mnemonic = fallback;
        const size_t mnemonicEnd = mnemonic.find_first_of(L" \t");
        if (mnemonicEnd != std::wstring::npos) {
            mnemonic = mnemonic.substr(0, mnemonicEnd);
        }
        const std::wstring lowerMnemonic = ToLower(mnemonic);
        const bool mnemonicOnly = fallback.find_first_of(L" \t") == std::wstring::npos;
        const bool isIntInstruction = lowerMnemonic == L"int" || lowerMnemonic == L"int1" ||
            lowerMnemonic == L"int3" || lowerMnemonic == L"into";

        int drawX = r.left + textInsetX;
        for (size_t i = 0; i < segments.size() && drawX < r.right; ++i) {
            const DisasmTextSegment& segment = segments[i];
            if (segment.text.empty()) {
                continue;
            }
            SIZE extent = {};
            GetTextExtentPoint32W(targetDc, segment.text.c_str(), static_cast<int>(segment.text.size()), &extent);
            const int segW = std::max<int>(1, extent.cx);
            if (segment.hasBg || mnemonicOnly) {
                const COLORREF segmentBg = mnemonicOnly ? RGB(0, 255, 255) : segment.bg;
                HBRUSH segBrush = CreateSolidBrush(segmentBg);
                RECT bgRc = {drawX, r.top, std::min<int>(r.right, drawX + segW), r.bottom};
                FillRect(targetDc, &bgRc, segBrush);
                DeleteObject(segBrush);
            }
            SetTextColor(targetDc, isIntInstruction ? RGB(0, 0, 255) : segment.fg);
            RECT textRc = {drawX, r.top, std::min<int>(r.right, drawX + segW), r.bottom};
            DrawTextW(
                targetDc,
                segment.text.c_str(),
                static_cast<int>(segment.text.size()),
                &textRc,
                DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
            drawX += segW;
        }
        if (drawX < r.right) {
            HBRUSH tailBrush = CreateSolidBrush(disasmDataBg);
            RECT tailRc = {drawX, r.top, r.right, r.bottom};
            FillRect(targetDc, &tailRc, tailBrush);
            DeleteObject(tailBrush);
        }
    };
    auto drawPlainDisasmRow = [&](const DisassemblyUiRow& row, int y, COLORREF color) {
        RECT addrRc = {xAddr + textInsetX, y, xAddr + addrW, y + disasmRowHeight_};
        RECT hexRc = {xHex + textInsetX, y, xHex + hexW, y + disasmRowHeight_};
        RECT asmRc = {xAsm + textInsetX, y, xAsm + asmW, y + disasmRowHeight_};
        RECT cmtRc = {xCmt + textInsetX, y, xCmt + cmtW, y + disasmRowHeight_};
        SetTextColor(targetDc, color);
        DrawTextW(targetDc, row.addressText.c_str(), static_cast<int>(row.addressText.size()), &addrRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        std::wstring compactHexText;
        compactHexText.reserve(row.hexBytes.size());
        for (size_t i = 0; i < row.hexBytes.size(); ++i) {
            const wchar_t ch = row.hexBytes[i];
            if (ch != L' ' && ch != L'\t') {
                compactHexText.push_back(ch);
            }
        }
        DrawTextW(targetDc, compactHexText.c_str(), static_cast<int>(compactHexText.size()), &hexRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        DrawTextW(targetDc, row.instruction.c_str(), static_cast<int>(row.instruction.size()), &asmRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        DrawTextW(targetDc, row.comment.c_str(), static_cast<int>(row.comment.size()), &cmtRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    };

    RECT header = {0, 0, rc.right, headerH};
    HBRUSH headerBrush = CreateSolidBrush(RGB(34, 34, 34));
    FillRect(targetDc, &header, headerBrush);
    DeleteObject(headerBrush);
    drawCell(L"Address", xAddr, 0, addrW, RGB(210, 210, 210));
    drawCell(L"Hex", xHex, 0, hexW, RGB(210, 210, 210));
    drawCell(L"Assembly", xAsm, 0, asmW, RGB(210, 210, 210));
    drawCell(L"Comment", xCmt, 0, cmtW, RGB(210, 210, 210));

    const int maxRows = static_cast<int>(disasmRows_.size());
    const int last = std::min<int>(maxRows, disasmTopRow_ + disasmVisibleRows_ + 1);
    const int selStart = (disasmSelectionAnchor_ >= 0 && disasmSelectionEnd_ >= 0)
        ? std::min<int>(disasmSelectionAnchor_, disasmSelectionEnd_)
        : -1;
    const int selEnd = (disasmSelectionAnchor_ >= 0 && disasmSelectionEnd_ >= 0)
        ? std::max<int>(disasmSelectionAnchor_, disasmSelectionEnd_)
        : -1;
    for (int rowIndex = disasmTopRow_; rowIndex < last; ++rowIndex) {
        const int y = headerH + (rowIndex - disasmTopRow_) * disasmRowHeight_;
        const DisassemblyUiRow& row = disasmRows_[rowIndex];
        RECT rowBgRc = {0, y, rc.right, y + disasmRowHeight_};
        HBRUSH rowBgBrush = CreateSolidBrush(disasmDataBg);
        FillRect(targetDc, &rowBgRc, rowBgBrush);
        DeleteObject(rowBgBrush);
        drawCell(row.addressText, xAddr, y, addrW, RGB(40, 135, 220));
        std::wstring compactHexText;
        compactHexText.reserve(row.hexBytes.size());
        for (size_t i = 0; i < row.hexBytes.size(); ++i) {
            const wchar_t ch = row.hexBytes[i];
            if (ch != L' ' && ch != L'\t') {
                compactHexText.push_back(ch);
            }
        }
        drawCell(compactHexText, xHex, y, hexW, RGB(0, 0, 0));
        drawSegments(row.instructionSegments, row.instruction, xAsm, y, asmW);
        drawCell(row.comment, xCmt, y, cmtW, RGB(0, 64, 160));
    }

    if (selStart >= 0) {
        HBRUSH selectionBrush = CreateSolidBrush(RGB(186, 186, 186));
        const COLORREF oldTextColor = SetTextColor(targetDc, RGB(0, 0, 0));
        for (int rowIndex = std::max<int>(disasmTopRow_, selStart); rowIndex <= selEnd && rowIndex < last; ++rowIndex) {
            const int y = headerH + (rowIndex - disasmTopRow_) * disasmRowHeight_;
            RECT lineRc = {0, y, rc.right, y + disasmRowHeight_};
            FillRect(targetDc, &lineRc, selectionBrush);

            const DisassemblyUiRow& row = disasmRows_[rowIndex];
            drawPlainDisasmRow(row, y, RGB(0, 0, 0));
        }
        SetTextColor(targetDc, oldTextColor);
        DeleteObject(selectionBrush);
    }

    HBRUSH breakpointBrush = CreateSolidBrush(RGB(255, 0, 0));
    for (int rowIndex = disasmTopRow_; rowIndex < last; ++rowIndex) {
        const DisassemblyUiRow& row = disasmRows_[rowIndex];
        if (!row.currentIp) {
            continue;
        }
        const int y = headerH + (rowIndex - disasmTopRow_) * disasmRowHeight_;
        RECT lineRc = {0, y, rc.right, y + disasmRowHeight_};
        FillRect(targetDc, &lineRc, breakpointBrush);
        drawPlainDisasmRow(row, y, RGB(0, 0, 0));
    }
    DeleteObject(breakpointBrush);

    const int sepW = 1;
    const COLORREF sepColor = RGB(86, 86, 86);
    HBRUSH sepBrush = CreateSolidBrush(sepColor);
    auto fillSeparator = [&](int x) {
        RECT sepRc = {x, 0, x + sepW, rc.bottom};
        FillRect(targetDc, &sepRc, sepBrush);
    };
    fillSeparator(xHex - gapX);
    fillSeparator(xAsm - gapX);
    fillSeparator(xCmt - gapX);
    DeleteObject(sepBrush);

    if (oldFont != nullptr) {
        SelectObject(targetDc, oldFont);
    }
}

void GuiTerminalApp::PaintMemoryView(HDC targetDc, const RECT& clip) {
    RECT rc = {};
    GetClientRect(memoryViewWnd_, &rc);
    HBRUSH bg = CreateSolidBrush(RGB(18, 18, 18));
    FillRect(targetDc, &rc, bg);
    DeleteObject(bg);

    HGDIOBJ oldFont = nullptr;
    if (font_ != nullptr) {
        oldFont = SelectObject(targetDc, font_);
    }
    SetBkMode(targetDc, TRANSPARENT);

    const int padX = 8;
    const int gapX = 1;
    const int textInsetX = 4;
    const int headerH = memoryRowHeight_;
    const int addrW = std::max<int>(100, memoryColAddrW_);
    const int hexW = std::max<int>(180, memoryColHexW_);
    const int xAddr = padX;
    const int xHex = xAddr + addrW + gapX;
    const int xAnsi = xHex + hexW + gapX;
    const int ansiW = std::max<int>(80, rc.right - xAnsi - padX);
    const COLORREF dataBg = RGB(255, 251, 241);

    auto drawCell = [&](const std::wstring& text, int x, int y, int w, COLORREF color) {
        RECT r = {x + textInsetX, y, x + w, y + memoryRowHeight_};
        if (r.bottom <= clip.top || r.top >= clip.bottom) {
            return;
        }
        SetTextColor(targetDc, color);
        DrawTextW(targetDc, text.c_str(), static_cast<int>(text.size()), &r, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    };

    RECT header = {0, 0, rc.right, headerH};
    HBRUSH headerBrush = CreateSolidBrush(RGB(34, 34, 34));
    FillRect(targetDc, &header, headerBrush);
    DeleteObject(headerBrush);
    drawCell(L"Address", xAddr, 0, addrW, RGB(210, 210, 210));
    drawCell(L"Hex", xHex, 0, hexW, RGB(210, 210, 210));
    drawCell(L"ANSI", xAnsi, 0, ansiW, RGB(210, 210, 210));

    const int maxRows = static_cast<int>(memoryRows_.size());
    const int last = std::min<int>(maxRows, memoryTopRow_ + memoryVisibleRows_ + 1);
    const int selStart = (memorySelectionAnchor_ >= 0 && memorySelectionEnd_ >= 0)
        ? std::min<int>(memorySelectionAnchor_, memorySelectionEnd_)
        : -1;
    const int selEnd = (memorySelectionAnchor_ >= 0 && memorySelectionEnd_ >= 0)
        ? std::max<int>(memorySelectionAnchor_, memorySelectionEnd_)
        : -1;
    for (int rowIndex = memoryTopRow_; rowIndex < last; ++rowIndex) {
        const int y = headerH + (rowIndex - memoryTopRow_) * memoryRowHeight_;
        RECT rowBgRc = {0, y, rc.right, y + memoryRowHeight_};
        HBRUSH rowBrush = CreateSolidBrush(dataBg);
        FillRect(targetDc, &rowBgRc, rowBrush);
        DeleteObject(rowBrush);
        const MemoryUiRow& row = memoryRows_[rowIndex];
        drawCell(row.addressText, xAddr, y, addrW, RGB(40, 135, 220));
        drawCell(row.hexText, xHex, y, hexW, RGB(0, 0, 0));
        drawCell(row.ansiText, xAnsi, y, ansiW, RGB(0, 0, 0));
    }
    if (selStart >= 0) {
        HBRUSH selectionBrush = CreateSolidBrush(RGB(186, 186, 186));
        for (int rowIndex = std::max<int>(memoryTopRow_, selStart); rowIndex <= selEnd && rowIndex < last; ++rowIndex) {
            const int y = headerH + (rowIndex - memoryTopRow_) * memoryRowHeight_;
            RECT lineRc = {0, y, rc.right, y + memoryRowHeight_};
            FillRect(targetDc, &lineRc, selectionBrush);
            const MemoryUiRow& row = memoryRows_[rowIndex];
            drawCell(row.addressText, xAddr, y, addrW, RGB(0, 0, 0));
            drawCell(row.hexText, xHex, y, hexW, RGB(0, 0, 0));
            drawCell(row.ansiText, xAnsi, y, ansiW, RGB(0, 0, 0));
        }
        DeleteObject(selectionBrush);
    }

    HBRUSH sepBrush = CreateSolidBrush(RGB(86, 86, 86));
    RECT sep1 = {xHex - gapX, 0, xHex - gapX + 1, rc.bottom};
    RECT sep2 = {xAnsi - gapX, 0, xAnsi - gapX + 1, rc.bottom};
    FillRect(targetDc, &sep1, sepBrush);
    FillRect(targetDc, &sep2, sepBrush);
    DeleteObject(sepBrush);

    if (oldFont != nullptr) {
        SelectObject(targetDc, oldFont);
    }
}

void GuiTerminalApp::SubmitInput() {
    const std::wstring text = Trim(ReadInputText());
    if (text.empty()) {
        UpdateInputText(L"");
        ClearInputHistoryState();
        return;
    }

    const bool batchOutput = !IsClearCommand(text);
    if (batchOutput) {
        BeginOutputBatch();
    }
    AddHistory(text);
    AppendPromptedCommand(text);
    if (IsClearCommand(text)) {
        if (outputWnd_ != nullptr) {
            SetWindowTextW(outputWnd_, L"");
            ResetOutputTextIndex();
        }
        UpdateInputText(L"");
        ClearInputHistoryState();
        return;
    }
    if (IsHistoryCommand(text)) {
        AppendHistory();
        if (batchOutput) {
            EndOutputBatch(true);
        }
        UpdateInputText(L"");
        ClearInputHistoryState();
        return;
    }
    if (IsQuitCommand(text)) {
        if (batchOutput) {
            EndOutputBatch(true);
        }
        UpdateInputText(L"");
        PostMessageW(hwnd_, WM_CLOSE, 0, 0);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(commandMutex_);
        commandQueue_.push_back(text);
    }
    commandCv_.notify_one();
    if (batchOutput) {
        EndOutputBatch(true);
    }
    UpdateInputText(L"");
    ClearInputHistoryState();
}

bool GuiTerminalApp::HandlePythonCommand(const std::wstring& command) {
    const std::vector<std::wstring> tokens = Tokenize(command);
    if (tokens.empty() || ToLower(tokens[0]) != L"py") {
        return false;
    }

    const WdblDebuggerApi* api = debugger_.GetDebuggerApi();
    if (api == nullptr) {
        QueueOutput(L"Python bridge is unavailable.\r\n");
        return false;
    }

    if (!pythonBridge_.IsInitialized()) {
        if (!pythonBridge_.Initialize(api, api->context)) {
            QueueOutput(L"Python runtime not found or failed to initialize.\r\n");
            return false;
        }
    }

    if (tokens.size() == 1) {
        QueueOutput(L"Usage: py run <file> [args...] | py exec <code>\r\n");
        return true;
    }

    const std::wstring subcmd = ToLower(tokens[1]);
    if (subcmd == L"help" || subcmd == L"h" || subcmd == L"?") {
        QueueOutput(
            L"Python bridge commands:\r\n"
            L"  py run <file> [args...]        Run a Python file\r\n"
            L"  py exec <code>                 Execute inline Python code\r\n"
            L"\r\n"
            L"z0dbg module API:\r\n"
            L"  emit(text)\r\n"
            L"  emit_line(text)\r\n"
            L"  emit_color(text, fg)\r\n"
            L"  emit_color_bg(text, fg, bg)\r\n"
            L"  emit_info(text)\r\n"
            L"  emit_warn(text)\r\n"
            L"  emit_error(text)\r\n"
            L"  launch(command_line) -> bool\r\n"
            L"  attach(pid) -> bool\r\n"
            L"  detach() -> bool\r\n"
            L"  continue_execution() -> bool\r\n"
            L"  single_step() -> bool\r\n"
            L"  step_over() -> bool\r\n"
            L"  execute(command, capture_output=False) -> bool | dict  # dict: {ok, output}\r\n"
            L"  execute_capture(command) -> dict  # same as execute(..., capture_output=True)\r\n"
            L"  dump(file_path, base_address=0, length=0) -> bool\r\n"
            L"  read_memory(address, size) -> bytes\r\n"
            L"  write_memory(address, data) -> int\r\n"
            L"  resolve_symbol(address) -> str\r\n"
            L"  resolve_address_expression(expression) -> dict  # {address, text}\r\n"
            L"  read_cstr(address, max_bytes=4096) -> str\r\n"
            L"  read_wstr(address, max_chars=2048) -> str\r\n"
            L"  add_software_breakpoint(address_expression) -> int\r\n"
            L"  add_hardware_breakpoint(address_expression, access='x', length=1, slot=-1, thread_id=0) -> int\r\n"
            L"  add_memory_breakpoint(address_expression, size, access='rw') -> int\r\n"
            L"  enable_breakpoint(id) -> bool\r\n"
            L"  disable_breakpoint(id) -> bool\r\n"
            L"  remove_breakpoint(id) -> bool\r\n"
            L"  set_breakpoint_condition(id, expression) -> bool\r\n"
            L"  clear_breakpoint_condition(id) -> bool\r\n"
            L"  load_symbols(target='*') -> dict  # {target, pdb_path, downloaded}\r\n"
            L"  download_symbols(target='*', cache_dir=None, server_url=None) -> dict\r\n"
            L"  set_symbol_search_path(path) -> bool\r\n"
            L"  get_symbol_search_path() -> str\r\n"
            L"  select_thread(index) -> bool\r\n"
            L"  set_register_value(assignment) -> bool\r\n"
            L"  write_memory_patch(address, data) -> bool\r\n"
            L"  undo_memory_patch(count=1) -> bool\r\n"
            L"  save_current_stop_snapshot() -> bool\r\n"
            L"  save_named_snapshot(name) -> bool\r\n"
            L"  restore_named_snapshot(name, rerun_after_restore=False) -> bool\r\n"
            L"  list_named_snapshots() -> bool\r\n"
            L"  step_back_to_previous_snapshot() -> bool\r\n"
            L"  add_source_root(path) -> bool\r\n"
            L"  remove_source_root(path) -> bool\r\n"
            L"  clear_source_roots() -> bool\r\n"
            L"  list_source_roots() -> bool\r\n"
            L"  load_script_file(path) -> bool\r\n"
            L"  set_script_breakpoint(line) -> bool\r\n"
            L"  remove_script_breakpoint(line) -> bool\r\n"
            L"  list_script_breakpoints() -> bool\r\n"
            L"  configure_exception_ignore_all(scope, enabled) -> bool\r\n"
            L"  add_ignored_exception_code(scope, code) -> bool\r\n"
            L"  remove_ignored_exception_code(scope, code) -> bool\r\n"
            L"  clear_ignored_exception_codes(scope) -> bool\r\n"
            L"  list_exception_settings() -> bool\r\n"
            L"  add_run_stop_expression(expression) -> bool\r\n"
            L"  remove_run_stop_expression(index) -> bool\r\n"
            L"  clear_run_stop_expressions() -> bool\r\n"
            L"  list_run_stop_expressions() -> bool\r\n"
            L"  step_until_condition(condition, max_steps=1) -> bool\r\n"
            L"  run_until_condition(condition, max_pauses=1) -> bool\r\n"
            L"  auto_step(steps, delay_ms=0) -> bool\r\n"
            L"  auto_run(pauses, delay_ms=0) -> bool\r\n"
            L"  get_stop_info() -> dict\r\n"
            L"  get_context() -> dict  # stop_info + thread + registers + stack_frames\r\n"
            L"  print_stop_info() -> None\r\n"
            L"  get_thread_count() -> int\r\n"
            L"  get_thread_info(index) -> dict\r\n"
            L"  print_threads() -> None\r\n"
            L"  print_thread(index) -> None\r\n"
            L"  get_registers(index=None) -> dict\r\n"
            L"  get_stack_frames(index=None, max_frames=32) -> list[dict]\r\n"
            L"  get_stack(index=None, max_frames=32) -> list[dict]\r\n"
            L"  get_modules() -> list[dict]\r\n"
            L"  get_breakpoints() -> list[dict]\r\n"
            L"\r\n"
            L"Print helpers:\r\n"
            L"  print_stop_info()\r\n"
            L"  print_threads()\r\n"
            L"  print_thread(index)\r\n"
            L"  print_modules()\r\n"
            L"  print_breakpoints()\r\n"
            L"  print_registers()\r\n"
            L"  print_stack()\r\n"
            L"  print_context()\r\n");
        return true;
    }
    if (subcmd == L"run") {
        if (tokens.size() < 3) {
            QueueOutput(L"Usage: py run <file> [args...]\r\n");
            return false;
        }
        std::vector<std::wstring> args;
        for (size_t i = 3; i < tokens.size(); ++i) {
            args.push_back(tokens[i]);
        }
        return pythonBridge_.RunFile(tokens[2], args);
    }
    if (subcmd == L"exec") {
        if (tokens.size() < 3) {
            QueueOutput(L"Usage: py exec <code>\r\n");
            return false;
        }
        return pythonBridge_.RunCode(JoinTokens(tokens, 2));
    }

    QueueOutput(L"Usage: py run <file> [args...] | py exec <code>\r\n");
    return false;
}

void GuiTerminalApp::RunStartupPython() {
    if (startupPythonRequest_.mode == STARTUP_PYTHON_MODE_NONE) {
        return;
    }

    std::wstring command;
    if (startupPythonRequest_.mode == STARTUP_PYTHON_MODE_FILE) {
        command = L"py run " + QuoteCommandToken(startupPythonRequest_.payload);
        for (size_t i = 0; i < startupPythonRequest_.args.size(); ++i) {
            command.push_back(L' ');
            command += QuoteCommandToken(startupPythonRequest_.args[i]);
        }
    } else if (startupPythonRequest_.mode == STARTUP_PYTHON_MODE_EXEC) {
        command = L"py exec " + startupPythonRequest_.payload;
    }

    startupPythonRequest_ = StartupPythonRequest();

    if (command.empty()) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(commandMutex_);
        commandQueue_.push_back(command);
    }
    commandCv_.notify_one();
}

void GuiTerminalApp::WorkerLoop() {
    try {
        while (true) {
            std::wstring command;
            {
                std::unique_lock<std::mutex> lock(commandMutex_);
                commandCv_.wait(lock, [&]() { return stopWorker_ || !commandQueue_.empty(); });
                if (stopWorker_ && commandQueue_.empty()) {
                    break;
                }
                command = commandQueue_.front();
                commandQueue_.pop_front();
            }

            const std::wstring lower = ToLower(command);
            if (lower == L"clear" || lower == L"cls" || lower == L"history" || IsQuitCommand(lower)) {
                continue;
            }
            if (ToLower(Trim(command)).rfind(L"py", 0) == 0) {
                if (!HandlePythonCommand(command)) {
                    QueueOutput(L"Python command failed.\r\n");
                }
                continue;
            }

            const std::vector<std::wstring> tokens = Tokenize(command);
            if (tokens.empty()) {
                continue;
            }
            bool ok = false;
            {
                std::lock_guard<std::mutex> lock(debuggerCommandMutex_);
                ok = debugger_.ExecuteCommand(tokens);
            }
            if (!ok) {
                QueueOutput(L"Command failed.\r\n");
            }
        }
    } catch (const std::exception& ex) {
        QueueOutput(std::wstring(L"Worker exception: ") + AnsiToWide(ex.what()) + L"\r\n");
    } catch (...) {
        QueueOutput(L"Worker crashed.\r\n");
    }
}

LRESULT CALLBACK GuiTerminalApp::MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->hwnd_ = hwnd;
            app->ApplyWindowIcon();
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SETCURSOR:
            if (LOWORD(lParam) != HTCLIENT) {
                return DefWindowProcW(hwnd, msg, wParam, lParam);
            }
            SetCursor(ArrowCursor());
            return TRUE;
        case WM_GETDLGCODE:
            return DLGC_WANTALLKEYS | DLGC_WANTARROWS;
        case WM_ERASEBKGND:
            return 1;
        case WM_KEYDOWN:
            if (wParam == 'G' && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                app->ShowGotoDialog();
                return 0;
            }
            break;
        case WM_NCHITTEST: {
            POINT pt = {GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
            ScreenToClient(hwnd, &pt);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int resizeBorder = std::max<int>(
                6,
                GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER));
            const bool left = pt.x >= rc.left && pt.x < rc.left + resizeBorder;
            const bool right = pt.x < rc.right && pt.x >= rc.right - resizeBorder;
            const bool top = pt.y >= rc.top && pt.y < rc.top + resizeBorder;
            const bool bottom = pt.y < rc.bottom && pt.y >= rc.bottom - resizeBorder;
            if (top && left) {
                return HTTOPLEFT;
            }
            if (top && right) {
                return HTTOPRIGHT;
            }
            if (bottom && left) {
                return HTBOTTOMLEFT;
            }
            if (bottom && right) {
                return HTBOTTOMRIGHT;
            }
            if (top) {
                return HTTOP;
            }
            if (bottom) {
                return HTBOTTOM;
            }
            if (left) {
                return HTLEFT;
            }
            if (right) {
                return HTRIGHT;
            }
            if (pt.y >= 0 && pt.y < kCustomTitleHeight) {
                const int buttonLeft = std::max<int>(0, rc.right - kTitleButtonWidth * 3);
                const int iconSize = GetSystemMetrics(SM_CXSMICON);
                const int tabLeft = kTitleLeftSlotWidth;
                const int tabTop = 3;
                const int textX = kTitleTabIconX + iconSize + 11;
                const int tabWidth = std::min<int>(
                    std::max<int>(kTitleTabMinWidth, textX + 120),
                    std::max<int>(1, buttonLeft - tabLeft - 8));
                const int actionLeft = tabLeft + tabWidth + 3;
                const int actionRight = actionLeft + kTitleActionWidth;
                if (pt.x >= actionLeft && pt.x < actionRight) {
                    return HTCLIENT;
                }
                if (pt.x >= rc.right - kTitleButtonWidth * 3) {
                    return HTCLIENT;
                }
                return HTCAPTION;
            }
            return HTCLIENT;
        }
        case WM_ACTIVATE:
        case WM_ACTIVATEAPP:
            app->UpdateTitleTabWindow();
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        case WM_SETTEXT: {
            const LRESULT result = DefWindowProcW(hwnd, msg, wParam, lParam);
            app->UpdateTitleTabWindow();
            return result;
        }
        case WM_CREATE:
            if (!app->CreateChildControls()) {
                return -1;
            }
            app->CreateTitleTabWindow();
            app->UpdateTitleTabWindow();
            app->RedrawCommandLineArea();
            return 0;
        case WM_SIZE:
            ApplySmoothSmallWindowCorners(hwnd, wParam != SIZE_MAXIMIZED);
            app->Layout(LOWORD(lParam), HIWORD(lParam));
            app->UpdateTitleTabWindow();
            app->RedrawCommandLineArea();
            return 0;
        case WM_MOVE:
        case WM_WINDOWPOSCHANGED:
        case WM_SHOWWINDOW:
            app->UpdateTitleTabWindow();
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        case WM_APP_PAINT_TITLE_TAB:
            app->PaintTitleBarTab();
            return 0;
        case WM_MOUSEMOVE: {
            const int x = GET_X_LPARAM(lParam);
            const int y = GET_Y_LPARAM(lParam);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int buttonLeft = std::max<int>(0, rc.right - kTitleButtonWidth * 3);
            const int iconSize = GetSystemMetrics(SM_CXSMICON);
            const int tabLeft = kTitleLeftSlotWidth;
            const int tabTop = 3;
            const int tabHeight = kCustomTitleHeight - tabTop;
            const int textX = kTitleTabIconX + iconSize + 11;
            const int tabWidth = std::min<int>(
                std::max<int>(kTitleTabMinWidth, textX + 120),
                std::max<int>(1, buttonLeft - tabLeft - 8));
            const int actionLeft = tabLeft + tabWidth + 3;
            const int actionRight = actionLeft + kTitleActionWidth;
            int actionHover = -1;
            int buttonHover = -1;
            if (y >= 0 && y < kCustomTitleHeight) {
                if (x >= actionLeft && x < actionRight) {
                    if (x < actionLeft + kTitleActionSeparatorX) {
                        actionHover = 0;
                    } else if (x > actionLeft + kTitleActionSeparatorX) {
                        actionHover = 1;
                    }
                } else if (x >= rc.right - kTitleButtonWidth && x < rc.right) {
                    buttonHover = 2;
                } else if (x >= rc.right - kTitleButtonWidth * 2 && x < rc.right - kTitleButtonWidth) {
                    buttonHover = 1;
                } else if (x >= rc.right - kTitleButtonWidth * 3 && x < rc.right - kTitleButtonWidth * 2) {
                    buttonHover = 0;
                }
            }
            if (actionHover != app->titleActionHover_) {
                app->titleActionHover_ = actionHover;
                app->UpdateTitleTabWindow();
            }
            if (buttonHover != app->titleButtonHover_) {
                app->titleButtonHover_ = buttonHover;
                app->UpdateTitleTabWindow();
            }
            if (!app->titleMouseTracking_) {
                TRACKMOUSEEVENT tme = {};
                tme.cbSize = sizeof(tme);
                tme.dwFlags = TME_LEAVE;
                tme.hwndTrack = hwnd;
                if (TrackMouseEvent(&tme)) {
                    app->titleMouseTracking_ = true;
                }
            }
            break;
        }
        case WM_MOUSELEAVE:
            app->titleMouseTracking_ = false;
            if (app->titleActionPressed_ < 0 && app->titleActionHover_ != -1) {
                app->titleActionHover_ = -1;
                app->UpdateTitleTabWindow();
            }
            if (app->titleButtonPressed_ < 0 && app->titleButtonHover_ != -1) {
                app->titleButtonHover_ = -1;
                app->UpdateTitleTabWindow();
            }
            return 0;
        case WM_CAPTURECHANGED:
            if (reinterpret_cast<HWND>(lParam) != hwnd && (app->titleButtonPressed_ >= 0 || app->titleActionPressed_ >= 0)) {
                app->titleButtonPressed_ = -1;
                app->titleActionPressed_ = -1;
                app->titleActionHover_ = -1;
                app->titleButtonHover_ = -1;
                app->UpdateTitleTabWindow();
            }
            break;
        case WM_LBUTTONDBLCLK: {
            const int x = GET_X_LPARAM(lParam);
            const int y = GET_Y_LPARAM(lParam);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int buttonLeft = std::max<int>(0, rc.right - kTitleButtonWidth * 3);
            const int iconSize = GetSystemMetrics(SM_CXSMICON);
            const int tabLeft = kTitleLeftSlotWidth;
            const int tabTop = 3;
            const int tabHeight = kCustomTitleHeight - tabTop;
            const int textX = kTitleTabIconX + iconSize + 11;
            const int tabWidth = std::min<int>(
                std::max<int>(kTitleTabMinWidth, textX + 120),
                std::max<int>(1, buttonLeft - tabLeft - 8));
            const int actionLeft = tabLeft + tabWidth + 3;
            const int actionRight = actionLeft + kTitleActionWidth;
            if (y >= 0 && y < kCustomTitleHeight && x < actionLeft) {
                ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE);
                return 0;
            }
            break;
        }
        case WM_LBUTTONDOWN: {
            const int x = GET_X_LPARAM(lParam);
            const int y = GET_Y_LPARAM(lParam);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int buttonLeft = std::max<int>(0, rc.right - kTitleButtonWidth * 3);
            const int iconSize = GetSystemMetrics(SM_CXSMICON);
            const int tabLeft = kTitleLeftSlotWidth;
            const int tabTop = 3;
            const int tabHeight = kCustomTitleHeight - tabTop;
            const int textX = kTitleTabIconX + iconSize + 11;
            const int tabWidth = std::min<int>(
                std::max<int>(kTitleTabMinWidth, textX + 120),
                std::max<int>(1, buttonLeft - tabLeft - 8));
            const int actionLeft = tabLeft + tabWidth + 3;
            const int actionRight = actionLeft + kTitleActionWidth;
            int pressed = -1;
            int actionPressed = -1;
            if (y >= 0 && y < kCustomTitleHeight) {
                if (x >= actionLeft && x < actionRight) {
                    if (x < actionLeft + kTitleActionSeparatorX) {
                        actionPressed = 0;
                    } else if (x > actionLeft + kTitleActionSeparatorX) {
                        actionPressed = 1;
                    }
                } else if (x >= rc.right - kTitleButtonWidth && x < rc.right) {
                    pressed = 2;
                } else if (x >= rc.right - kTitleButtonWidth * 2 && x < rc.right - kTitleButtonWidth) {
                    pressed = 1;
                } else if (x >= rc.right - kTitleButtonWidth * 3 && x < rc.right - kTitleButtonWidth * 2) {
                    pressed = 0;
                }
            }
            if (actionPressed >= 0) {
                app->titleActionPressed_ = actionPressed;
                app->titleActionHover_ = actionPressed;
                SetCapture(hwnd);
                app->UpdateTitleTabWindow();
                return 0;
            }
            if (pressed >= 0) {
                app->titleButtonPressed_ = pressed;
                app->titleButtonHover_ = pressed;
                SetCapture(hwnd);
                app->UpdateTitleTabWindow();
                return 0;
            }
            break;
        }
        case WM_LBUTTONUP: {
            const int x = GET_X_LPARAM(lParam);
            const int y = GET_Y_LPARAM(lParam);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int buttonLeft = std::max<int>(0, rc.right - kTitleButtonWidth * 3);
            const int iconSize = GetSystemMetrics(SM_CXSMICON);
            const int tabLeft = kTitleLeftSlotWidth;
            const int tabTop = 3;
            const int tabHeight = kCustomTitleHeight - tabTop;
            const int textX = kTitleTabIconX + iconSize + 11;
            const int tabWidth = std::min<int>(
                std::max<int>(kTitleTabMinWidth, textX + 120),
                std::max<int>(1, buttonLeft - tabLeft - 8));
            const int actionLeft = tabLeft + tabWidth + 3;
            const int actionRight = actionLeft + kTitleActionWidth;
            const int pressed = app->titleButtonPressed_;
            const int actionPressed = app->titleActionPressed_;
            app->titleButtonPressed_ = -1;
            app->titleActionPressed_ = -1;
            if (GetCapture() == hwnd) {
                ReleaseCapture();
            }
            if (y >= 0 && y < kCustomTitleHeight) {
                if (actionPressed == 1 && x >= actionLeft + kTitleActionSeparatorX && x < actionRight) {
                    app->titleActionHover_ = 1;
                    app->UpdateTitleTabWindow();
                    POINT pt = {};
                    GetCursorPos(&pt);
                    app->ShowTitleMenu(pt);
                    return 0;
                }
                if (pressed == 2 && x >= rc.right - kTitleButtonWidth && x < rc.right) {
                    app->titleButtonHover_ = 2;
                    app->UpdateTitleTabWindow();
                    PostMessageW(hwnd, WM_CLOSE, 0, 0);
                    return 0;
                }
                if (pressed == 1 && x >= rc.right - kTitleButtonWidth * 2 && x < rc.right - kTitleButtonWidth) {
                    app->titleButtonHover_ = 1;
                    ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE);
                    app->UpdateTitleTabWindow();
                    return 0;
                }
                if (pressed == 0 && x >= rc.right - kTitleButtonWidth * 3 && x < rc.right - kTitleButtonWidth * 2) {
                    app->titleButtonHover_ = 0;
                    app->UpdateTitleTabWindow();
                    ShowWindow(hwnd, SW_MINIMIZE);
                    return 0;
                }
            }
            app->titleActionHover_ = -1;
            app->titleButtonHover_ = -1;
            app->UpdateTitleTabWindow();
            break;
        }
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            if (dc == nullptr) {
                EndPaint(hwnd, &ps);
                return 0;
            }
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int width = std::max<int>(1, rc.right - rc.left);
            const int height = std::max<int>(1, rc.bottom - rc.top);
            HDC memDc = CreateCompatibleDC(dc);
            HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, width, height) : nullptr;
            if (memDc != nullptr && memBitmap != nullptr) {
                HGDIOBJ oldBitmap = SelectObject(memDc, memBitmap);
                HBRUSH bg = CreateSolidBrush(kBackground);
                FillRect(memDc, &rc, bg);
                DeleteObject(bg);
                app->PaintTitleBarTab(memDc, width);
                app->PaintCommandLinePrompt(memDc);
                BitBlt(dc, 0, 0, width, height, memDc, 0, 0, SRCCOPY);
                SelectObject(memDc, oldBitmap);
            } else {
                app->PaintTitleBarTab(dc, width);
                app->PaintCommandLinePrompt(dc);
            }
            if (memBitmap != nullptr) {
                DeleteObject(memBitmap);
            }
            if (memDc != nullptr) {
                DeleteDC(memDc);
            }
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_APP_OUTPUT_READY:
            app->HandleOutputReady();
            return 0;
        case WM_APP_SHOW_DISASM_UI:
            app->ShowPendingDisassemblyUi();
            return 0;
        case WM_APP_SHOW_MEMORY_UI:
            app->ShowPendingMemoryUi();
            return 0;
        case WM_APP_SHOW_REGISTER_UI:
            app->ShowPendingRegisterUi();
            return 0;
        case WM_APP_SHOW_STACK_UI:
            app->ShowPendingStackUi();
            return 0;
        case WM_APP_SHOW_PSEUDOC_UI:
            app->ShowPendingPseudoCUi();
            return 0;
        case WM_APP_GOTO_COMPLETE:
            app->CompleteGotoDialog(reinterpret_cast<GotoResult*>(lParam));
            return 0;
        case WM_APP_DISASM_PAGE_READY:
            app->CompleteDisassemblyPageRefresh(reinterpret_cast<DisasmPageResult*>(lParam));
            return 0;
        case WM_APP_RUN_STARTUP_PY:
            try {
                app->RunStartupPython();
            } catch (const std::exception& ex) {
                app->QueueOutput(std::wstring(L"Startup Python exception: ") + AnsiToWide(ex.what()) + L"\r\n");
            } catch (...) {
                app->QueueOutput(L"Startup Python crashed.\r\n");
            }
            return 0;
        case WM_APP_PAINT_OUTPUT_SELECTION:
            app->outputSelectionPaintPending_ = false;
            app->PaintOutputSelection();
            return 0;
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_TITLE_MENU_SETTINGS:
                    MessageBoxW(
                        hwnd, 
                        TitleMenuText(ID_TITLE_MENU_SETTINGS, IsChineseUserInterface()), 
                        L"Z0BDbgCli", 
                        MB_OK | MB_ICONINFORMATION);
                    return 0;
                case ID_TITLE_MENU_COMMAND_PANEL:
                    MessageBoxW(
                        hwnd, 
                        TitleMenuText(ID_TITLE_MENU_COMMAND_PANEL, IsChineseUserInterface()), 
                        L"Z0BDbgCli", 
                        MB_OK | MB_ICONINFORMATION);
                    return 0;
                case ID_TITLE_MENU_ABOUT:
                    MessageBoxW(
                        hwnd, 
                        TitleMenuText(ID_TITLE_MENU_ABOUT, IsChineseUserInterface()),
                        L"Z0BDbgCli", 
                        MB_OK | MB_ICONINFORMATION);
                    return 0;
                default:
                    break;
            }
            break;
        case WM_MEASUREITEM: {
            const MEASUREITEMSTRUCT* mis = reinterpret_cast<const MEASUREITEMSTRUCT*>(lParam);
            if (mis != nullptr && mis->CtlType == ODT_MENU) {
                MEASUREITEMSTRUCT* out = reinterpret_cast<MEASUREITEMSTRUCT*>(lParam);
                out->itemWidth = 280;
                out->itemHeight = 36;
                return TRUE;
            }
            break;
        }
        case WM_DRAWITEM: {
            const DRAWITEMSTRUCT* dis = reinterpret_cast<const DRAWITEMSTRUCT*>(lParam);
            if (dis != nullptr && dis->CtlType == ODT_MENU) {
                RECT rcItem = dis->rcItem;
                const wchar_t* text = reinterpret_cast<const wchar_t*>(dis->itemData);
                const bool selected = (dis->itemState & ODS_SELECTED) != 0;
                const COLORREF menuColor = selected ? RGB(56, 56, 56) : RGB(24, 24, 24);
                HBRUSH bgBrush = CreateSolidBrush(menuColor);
                HRGN clipRgn = CreateRoundRectRgn(
                    rcItem.left + 1,
                    rcItem.top + 1,
                    rcItem.right - 1,
                    rcItem.bottom - 1,
                    12,
                    12);
                if (clipRgn != nullptr) {
                    SelectClipRgn(dis->hDC, clipRgn);
                }
                FillRect(dis->hDC, &rcItem, bgBrush);
                if (clipRgn != nullptr) {
                    SelectClipRgn(dis->hDC, nullptr);
                    DeleteObject(clipRgn);
                }
                DeleteObject(bgBrush);

                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, RGB(255, 255, 255));

                RECT textRc = rcItem;
                textRc.left += 18;
                textRc.right -= 18;
                DrawTextW(dis->hDC, text != nullptr ? text : L"", -1, &textRc, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
                return TRUE;
            }
            break;
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetTextColor(dc, kForeground);
            SetBkColor(dc, kBackground);
            static HBRUSH brush = CreateSolidBrush(kBackground);
            return reinterpret_cast<LRESULT>(brush);
        }
        case WM_APP_SUBMIT_INPUT:
            app->SubmitInput();
            return 0;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            app->HandleRightClickPasteOrCopy();
            return 0;
        case WM_SETFOCUS:
            if (app->inputWnd_ != nullptr) {
                SetFocus(app->inputWnd_);
            }
            return 0;
        case WM_CLOSE:
            app->DestroyTitleTabWindow();
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::OutputWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SETCURSOR:
            SetCursor(ArrowCursor());
            return TRUE;
        case WM_ERASEBKGND: {
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            HBRUSH brush = CreateSolidBrush(kBackground);
            FillRect(reinterpret_cast<HDC>(wParam), &rc, brush);
            DeleteObject(brush);
            return 1;
        }
        case WM_SIZE:
            app->UpdateOutputMetrics();
            app->UpdateOutputScrollInfo();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_VSCROLL: {
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);

            const LONG maxPos = std::max<LONG>(0, static_cast<LONG>(app->outputLineStarts_.size()) - app->visibleRows_);
            LONG pos = app->topLine_;
            switch (LOWORD(wParam)) {
                case SB_LINEUP: pos -= 1; break;
                case SB_LINEDOWN: pos += 1; break;
                case SB_PAGEUP: pos -= app->visibleRows_; break;
                case SB_PAGEDOWN: pos += app->visibleRows_; break;
                case SB_TOP: pos = 0; break;
                case SB_BOTTOM: pos = maxPos; break;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: pos = si.nTrackPos; break;
                default: break;
            }
            pos = std::clamp<LONG>(pos, 0, maxPos);
            if (pos != app->topLine_) {
                app->topLine_ = static_cast<int>(pos);
                app->UpdateOutputScrollInfo();
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_MOUSEWHEEL: {
            const short delta = GET_WHEEL_DELTA_WPARAM(wParam);
            const int lines = std::max<int>(1, 3);
            app->topLine_ = std::clamp<int>(app->topLine_ - (delta / WHEEL_DELTA) * lines, 0,
                                            std::max<int>(0, static_cast<int>(app->outputLineStarts_.size()) - app->visibleRows_));
            app->UpdateOutputScrollInfo();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_MOUSEHWHEEL: {
            return 0;
        }
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            if (dc == nullptr) {
                return 0;
            }

            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int width = std::max<int>(1, rc.right - rc.left);
            const int height = std::max<int>(1, rc.bottom - rc.top);

            HDC memDc = CreateCompatibleDC(dc);
            HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, width, height) : nullptr;
            if (memDc == nullptr || memBitmap == nullptr) {
                if (memBitmap != nullptr) {
                    DeleteObject(memBitmap);
                }
                if (memDc != nullptr) {
                    DeleteDC(memDc);
                }
                EndPaint(hwnd, &ps);
                return 0;
            }

            HGDIOBJ oldBitmap = SelectObject(memDc, memBitmap);
            HBRUSH brush = CreateSolidBrush(kBackground);
            FillRect(memDc, &rc, brush);
            DeleteObject(brush);
            app->PaintOutputContentToDc(memDc, rc);
            app->PaintOutputSelectionToDc(memDc, rc);

            BitBlt(dc, 0, 0, width, height, memDc, 0, 0, SRCCOPY);

            SelectObject(memDc, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_SETFOCUS:
            return 0;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            app->HandleRightClickPasteOrCopy();
            return 0;
        case WM_LBUTTONDOWN:
        case WM_LBUTTONDBLCLK: {
            app->HideTitleMenu();
            POINTL pt = {};
            pt.x = GET_X_LPARAM(lParam);
            pt.y = GET_Y_LPARAM(lParam);
            app->outputSelectionAnchor_ = app->OutputCharFromPoint(pt);
            app->outputSelecting_ = true;
            app->outputSelectionAutoScrollDirection_ = 0;
            app->outputSelectionLastPoint_ = pt;
            app->hasOutputSelection_ = false;
            app->outputSelectionStart_ = app->outputSelectionAnchor_;
            app->outputSelectionEnd_ = app->outputSelectionAnchor_;
            SetCapture(hwnd);
            app->RefreshOutputSelection();
            return 0;
        }
        case WM_MOUSEMOVE:
            if (app->outputSelecting_ && (wParam & MK_LBUTTON) != 0) {
                POINTL pt = {};
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
                app->outputSelectionLastPoint_ = pt;
                const LONG current = app->OutputCharFromPoint(pt);
                app->outputSelectionStart_ = std::min<LONG>(app->outputSelectionAnchor_, current);
                app->outputSelectionEnd_ = std::max<LONG>(app->outputSelectionAnchor_, current);
                app->hasOutputSelection_ = app->outputSelectionEnd_ > app->outputSelectionStart_;
                app->RefreshOutputSelection();

                RECT rc = {};
                GetClientRect(hwnd, &rc);
                int direction = 0;
                if (pt.y < rc.top) {
                    direction = -1;
                } else if (pt.y >= rc.bottom) {
                    direction = 1;
                }
                app->outputSelectionAutoScrollDirection_ = direction;
                if (direction != 0) {
                    SetTimer(hwnd, kOutputSelectionAutoScrollTimer, kSelectionAutoScrollIntervalMs, nullptr);
                } else {
                    KillTimer(hwnd, kOutputSelectionAutoScrollTimer);
                }
                return 0;
            }
            break;
        case WM_TIMER:
            if (wParam == kOutputSelectionAutoScrollTimer) {
                if (!app->outputSelecting_ || app->outputSelectionAutoScrollDirection_ == 0) {
                    KillTimer(hwnd, kOutputSelectionAutoScrollTimer);
                    app->outputSelectionAutoScrollDirection_ = 0;
                    return 0;
                }

                const int maxTop = std::max<int>(
                    0,
                    static_cast<int>(app->outputLineStarts_.size()) - app->visibleRows_);
                const int oldTop = app->topLine_;
                app->topLine_ = std::clamp<int>(
                    app->topLine_ + app->outputSelectionAutoScrollDirection_,
                    0,
                    maxTop);
                if (app->topLine_ == oldTop) {
                    return 0;
                }

                const LONG current = app->OutputCharFromPoint(app->outputSelectionLastPoint_);
                app->outputSelectionStart_ = std::min<LONG>(app->outputSelectionAnchor_, current);
                app->outputSelectionEnd_ = std::max<LONG>(app->outputSelectionAnchor_, current);
                app->hasOutputSelection_ = app->outputSelectionEnd_ > app->outputSelectionStart_;
                app->UpdateOutputScrollInfo();
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            break;
        case WM_KEYDOWN:
        case WM_KEYUP: {
            if (msg == WM_KEYDOWN && wParam == 'G' && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                app->ShowGotoDialog();
                HideCaret(hwnd);
                return 0;
            }
            const LRESULT result = app->outputOrigProc_ != nullptr
                ? CallWindowProcW(app->outputOrigProc_, hwnd, msg, wParam, lParam)
                : DefWindowProcW(hwnd, msg, wParam, lParam);
            if (msg == WM_KEYDOWN &&
                (wParam == VK_PRIOR || wParam == VK_NEXT ||
                 wParam == VK_HOME || wParam == VK_END ||
                 wParam == VK_UP || wParam == VK_DOWN)) {
                InvalidateRect(hwnd, nullptr, FALSE);
                UpdateWindow(hwnd);
            }
            HideCaret(hwnd);
            return result;
        }
        case WM_LBUTTONUP: {
            if (app->outputSelecting_) {
                POINTL pt = {};
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
                const LONG current = app->OutputCharFromPoint(pt);
                CHARRANGE range = {};
                range.cpMin = std::min<LONG>(app->outputSelectionAnchor_, current);
                range.cpMax = std::max<LONG>(app->outputSelectionAnchor_, current);
                app->outputSelectionStart_ = range.cpMin;
                app->outputSelectionEnd_ = range.cpMax;
                app->hasOutputSelection_ = range.cpMax > range.cpMin;
                app->outputSelecting_ = false;
                app->outputSelectionAutoScrollDirection_ = 0;
                KillTimer(hwnd, kOutputSelectionAutoScrollTimer);
                ReleaseCapture();
            }
            if (app->inputWnd_ != nullptr) {
                SetFocus(app->inputWnd_);
            }
            app->RefreshOutputSelection();
            return 0;
        }
        case WM_KILLFOCUS:
        case WM_CAPTURECHANGED:
            app->outputSelecting_ = false;
            app->outputSelectionAutoScrollDirection_ = 0;
            KillTimer(hwnd, kOutputSelectionAutoScrollTimer);
            app->QueueOutputSelectionPaint();
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::GotoDialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->gotoDialogWnd_ = hwnd;
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_CREATE: {
            const bool zh = IsChineseUserInterface();
            HWND label = CreateWindowExW(
                0,
                L"STATIC",
                zh ? L"地址或符号:" : L"Address or symbol:",
                WS_CHILD | WS_VISIBLE,
                16,
                18,
                380,
                18,
                hwnd,
                nullptr,
                app->instance_,
                nullptr);
            app->gotoEditWnd_ = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"COMBOBOX",
                L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWN | CBS_AUTOHSCROLL,
                16,
                42,
                388,
                180,
                hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_GOTO_EDIT)),
                app->instance_,
                nullptr);
            app->gotoErrorWnd_ = CreateWindowExW(
                0,
                L"STATIC",
                L"",
                WS_CHILD | WS_VISIBLE,
                16,
                72,
                388,
                34,
                hwnd,
                nullptr,
                app->instance_,
                nullptr);
            HWND ok = CreateWindowExW(
                0,
                L"BUTTON",
                zh ? L"确定" : L"OK",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                226,
                112,
                82,
                26,
                hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_GOTO_OK)),
                app->instance_,
                nullptr);
            HWND cancel = CreateWindowExW(
                0,
                L"BUTTON",
                zh ? L"取消" : L"Cancel",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                322,
                112,
                82,
                26,
                hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_GOTO_CANCEL)),
                app->instance_,
                nullptr);
            HWND controls[] = {label, app->gotoEditWnd_, app->gotoErrorWnd_, ok, cancel};
            for (size_t i = 0; i < sizeof(controls) / sizeof(controls[0]); ++i) {
                if (controls[i] != nullptr && app->font_ != nullptr) {
                    SendMessageW(controls[i], WM_SETFONT, reinterpret_cast<WPARAM>(app->font_), TRUE);
                }
            }
            if (app->gotoEditWnd_ != nullptr) {
                SendMessageW(app->gotoEditWnd_, CB_LIMITTEXT, 480, 0);
                for (size_t i = 0; i < app->gotoHistory_.size(); ++i) {
                    SendMessageW(app->gotoEditWnd_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(app->gotoHistory_[i].c_str()));
                }
            }
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            HBRUSH brush = CreateSolidBrush(RGB(24, 24, 24));
            FillRect(dc, &rc, brush);
            DeleteObject(brush);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            HWND child = reinterpret_cast<HWND>(lParam);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, child == app->gotoErrorWnd_ ? app->gotoStatusColor_ : RGB(235, 235, 235));
            return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetTextColor(dc, RGB(255, 255, 255));
            SetBkColor(dc, RGB(24, 24, 24));
            static HBRUSH editBrush = CreateSolidBrush(RGB(24, 24, 24));
            return reinterpret_cast<LRESULT>(editBrush);
        }
        case WM_CTLCOLORLISTBOX: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetTextColor(dc, RGB(255, 255, 255));
            SetBkColor(dc, RGB(24, 24, 24));
            static HBRUSH listBrush = CreateSolidBrush(RGB(24, 24, 24));
            return reinterpret_cast<LRESULT>(listBrush);
        }
        case WM_DRAWITEM: {
            DRAWITEMSTRUCT* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
            if (dis != nullptr && dis->CtlType == ODT_BUTTON) {
                const bool disabled = (dis->itemState & ODS_DISABLED) != 0;
                const bool pressed = (dis->itemState & ODS_SELECTED) != 0;
                const COLORREF bgColor = disabled ? RGB(28, 28, 28) : (pressed ? RGB(58, 58, 58) : RGB(36, 36, 36));
                HBRUSH brush = CreateSolidBrush(bgColor);
                FillRect(dis->hDC, &dis->rcItem, brush);
                DeleteObject(brush);
                HPEN pen = CreatePen(PS_SOLID, 1, RGB(80, 80, 80));
                HGDIOBJ oldPen = SelectObject(dis->hDC, pen);
                HGDIOBJ oldBrush = SelectObject(dis->hDC, GetStockObject(NULL_BRUSH));
                Rectangle(dis->hDC, dis->rcItem.left, dis->rcItem.top, dis->rcItem.right, dis->rcItem.bottom);
                SelectObject(dis->hDC, oldBrush);
                SelectObject(dis->hDC, oldPen);
                DeleteObject(pen);

                wchar_t text[64] = {};
                GetWindowTextW(dis->hwndItem, text, static_cast<int>(sizeof(text) / sizeof(text[0])));
                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, disabled ? RGB(120, 120, 120) : RGB(255, 255, 255));
                RECT textRc = dis->rcItem;
                DrawTextW(dis->hDC, text, -1, &textRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                return TRUE;
            }
            break;
        }
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_GOTO_OK:
                    app->SubmitGotoDialog();
                    return 0;
                case ID_GOTO_CANCEL:
                    app->HideGotoDialog();
                    return 0;
                default:
                    break;
            }
            break;
        case WM_KEYDOWN:
            if (wParam == VK_RETURN) {
                app->SubmitGotoDialog();
                return 0;
            }
            if (wParam == VK_ESCAPE) {
                app->HideGotoDialog();
                return 0;
            }
            break;
        case WM_CLOSE:
            app->HideGotoDialog();
            return 0;
        case WM_DESTROY:
            if (app->gotoDialogWnd_ == hwnd) {
                app->gotoDialogWnd_ = nullptr;
                app->gotoEditWnd_ = nullptr;
                app->gotoErrorWnd_ = nullptr;
            }
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::DisasmToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->disasmToolWnd_ = hwnd;
            ApplyConsoleLikeChrome(hwnd);
            app->ApplyWindowIcon();
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SIZE:
            app->LayoutDisassemblyTool();
            return 0;
        case WM_KEYDOWN:
            if (wParam == 'G' && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                app->ShowGotoDialog();
                return 0;
            }
            break;
        case WM_MOUSEWHEEL:
            if (app->disasmViewWnd_ != nullptr && IsWindow(app->disasmViewWnd_)) {
                SendMessageW(app->disasmViewWnd_, msg, wParam, lParam);
                return 0;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            if (app->disasmToolWnd_ == hwnd) {
                app->disasmToolWnd_ = nullptr;
                app->disasmViewWnd_ = nullptr;
            }
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::DisasmViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->disasmViewWnd_ = hwnd;
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SETCURSOR:
            if (LOWORD(lParam) == HTCLIENT) {
                POINT pt = {};
                GetCursorPos(&pt);
                ScreenToClient(hwnd, &pt);
                if (app->disasmDragCol_ >= 0 || app->HitTestDisassemblyColumnSeparator(pt.x) >= 0) {
                    SetCursor(SizeWeCursor());
                    return TRUE;
                }
            }
            SetCursor(ArrowCursor());
            return TRUE;
        case WM_GETDLGCODE:
            return DLGC_WANTALLKEYS | DLGC_WANTARROWS;
        case WM_ERASEBKGND:
            return 1;
        case WM_KEYDOWN:
            if (wParam == 'G' && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                app->ShowGotoDialog();
                return 0;
            }
            if (wParam == VK_RETURN) {
                app->JumpSelectedDisassemblyTarget();
                return 0;
            }
            break;
        case WM_SIZE:
            app->UpdateDisassemblyMetrics();
            app->UpdateDisassemblyScrollInfo();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_VSCROLL: {
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            const int maxTop = std::max<int>(0, static_cast<int>(app->disasmRows_.size()) - app->disasmVisibleRows_);
            int pos = app->disasmTopRow_;
            switch (LOWORD(wParam)) {
                case SB_LINEUP: pos -= 1; break;
                case SB_LINEDOWN: pos += 1; break;
                case SB_PAGEUP: pos -= app->disasmVisibleRows_; break;
                case SB_PAGEDOWN: pos += app->disasmVisibleRows_; break;
                case SB_TOP: pos = 0; break;
                case SB_BOTTOM: pos = maxTop; break;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: pos = si.nTrackPos; break;
                default: break;
            }
            pos = std::clamp<int>(pos, 0, maxTop);
            if (pos != app->disasmTopRow_) {
                app->disasmTopRow_ = pos;
                app->UpdateDisassemblyScrollInfo();
                app->RefreshDisassemblyPageIfNeeded();
                if (app->DisassemblyVisibleRangeHasInstruction()) {
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                KillTimer(hwnd, kDisasmPageLoadTimer);
                SetTimer(hwnd, kDisasmPageLoadTimer, 20, nullptr);
            }
            return 0;
        }
        case WM_MOUSEWHEEL: {
            const short delta = GET_WHEEL_DELTA_WPARAM(wParam);
            if (delta == 0) {
                return 0;
            }
            const int maxTop = std::max<int>(0, static_cast<int>(app->disasmRows_.size()) - app->disasmVisibleRows_);
            const int oldTop = app->disasmTopRow_;
            const int wheelNotches = std::max<int>(1, std::abs(static_cast<int>(delta)) / WHEEL_DELTA);
            const int wheelLines = wheelNotches * 3;
            app->disasmTopRow_ = std::clamp<int>(
                app->disasmTopRow_ + (delta < 0 ? wheelLines : -wheelLines),
                0,
                maxTop);
            if (app->disasmTopRow_ != oldTop) {
                app->UpdateDisassemblyScrollInfo();
                app->RefreshDisassemblyPageIfNeeded();
                if (app->DisassemblyVisibleRangeHasInstruction()) {
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                KillTimer(hwnd, kDisasmPageLoadTimer);
                SetTimer(hwnd, kDisasmPageLoadTimer, 20, nullptr);
            }
            return 0;
        }
        case WM_TIMER:
            if (wParam == kDisasmPageLoadTimer) {
                KillTimer(hwnd, kDisasmPageLoadTimer);
                app->RefreshDisassemblyPageIfNeeded();
                return 0;
            }
            break;
        case WM_CONTEXTMENU: {
            POINT pt = {};
            if (GET_X_LPARAM(lParam) == -1 && GET_Y_LPARAM(lParam) == -1) {
                RECT rc = {};
                GetClientRect(hwnd, &rc);
                pt.x = rc.left + 24;
                pt.y = rc.top + app->disasmRowHeight_ + 4;
                ClientToScreen(hwnd, &pt);
            } else {
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
            }

            POINT clientPt = pt;
            ScreenToClient(hwnd, &clientPt);
            const int row = app->DisassemblyRowFromPoint(clientPt.y);
            if (row >= 0) {
                const int selStart = (app->disasmSelectionAnchor_ >= 0 && app->disasmSelectionEnd_ >= 0)
                    ? std::min<int>(app->disasmSelectionAnchor_, app->disasmSelectionEnd_)
                    : -1;
                const int selEnd = (app->disasmSelectionAnchor_ >= 0 && app->disasmSelectionEnd_ >= 0)
                    ? std::max<int>(app->disasmSelectionAnchor_, app->disasmSelectionEnd_)
                    : -1;
                if (row < selStart || row > selEnd) {
                    app->disasmSelectionAnchor_ = row;
                    app->disasmSelectionEnd_ = row;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
            }

            HMENU menu = CreatePopupMenu();
            HMENU copyMenu = CreatePopupMenu();
            if (menu == nullptr || copyMenu == nullptr) {
                if (copyMenu != nullptr) {
                    DestroyMenu(copyMenu);
                }
                if (menu != nullptr) {
                    DestroyMenu(menu);
                }
                return 0;
            }
            const bool zh = IsChineseUserInterface();
            const bool hasSelection = !app->BuildDisassemblySelectionText().empty();
            std::wstring jumpTarget;
            const bool canFollow = app->TryGetSelectedDisassemblyJumpTarget(jumpTarget);
            AppendMenuW(
                menu,
                MF_STRING | (canFollow ? MF_ENABLED : MF_GRAYED),
                ID_DISASM_FOLLOW,
                zh ? L"跟随" : L"Follow");
            AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(
                copyMenu,
                MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED),
                ID_DISASM_COPY_CLIPBOARD,
                zh ? L"到剪切板" : L"To Clipboard");
            AppendMenuW(
                copyMenu,
                MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED),
                ID_DISASM_COPY_FILE,
                zh ? L"到文件" : L"To File");
            AppendMenuW(
                menu,
                MF_POPUP | (hasSelection ? MF_ENABLED : MF_GRAYED),
                reinterpret_cast<UINT_PTR>(copyMenu),
                zh ? L"复制" : L"Copy");
            const UINT cmd = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                pt.x,
                pt.y,
                0,
                hwnd,
                nullptr);
            DestroyMenu(menu);
            if (cmd == ID_DISASM_FOLLOW) {
                app->JumpSelectedDisassemblyTarget();
            } else if (cmd == ID_DISASM_COPY_CLIPBOARD) {
                app->CopyDisassemblySelectionToClipboard();
            } else if (cmd == ID_DISASM_COPY_FILE) {
                app->SaveDisassemblySelectionToFile();
            }
            return 0;
        }
        case WM_LBUTTONDOWN: {
            SetFocus(hwnd);
            app->HideTitleMenu();
            const int x = GET_X_LPARAM(lParam);
            const int hit = app->HitTestDisassemblyColumnSeparator(x);
            if (hit >= 0) {
                app->disasmDragCol_ = hit;
                app->disasmDragStartX_ = x;
                if (hit == 0) {
                    app->disasmDragStartW_ = app->disasmColAddrW_;
                } else if (hit == 1) {
                    app->disasmDragStartW_ = app->disasmColHexW_;
                } else {
                    app->disasmDragStartW_ = app->disasmColAsmW_;
                }
                SetCapture(hwnd);
                return 0;
            }
            const int row = app->DisassemblyRowFromPoint(GET_Y_LPARAM(lParam));
            app->disasmSelecting_ = row >= 0;
            app->disasmSelectionAnchor_ = row;
            app->disasmSelectionEnd_ = row;
            if (row >= 0) {
                SetCapture(hwnd);
            }
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_MOUSEMOVE:
            if (app->disasmDragCol_ >= 0 && GetCapture() == hwnd) {
                const int delta = GET_X_LPARAM(lParam) - app->disasmDragStartX_;
                const int width = std::max<int>(60, app->disasmDragStartW_ + delta);
                if (app->disasmDragCol_ == 0) {
                    app->disasmColAddrW_ = width;
                } else if (app->disasmDragCol_ == 1) {
                    app->disasmColHexW_ = width;
                } else {
                    app->disasmColAsmW_ = width;
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (app->disasmSelecting_ && GetCapture() == hwnd) {
                int row = app->DisassemblyRowFromPoint(GET_Y_LPARAM(lParam));
                if (row < 0 && !app->disasmRows_.empty()) {
                    row = GET_Y_LPARAM(lParam) < app->disasmRowHeight_
                        ? 0
                        : static_cast<int>(app->disasmRows_.size()) - 1;
                }
                if (row >= 0 && row != app->disasmSelectionEnd_) {
                    app->disasmSelectionEnd_ = row;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return 0;
            }
            break;
        case WM_LBUTTONUP:
            if (app->disasmDragCol_ >= 0) {
                app->disasmDragCol_ = -1;
                app->disasmDragStartX_ = 0;
                app->disasmDragStartW_ = 0;
                if (GetCapture() == hwnd) {
                    ReleaseCapture();
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (app->disasmSelecting_) {
                const int row = app->DisassemblyRowFromPoint(GET_Y_LPARAM(lParam));
                if (row >= 0) {
                    app->disasmSelectionEnd_ = row;
                }
                app->disasmSelecting_ = false;
                if (GetCapture() == hwnd) {
                    ReleaseCapture();
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            break;
        case WM_CAPTURECHANGED:
            app->disasmDragCol_ = -1;
            app->disasmDragStartX_ = 0;
            app->disasmDragStartW_ = 0;
            app->disasmSelecting_ = false;
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            if (dc == nullptr) {
                return 0;
            }
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int width = std::max<int>(1, rc.right - rc.left);
            const int height = std::max<int>(1, rc.bottom - rc.top);
            HDC memDc = CreateCompatibleDC(dc);
            HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, width, height) : nullptr;
            if (memDc == nullptr || memBitmap == nullptr) {
                if (memBitmap != nullptr) {
                    DeleteObject(memBitmap);
                }
                if (memDc != nullptr) {
                    DeleteDC(memDc);
                }
                EndPaint(hwnd, &ps);
                return 0;
            }
            HGDIOBJ oldBitmap = SelectObject(memDc, memBitmap);
            app->PaintDisassemblyView(memDc, ps.rcPaint);
            BitBlt(dc, 0, 0, width, height, memDc, 0, 0, SRCCOPY);
            SelectObject(memDc, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::MemoryToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->memoryToolWnd_ = hwnd;
            ApplyConsoleLikeChrome(hwnd);
            app->ApplyWindowIcon();
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SIZE:
            app->LayoutMemoryTool();
            return 0;
        case WM_MOUSEWHEEL:
            if (app->memoryViewWnd_ != nullptr && IsWindow(app->memoryViewWnd_)) {
                SendMessageW(app->memoryViewWnd_, msg, wParam, lParam);
                return 0;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            if (app->memoryToolWnd_ == hwnd) {
                app->memoryToolWnd_ = nullptr;
                app->memoryViewWnd_ = nullptr;
            }
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::MemoryViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->memoryViewWnd_ = hwnd;
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SETCURSOR:
            if (LOWORD(lParam) == HTCLIENT) {
                POINT pt = {};
                GetCursorPos(&pt);
                ScreenToClient(hwnd, &pt);
                if (app->memoryDragCol_ >= 0 || app->HitTestMemoryColumnSeparator(pt.x) >= 0) {
                    SetCursor(SizeWeCursor());
                    return TRUE;
                }
            }
            SetCursor(ArrowCursor());
            return TRUE;
        case WM_GETDLGCODE:
            return DLGC_WANTALLKEYS | DLGC_WANTARROWS;
        case WM_ERASEBKGND:
            return 1;
        case WM_SIZE:
            app->UpdateMemoryMetrics();
            app->UpdateMemoryScrollInfo();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_VSCROLL: {
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            const int maxTop = std::max<int>(0, static_cast<int>(app->memoryRows_.size()) - app->memoryVisibleRows_);
            int pos = app->memoryTopRow_;
            switch (LOWORD(wParam)) {
                case SB_LINEUP: pos -= 1; break;
                case SB_LINEDOWN: pos += 1; break;
                case SB_PAGEUP: pos -= app->memoryVisibleRows_; break;
                case SB_PAGEDOWN: pos += app->memoryVisibleRows_; break;
                case SB_TOP: pos = 0; break;
                case SB_BOTTOM: pos = maxTop; break;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: pos = si.nTrackPos; break;
                default: break;
            }
            pos = std::clamp<int>(pos, 0, maxTop);
            if (pos != app->memoryTopRow_) {
                app->memoryTopRow_ = pos;
                app->UpdateMemoryScrollInfo();
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_MOUSEWHEEL: {
            const short delta = GET_WHEEL_DELTA_WPARAM(wParam);
            if (delta == 0) {
                return 0;
            }
            const int maxTop = std::max<int>(0, static_cast<int>(app->memoryRows_.size()) - app->memoryVisibleRows_);
            const int oldTop = app->memoryTopRow_;
            const int wheelNotches = std::max<int>(1, std::abs(static_cast<int>(delta)) / WHEEL_DELTA);
            app->memoryTopRow_ = std::clamp<int>(
                app->memoryTopRow_ + (delta < 0 ? wheelNotches * 3 : -wheelNotches * 3),
                0,
                maxTop);
            if (app->memoryTopRow_ != oldTop) {
                app->UpdateMemoryScrollInfo();
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_KEYDOWN:
            if (wParam == 'C' && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                app->CopyMemorySelectionToClipboard();
                return 0;
            }
            break;
        case WM_CONTEXTMENU: {
            POINT pt = {};
            if (GET_X_LPARAM(lParam) == -1 && GET_Y_LPARAM(lParam) == -1) {
                RECT rc = {};
                GetClientRect(hwnd, &rc);
                pt.x = rc.left + 24;
                pt.y = rc.top + app->memoryRowHeight_ + 4;
                ClientToScreen(hwnd, &pt);
            } else {
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
            }
            POINT clientPt = pt;
            ScreenToClient(hwnd, &clientPt);
            const int row = app->MemoryRowFromPoint(clientPt.y);
            if (row >= 0) {
                const int selStart = (app->memorySelectionAnchor_ >= 0 && app->memorySelectionEnd_ >= 0)
                    ? std::min<int>(app->memorySelectionAnchor_, app->memorySelectionEnd_)
                    : -1;
                const int selEnd = (app->memorySelectionAnchor_ >= 0 && app->memorySelectionEnd_ >= 0)
                    ? std::max<int>(app->memorySelectionAnchor_, app->memorySelectionEnd_)
                    : -1;
                if (row < selStart || row > selEnd) {
                    app->memorySelectionAnchor_ = row;
                    app->memorySelectionEnd_ = row;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
            }
            HMENU menu = CreatePopupMenu();
            HMENU copyMenu = CreatePopupMenu();
            if (menu == nullptr || copyMenu == nullptr) {
                if (copyMenu != nullptr) {
                    DestroyMenu(copyMenu);
                }
                if (menu != nullptr) {
                    DestroyMenu(menu);
                }
                return 0;
            }
            const bool zh = IsChineseUserInterface();
            const bool hasSelection = !app->BuildMemorySelectionText().empty();
            AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), ID_VIEW_COPY_CLIPBOARD, zh ? L"到剪切板" : L"To Clipboard");
            AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), ID_VIEW_COPY_FILE, zh ? L"到文件" : L"To File");
            AppendMenuW(menu, MF_POPUP | (hasSelection ? MF_ENABLED : MF_GRAYED), reinterpret_cast<UINT_PTR>(copyMenu), zh ? L"复制" : L"Copy");
            const UINT cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(menu);
            if (cmd == ID_VIEW_COPY_CLIPBOARD) {
                app->CopyMemorySelectionToClipboard();
            } else if (cmd == ID_VIEW_COPY_FILE) {
                app->SaveMemorySelectionToFile();
            }
            return 0;
        }
        case WM_LBUTTONDOWN: {
            SetFocus(hwnd);
            app->HideTitleMenu();
            const int x = GET_X_LPARAM(lParam);
            const int hit = app->HitTestMemoryColumnSeparator(x);
            if (hit >= 0) {
                app->memoryDragCol_ = hit;
                app->memoryDragStartX_ = x;
                app->memoryDragStartW_ = hit == 0 ? app->memoryColAddrW_ : app->memoryColHexW_;
                SetCapture(hwnd);
                return 0;
            }
            const int row = app->MemoryRowFromPoint(GET_Y_LPARAM(lParam));
            app->memorySelecting_ = row >= 0;
            app->memorySelectionAnchor_ = row;
            app->memorySelectionEnd_ = row;
            if (row >= 0) {
                SetCapture(hwnd);
            }
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_MOUSEMOVE:
            if (app->memoryDragCol_ >= 0 && GetCapture() == hwnd) {
                SetCursor(SizeWeCursor());
                const int delta = GET_X_LPARAM(lParam) - app->memoryDragStartX_;
                const int width = std::max<int>(60, app->memoryDragStartW_ + delta);
                if (app->memoryDragCol_ == 0) {
                    app->memoryColAddrW_ = width;
                } else {
                    app->memoryColHexW_ = width;
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (app->memorySelecting_ && GetCapture() == hwnd) {
                int row = app->MemoryRowFromPoint(GET_Y_LPARAM(lParam));
                if (row < 0 && !app->memoryRows_.empty()) {
                    row = GET_Y_LPARAM(lParam) < app->memoryRowHeight_
                        ? 0
                        : static_cast<int>(app->memoryRows_.size()) - 1;
                }
                if (row >= 0 && row != app->memorySelectionEnd_) {
                    app->memorySelectionEnd_ = row;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return 0;
            }
            if (app->HitTestMemoryColumnSeparator(GET_X_LPARAM(lParam)) >= 0) {
                SetCursor(SizeWeCursor());
                return 0;
            }
            SetCursor(ArrowCursor());
            break;
        case WM_LBUTTONUP:
            if (app->memoryDragCol_ >= 0) {
                app->memoryDragCol_ = -1;
                app->memoryDragStartX_ = 0;
                app->memoryDragStartW_ = 0;
                if (GetCapture() == hwnd) {
                    ReleaseCapture();
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (app->memorySelecting_) {
                const int row = app->MemoryRowFromPoint(GET_Y_LPARAM(lParam));
                if (row >= 0) {
                    app->memorySelectionEnd_ = row;
                }
                app->memorySelecting_ = false;
                if (GetCapture() == hwnd) {
                    ReleaseCapture();
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            break;
        case WM_CAPTURECHANGED:
            app->memoryDragCol_ = -1;
            app->memoryDragStartX_ = 0;
            app->memoryDragStartW_ = 0;
            app->memorySelecting_ = false;
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            if (dc == nullptr) {
                return 0;
            }
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int width = std::max<int>(1, rc.right - rc.left);
            const int height = std::max<int>(1, rc.bottom - rc.top);
            HDC memDc = CreateCompatibleDC(dc);
            HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, width, height) : nullptr;
            if (memDc == nullptr || memBitmap == nullptr) {
                if (memBitmap != nullptr) {
                    DeleteObject(memBitmap);
                }
                if (memDc != nullptr) {
                    DeleteDC(memDc);
                }
                EndPaint(hwnd, &ps);
                return 0;
            }
            HGDIOBJ oldBitmap = SelectObject(memDc, memBitmap);
            app->PaintMemoryView(memDc, ps.rcPaint);
            BitBlt(dc, 0, 0, width, height, memDc, 0, 0, SRCCOPY);
            SelectObject(memDc, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::RegisterToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->registerToolWnd_ = hwnd;
            ApplyConsoleLikeChrome(hwnd);
            app->ApplyWindowIcon();
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SIZE:
            app->LayoutRegisterTool();
            return 0;
        case WM_MOUSEWHEEL:
            if (app->registerViewWnd_ != nullptr && IsWindow(app->registerViewWnd_)) {
                SendMessageW(app->registerViewWnd_, msg, wParam, lParam);
                return 0;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            if (app->registerToolWnd_ == hwnd) {
                app->registerToolWnd_ = nullptr;
                app->registerViewWnd_ = nullptr;
            }
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::RegisterViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->registerViewWnd_ = hwnd;
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SETCURSOR:
            if (LOWORD(lParam) == HTCLIENT) {
                POINT pt = {};
                GetCursorPos(&pt);
                ScreenToClient(hwnd, &pt);
                if (app->registerDragCol_ >= 0 || app->HitTestRegisterColumnSeparator(pt.x) >= 0) {
                    SetCursor(SizeWeCursor());
                    return TRUE;
                }
            }
            SetCursor(ArrowCursor());
            return TRUE;
        case WM_GETDLGCODE:
            return DLGC_WANTALLKEYS | DLGC_WANTARROWS;
        case WM_ERASEBKGND:
            return 1;
        case WM_SIZE:
            app->UpdateRegisterMetrics();
            app->UpdateRegisterScrollInfo();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_VSCROLL: {
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            const int maxTop = std::max<int>(0, static_cast<int>(app->registerRows_.size()) - app->registerVisibleRows_);
            int pos = app->registerTopRow_;
            switch (LOWORD(wParam)) {
                case SB_LINEUP: pos -= 1; break;
                case SB_LINEDOWN: pos += 1; break;
                case SB_PAGEUP: pos -= app->registerVisibleRows_; break;
                case SB_PAGEDOWN: pos += app->registerVisibleRows_; break;
                case SB_TOP: pos = 0; break;
                case SB_BOTTOM: pos = maxTop; break;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: pos = si.nTrackPos; break;
                default: break;
            }
            pos = std::clamp<int>(pos, 0, maxTop);
            if (pos != app->registerTopRow_) {
                app->registerTopRow_ = pos;
                app->UpdateRegisterScrollInfo();
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_MOUSEWHEEL: {
            const short delta = GET_WHEEL_DELTA_WPARAM(wParam);
            if (delta == 0) {
                return 0;
            }
            const int maxTop = std::max<int>(0, static_cast<int>(app->registerRows_.size()) - app->registerVisibleRows_);
            const int oldTop = app->registerTopRow_;
            const int wheelNotches = std::max<int>(1, std::abs(static_cast<int>(delta)) / WHEEL_DELTA);
            app->registerTopRow_ = std::clamp<int>(
                app->registerTopRow_ + (delta < 0 ? wheelNotches * 3 : -wheelNotches * 3),
                0,
                maxTop);
            if (app->registerTopRow_ != oldTop) {
                app->UpdateRegisterScrollInfo();
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_KEYDOWN:
            if (wParam == 'C' && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                app->CopyRegisterSelectionToClipboard();
                return 0;
            }
            break;
        case WM_CONTEXTMENU: {
            POINT pt = {};
            if (GET_X_LPARAM(lParam) == -1 && GET_Y_LPARAM(lParam) == -1) {
                RECT rc = {};
                GetClientRect(hwnd, &rc);
                pt.x = rc.left + 24;
                pt.y = rc.top + app->registerRowHeight_ + 4;
                ClientToScreen(hwnd, &pt);
            } else {
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
            }
            POINT clientPt = pt;
            ScreenToClient(hwnd, &clientPt);
            const int row = app->RegisterRowFromPoint(clientPt.y);
            if (row >= 0) {
                const int selStart = (app->registerSelectionAnchor_ >= 0 && app->registerSelectionEnd_ >= 0)
                    ? std::min<int>(app->registerSelectionAnchor_, app->registerSelectionEnd_)
                    : -1;
                const int selEnd = (app->registerSelectionAnchor_ >= 0 && app->registerSelectionEnd_ >= 0)
                    ? std::max<int>(app->registerSelectionAnchor_, app->registerSelectionEnd_)
                    : -1;
                if (row < selStart || row > selEnd) {
                    app->registerSelectionAnchor_ = row;
                    app->registerSelectionEnd_ = row;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
            }
            HMENU menu = CreatePopupMenu();
            HMENU copyMenu = CreatePopupMenu();
            if (menu == nullptr || copyMenu == nullptr) {
                if (copyMenu != nullptr) {
                    DestroyMenu(copyMenu);
                }
                if (menu != nullptr) {
                    DestroyMenu(menu);
                }
                return 0;
            }
            const bool zh = IsChineseUserInterface();
            const bool hasSelection = !app->BuildRegisterSelectionText().empty();
            AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), ID_VIEW_COPY_CLIPBOARD, zh ? L"到剪切板" : L"To Clipboard");
            AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), ID_VIEW_COPY_FILE, zh ? L"到文件" : L"To File");
            AppendMenuW(menu, MF_POPUP | (hasSelection ? MF_ENABLED : MF_GRAYED), reinterpret_cast<UINT_PTR>(copyMenu), zh ? L"复制" : L"Copy");
            const UINT cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(menu);
            if (cmd == ID_VIEW_COPY_CLIPBOARD) {
                app->CopyRegisterSelectionToClipboard();
            } else if (cmd == ID_VIEW_COPY_FILE) {
                app->SaveRegisterSelectionToFile();
            }
            return 0;
        }
        case WM_LBUTTONDOWN: {
            SetFocus(hwnd);
            app->HideTitleMenu();
            const int x = GET_X_LPARAM(lParam);
            const int hit = app->HitTestRegisterColumnSeparator(x);
            if (hit >= 0) {
                app->registerDragCol_ = hit;
                app->registerDragStartX_ = x;
                app->registerDragStartW_ = hit == 0 ? app->registerColNameW_ : app->registerColValueW_;
                SetCapture(hwnd);
                return 0;
            }
            const int row = app->RegisterRowFromPoint(GET_Y_LPARAM(lParam));
            app->registerSelecting_ = row >= 0;
            app->registerSelectionAnchor_ = row;
            app->registerSelectionEnd_ = row;
            if (row >= 0) {
                SetCapture(hwnd);
            }
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_MOUSEMOVE:
            if (app->registerDragCol_ >= 0 && GetCapture() == hwnd) {
                SetCursor(SizeWeCursor());
                const int delta = GET_X_LPARAM(lParam) - app->registerDragStartX_;
                const int width = std::max<int>(60, app->registerDragStartW_ + delta);
                if (app->registerDragCol_ == 0) {
                    app->registerColNameW_ = width;
                } else {
                    app->registerColValueW_ = width;
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (app->registerSelecting_ && GetCapture() == hwnd) {
                int row = app->RegisterRowFromPoint(GET_Y_LPARAM(lParam));
                if (row < 0 && !app->registerRows_.empty()) {
                    row = GET_Y_LPARAM(lParam) < app->registerRowHeight_
                        ? 0
                        : static_cast<int>(app->registerRows_.size()) - 1;
                }
                if (row >= 0 && row != app->registerSelectionEnd_) {
                    app->registerSelectionEnd_ = row;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return 0;
            }
            if (app->HitTestRegisterColumnSeparator(GET_X_LPARAM(lParam)) >= 0) {
                SetCursor(SizeWeCursor());
                return 0;
            }
            SetCursor(ArrowCursor());
            break;
        case WM_LBUTTONUP:
            if (app->registerDragCol_ >= 0) {
                app->registerDragCol_ = -1;
                app->registerDragStartX_ = 0;
                app->registerDragStartW_ = 0;
                if (GetCapture() == hwnd) {
                    ReleaseCapture();
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (app->registerSelecting_) {
                const int row = app->RegisterRowFromPoint(GET_Y_LPARAM(lParam));
                if (row >= 0) {
                    app->registerSelectionEnd_ = row;
                }
                app->registerSelecting_ = false;
                if (GetCapture() == hwnd) {
                    ReleaseCapture();
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            break;
        case WM_CAPTURECHANGED:
            app->registerDragCol_ = -1;
            app->registerDragStartX_ = 0;
            app->registerDragStartW_ = 0;
            app->registerSelecting_ = false;
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            if (dc == nullptr) {
                return 0;
            }
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int width = std::max<int>(1, rc.right - rc.left);
            const int height = std::max<int>(1, rc.bottom - rc.top);
            HDC memDc = CreateCompatibleDC(dc);
            HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, width, height) : nullptr;
            if (memDc == nullptr || memBitmap == nullptr) {
                if (memBitmap != nullptr) {
                    DeleteObject(memBitmap);
                }
                if (memDc != nullptr) {
                    DeleteDC(memDc);
                }
                EndPaint(hwnd, &ps);
                return 0;
            }
            HGDIOBJ oldBitmap = SelectObject(memDc, memBitmap);
            app->PaintRegisterView(memDc, ps.rcPaint);
            BitBlt(dc, 0, 0, width, height, memDc, 0, 0, SRCCOPY);
            SelectObject(memDc, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::StackToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->stackToolWnd_ = hwnd;
            ApplyConsoleLikeChrome(hwnd);
            app->ApplyWindowIcon();
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SIZE:
            app->LayoutStackTool();
            return 0;
        case WM_MOUSEWHEEL:
            if (app->stackViewWnd_ != nullptr && IsWindow(app->stackViewWnd_)) {
                SendMessageW(app->stackViewWnd_, msg, wParam, lParam);
                return 0;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            if (app->stackToolWnd_ == hwnd) {
                app->stackToolWnd_ = nullptr;
                app->stackViewWnd_ = nullptr;
            }
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::StackViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->stackViewWnd_ = hwnd;
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SETCURSOR:
            if (LOWORD(lParam) == HTCLIENT) {
                POINT pt = {};
                GetCursorPos(&pt);
                ScreenToClient(hwnd, &pt);
                if (app->stackDragCol_ >= 0 || app->HitTestStackColumnSeparator(pt.x) >= 0) {
                    SetCursor(SizeWeCursor());
                    return TRUE;
                }
            }
            SetCursor(ArrowCursor());
            return TRUE;
        case WM_ERASEBKGND:
            return 1;
        case WM_SIZE:
            app->UpdateStackMetrics();
            app->UpdateStackScrollInfo();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_VSCROLL: {
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            const int maxTop = std::max<int>(0, static_cast<int>(app->stackRows_.size()) - app->stackVisibleRows_);
            int pos = app->stackTopRow_;
            switch (LOWORD(wParam)) {
                case SB_LINEUP: pos -= 1; break;
                case SB_LINEDOWN: pos += 1; break;
                case SB_PAGEUP: pos -= app->stackVisibleRows_; break;
                case SB_PAGEDOWN: pos += app->stackVisibleRows_; break;
                case SB_TOP: pos = 0; break;
                case SB_BOTTOM: pos = maxTop; break;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: pos = si.nTrackPos; break;
                default: break;
            }
            pos = std::clamp<int>(pos, 0, maxTop);
            if (pos != app->stackTopRow_) {
                app->stackTopRow_ = pos;
                app->UpdateStackScrollInfo();
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_MOUSEWHEEL: {
            const short delta = GET_WHEEL_DELTA_WPARAM(wParam);
            if (delta == 0) {
                return 0;
            }
            const int maxTop = std::max<int>(0, static_cast<int>(app->stackRows_.size()) - app->stackVisibleRows_);
            const int oldTop = app->stackTopRow_;
            const int wheelNotches = std::max<int>(1, std::abs(static_cast<int>(delta)) / WHEEL_DELTA);
            app->stackTopRow_ = std::clamp<int>(
                app->stackTopRow_ + (delta < 0 ? wheelNotches * 3 : -wheelNotches * 3),
                0,
                maxTop);
            if (app->stackTopRow_ != oldTop) {
                app->UpdateStackScrollInfo();
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_KEYDOWN:
            if (wParam == 'C' && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                app->CopyStackSelectionToClipboard();
                return 0;
            }
            break;
        case WM_CONTEXTMENU: {
            POINT pt = {};
            if (GET_X_LPARAM(lParam) == -1 && GET_Y_LPARAM(lParam) == -1) {
                RECT rc = {};
                GetClientRect(hwnd, &rc);
                pt.x = rc.left + 24;
                pt.y = rc.top + app->stackRowHeight_ + 4;
                ClientToScreen(hwnd, &pt);
            } else {
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
            }
            POINT clientPt = pt;
            ScreenToClient(hwnd, &clientPt);
            const int row = app->StackRowFromPoint(clientPt.y);
            if (row >= 0) {
                const int selStart = (app->stackSelectionAnchor_ >= 0 && app->stackSelectionEnd_ >= 0)
                    ? std::min<int>(app->stackSelectionAnchor_, app->stackSelectionEnd_)
                    : -1;
                const int selEnd = (app->stackSelectionAnchor_ >= 0 && app->stackSelectionEnd_ >= 0)
                    ? std::max<int>(app->stackSelectionAnchor_, app->stackSelectionEnd_)
                    : -1;
                if (row < selStart || row > selEnd) {
                    app->stackSelectionAnchor_ = row;
                    app->stackSelectionEnd_ = row;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
            }
            HMENU menu = CreatePopupMenu();
            HMENU copyMenu = CreatePopupMenu();
            if (menu == nullptr || copyMenu == nullptr) {
                if (copyMenu != nullptr) {
                    DestroyMenu(copyMenu);
                }
                if (menu != nullptr) {
                    DestroyMenu(menu);
                }
                return 0;
            }
            const bool zh = IsChineseUserInterface();
            const bool hasSelection = !app->BuildStackSelectionText().empty();
            AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), ID_VIEW_COPY_CLIPBOARD, zh ? L"到剪切板" : L"To Clipboard");
            AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), ID_VIEW_COPY_FILE, zh ? L"到文件" : L"To File");
            AppendMenuW(menu, MF_POPUP | (hasSelection ? MF_ENABLED : MF_GRAYED), reinterpret_cast<UINT_PTR>(copyMenu), zh ? L"复制" : L"Copy");
            const UINT cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(menu);
            if (cmd == ID_VIEW_COPY_CLIPBOARD) {
                app->CopyStackSelectionToClipboard();
            } else if (cmd == ID_VIEW_COPY_FILE) {
                app->SaveStackSelectionToFile();
            }
            return 0;
        }
        case WM_LBUTTONDOWN: {
            SetFocus(hwnd);
            app->HideTitleMenu();
            const int x = GET_X_LPARAM(lParam);
            const int hit = app->HitTestStackColumnSeparator(x);
            if (hit >= 0) {
                app->stackDragCol_ = hit;
                app->stackDragStartX_ = x;
                if (hit == 0) {
                    app->stackDragStartW_ = app->stackColAddressW_;
                } else {
                    app->stackDragStartW_ = app->stackColValueW_;
                }
                SetCapture(hwnd);
                return 0;
            }
            const int row = app->StackRowFromPoint(GET_Y_LPARAM(lParam));
            app->stackSelecting_ = row >= 0;
            app->stackSelectionAnchor_ = row;
            app->stackSelectionEnd_ = row;
            if (row >= 0) {
                SetCapture(hwnd);
            }
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_MOUSEMOVE:
            if (app->stackDragCol_ >= 0 && GetCapture() == hwnd) {
                SetCursor(SizeWeCursor());
                const int delta = GET_X_LPARAM(lParam) - app->stackDragStartX_;
                const int width = std::max<int>(50, app->stackDragStartW_ + delta);
                if (app->stackDragCol_ == 0) {
                    app->stackColAddressW_ = width;
                } else {
                    app->stackColValueW_ = width;
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (app->stackSelecting_ && GetCapture() == hwnd) {
                int row = app->StackRowFromPoint(GET_Y_LPARAM(lParam));
                if (row < 0 && !app->stackRows_.empty()) {
                    row = GET_Y_LPARAM(lParam) < app->stackRowHeight_
                        ? 0
                        : static_cast<int>(app->stackRows_.size()) - 1;
                }
                if (row >= 0 && row != app->stackSelectionEnd_) {
                    app->stackSelectionEnd_ = row;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return 0;
            }
            if (app->HitTestStackColumnSeparator(GET_X_LPARAM(lParam)) >= 0) {
                SetCursor(SizeWeCursor());
                return 0;
            }
            SetCursor(ArrowCursor());
            break;
        case WM_LBUTTONUP:
            if (app->stackDragCol_ >= 0) {
                app->stackDragCol_ = -1;
                app->stackDragStartX_ = 0;
                app->stackDragStartW_ = 0;
                if (GetCapture() == hwnd) {
                    ReleaseCapture();
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (app->stackSelecting_) {
                const int row = app->StackRowFromPoint(GET_Y_LPARAM(lParam));
                if (row >= 0) {
                    app->stackSelectionEnd_ = row;
                }
                app->stackSelecting_ = false;
                if (GetCapture() == hwnd) {
                    ReleaseCapture();
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            break;
        case WM_CAPTURECHANGED:
            app->stackDragCol_ = -1;
            app->stackDragStartX_ = 0;
            app->stackDragStartW_ = 0;
            app->stackSelecting_ = false;
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            if (dc == nullptr) {
                return 0;
            }
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int width = std::max<int>(1, rc.right - rc.left);
            const int height = std::max<int>(1, rc.bottom - rc.top);
            HDC memDc = CreateCompatibleDC(dc);
            HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, width, height) : nullptr;
            if (memDc == nullptr || memBitmap == nullptr) {
                if (memBitmap != nullptr) {
                    DeleteObject(memBitmap);
                }
                if (memDc != nullptr) {
                    DeleteDC(memDc);
                }
                EndPaint(hwnd, &ps);
                return 0;
            }
            HGDIOBJ oldBitmap = SelectObject(memDc, memBitmap);
            app->PaintStackView(memDc, ps.rcPaint);
            BitBlt(dc, 0, 0, width, height, memDc, 0, 0, SRCCOPY);
            SelectObject(memDc, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::PseudoCToolWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->pseudoCToolWnd_ = hwnd;
            ApplyConsoleLikeChrome(hwnd);
            app->ApplyWindowIcon();
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SIZE:
            app->LayoutPseudoCTool();
            return 0;
        case WM_MOUSEWHEEL:
            if (app->pseudoCViewWnd_ != nullptr && IsWindow(app->pseudoCViewWnd_)) {
                SendMessageW(app->pseudoCViewWnd_, msg, wParam, lParam);
                return 0;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            if (app->pseudoCToolWnd_ == hwnd) {
                app->pseudoCToolWnd_ = nullptr;
                app->pseudoCViewWnd_ = nullptr;
            }
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::PseudoCViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = reinterpret_cast<GuiTerminalApp*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        if (app != nullptr) {
            app->pseudoCViewWnd_ = hwnd;
        }
        return TRUE;
    }
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SETCURSOR:
            SetCursor(IBeamCursor());
            return TRUE;
        case WM_SIZE:
            app->UpdatePseudoCMetrics();
            app->UpdatePseudoCScrollInfo();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_MOUSEWHEEL: {
            const int delta = GET_WHEEL_DELTA_WPARAM(wParam);
            const int lines = std::max<int>(1, static_cast<int>(std::abs(delta) / WHEEL_DELTA) * 3);
            const int maxTop = std::max<int>(0, static_cast<int>(app->pseudoCLines_.size()) - app->pseudoCVisibleRows_);
            app->pseudoCTopLine_ = std::max<int>(
                0,
                std::min<int>(maxTop, app->pseudoCTopLine_ + (delta < 0 ? lines : -lines)));
            app->UpdatePseudoCScrollInfo();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_VSCROLL: {
            const int maxTop = std::max<int>(0, static_cast<int>(app->pseudoCLines_.size()) - app->pseudoCVisibleRows_);
            int pos = app->pseudoCTopLine_;
            switch (LOWORD(wParam)) {
                case SB_LINEUP: pos -= 1; break;
                case SB_LINEDOWN: pos += 1; break;
                case SB_PAGEUP: pos -= app->pseudoCVisibleRows_; break;
                case SB_PAGEDOWN: pos += app->pseudoCVisibleRows_; break;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: {
                    SCROLLINFO si = {};
                    si.cbSize = sizeof(si);
                    si.fMask = SIF_TRACKPOS;
                    GetScrollInfo(hwnd, SB_VERT, &si);
                    pos = si.nTrackPos;
                    break;
                }
                case SB_TOP: pos = 0; break;
                case SB_BOTTOM: pos = maxTop; break;
                default: break;
            }
            app->pseudoCTopLine_ = std::max<int>(0, std::min<int>(pos, maxTop));
            app->UpdatePseudoCScrollInfo();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU: {
            POINT pt = {};
            if (msg == WM_CONTEXTMENU && GET_X_LPARAM(lParam) != -1 && GET_Y_LPARAM(lParam) != -1) {
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
            } else {
                if (msg == WM_RBUTTONUP) {
                    pt.x = GET_X_LPARAM(lParam);
                    pt.y = GET_Y_LPARAM(lParam);
                } else {
                    RECT rc = {};
                    GetClientRect(hwnd, &rc);
                    pt.x = rc.left + 24;
                    pt.y = rc.top + 24;
                }
                ClientToScreen(hwnd, &pt);
            }

            HMENU menu = CreatePopupMenu();
            HMENU copyMenu = CreatePopupMenu();
            if (menu == nullptr || copyMenu == nullptr) {
                if (copyMenu != nullptr) {
                    DestroyMenu(copyMenu);
                }
                if (menu != nullptr) {
                    DestroyMenu(menu);
                }
                return 0;
            }
            const bool zh = IsChineseUserInterface();
            const bool hasText = !app->BuildPseudoCText().empty();
            AppendMenuW(copyMenu, MF_STRING | (hasText ? MF_ENABLED : MF_GRAYED), ID_VIEW_COPY_CLIPBOARD, zh ? L"到剪切板" : L"To Clipboard");
            AppendMenuW(copyMenu, MF_STRING | (hasText ? MF_ENABLED : MF_GRAYED), ID_VIEW_COPY_FILE, zh ? L"到文件" : L"To File");
            AppendMenuW(menu, MF_POPUP | (hasText ? MF_ENABLED : MF_GRAYED), reinterpret_cast<UINT_PTR>(copyMenu), zh ? L"复制" : L"Copy");

            const UINT cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(menu);
            if (cmd == ID_VIEW_COPY_CLIPBOARD) {
                app->CopyPseudoCToClipboard();
            } else if (cmd == ID_VIEW_COPY_FILE) {
                app->SavePseudoCToFile();
            }
            return 0;
        }
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            if (dc == nullptr) {
                return 0;
            }
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            const int width = std::max<int>(1, rc.right - rc.left);
            const int height = std::max<int>(1, rc.bottom - rc.top);
            HDC memDc = CreateCompatibleDC(dc);
            HBITMAP memBitmap = memDc != nullptr ? CreateCompatibleBitmap(dc, width, height) : nullptr;
            if (memDc == nullptr || memBitmap == nullptr) {
                if (memBitmap != nullptr) {
                    DeleteObject(memBitmap);
                }
                if (memDc != nullptr) {
                    DeleteDC(memDc);
                }
                EndPaint(hwnd, &ps);
                return 0;
            }
            HGDIOBJ oldBitmap = SelectObject(memDc, memBitmap);
            app->PaintPseudoCView(memDc, ps.rcPaint);
            BitBlt(dc, 0, 0, width, height, memDc, 0, 0, SRCCOPY);
            SelectObject(memDc, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuiTerminalApp::InputWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiTerminalApp* app = reinterpret_cast<GuiTerminalApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (app == nullptr) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_SETCURSOR:
            SetCursor(IBeamCursor());
            return TRUE;
        case WM_GETDLGCODE:
            return DLGC_WANTALLKEYS | DLGC_WANTARROWS;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            app->HandleRightClickPasteOrCopy();
            return 0;
        case WM_KEYDOWN:
            if (wParam == 'G' && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                app->ShowGotoDialog();
                return 0;
            }
            if (wParam == 'C' && (GetKeyState(VK_CONTROL) & 0x8000) != 0 && app->outputWnd_ != nullptr) {
                CHARRANGE sel = {};
                SendMessageW(app->outputWnd_, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
                if (sel.cpMax > sel.cpMin) {
                    SendMessageW(app->outputWnd_, WM_COPY, 0, 0);
                    return 0;
                }
            }
            if (wParam == VK_RETURN) {
                PostMessageW(app->hwnd_, WM_APP_SUBMIT_INPUT, 0, 0);
                return 0;
            }
            if (wParam == VK_UP) {
                app->MoveHistory(-1);
                return 0;
            }
            if (wParam == VK_DOWN) {
                app->MoveHistory(1);
                return 0;
            }
            if (wParam == VK_ESCAPE) {
                app->UpdateInputText(L"");
                app->ClearInputHistoryState();
                return 0;
            }
            break;
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL: {
            const LRESULT result = app->inputOrigProc_ != nullptr
                ? CallWindowProcW(app->inputOrigProc_, hwnd, msg, wParam, lParam)
                : DefWindowProcW(hwnd, msg, wParam, lParam);
            app->RedrawCommandLineArea();
            return result;
        }
        case WM_CHAR:
            if (wParam == VK_RETURN) {
                return 0;
            }
            break;
        default:
            break;
    }

    if (app->inputOrigProc_ != nullptr) {
        return CallWindowProcW(app->inputOrigProc_, hwnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int GuiTerminalApp::Run() {
    FreeConsole();
    RedirectStreams();
    ParseStartupPythonRequest(startupPythonRequest_);
    if (!RegisterClasses()) {
        return 1;
    }
    if (!CreateMainWindow()) {
        return 1;
    }
    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);
    RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_FRAME | RDW_UPDATENOW);
    SetWindowTextW(hwnd_, kSystemWindowTitle);
    UpdateTitleTabWindow();
    AppendPlainLine(kWindowTitle, RGB(0, 255, 255));
    AppendText(
        L"\x1b[38;2;36;114;200m"
        L"  _____     ___      ____      ____        ____         _____\r\n"
        L" |__  /    / _ \\    |  _ \\    |  __ \\     |  _ \\      /  ____|\r\n"
        L"\x1b[38;2;13;188;121m"
        L"   / /    | | | |   | |_) |   | |  \\ |    | |_) |    | /   __\r\n"
        L"  / /     | | | |   |  _ <    | |   ||    |  _ <     | |  /_ |\r\n"
        L"\x1b[38;2;229;229;16m"
        L" / / _    | |_| |   | |_) |   | |__/ |    | |_) |    |  \\__| |\r\n"
        L"/_____|    \\___/    |____/    |_____/     |____/      \\____ /\r\n"
        L"\r\n"
        L"\x1b[38;2;188;63;188m"
        L"Z0dbgcli Terminal, Type 'help' for commands, 'quit' to exit\r\n"
        L"\x1b[0m");
    StartWorker();
    if (startupPythonRequest_.mode != STARTUP_PYTHON_MODE_NONE) {
        PostMessageW(hwnd_, WM_APP_RUN_STARTUP_PY, 0, 0);
    }

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (gotoDialogWnd_ != nullptr && IsWindow(gotoDialogWnd_) && msg.message == WM_KEYDOWN) {
            if (msg.wParam == VK_RETURN) {
                SubmitGotoDialog();
                continue;
            }
            if (msg.wParam == VK_ESCAPE) {
                HideGotoDialog();
                continue;
            }
        }
        if (gotoDialogWnd_ != nullptr && IsWindow(gotoDialogWnd_) && IsDialogMessageW(gotoDialogWnd_, &msg)) {
            continue;
        }
        if (msg.message == WM_APP_SUBMIT_INPUT) {
            SubmitInput();
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    StopWorker();
    RestoreStreams();
    pythonBridge_.Shutdown();
    debugger_.Shutdown();
    return 0;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    GuiTerminalApp app;
    return app.Run();
}
