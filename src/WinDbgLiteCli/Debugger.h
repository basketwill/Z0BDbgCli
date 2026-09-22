#pragma once

#include "PluginApi.h"

#include <Windows.h>
#include <DbgHelp.h>

#include <cstdint>
#include <functional>
#include <fstream>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "StdCompat.h"


class TraceLogger {
public:
    explicit TraceLogger(const std::wstring& filePath);
    ~TraceLogger();

    void Log(const std::wstring& message);
    void LogEvent(const std::wstring& prefix, const DEBUG_EVENT& event);

private:
    std::wofstream stream_;
};

struct BreakpointKind {
    enum Enum {
        Software,
        Hardware,
        Memory
    };
    BreakpointKind(Enum v = Software) : value(v) {}
    operator Enum() const { return value; }
    Enum value;
};

struct ExceptionScope {
    enum Enum {
        Debugging,
        Runtime,
        Stepping
    };
    ExceptionScope(Enum v = Debugging) : value(v) {}
    operator Enum() const { return value; }
    Enum value;
};

struct HardwareAccessType {
    enum Enum {
        Execute,
        Write,
        Access
    };
    HardwareAccessType(Enum v = Execute) : value(v) {}
    operator Enum() const { return value; }
    Enum value;
};

struct MemoryAccessType {
    enum Enum {
        Read = 1,
        Write = 2,
        Execute = 4
    };
    MemoryAccessType(Enum v = Read) : value(v) {}
    operator Enum() const { return value; }
    operator uint32_t() const { return static_cast<uint32_t>(value); }
    Enum value;
};

inline MemoryAccessType operator|(MemoryAccessType a, MemoryAccessType b) {
    return MemoryAccessType(static_cast<MemoryAccessType::Enum>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b)));
}

inline bool HasMemoryAccess(MemoryAccessType mask, MemoryAccessType bit) {
    return (static_cast<uint32_t>(mask) & static_cast<uint32_t>(bit)) != 0;
}

struct SoftwareBreakpoint {
    int id;
    uint64_t address;
    uint8_t originalByte;
    bool enabled;
    uint64_t hitCount;
    std::wstring condition;

    SoftwareBreakpoint()
        : id(0),
          address(0),
          originalByte(0),
          enabled(false),
          hitCount(0) {}
};

struct HardwareBreakpoint {
    int id;
    int slot;
    uint64_t address;
    HardwareAccessType access;
    int length;
    DWORD threadId;
    bool enabled;
    uint64_t hitCount;
    std::wstring condition;

    HardwareBreakpoint()
        : id(0),
          slot(0),
          address(0),
          access(HardwareAccessType::Execute),
          length(1),
          threadId(0),
          enabled(false),
          hitCount(0) {}
};

struct GuardPageInfo {
    uint64_t base;
    size_t size;
    DWORD originalProtection;

    GuardPageInfo()
        : base(0),
          size(0),
          originalProtection(0) {}
};

struct MemoryBreakpoint {
    int id;
    uint64_t address;
    size_t size;
    MemoryAccessType access;
    bool enabled;
    uint64_t hitCount;
    std::wstring condition;
    std::vector<GuardPageInfo> guardedPages;

    MemoryBreakpoint()
        : id(0),
          address(0),
          size(0),
          access(MemoryAccessType::Read),
          enabled(false),
          hitCount(0) {}
};

struct PendingDebugEvent {
    bool valid;
    DWORD processId;
    DWORD threadId;
    DWORD continueStatus;
    DEBUG_EVENT event;

    PendingDebugEvent()
        : valid(false),
          processId(0),
          threadId(0),
          continueStatus(DBG_CONTINUE),
          event() {
        ZeroMemory(&event, sizeof(event));
    }
};

struct StopState {
    bool valid;
    DWORD processId;
    DWORD threadId;
    DWORD exceptionCode;
    bool firstChance;
    uint64_t address;
    CONTEXT context;
    std::wstring reason;

    StopState()
        : valid(false),
          processId(0),
          threadId(0),
          exceptionCode(0),
          firstChance(false),
          address(0),
          context() {
        ZeroMemory(&context, sizeof(context));
    }
};

struct MemorySnapshotRegion {
    uint64_t address;
    std::vector<uint8_t> bytes;

    MemorySnapshotRegion()
        : address(0) {}
};

struct StopSnapshot {
    StopState stop;
    std::vector<MemorySnapshotRegion> memoryRegions;
    std::unordered_map<DWORD, uint64_t> pendingSoftwareReinsert;
    std::unordered_map<DWORD, std::vector<int>> pendingMemoryRearm;
};

struct ModuleRecord {
    uint64_t baseAddress;
    uint32_t size;
    std::wstring imagePath;
    std::wstring moduleName;

    ModuleRecord()
        : baseAddress(0),
          size(0) {}
};

struct ScriptLine {
    size_t sourceLine;
    std::wstring text;

    ScriptLine()
        : sourceLine(0) {}
};

struct ExceptionRuleSet {
    bool ignoreAll;
    std::unordered_set<DWORD> ignoredCodes;

    ExceptionRuleSet()
        : ignoreAll(false) {}
};

struct PluginModule {
    int id;
    HMODULE module;
    std::wstring path;
    std::wstring name;
    std::wstring version;
    std::wstring description;
    void* context;
    bool enabled;
    bool subscribedEvents;
    WdblPluginExecuteFn execute;
    WdblPluginShutdownFn shutdown;
    WdblPluginOnEventFn onEvent;

    PluginModule()
        : id(0),
          module(NULL),
          context(NULL),
          enabled(true),
          subscribedEvents(true),
          execute(NULL),
          shutdown(NULL),
          onEvent(NULL) {}
};

struct MemoryPatchRecord {
    uint64_t address;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> patchedBytes;

    MemoryPatchRecord()
        : address(0) {}
};

struct DisasmTextSegment {
    std::wstring text;
    COLORREF fg;
    COLORREF bg;
    bool hasBg;

    DisasmTextSegment()
        : fg(0),
          bg(0),
          hasBg(false) {}
};

struct DisassemblyUiRow {
    uint64_t address;
    std::wstring addressText;
    std::wstring hexBytes;
    std::wstring instruction;
    std::wstring comment;
    bool currentIp;
    bool breakpoint;
    std::vector<DisasmTextSegment> instructionSegments;

    DisassemblyUiRow()
        : address(0),
          currentIp(false),
          breakpoint(false) {}
};

struct MemoryUiRow {
    uint64_t address;
    std::wstring addressText;
    std::wstring hexText;
    std::wstring ansiText;

    MemoryUiRow()
        : address(0) {}
};

struct RegisterUiRow {
    std::wstring name;
    std::wstring value;
    std::wstring info;
};

struct StackUiRow {
    uint64_t addressValue;
    std::wstring index;
    std::wstring address;
    std::wstring value;
    std::wstring symbol;

    StackUiRow()
        : addressValue(0) {}
};

class Debugger {
public:
    typedef std::function<void(const std::vector<DisassemblyUiRow>&, uint64_t, uint64_t, uint64_t)> DisassemblyUiCallback;
    typedef std::function<void(const std::vector<MemoryUiRow>&, uint64_t, uint64_t, size_t, size_t, size_t)> MemoryUiCallback;
    typedef std::function<void(const std::vector<RegisterUiRow>&, const std::wstring&)> RegisterUiCallback;
    typedef std::function<void(const std::vector<StackUiRow>&, const std::wstring&, uint64_t)> StackUiCallback;
    typedef std::function<void(const std::wstring&, uint64_t)> PseudoCUiCallback;

    explicit Debugger(const std::wstring& tracePath);
    ~Debugger();

    const WdblDebuggerApi* GetDebuggerApi() const { return &debuggerApi_; }
    bool ExecuteCommand(const std::vector<std::wstring>& tokens, bool fromScript = false);
    void PrintHelp() const;
    bool IsDisasmColorEnabled() const { return disasmColorEnabled_; }
    std::wstring GetDebuggeeImagePath() const;
    void SetDisasmColorEnabled(bool enabled);
    void SetDisassemblyUiCallback(DisassemblyUiCallback callback);
    void SetMemoryUiCallback(MemoryUiCallback callback);
    void SetRegisterUiCallback(RegisterUiCallback callback);
    void SetStackUiCallback(StackUiCallback callback);
    void SetPseudoCUiCallback(PseudoCUiCallback callback);
    void EnsureConsoleColorEnabled() const;
    void BuildColoredInstructionSegments(const std::wstring& text, std::vector<DisasmTextSegment>& segments) const;
    void PrintColoredInstructionText(const std::wstring& text) const;
    bool IsBreakpointAtAddress(uint64_t address) const;
    bool CollectDisassemblyUiRows(uint64_t address, std::vector<DisassemblyUiRow>& rows, uint64_t& regionBase, uint64_t& regionEnd, size_t preferredPlacementStart = static_cast<size_t>(-1), size_t preciseBytes = 0x1000, size_t* exactPlacementStart = nullptr) const;
    bool CollectMemoryUiRows(uint64_t address, size_t unitSize, size_t unitsPerLine, bool compactHex, std::vector<MemoryUiRow>& rows, uint64_t& regionBase) const;
    bool CollectRegisterUiRows(const std::wstring& view, std::vector<RegisterUiRow>& rows) const;
    bool CollectStackUiRows(size_t maxFrames, std::vector<StackUiRow>& rows, uint64_t& stackPointer) const;
    bool PollDebugEvents();
    void Shutdown();
    static std::wstring ToLower(std::wstring value);

private:
    bool Launch(const std::wstring& commandLine);
    bool LaunchVeh(const std::wstring& commandLine, const std::wstring& dllPath);
    bool Attach(DWORD processId);
    bool Detach();
    bool ExecuteThreadCommand(const std::wstring& expression);
    bool ContinueExecution();
    bool SingleStep();
    bool StepOver();
    void CancelPendingStepOver();

    bool HandleDebugEvent(const DEBUG_EVENT& event, DWORD& continueStatus, bool& shouldPause);
    bool HandleExceptionEvent(const DEBUG_EVENT& event, DWORD& continueStatus, bool& shouldPause);
    bool PumpEventsUntilPause(DWORD waitMilliseconds = INFINITE);
    bool StartBackgroundEventPump();
    static DWORD WINAPI BackgroundEventPumpThreadProc(LPVOID param);
    bool IsBackgroundEventPumpRunning() const;
    bool SignalResumeForBackgroundPump();

    bool ContinuePendingEvent();
    void SetStoppedState(const DEBUG_EVENT& event, const std::wstring& reason, DWORD exceptionCode, bool firstChance);
    void ClearStopState();

    bool EnsureDebuggee() const;
    bool EnsurePaused() const;
    bool CaptureThreadContext(DWORD threadId, CONTEXT& ctx) const;
    bool ApplyThreadContext(DWORD threadId, CONTEXT& ctx) const;

    bool InitializeSymbolEngine();
    bool ConfigureDefaultSymbolPath(bool forceReset);
    bool SetSymbolSearchPath(const std::wstring& symbolPath);
    std::wstring GetSymbolSearchPath() const;
    bool ReloadSymbols(bool forceDownload, const std::optional<std::wstring>& moduleFilter = std::nullopt);
    bool ReloadSymbolsDetailed(bool forceDownload, const std::optional<std::wstring>& moduleFilter, std::wstring* outPdbPath = nullptr);
    bool CollectModuleRecords(std::vector<ModuleRecord>& modules) const;
    bool AddSourceRoot(const std::wstring& path);
    bool RemoveSourceRoot(const std::wstring& path);
    void ClearSourceRoots();
    void ListSourceRoots() const;
    bool ResolveSourceLocation(uint64_t address, std::wstring& filePath, uint32_t& line, uint32_t& displacement) const;
    std::wstring LocalizeSourcePath(const std::wstring& sourcePath) const;
    void PrintSourceAtAddress(uint64_t address, size_t contextLines = 2) const;
    bool ResolveSourceAddress(const std::wstring& sourceFile, uint32_t line, uint64_t& address, std::wstring& matchedFile);
    bool SetSourceBreakpoint(const std::wstring& sourceFile, uint32_t line);
    bool LoadScriptFile(const std::wstring& path);
    void ClearScriptState();
    void ShowScript() const;
    void ShowScriptVariables() const;
    bool SetScriptBreakpoint(size_t sourceLine);
    bool RemoveScriptBreakpoint(size_t sourceLine);
    void ListScriptBreakpoints() const;
    bool SaveEnvironmentSnapshot(const std::wstring& filePath) const;
    bool LoadEnvironmentSnapshot(const std::wstring& filePath);
    bool RunScript(bool singleStep);
    bool RunScriptUntilLabel(const std::wstring& label);
    bool ExecuteScriptLine(const ScriptLine& line, size_t& nextIndex);
    std::wstring ExpandScriptVariables(const std::wstring& text) const;
    void CleanupDebuggee();

    uint64_t GetInstructionPointer(const CONTEXT& ctx) const;
    uint64_t GetStackPointer(const CONTEXT& ctx) const;
    void SetInstructionPointer(CONTEXT& ctx, uint64_t ip) const;
    void SetTrapFlag(CONTEXT& ctx, bool enabled) const;
    bool ResolveEntryPointFromModuleBase(uint64_t moduleBase, uint64_t& entryPointAddress) const;
    bool ResolveMainModuleEntryPoint(uint64_t& moduleBase, uint64_t& entryPointAddress) const;
    bool ResolveMainModuleRange(uint64_t& moduleBase, size_t& moduleSize) const;
    bool CaptureSnapshotMemory(std::vector<MemorySnapshotRegion>& regions) const;
    bool RestoreSnapshotMemory(const std::vector<MemorySnapshotRegion>& regions) const;

    bool IsKnownSoftwareBreakpointHit(const DEBUG_EVENT& event, CONTEXT& ctx, int& breakpointId, uint64_t& breakpointAddress);
    bool RearmSoftwareBreakpoint(DWORD threadId);
    bool RearmMemoryBreakpoints(DWORD threadId);
    bool ResolvePendingSoftwareBreakpoints();
    bool WasHardwareBreakpointTriggered(const CONTEXT& ctx, int& breakpointId) const;
    bool ApplyHardwareBreakpointsForThread(DWORD threadId);
    bool ApplyHardwareBreakpointsForAllThreads();

    int AddSoftwareBreakpoint(uint64_t address);
    int AddHardwareBreakpoint(int slot, uint64_t address, HardwareAccessType access, int length, DWORD threadId);
    int FindFreeHardwareBreakpointSlot(DWORD threadId) const;
    int AddMemoryBreakpoint(uint64_t address, size_t size, MemoryAccessType access);
    bool EnableBreakpoint(int breakpointId);
    bool DisableBreakpoint(int breakpointId);
    bool RemoveBreakpoint(int breakpointId);
    size_t RemoveAllBreakpoints();
    bool SetBreakpointCondition(int breakpointId, const std::wstring& expression);
    bool ClearBreakpointCondition(int breakpointId);
    void ListBreakpoints() const;

    static bool EvaluateBreakpointCondition(
        const std::wstring& expression,
        uint64_t hitCount,
        DWORD threadId,
        uint64_t instructionPointer,
        uint64_t address,
        bool& matched,
        std::wstring& error);

    bool EnableSoftwareBreakpoint(SoftwareBreakpoint& bp);
    bool DisableSoftwareBreakpoint(SoftwareBreakpoint& bp);
    bool EnableHardwareBreakpoint(HardwareBreakpoint& bp);
    bool DisableHardwareBreakpoint(HardwareBreakpoint& bp);
    bool EnableMemoryBreakpoint(MemoryBreakpoint& bp);
    bool DisableMemoryBreakpoint(MemoryBreakpoint& bp);
    void RearmMemoryBreakpoint(MemoryBreakpoint& bp) const;
    void ClearDanglingTrapFlagForAddress(uint64_t address);

    void PrintStopSummary() const;
    void PrintProcessList() const;
    void PrintProcessInfo() const;
    void PrintThreadInfo() const;
    void PrintCurrentThreadInfo() const;
    void PrintPebInfo() const;
    void PrintTebInfo() const;
    void PrintVirtualMemoryInfo() const;
    void PrintMemoryMapInfo() const;
    void PrintVadInfo() const;
    void PrintVadDump(const std::wstring& selector, const std::wstring& filePath) const;
    void PrintIatCheck(const std::wstring& moduleName = L"") const;
    void PrintModifyCheck(const std::wstring& moduleName = L"ntdll.dll") const;
    void PrintSyscallCheck(const std::wstring& moduleName = L"ntdll.dll") const;
    void PrintThreadCheck() const;
    void PrintAnalysisReport() const;
    void PrintTimeline(size_t maxEvents = 256) const;
    void PrintExceptionCheck() const;
    void PrintModuleCheck() const;
    bool ExportAnalysisReport(const std::wstring& filePath, const std::wstring& format) const;
    void PrintApiTrace(size_t maxEvents = 256, const std::wstring& filter = L"") const;
    void PrintModuleInfo(const std::wstring& filter = L"") const;
    void PrintExceptionInfo() const;
    void PrintRegisterInfo() const;
    void PrintMmxRegisterInfo() const;
    void PrintFloatRegisterInfo() const;
    void PrintDebugRegisterInfo() const;
    void PrintStackInfo(size_t maxFrames = 32) const;
    void PrintThreadStackInfo(DWORD threadId, size_t maxFrames = 32, bool showHeader = true) const;
    void PrintSehChain() const;
    void PrintHandleInfo(size_t maxHandles = 200) const;
    void PrintMemoryStrings(size_t minLength = 6, size_t maxMatches = 200) const;
    bool SearchMemory(const std::vector<std::wstring>& tokens) const;
    void PrintMemoryBinary(uint64_t address, size_t size) const;
    void PrintMemoryDump(uint64_t address, size_t byteCount, size_t unitSize, size_t unitsPerLine) const;
    void PrintAsciiMemory(uint64_t address, size_t byteCount) const;
    bool DisplayType(const std::wstring& typeName, uint64_t address, size_t depth) const;
    bool WriteMemoryRangeToFile(const std::wstring& filePath, uint64_t address, size_t size) const;
    bool DumpMemoryRangeToFile(const std::wstring& filePath, uint64_t address, size_t size) const;
    bool DumpCurrentImageToFile(const std::wstring& filePath) const;
    bool AllocateVirtualMemory(size_t size) const;
    bool SetRegisterValue(const std::wstring& assignment);
    void PrintCallStack(size_t maxFrames, bool showParams, bool verbose) const;
    bool ExamineSymbols(const std::wstring& pattern) const;
    bool GoUp();
    bool TraceWatch(uint64_t maxSteps);
    void PrintDisassembly(uint64_t address, size_t instructionCount = 16) const;
    void PrintPseudoC(uint64_t address, size_t instructionCount = 128, bool showUi = false) const;
    bool ShowDisassemblyUi(uint64_t address) const;
    bool ShowMemoryUi(uint64_t address, size_t byteCount, size_t unitSize, size_t unitsPerLine, bool compactHex = false) const;
    bool ShowRegisterUi(const std::wstring& view = L"") const;
    bool ShowStackUi(size_t maxFrames = 32, const std::wstring& view = L"stack") const;
    bool WriteMemoryPatch(uint64_t address, const std::vector<uint8_t>& bytes, bool recordHistory = true);
    bool UndoMemoryPatch(size_t count);
    void ListMemoryPatchHistory(size_t maxItems = 32) const;
    bool EvaluateCurrentStopCondition(const std::wstring& expression, uint64_t iteration, bool& matched, std::wstring& error) const;
    bool StepUntilCondition(const std::wstring& condition, uint64_t maxSteps);
    bool RunUntilCondition(const std::wstring& condition, uint64_t maxPauses);
    bool AutoStep(uint64_t steps, uint32_t delayMs);
    bool AutoRun(uint64_t pauses, uint32_t delayMs);
    void SaveCurrentStopSnapshot();
    bool SaveNamedSnapshot(const std::wstring& name);
    bool RestoreNamedSnapshot(const std::wstring& name, bool rerunAfterRestore);
    void ListNamedSnapshots() const;
    bool RestoreStopSnapshot(const StopSnapshot& snapshot, const std::wstring& reasonTag, bool includeOriginalReason);
    bool StepBackToPreviousSnapshot();
    bool RunToEntryPoint();
    bool SetInstructionComment(uint64_t address, const std::wstring& comment);
    bool RemoveInstructionComment(uint64_t address);
    void ListInstructionComments() const;
    void PrintFlowGraph(uint64_t address, size_t maxBlocks) const;
    bool ConfigureExceptionIgnoreAll(ExceptionScope scope, bool enabled);
    bool AddIgnoredExceptionCode(ExceptionScope scope, DWORD code);
    bool RemoveIgnoredExceptionCode(ExceptionScope scope, DWORD code);
    void ClearIgnoredExceptionCodes(ExceptionScope scope);
    void ListExceptionSettings() const;
    bool AddRunStopExpression(const std::wstring& expression);
    bool RemoveRunStopExpression(size_t index);
    void ClearRunStopExpressions();
    void ListRunStopExpressions() const;
    bool EvaluateRunStopExpressions(bool& matched, std::wstring& detail) const;
    bool ShouldIgnoreException(DWORD code) const;
    bool LoadPluginModule(const std::wstring& path);
    bool UnloadPluginModule(const std::wstring& token);
    void UnloadAllPluginModules();
    void ListPluginModules() const;
    bool ExecutePluginModule(const std::wstring& token, const std::wstring& args);
    bool SetPluginModuleEnabled(const std::wstring& token, bool enabled);
    void AutoLoadPluginModules();

    PluginModule* FindPluginModule(const std::wstring& token);
    const PluginModule* FindPluginModule(const std::wstring& token) const;
    static void WDBL_CALL PluginHostLogThunk(void* context, const wchar_t* text);
    static int32_t WDBL_CALL PluginHostExecuteThunk(void* context, const wchar_t* command);
    static int32_t WDBL_CALL PluginHostGetStopInfoThunk(void* context, WdblStopInfo* outInfo);
    static int32_t WDBL_CALL PluginHostSubscribeEventsThunk(void* context, int32_t enabled);
    static int32_t WDBL_CALL DebuggerApiLaunchThunk(void* context, const wchar_t* commandLine);
    static int32_t WDBL_CALL DebuggerApiAttachThunk(void* context, uint32_t processId);
    static int32_t WDBL_CALL DebuggerApiDetachThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiContinueThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiSingleStepThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiStepOverThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiReadMemoryThunk(void* context, uint64_t address, void* buffer, uint32_t bufferSize, uint32_t* bytesRead);
    static int32_t WDBL_CALL DebuggerApiWriteMemoryThunk(void* context, uint64_t address, const void* buffer, uint32_t bufferSize, uint32_t* bytesWritten);
    static int32_t WDBL_CALL DebuggerApiResolveSymbolThunk(void* context, uint64_t address, wchar_t* outText, uint32_t outTextChars);
    static int32_t WDBL_CALL DebuggerApiResolveAddressExpressionThunk(void* context, const wchar_t* expression, uint64_t* outAddress, wchar_t* outText, uint32_t outTextChars);
    static int32_t WDBL_CALL DebuggerApiAddSoftwareBreakpointThunk(void* context, uint64_t address, int32_t* outBreakpointId);
    static int32_t WDBL_CALL DebuggerApiAddHardwareBreakpointThunk(void* context, int32_t slot, uint64_t address, int32_t access, int32_t length, uint32_t threadId, int32_t* outBreakpointId);
    static int32_t WDBL_CALL DebuggerApiAddMemoryBreakpointThunk(void* context, uint64_t address, uint64_t size, uint32_t access, int32_t* outBreakpointId);
    static int32_t WDBL_CALL DebuggerApiEnableBreakpointThunk(void* context, int32_t breakpointId);
    static int32_t WDBL_CALL DebuggerApiDisableBreakpointThunk(void* context, int32_t breakpointId);
    static int32_t WDBL_CALL DebuggerApiRemoveBreakpointThunk(void* context, int32_t breakpointId);
    static int32_t WDBL_CALL DebuggerApiSetBreakpointConditionThunk(void* context, int32_t breakpointId, const wchar_t* expression);
    static int32_t WDBL_CALL DebuggerApiClearBreakpointConditionThunk(void* context, int32_t breakpointId);
    static int32_t WDBL_CALL DebuggerApiLoadSymbolsThunk(void* context, const wchar_t* target, wchar_t* outPdbPath, uint32_t outPdbPathChars);
    static int32_t WDBL_CALL DebuggerApiDownloadSymbolsThunk(void* context, const wchar_t* target, const wchar_t* cacheDir, const wchar_t* serverUrl, wchar_t* outPdbPath, uint32_t outPdbPathChars);
    static int32_t WDBL_CALL DebuggerApiSetSymbolSearchPathThunk(void* context, const wchar_t* symbolPath);
    static int32_t WDBL_CALL DebuggerApiGetSymbolSearchPathThunk(void* context, wchar_t* outText, uint32_t outTextChars);
    static int32_t WDBL_CALL DebuggerApiSelectThreadThunk(void* context, uint32_t index);
    static int32_t WDBL_CALL DebuggerApiSetRegisterValueThunk(void* context, const wchar_t* assignment);
    static int32_t WDBL_CALL DebuggerApiWriteMemoryPatchThunk(void* context, uint64_t address, const void* bytes, uint32_t size);
    static int32_t WDBL_CALL DebuggerApiUndoMemoryPatchThunk(void* context, uint32_t count);
    static int32_t WDBL_CALL DebuggerApiSaveCurrentStopSnapshotThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiSaveNamedSnapshotThunk(void* context, const wchar_t* name);
    static int32_t WDBL_CALL DebuggerApiRestoreNamedSnapshotThunk(void* context, const wchar_t* name, int32_t rerunAfterRestore);
    static int32_t WDBL_CALL DebuggerApiListNamedSnapshotsThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiStepBackToPreviousSnapshotThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiAddSourceRootThunk(void* context, const wchar_t* path);
    static int32_t WDBL_CALL DebuggerApiRemoveSourceRootThunk(void* context, const wchar_t* path);
    static int32_t WDBL_CALL DebuggerApiClearSourceRootsThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiListSourceRootsThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiLoadScriptFileThunk(void* context, const wchar_t* path);
    static int32_t WDBL_CALL DebuggerApiSetScriptBreakpointThunk(void* context, uint32_t line);
    static int32_t WDBL_CALL DebuggerApiRemoveScriptBreakpointThunk(void* context, uint32_t line);
    static int32_t WDBL_CALL DebuggerApiListScriptBreakpointsThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiConfigureExceptionIgnoreAllThunk(void* context, int32_t scope, int32_t enabled);
    static int32_t WDBL_CALL DebuggerApiAddIgnoredExceptionCodeThunk(void* context, int32_t scope, uint32_t code);
    static int32_t WDBL_CALL DebuggerApiRemoveIgnoredExceptionCodeThunk(void* context, int32_t scope, uint32_t code);
    static int32_t WDBL_CALL DebuggerApiClearIgnoredExceptionCodesThunk(void* context, int32_t scope);
    static int32_t WDBL_CALL DebuggerApiListExceptionSettingsThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiAddRunStopExpressionThunk(void* context, const wchar_t* expression);
    static int32_t WDBL_CALL DebuggerApiRemoveRunStopExpressionThunk(void* context, uint32_t index);
    static int32_t WDBL_CALL DebuggerApiClearRunStopExpressionsThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiListRunStopExpressionsThunk(void* context);
    static int32_t WDBL_CALL DebuggerApiStepUntilConditionThunk(void* context, const wchar_t* condition, uint64_t maxSteps);
    static int32_t WDBL_CALL DebuggerApiRunUntilConditionThunk(void* context, const wchar_t* condition, uint64_t maxPauses);
    static int32_t WDBL_CALL DebuggerApiAutoStepThunk(void* context, uint64_t steps, uint32_t delayMs);
    static int32_t WDBL_CALL DebuggerApiAutoRunThunk(void* context, uint64_t pauses, uint32_t delayMs);
    static int32_t WDBL_CALL DebuggerApiGetStopInfoThunk(void* context, WdblStopInfo* outInfo);
    static int32_t WDBL_CALL DebuggerApiGetThreadCountThunk(void* context, uint32_t* outCount);
    static int32_t WDBL_CALL DebuggerApiGetThreadInfoThunk(void* context, uint32_t index, WdblThreadInfo* outInfo);
    static int32_t WDBL_CALL DebuggerApiGetRegisterInfoThunk(void* context, uint32_t index, WdblRegisterInfo* outInfo);
    static int32_t WDBL_CALL DebuggerApiGetStackFrameInfoThunk(void* context, uint32_t index, uint32_t frameIndex, WdblStackFrameInfo* outInfo);
    static int32_t WDBL_CALL DebuggerApiGetModuleCountThunk(void* context, uint32_t* outCount);
    static int32_t WDBL_CALL DebuggerApiGetModuleInfoThunk(void* context, uint32_t index, WdblModuleInfo* outInfo);
    static int32_t WDBL_CALL DebuggerApiGetBreakpointCountThunk(void* context, uint32_t* outCount);
    static int32_t WDBL_CALL DebuggerApiGetBreakpointInfoThunk(void* context, uint32_t index, WdblBreakpointInfo* outInfo);
    static int32_t WDBL_CALL DebuggerApiExecuteCommandThunk(void* context, const wchar_t* command);
    void PluginHostLog(const wchar_t* text);
    int32_t PluginHostExecute(const wchar_t* command);
    int32_t PluginHostGetStopInfo(WdblStopInfo* outInfo) const;
    int32_t PluginHostSubscribeEvents(int32_t enabled);
    int32_t DebuggerApiLaunch(const wchar_t* commandLine);
    int32_t DebuggerApiAttach(uint32_t processId);
    int32_t DebuggerApiDetach();
    int32_t DebuggerApiContinue();
    int32_t DebuggerApiSingleStep();
    int32_t DebuggerApiStepOver();
    int32_t DebuggerApiReadMemory(uint64_t address, void* buffer, uint32_t bufferSize, uint32_t* bytesRead) const;
    int32_t DebuggerApiWriteMemory(uint64_t address, const void* buffer, uint32_t bufferSize, uint32_t* bytesWritten);
    int32_t DebuggerApiResolveSymbol(uint64_t address, wchar_t* outText, uint32_t outTextChars) const;
    int32_t DebuggerApiResolveAddressExpression(const wchar_t* expression, uint64_t* outAddress, wchar_t* outText, uint32_t outTextChars) const;
    int32_t DebuggerApiAddSoftwareBreakpoint(uint64_t address, int32_t* outBreakpointId);
    int32_t DebuggerApiAddHardwareBreakpoint(int32_t slot, uint64_t address, int32_t access, int32_t length, uint32_t threadId, int32_t* outBreakpointId);
    int32_t DebuggerApiAddMemoryBreakpoint(uint64_t address, uint64_t size, uint32_t access, int32_t* outBreakpointId);
    int32_t DebuggerApiEnableBreakpoint(int32_t breakpointId);
    int32_t DebuggerApiDisableBreakpoint(int32_t breakpointId);
    int32_t DebuggerApiRemoveBreakpoint(int32_t breakpointId);
    int32_t DebuggerApiSetBreakpointCondition(int32_t breakpointId, const wchar_t* expression);
    int32_t DebuggerApiClearBreakpointCondition(int32_t breakpointId);
    int32_t DebuggerApiLoadSymbols(const wchar_t* target, wchar_t* outPdbPath, uint32_t outPdbPathChars) const;
    int32_t DebuggerApiDownloadSymbols(const wchar_t* target, const wchar_t* cacheDir, const wchar_t* serverUrl, wchar_t* outPdbPath, uint32_t outPdbPathChars) const;
    int32_t DebuggerApiSetSymbolSearchPath(const wchar_t* symbolPath) const;
    int32_t DebuggerApiGetSymbolSearchPath(wchar_t* outText, uint32_t outTextChars) const;
    int32_t DebuggerApiSelectThread(uint32_t index) const;
    int32_t DebuggerApiSetRegisterValue(const wchar_t* assignment) const;
    int32_t DebuggerApiWriteMemoryPatch(uint64_t address, const void* bytes, uint32_t size) const;
    int32_t DebuggerApiUndoMemoryPatch(uint32_t count) const;
    int32_t DebuggerApiSaveCurrentStopSnapshot() const;
    int32_t DebuggerApiSaveNamedSnapshot(const wchar_t* name) const;
    int32_t DebuggerApiRestoreNamedSnapshot(const wchar_t* name, int32_t rerunAfterRestore) const;
    int32_t DebuggerApiListNamedSnapshots() const;
    int32_t DebuggerApiStepBackToPreviousSnapshot() const;
    int32_t DebuggerApiAddSourceRoot(const wchar_t* path) const;
    int32_t DebuggerApiRemoveSourceRoot(const wchar_t* path) const;
    int32_t DebuggerApiClearSourceRoots() const;
    int32_t DebuggerApiListSourceRoots() const;
    int32_t DebuggerApiLoadScriptFile(const wchar_t* path) const;
    int32_t DebuggerApiSetScriptBreakpoint(uint32_t line) const;
    int32_t DebuggerApiRemoveScriptBreakpoint(uint32_t line) const;
    int32_t DebuggerApiListScriptBreakpoints() const;
    int32_t DebuggerApiConfigureExceptionIgnoreAll(int32_t scope, int32_t enabled) const;
    int32_t DebuggerApiAddIgnoredExceptionCode(int32_t scope, uint32_t code) const;
    int32_t DebuggerApiRemoveIgnoredExceptionCode(int32_t scope, uint32_t code) const;
    int32_t DebuggerApiClearIgnoredExceptionCodes(int32_t scope) const;
    int32_t DebuggerApiListExceptionSettings() const;
    int32_t DebuggerApiAddRunStopExpression(const wchar_t* expression) const;
    int32_t DebuggerApiRemoveRunStopExpression(uint32_t index) const;
    int32_t DebuggerApiClearRunStopExpressions() const;
    int32_t DebuggerApiListRunStopExpressions() const;
    int32_t DebuggerApiStepUntilCondition(const wchar_t* condition, uint64_t maxSteps) const;
    int32_t DebuggerApiRunUntilCondition(const wchar_t* condition, uint64_t maxPauses) const;
    int32_t DebuggerApiAutoStep(uint64_t steps, uint32_t delayMs) const;
    int32_t DebuggerApiAutoRun(uint64_t pauses, uint32_t delayMs) const;
    int32_t DebuggerApiGetStopInfo(WdblStopInfo* outInfo) const;
    int32_t DebuggerApiGetThreadCount(uint32_t* outCount) const;
    int32_t DebuggerApiGetThreadInfo(uint32_t index, WdblThreadInfo* outInfo) const;
    int32_t DebuggerApiGetRegisterInfo(uint32_t index, WdblRegisterInfo* outInfo) const;
    int32_t DebuggerApiGetStackFrameInfo(uint32_t index, uint32_t frameIndex, WdblStackFrameInfo* outInfo) const;
    int32_t DebuggerApiGetModuleCount(uint32_t* outCount) const;
    int32_t DebuggerApiGetModuleInfo(uint32_t index, WdblModuleInfo* outInfo) const;
    int32_t DebuggerApiGetBreakpointCount(uint32_t* outCount) const;
    int32_t DebuggerApiGetBreakpointInfo(uint32_t index, WdblBreakpointInfo* outInfo) const;
    int32_t DebuggerApiExecuteCommand(const wchar_t* command);
    void DispatchPluginEvent(const WdblPluginEvent& eventData);
    static std::wstring ModulePathFromBase(uint64_t moduleBase, DWORD processId);
    bool QueryThreadTeb(DWORD tid, uint64_t& teb) const;
    bool FillThreadInfoByIndex(uint32_t index, WdblThreadInfo& outInfo) const;
    bool FillRegisterInfoByIndex(uint32_t index, WdblRegisterInfo& outInfo) const;
    bool FillStackFrameByIndex(uint32_t index, uint32_t frameIndex, WdblStackFrameInfo& outInfo) const;

    std::wstring ResolveSymbol(uint64_t address) const;
    std::wstring ResolveExactSymbol(uint64_t address) const;
    std::wstring RewriteImportedThunkSymbols(const std::wstring& text) const;
    std::wstring ResolveImportedThunkSymbol(uint64_t address) const;
    std::wstring ResolveExportSymbol(uint64_t address) const;
    bool IsImportedFunctionAddress(uint64_t address) const;
    std::vector<DWORD> EnumerateThreadIds() const;
    bool ResolveAddressExpression(const std::wstring& expression, uint64_t& address, std::wstring& resolvedText) const;

    static std::wstring JoinTokens(const std::vector<std::wstring>& tokens, size_t startIndex);
    static bool ParseUInt64(const std::wstring& text, uint64_t& value);
    static bool ParseUInt32(const std::wstring& text, uint32_t& value);
    static std::wstring GetModuleNameFromPath(const std::wstring& path);
    static bool IsScriptComment(const std::wstring& text);
    static std::wstring ExceptionCodeToString(DWORD code);
    static std::wstring EventCodeToString(DWORD eventCode);
    static std::wstring MemoryAccessToString(MemoryAccessType access);
    static std::optional<MemoryAccessType> ParseMemoryAccess(const std::wstring& value);
    static std::optional<HardwareAccessType> ParseHardwareAccess(const std::wstring& value);
    static std::optional<ExceptionScope> ParseExceptionScope(const std::wstring& text);
    static std::wstring ExceptionScopeToString(ExceptionScope scope);
    static bool ParseExceptionCodeToken(const std::wstring& text, DWORD& code);

private:
    TraceLogger logger_;

    bool active_;
    bool attached_;
    DWORD processId_;
    HANDLE processHandle_;
    bool symbolsInitialized_;
    bool symbolInitAttempted_;
    std::wstring symbolSearchPath_;
    std::wstring symbolCacheDirectory_;
    std::wstring symbolServerUrl_;
    std::vector<std::wstring> sourceRoots_;
    std::wstring scriptPath_;
    std::vector<ScriptLine> scriptLines_;
    std::unordered_map<std::wstring, size_t> scriptLabels_;
    std::unordered_map<std::wstring, std::wstring> scriptVariables_;
    std::unordered_set<size_t> scriptBreakpoints_;
    size_t scriptCursor_;
    bool scriptLoaded_;
    bool scriptResumePastBreakpoint_;

    PendingDebugEvent pendingEvent_;
    StopState stopState_;

    bool stepRequested_;
    DWORD stepThreadId_;
    bool runFlowActive_;
    uint64_t mainModuleBase_;
    uint64_t entryPointAddress_;
    bool runToEntryOnLaunch_;
    int runToEntryBreakpointId_;
    bool runToEntryOwnsBreakpoint_;
    int stepOverBreakpointId_;
    HANDLE eventPumpThreadHandle_;
    HANDLE eventPumpResumeEvent_;
    HANDLE eventPumpReadyEvent_;
    CRITICAL_SECTION stateLock_;
    bool stateLockInitialized_;
    int eventPumpStartMode_;
    bool eventPumpStartSucceeded_;
    bool detachRequested_;
    std::wstring eventPumpLaunchCommandLine_;
    DWORD eventPumpAttachProcessId_;
    std::vector<StopSnapshot> stopHistory_;
    WdblDebuggerApi debuggerApi_;
    DisassemblyUiCallback disassemblyUiCallback_;
    MemoryUiCallback memoryUiCallback_;
    RegisterUiCallback registerUiCallback_;
    StackUiCallback stackUiCallback_;
    PseudoCUiCallback pseudoCUiCallback_;

    std::unordered_map<DWORD, uint64_t> pendingSoftwareReinsert_;
    std::unordered_map<DWORD, std::vector<int>> pendingMemoryRearm_;

    int nextBreakpointId_;

    std::map<int, SoftwareBreakpoint> softwareBreakpoints_;
    std::map<uint64_t, int> softwareBreakpointByAddress_;
    std::vector<std::wstring> pendingSoftwareBreakpoints_;
    std::map<int, HardwareBreakpoint> hardwareBreakpoints_;
    std::map<int, MemoryBreakpoint> memoryBreakpoints_;
    std::vector<MemoryPatchRecord> patchHistory_;
    ExceptionRuleSet debuggingExceptionRules_;
    ExceptionRuleSet runtimeExceptionRules_;
    ExceptionRuleSet steppingExceptionRules_;
    std::vector<std::wstring> runStopExpressions_;
    std::vector<PluginModule> pluginModules_;
    int nextPluginId_;
    bool pluginEventDispatchActive_;
    int activePluginDispatchIndex_;
    std::map<std::wstring, StopSnapshot> namedSnapshots_;
    std::map<uint64_t, std::wstring> instructionComments_;
    bool disasmColorEnabled_;
};

std::vector<std::wstring> Tokenize(const std::wstring& line);
