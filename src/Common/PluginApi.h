#pragma once

#include <cstdint>
#include <cstring>

#if defined(_WIN32)
#define WDBL_CALL __stdcall
#else
#define WDBL_CALL
#endif

const uint32_t WDBL_PLUGIN_API_VERSION = 2u;
const uint32_t WDBL_DEBUGGER_API_VERSION = 11u;

struct WdblPluginInfo {
    uint32_t size;
    uint32_t apiVersion;
    wchar_t name[64];
    wchar_t version[32];
    wchar_t description[160];

    WdblPluginInfo()
        : size(sizeof(WdblPluginInfo)),
          apiVersion(WDBL_PLUGIN_API_VERSION) {
        std::memset(name, 0, sizeof(name));
        std::memset(version, 0, sizeof(version));
        std::memset(description, 0, sizeof(description));
    }
};

struct WdblStopInfo {
    uint32_t size;
    int32_t paused;
    uint32_t processId;
    uint32_t threadId;
    uint32_t exceptionCode;
    int32_t firstChance;
    uint64_t exceptionAddress;
    uint64_t instructionPointer;
    wchar_t reason[256];

    WdblStopInfo()
        : size(sizeof(WdblStopInfo)),
          paused(0),
          processId(0),
          threadId(0),
          exceptionCode(0),
          firstChance(0),
          exceptionAddress(0),
          instructionPointer(0) {
        std::memset(reason, 0, sizeof(reason));
    }
};

enum WdblPluginEventType {
    WDBL_PLUGIN_EVENT_UNKNOWN = 0,
    WDBL_PLUGIN_EVENT_CONTINUE_REQUESTED = 1,
    WDBL_PLUGIN_EVENT_SINGLE_STEP_REQUESTED = 2,
    WDBL_PLUGIN_EVENT_PAUSED = 3,
    WDBL_PLUGIN_EVENT_MODULE_LOADED = 4
};

struct WdblPluginEvent {
    uint32_t size;
    uint32_t type;
    uint32_t processId;
    uint32_t threadId;
    uint32_t debugEventCode;
    uint64_t address;
    wchar_t modulePath[260];
    wchar_t message[160];
    WdblStopInfo stopInfo;

    WdblPluginEvent()
        : size(sizeof(WdblPluginEvent)),
          type(static_cast<uint32_t>(WDBL_PLUGIN_EVENT_UNKNOWN)),
          processId(0),
          threadId(0),
          debugEventCode(0),
          address(0),
          stopInfo() {
        std::memset(modulePath, 0, sizeof(modulePath));
        std::memset(message, 0, sizeof(message));
    }
};

struct WdblHostApi {
    uint32_t size;
    uint32_t apiVersion;
    void* context;
    void (WDBL_CALL* log)(void* context, const wchar_t* text);
    int32_t (WDBL_CALL* execute)(void* context, const wchar_t* command);
    int32_t (WDBL_CALL* getStopInfo)(void* context, WdblStopInfo* outInfo);
    int32_t (WDBL_CALL* subscribeEvents)(void* context, int32_t enabled);
    const struct WdblDebuggerApi* debuggerApi;

    WdblHostApi()
        : size(sizeof(WdblHostApi)),
          apiVersion(WDBL_PLUGIN_API_VERSION),
          context(NULL),
          log(NULL),
          execute(NULL),
          getStopInfo(NULL),
          subscribeEvents(NULL),
          debuggerApi(NULL) {
    }
};

struct WdblThreadInfo {
    uint32_t size;
    uint32_t index;
    uint32_t processId;
    uint32_t threadId;
    uint32_t isCurrent;
    uint32_t hasContext;
    uint64_t teb;
    uint64_t instructionPointer;
    uint64_t stackPointer;
    int32_t priority;
    int32_t basePriority;
    int32_t deltaPriority;
    wchar_t symbol[260];

    WdblThreadInfo()
        : size(sizeof(WdblThreadInfo)),
          index(0),
          processId(0),
          threadId(0),
          isCurrent(0),
          hasContext(0),
          teb(0),
          instructionPointer(0),
          stackPointer(0),
          priority(0),
          basePriority(0),
          deltaPriority(0) {
        std::memset(symbol, 0, sizeof(symbol));
    }
};

struct WdblRegisterInfo {
    uint32_t size;
    uint32_t threadId;
    uint32_t isWow64;
    uint32_t architectureBits;
    uint64_t instructionPointer;
    uint64_t stackPointer;
    uint64_t framePointer;
    uint64_t flags;
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t rip;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t dr7;
    uint64_t eax;
    uint64_t ebx;
    uint64_t ecx;
    uint64_t edx;
    uint64_t esi;
    uint64_t edi;
    uint64_t ebp;
    uint64_t esp;
    uint64_t eip;
    uint64_t eflags;

    WdblRegisterInfo()
        : size(sizeof(WdblRegisterInfo)),
          threadId(0),
          isWow64(0),
          architectureBits(0),
          instructionPointer(0),
          stackPointer(0),
          framePointer(0),
          flags(0),
          rax(0),
          rbx(0),
          rcx(0),
          rdx(0),
          rsi(0),
          rdi(0),
          rbp(0),
          rsp(0),
          rip(0),
          r8(0),
          r9(0),
          r10(0),
          r11(0),
          r12(0),
          r13(0),
          r14(0),
          r15(0),
          dr0(0),
          dr1(0),
          dr2(0),
          dr3(0),
          dr6(0),
          dr7(0),
          eax(0),
          ebx(0),
          ecx(0),
          edx(0),
          esi(0),
          edi(0),
          ebp(0),
          esp(0),
          eip(0),
          eflags(0) {
    }
};

struct WdblStackFrameInfo {
    uint32_t size;
    uint32_t index;
    uint32_t threadId;
    uint32_t isCurrent;
    uint64_t instructionPointer;
    uint64_t stackPointer;
    uint64_t framePointer;
    uint64_t returnAddress;
    uint32_t sourceLine;
    uint32_t sourceDisplacement;
    wchar_t symbol[260];
    wchar_t sourcePath[260];

    WdblStackFrameInfo()
        : size(sizeof(WdblStackFrameInfo)),
          index(0),
          threadId(0),
          isCurrent(0),
          instructionPointer(0),
          stackPointer(0),
          framePointer(0),
          returnAddress(0),
          sourceLine(0),
          sourceDisplacement(0) {
        std::memset(symbol, 0, sizeof(symbol));
        std::memset(sourcePath, 0, sizeof(sourcePath));
    }
};

enum WdblBreakpointKind {
    WDBL_BREAKPOINT_SOFTWARE = 0,
    WDBL_BREAKPOINT_HARDWARE = 1,
    WDBL_BREAKPOINT_MEMORY = 2
};

struct WdblModuleInfo {
    uint32_t size;
    uint64_t baseAddress;
    uint32_t imageSize;
    wchar_t imagePath[260];
    wchar_t moduleName[64];

    WdblModuleInfo()
        : size(sizeof(WdblModuleInfo)),
          baseAddress(0),
          imageSize(0) {
        std::memset(imagePath, 0, sizeof(imagePath));
        std::memset(moduleName, 0, sizeof(moduleName));
    }
};

struct WdblBreakpointInfo {
    uint32_t size;
    int32_t id;
    uint32_t kind;
    uint64_t address;
    int32_t slot;
    uint32_t threadId;
    int32_t enabled;
    uint64_t hitCount;
    uint32_t length;
    uint32_t access;
    wchar_t condition[256];

    WdblBreakpointInfo()
        : size(sizeof(WdblBreakpointInfo)),
          id(0),
          kind(0),
          address(0),
          slot(0),
          threadId(0),
          enabled(0),
          hitCount(0),
          length(0),
          access(0) {
        std::memset(condition, 0, sizeof(condition));
    }
};

struct WdblVmDisasmInput {
    uint32_t size;
    uint64_t address;
    uint32_t architectureBits;
    uint32_t threadId;
    const uint8_t* bytes;
    uint32_t byteCount;
    const WdblRegisterInfo* registers;
    uint64_t stackPointer;

    WdblVmDisasmInput()
        : size(sizeof(WdblVmDisasmInput)),
          address(0),
          architectureBits(0),
          threadId(0),
          bytes(NULL),
          byteCount(0),
          registers(NULL),
          stackPointer(0) {
    }
};

struct WdblVmDisasmOutput {
    uint32_t size;
    uint32_t consumedBytes;
    uint32_t confidence;
    wchar_t text[256];
    wchar_t comment[256];

    WdblVmDisasmOutput()
        : size(sizeof(WdblVmDisasmOutput)),
          consumedBytes(0),
          confidence(0) {
        std::memset(text, 0, sizeof(text));
        std::memset(comment, 0, sizeof(comment));
    }
};

typedef int32_t (WDBL_CALL* WdblVmDisasmDecodeFn)(void* providerContext, const WdblVmDisasmInput* input, WdblVmDisasmOutput* output);
typedef int32_t (WDBL_CALL* WdblPluginCommandFn)(void* commandContext, const wchar_t* commandName, const wchar_t* args);

struct WdblDebuggerApi {
    uint32_t size;
    uint32_t apiVersion;
    void* context;
    int32_t (WDBL_CALL* launch)(void* context, const wchar_t* commandLine);
    int32_t (WDBL_CALL* attach)(void* context, uint32_t processId);
    int32_t (WDBL_CALL* detach)(void* context);
    int32_t (WDBL_CALL* continueExecution)(void* context);
    int32_t (WDBL_CALL* singleStep)(void* context);
    int32_t (WDBL_CALL* stepOver)(void* context);
    int32_t (WDBL_CALL* readMemory)(void* context, uint64_t address, void* buffer, uint32_t bufferSize, uint32_t* bytesRead);
    int32_t (WDBL_CALL* writeMemory)(void* context, uint64_t address, const void* buffer, uint32_t bufferSize, uint32_t* bytesWritten);
    int32_t (WDBL_CALL* resolveSymbol)(void* context, uint64_t address, wchar_t* outText, uint32_t outTextChars);
    int32_t (WDBL_CALL* resolveAddressExpression)(void* context, const wchar_t* expression, uint64_t* outAddress, wchar_t* outText, uint32_t outTextChars);
    int32_t (WDBL_CALL* addSoftwareBreakpoint)(void* context, uint64_t address, int32_t* outBreakpointId);
    int32_t (WDBL_CALL* addHardwareBreakpoint)(void* context, int32_t slot, uint64_t address, int32_t access, int32_t length, uint32_t threadId, int32_t* outBreakpointId);
    int32_t (WDBL_CALL* addMemoryBreakpoint)(void* context, uint64_t address, uint64_t size, uint32_t access, int32_t* outBreakpointId);
    int32_t (WDBL_CALL* enableBreakpoint)(void* context, int32_t breakpointId);
    int32_t (WDBL_CALL* disableBreakpoint)(void* context, int32_t breakpointId);
    int32_t (WDBL_CALL* removeBreakpoint)(void* context, int32_t breakpointId);
    int32_t (WDBL_CALL* setBreakpointCondition)(void* context, int32_t breakpointId, const wchar_t* expression);
    int32_t (WDBL_CALL* clearBreakpointCondition)(void* context, int32_t breakpointId);
    int32_t (WDBL_CALL* loadSymbols)(void* context, const wchar_t* target, wchar_t* outPdbPath, uint32_t outPdbPathChars);
    int32_t (WDBL_CALL* downloadSymbols)(void* context, const wchar_t* target, const wchar_t* cacheDir, const wchar_t* serverUrl, wchar_t* outPdbPath, uint32_t outPdbPathChars);
    int32_t (WDBL_CALL* setSymbolSearchPath)(void* context, const wchar_t* symbolPath);
    int32_t (WDBL_CALL* getSymbolSearchPath)(void* context, wchar_t* outText, uint32_t outTextChars);
    int32_t (WDBL_CALL* selectThread)(void* context, uint32_t index);
    int32_t (WDBL_CALL* setRegisterValue)(void* context, const wchar_t* assignment);
    int32_t (WDBL_CALL* writeMemoryPatch)(void* context, uint64_t address, const void* bytes, uint32_t size);
    int32_t (WDBL_CALL* undoMemoryPatch)(void* context, uint32_t count);
    int32_t (WDBL_CALL* saveCurrentStopSnapshot)(void* context);
    int32_t (WDBL_CALL* saveNamedSnapshot)(void* context, const wchar_t* name);
    int32_t (WDBL_CALL* restoreNamedSnapshot)(void* context, const wchar_t* name, int32_t rerunAfterRestore);
    int32_t (WDBL_CALL* listNamedSnapshots)(void* context);
    int32_t (WDBL_CALL* stepBackToPreviousSnapshot)(void* context);
    int32_t (WDBL_CALL* addSourceRoot)(void* context, const wchar_t* path);
    int32_t (WDBL_CALL* removeSourceRoot)(void* context, const wchar_t* path);
    int32_t (WDBL_CALL* clearSourceRoots)(void* context);
    int32_t (WDBL_CALL* listSourceRoots)(void* context);
    int32_t (WDBL_CALL* loadScriptFile)(void* context, const wchar_t* path);
    int32_t (WDBL_CALL* setScriptBreakpoint)(void* context, uint32_t line);
    int32_t (WDBL_CALL* removeScriptBreakpoint)(void* context, uint32_t line);
    int32_t (WDBL_CALL* listScriptBreakpoints)(void* context);
    int32_t (WDBL_CALL* configureExceptionIgnoreAll)(void* context, int32_t scope, int32_t enabled);
    int32_t (WDBL_CALL* addIgnoredExceptionCode)(void* context, int32_t scope, uint32_t code);
    int32_t (WDBL_CALL* removeIgnoredExceptionCode)(void* context, int32_t scope, uint32_t code);
    int32_t (WDBL_CALL* clearIgnoredExceptionCodes)(void* context, int32_t scope);
    int32_t (WDBL_CALL* listExceptionSettings)(void* context);
    int32_t (WDBL_CALL* addRunStopExpression)(void* context, const wchar_t* expression);
    int32_t (WDBL_CALL* removeRunStopExpression)(void* context, uint32_t index);
    int32_t (WDBL_CALL* clearRunStopExpressions)(void* context);
    int32_t (WDBL_CALL* listRunStopExpressions)(void* context);
    int32_t (WDBL_CALL* stepUntilCondition)(void* context, const wchar_t* condition, uint64_t maxSteps);
    int32_t (WDBL_CALL* runUntilCondition)(void* context, const wchar_t* condition, uint64_t maxPauses);
    int32_t (WDBL_CALL* autoStep)(void* context, uint64_t steps, uint32_t delayMs);
    int32_t (WDBL_CALL* autoRun)(void* context, uint64_t pauses, uint32_t delayMs);
    int32_t (WDBL_CALL* getStopInfo)(void* context, WdblStopInfo* outInfo);
    int32_t (WDBL_CALL* getThreadCount)(void* context, uint32_t* outCount);
    int32_t (WDBL_CALL* getThreadInfo)(void* context, uint32_t index, WdblThreadInfo* outInfo);
    int32_t (WDBL_CALL* getRegisterInfo)(void* context, uint32_t index, WdblRegisterInfo* outInfo);
    int32_t (WDBL_CALL* getStackFrameInfo)(void* context, uint32_t index, uint32_t frameIndex, WdblStackFrameInfo* outInfo);
    int32_t (WDBL_CALL* getModuleCount)(void* context, uint32_t* outCount);
    int32_t (WDBL_CALL* getModuleInfo)(void* context, uint32_t index, WdblModuleInfo* outInfo);
    int32_t (WDBL_CALL* getBreakpointCount)(void* context, uint32_t* outCount);
    int32_t (WDBL_CALL* getBreakpointInfo)(void* context, uint32_t index, WdblBreakpointInfo* outInfo);
    int32_t (WDBL_CALL* executeCommand)(void* context, const wchar_t* command);
    int32_t (WDBL_CALL* registerVmDisasmProvider)(void* context, const wchar_t* name, WdblVmDisasmDecodeFn decode, void* providerContext);
    int32_t (WDBL_CALL* unregisterVmDisasmProvider)(void* context, const wchar_t* name, void* providerContext);
    int32_t (WDBL_CALL* registerPluginCommand)(void* context, const wchar_t* name, const wchar_t* description, WdblPluginCommandFn callback, void* commandContext);
    int32_t (WDBL_CALL* unregisterPluginCommand)(void* context, const wchar_t* name, void* commandContext);

    WdblDebuggerApi()
        : size(sizeof(WdblDebuggerApi)),
          apiVersion(WDBL_DEBUGGER_API_VERSION),
          context(NULL),
          launch(NULL),
          attach(NULL),
          detach(NULL),
          continueExecution(NULL),
          singleStep(NULL),
          stepOver(NULL),
          readMemory(NULL),
          writeMemory(NULL),
          resolveSymbol(NULL),
          resolveAddressExpression(NULL),
          addSoftwareBreakpoint(NULL),
          addHardwareBreakpoint(NULL),
          addMemoryBreakpoint(NULL),
          enableBreakpoint(NULL),
          disableBreakpoint(NULL),
          removeBreakpoint(NULL),
          setBreakpointCondition(NULL),
          clearBreakpointCondition(NULL),
          loadSymbols(NULL),
          downloadSymbols(NULL),
          setSymbolSearchPath(NULL),
          getSymbolSearchPath(NULL),
          selectThread(NULL),
          setRegisterValue(NULL),
          writeMemoryPatch(NULL),
          undoMemoryPatch(NULL),
          saveCurrentStopSnapshot(NULL),
          saveNamedSnapshot(NULL),
          restoreNamedSnapshot(NULL),
          listNamedSnapshots(NULL),
          stepBackToPreviousSnapshot(NULL),
          addSourceRoot(NULL),
          removeSourceRoot(NULL),
          clearSourceRoots(NULL),
          listSourceRoots(NULL),
          loadScriptFile(NULL),
          setScriptBreakpoint(NULL),
          removeScriptBreakpoint(NULL),
          listScriptBreakpoints(NULL),
          configureExceptionIgnoreAll(NULL),
          addIgnoredExceptionCode(NULL),
          removeIgnoredExceptionCode(NULL),
          clearIgnoredExceptionCodes(NULL),
          listExceptionSettings(NULL),
          addRunStopExpression(NULL),
          removeRunStopExpression(NULL),
          clearRunStopExpressions(NULL),
          listRunStopExpressions(NULL),
          stepUntilCondition(NULL),
          runUntilCondition(NULL),
          autoStep(NULL),
          autoRun(NULL),
          getStopInfo(NULL),
          getThreadCount(NULL),
          getThreadInfo(NULL),
          getRegisterInfo(NULL),
          getStackFrameInfo(NULL),
          getModuleCount(NULL),
          getModuleInfo(NULL),
          getBreakpointCount(NULL),
          getBreakpointInfo(NULL),
          executeCommand(NULL),
          registerVmDisasmProvider(NULL),
          unregisterVmDisasmProvider(NULL),
          registerPluginCommand(NULL),
          unregisterPluginCommand(NULL) {
    }
};

typedef int32_t (WDBL_CALL* WdblPluginGetInfoFn)(WdblPluginInfo* outInfo);
typedef int32_t (WDBL_CALL* WdblPluginInitializeFn)(const WdblHostApi* hostApi, void** pluginContext);
typedef int32_t (WDBL_CALL* WdblPluginExecuteFn)(void* pluginContext, const wchar_t* args);
typedef void (WDBL_CALL* WdblPluginShutdownFn)(void* pluginContext);
typedef void (WDBL_CALL* WdblPluginOnEventFn)(void* pluginContext, const WdblPluginEvent* eventData);
