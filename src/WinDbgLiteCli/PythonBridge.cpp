#include "PythonBridge.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <iostream>
#include "StdCompat.h"
#include <streambuf>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct _typeobject;

typedef SSIZE_T Py_ssize_t;

struct PyObject {
    Py_ssize_t ob_refcnt;
    _typeobject* ob_type;
};

struct PyMethodDef;
struct PyModuleDef;

typedef PyObject* (__cdecl *PyCFunction)(PyObject*, PyObject*);

struct PyMethodDef {
    const char* ml_name;
    PyCFunction ml_meth;
    int ml_flags;
    const char* ml_doc;
};

struct PyModuleDef_Base {
    PyObject ob_base;
    PyObject* m_init;
    Py_ssize_t m_index;
    PyObject* m_copy;
};

struct PyModuleDef {
    PyModuleDef_Base m_base;
    const char* m_name;
    const char* m_doc;
    Py_ssize_t m_size;
    PyMethodDef* m_methods;
    void* m_slots;
    void* m_traverse;
    void* m_clear;
    void* m_free;
};

struct Py_buffer {
    void* buf;
    PyObject* obj;
    Py_ssize_t len;
    Py_ssize_t itemsize;
    int readonly;
    int ndim;
    char* format;
    Py_ssize_t* shape;
    Py_ssize_t* strides;
    Py_ssize_t* suboffsets;
    void* internal;
};

static const int METH_VARARGS = 0x0001;
static const int METH_NOARGS = 0x0004;
static const int Py_file_input = 257;
static const int PyBUF_SIMPLE = 0;
static const int kPyModuleApiVersion = 1013;

struct PythonApi {
    HMODULE module;

     typedef int(__cdecl *FnPyImport_AppendInittab)(const char*, PyObject* (__cdecl*)());
     typedef void(__cdecl *FnPy_Initialize)();
     typedef int(__cdecl *FnPy_IsInitialized)();
     typedef void(__cdecl *FnPy_Finalize)();
     typedef PyObject* (__cdecl *FnPyImport_ImportModule)(const char*);
     typedef PyObject* (__cdecl *FnPyImport_AddModule)(const char*);
     typedef PyObject* (__cdecl *FnPyModule_GetDict)(PyObject*);
     typedef int(__cdecl *FnPyRun_SimpleString)(const char*);
     typedef void(__cdecl *FnPyErr_Print)();
     typedef void(__cdecl *FnPyErr_SetString)(PyObject*, const char*);
     typedef PyObject* (__cdecl *FnPyObject_Str)(PyObject*);
     typedef wchar_t* (__cdecl *FnPyUnicode_AsWideCharString)(PyObject*, Py_ssize_t*);
     typedef void(__cdecl *FnPyMem_Free)(void*);
     typedef PyObject* (__cdecl *FnPyBool_FromLong)(long);
     typedef PyObject* (__cdecl *FnPyLong_FromUnsignedLong)(unsigned long);
     typedef PyObject* (__cdecl *FnPyLong_FromUnsignedLongLong)(unsigned long long);
     typedef PyObject* (__cdecl *FnPyLong_FromLong)(long);
     typedef PyObject* (__cdecl *FnPyDict_New)();
     typedef int(__cdecl *FnPyDict_SetItemString)(PyObject*, const char*, PyObject*);
     typedef PyObject* (__cdecl *FnPyList_New)(Py_ssize_t);
     typedef int(__cdecl *FnPyList_Append)(PyObject*, PyObject*);
     typedef PyObject* (__cdecl *FnPyUnicode_FromWideChar)(const wchar_t*, Py_ssize_t);
     typedef PyObject* (__cdecl *FnPyBytes_FromStringAndSize)(const char*, Py_ssize_t);
     typedef int(__cdecl *FnPyObject_GetBuffer)(PyObject*, Py_buffer*, int);
     typedef void(__cdecl *FnPyBuffer_Release)(Py_buffer*);
     typedef int(__cdecl *FnPyArg_ParseTuple)(PyObject*, const char*, ...);
     typedef PyObject* (__cdecl *FnPy_BuildValue)(const char*, ...);
     typedef PyObject* (__cdecl *FnPyModule_Create2)(PyModuleDef*, int);
     typedef void(__cdecl *FnPy_DecRef)(PyObject*);
     typedef void(__cdecl *FnPy_IncRef)(PyObject*);

     typedef std::wstring (__cdecl * FnPyObjectToWideString) (PyObject*);

    FnPyImport_AppendInittab PyImport_AppendInittab;
    FnPy_Initialize Py_Initialize;
    FnPy_IsInitialized Py_IsInitialized;
    FnPy_Finalize Py_Finalize;
    FnPyImport_ImportModule PyImport_ImportModule;
    FnPyImport_AddModule PyImport_AddModule;
    FnPyModule_GetDict PyModule_GetDict;
    FnPyRun_SimpleString PyRun_SimpleString;
    FnPyErr_Print PyErr_Print;
    FnPyErr_SetString PyErr_SetString;
    FnPyObject_Str PyObject_Str;
    FnPyUnicode_AsWideCharString PyUnicode_AsWideCharString;
    FnPyMem_Free PyMem_Free;
    FnPyBool_FromLong PyBool_FromLong;
    FnPyLong_FromUnsignedLong PyLong_FromUnsignedLong;
    FnPyLong_FromUnsignedLongLong PyLong_FromUnsignedLongLong;
    FnPyLong_FromLong PyLong_FromLong;
    FnPyDict_New PyDict_New;
    FnPyDict_SetItemString PyDict_SetItemString;
    FnPyList_New PyList_New;
    FnPyList_Append PyList_Append;
    FnPyUnicode_FromWideChar PyUnicode_FromWideChar;
    FnPyBytes_FromStringAndSize PyBytes_FromStringAndSize;
    FnPyObject_GetBuffer PyObject_GetBuffer;
    FnPyBuffer_Release PyBuffer_Release;
    FnPyArg_ParseTuple PyArg_ParseTuple;
    FnPy_BuildValue Py_BuildValue;
    FnPyModule_Create2 PyModule_Create2;
    FnPy_DecRef Py_DecRef;
    FnPy_IncRef Py_IncRef;
    PyObject* PyExc_RuntimeError;
    PyObject* PyExc_ValueError;
    _typeobject* PyModuleDef_Type;
};

PythonApi g_py;

struct BridgeState {
    const WdblDebuggerApi* api;
    void* context;
    PythonBridge* owner;
};

BridgeState* g_state = nullptr;
std::mutex g_stateMutex;

PyObject* MakeRuntimeError(const wchar_t* message);
void PySetDictItemString(PyObject* dict, const char* key, PyObject* value);

std::wstring TrimCopy(const std::wstring& value) {
    const size_t start = value.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) {
        return L"";
    }
    const size_t end = value.find_last_not_of(L" \t\r\n");
    return value.substr(start, end - start + 1);
}

std::wstring ToLowerCopy(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

std::string WideToUtf8(const std::wstring& text) {
    if (text.empty()) {
        return std::string();
    }
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (bytes <= 1) {
        return std::string();
    }
    std::string out(static_cast<size_t>(bytes - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, &out[0], bytes, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    const int chars = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (chars <= 1) {
        return std::wstring();
    }
    std::wstring out(static_cast<size_t>(chars - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &out[0], chars);
    return out;
}

std::wstring AnsiToWide(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    const int chars = MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, nullptr, 0);
    if (chars <= 1) {
        return std::wstring();
    }
    std::wstring out(static_cast<size_t>(chars - 1), L'\0');
    MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, &out[0], chars);
    return out;
}

std::wstring MakeAnsiColorEscape(uint64_t fg, bool hasBg, uint64_t bg, bool newline) {
    const unsigned int fr = static_cast<unsigned int>((fg >> 16) & 0xFF);
    const unsigned int fgG = static_cast<unsigned int>((fg >> 8) & 0xFF);
    const unsigned int fb = static_cast<unsigned int>(fg & 0xFF);

    std::wstringstream ss;
    ss << L"\x1b[38;2;" << fr << L';' << fgG << L';' << fb;
    if (hasBg) {
        const unsigned int br = static_cast<unsigned int>((bg >> 16) & 0xFF);
        const unsigned int bgG = static_cast<unsigned int>((bg >> 8) & 0xFF);
        const unsigned int bb = static_cast<unsigned int>(bg & 0xFF);
        ss << L";48;2;" << br << L';' << bgG << L';' << bb;
    }
    ss << L'm';
    if (newline) {
        ss << L"\x1b[0m";
    }
    return ss.str();
}

std::wstring GetParentDirectory(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return L"";
    }
    return path.substr(0, slash);
}

std::string EscapePythonRawString(const std::wstring& text) {
    std::string utf8 = WideToUtf8(text);
    std::string escaped;
    escaped.reserve(utf8.size() * 2);
    for (size_t ci = 0; ci < utf8.size(); ++ci) {
        char ch = utf8[ci];
        if (ch == '\\' || ch == '\'') {
            escaped.push_back('\\');
        }
        escaped.push_back(ch);
    }
    return escaped;
}

std::string BuildPythonArgvScript(const std::wstring& scriptPath, const std::vector<std::wstring>& args) {
    std::string script = "import sys\nsys.argv = [r'" + EscapePythonRawString(scriptPath) + "'";
    for (size_t ai = 0; ai < args.size(); ++ai) {
        const std::wstring& arg = args[ai];
        script += ", r'";
        script += EscapePythonRawString(arg);
        script += "'";
    }
    script += "]\n";
    return script;
}

template <typename T>
T LoadProc(HMODULE module, const char* name) {
    return reinterpret_cast<T>(GetProcAddress(module, name));
}

template <typename T>
T* LoadGlobalPtr(HMODULE module, const char* name) {
    auto slot = reinterpret_cast<T**>(GetProcAddress(module, name));
    return slot != nullptr ? *slot : nullptr;
}

void EmitText(const std::wstring& text) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (g_state == nullptr || g_state->owner == nullptr) {
        return;
    }
    g_state->owner->Emit(text);
}

void EmitColoredText(const std::wstring& text, uint64_t fg, bool hasBg, uint64_t bg, bool newline) {
    std::wstring styled;
    styled.reserve(text.size() + 48);
    styled += MakeAnsiColorEscape(fg, hasBg, bg, false);
    styled += text;
    styled += L"\x1b[0m";
    if (newline) {
        styled += L"\r\n";
    }
    EmitText(styled);
}

std::wstring FormatStopInfoText(const WdblStopInfo& info) {
    std::wstringstream ss;
    ss << L"paused=" << (info.paused != 0 ? L"yes" : L"no") << L"\r\n";
    ss << L"process_id=" << info.processId << L"\r\n";
    ss << L"thread_id=" << info.threadId << L"\r\n";
    ss << L"exception_code=0x" << std::hex << std::uppercase << info.exceptionCode << std::dec << L"\r\n";
    ss << L"first_chance=" << (info.firstChance != 0 ? L"yes" : L"no") << L"\r\n";
    ss << L"exception_address=0x" << std::hex << std::uppercase << info.exceptionAddress << std::dec << L"\r\n";
    ss << L"instruction_pointer=0x" << std::hex << std::uppercase << info.instructionPointer << std::dec << L"\r\n";
    ss << L"reason=" << info.reason << L"\r\n";
    return ss.str();
}

std::wstring FormatThreadInfoText(const WdblThreadInfo& info) {
    std::wstringstream ss;
    ss << L"index=" << info.index
       << L" thread_id=" << info.threadId
       << L" process_id=" << info.processId
       << L" current=" << (info.isCurrent != 0 ? L"yes" : L"no")
       << L" teb=0x" << std::hex << std::uppercase << info.teb
       << L" ip=0x" << info.instructionPointer
       << L" sp=0x" << info.stackPointer
       << std::dec
       << L" priority=" << info.priority
       << L" base_priority=" << info.basePriority
       << L" delta_priority=" << info.deltaPriority
       << L" symbol=" << info.symbol
       << L"\r\n";
    return ss.str();
}

std::wstring FormatRegisterInfoText(const WdblRegisterInfo& info) {
    std::wstringstream ss;
    ss << L"tid=" << info.threadId
       << L" bits=" << info.architectureBits
       << L" ip=0x" << std::hex << std::uppercase << info.instructionPointer
       << L" sp=0x" << info.stackPointer
       << L" fp=0x" << info.framePointer
       << L" flags=0x" << info.flags << std::dec << L"\r\n";
    ss << L"rax=0x" << std::hex << info.rax
       << L" rbx=0x" << info.rbx
       << L" rcx=0x" << info.rcx
       << L" rdx=0x" << info.rdx << std::dec << L"\r\n";
    ss << L"rsi=0x" << std::hex << info.rsi
       << L" rdi=0x" << info.rdi
       << L" rbp=0x" << info.rbp
       << L" rsp=0x" << info.rsp << std::dec << L"\r\n";
    ss << L"dr0=0x" << std::hex << info.dr0
       << L" dr1=0x" << info.dr1
       << L" dr2=0x" << info.dr2
       << L" dr3=0x" << info.dr3
       << L" dr6=0x" << info.dr6
       << L" dr7=0x" << info.dr7 << std::dec << L"\r\n";
    return ss.str();
}

PyObject* BuildRegisterDict(const WdblRegisterInfo& info) {
    if (g_py.PyDict_New == nullptr || g_py.PyBool_FromLong == nullptr || g_py.PyLong_FromUnsignedLong == nullptr ||
        g_py.PyLong_FromUnsignedLongLong == nullptr) {
        return MakeRuntimeError(L"python dict api is not available");
    }

    PyObject* dict = g_py.PyDict_New();
    if (dict == nullptr) {
        return nullptr;
    }

    PySetDictItemString(dict, "thread_id", g_py.PyLong_FromUnsignedLong(info.threadId));
    PySetDictItemString(dict, "is_wow64", g_py.PyBool_FromLong(info.isWow64 != 0));
    PySetDictItemString(dict, "architecture_bits", g_py.PyLong_FromUnsignedLong(info.architectureBits));
    PySetDictItemString(dict, "instruction_pointer", g_py.PyLong_FromUnsignedLongLong(info.instructionPointer));
    PySetDictItemString(dict, "stack_pointer", g_py.PyLong_FromUnsignedLongLong(info.stackPointer));
    PySetDictItemString(dict, "frame_pointer", g_py.PyLong_FromUnsignedLongLong(info.framePointer));
    PySetDictItemString(dict, "flags", g_py.PyLong_FromUnsignedLongLong(info.flags));
    PySetDictItemString(dict, "rax", g_py.PyLong_FromUnsignedLongLong(info.rax));
    PySetDictItemString(dict, "rbx", g_py.PyLong_FromUnsignedLongLong(info.rbx));
    PySetDictItemString(dict, "rcx", g_py.PyLong_FromUnsignedLongLong(info.rcx));
    PySetDictItemString(dict, "rdx", g_py.PyLong_FromUnsignedLongLong(info.rdx));
    PySetDictItemString(dict, "rsi", g_py.PyLong_FromUnsignedLongLong(info.rsi));
    PySetDictItemString(dict, "rdi", g_py.PyLong_FromUnsignedLongLong(info.rdi));
    PySetDictItemString(dict, "rbp", g_py.PyLong_FromUnsignedLongLong(info.rbp));
    PySetDictItemString(dict, "rsp", g_py.PyLong_FromUnsignedLongLong(info.rsp));
    PySetDictItemString(dict, "rip", g_py.PyLong_FromUnsignedLongLong(info.rip));
    PySetDictItemString(dict, "r8", g_py.PyLong_FromUnsignedLongLong(info.r8));
    PySetDictItemString(dict, "r9", g_py.PyLong_FromUnsignedLongLong(info.r9));
    PySetDictItemString(dict, "r10", g_py.PyLong_FromUnsignedLongLong(info.r10));
    PySetDictItemString(dict, "r11", g_py.PyLong_FromUnsignedLongLong(info.r11));
    PySetDictItemString(dict, "r12", g_py.PyLong_FromUnsignedLongLong(info.r12));
    PySetDictItemString(dict, "r13", g_py.PyLong_FromUnsignedLongLong(info.r13));
    PySetDictItemString(dict, "r14", g_py.PyLong_FromUnsignedLongLong(info.r14));
    PySetDictItemString(dict, "r15", g_py.PyLong_FromUnsignedLongLong(info.r15));
    PySetDictItemString(dict, "dr0", g_py.PyLong_FromUnsignedLongLong(info.dr0));
    PySetDictItemString(dict, "dr1", g_py.PyLong_FromUnsignedLongLong(info.dr1));
    PySetDictItemString(dict, "dr2", g_py.PyLong_FromUnsignedLongLong(info.dr2));
    PySetDictItemString(dict, "dr3", g_py.PyLong_FromUnsignedLongLong(info.dr3));
    PySetDictItemString(dict, "dr6", g_py.PyLong_FromUnsignedLongLong(info.dr6));
    PySetDictItemString(dict, "dr7", g_py.PyLong_FromUnsignedLongLong(info.dr7));
    PySetDictItemString(dict, "eax", g_py.PyLong_FromUnsignedLongLong(info.eax));
    PySetDictItemString(dict, "ebx", g_py.PyLong_FromUnsignedLongLong(info.ebx));
    PySetDictItemString(dict, "ecx", g_py.PyLong_FromUnsignedLongLong(info.ecx));
    PySetDictItemString(dict, "edx", g_py.PyLong_FromUnsignedLongLong(info.edx));
    PySetDictItemString(dict, "esi", g_py.PyLong_FromUnsignedLongLong(info.esi));
    PySetDictItemString(dict, "edi", g_py.PyLong_FromUnsignedLongLong(info.edi));
    PySetDictItemString(dict, "ebp", g_py.PyLong_FromUnsignedLongLong(info.ebp));
    PySetDictItemString(dict, "esp", g_py.PyLong_FromUnsignedLongLong(info.esp));
    PySetDictItemString(dict, "eip", g_py.PyLong_FromUnsignedLongLong(info.eip));
    PySetDictItemString(dict, "eflags", g_py.PyLong_FromUnsignedLongLong(info.eflags));
    return dict;
}

PyObject* BuildStackFrameDict(const WdblStackFrameInfo& info) {
    if (g_py.PyDict_New == nullptr || g_py.PyBool_FromLong == nullptr || g_py.PyLong_FromUnsignedLong == nullptr ||
        g_py.PyLong_FromUnsignedLongLong == nullptr || g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python dict api is not available");
    }

    PyObject* dict = g_py.PyDict_New();
    if (dict == nullptr) {
        return nullptr;
    }

    PySetDictItemString(dict, "index", g_py.PyLong_FromUnsignedLong(info.index));
    PySetDictItemString(dict, "thread_id", g_py.PyLong_FromUnsignedLong(info.threadId));
    PySetDictItemString(dict, "is_current", g_py.PyBool_FromLong(info.isCurrent != 0));
    PySetDictItemString(dict, "instruction_pointer", g_py.PyLong_FromUnsignedLongLong(info.instructionPointer));
    PySetDictItemString(dict, "stack_pointer", g_py.PyLong_FromUnsignedLongLong(info.stackPointer));
    PySetDictItemString(dict, "frame_pointer", g_py.PyLong_FromUnsignedLongLong(info.framePointer));
    PySetDictItemString(dict, "return_address", g_py.PyLong_FromUnsignedLongLong(info.returnAddress));
    PySetDictItemString(dict, "source_line", g_py.PyLong_FromUnsignedLong(info.sourceLine));
    PySetDictItemString(dict, "source_displacement", g_py.PyLong_FromUnsignedLong(info.sourceDisplacement));
    PySetDictItemString(dict, "symbol", g_py.PyUnicode_FromWideChar(info.symbol, -1));
    PySetDictItemString(dict, "source_path", g_py.PyUnicode_FromWideChar(info.sourcePath, -1));
    return dict;
}

PyObject* BuildStopInfoDict(const WdblStopInfo& info) {
    if (g_py.PyDict_New == nullptr || g_py.PyBool_FromLong == nullptr || g_py.PyLong_FromUnsignedLong == nullptr ||
        g_py.PyLong_FromUnsignedLongLong == nullptr || g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python dict api is not available");
    }

    PyObject* dict = g_py.PyDict_New();
    if (dict == nullptr) {
        return nullptr;
    }

    PySetDictItemString(dict, "paused", g_py.PyBool_FromLong(info.paused != 0));
    PySetDictItemString(dict, "process_id", g_py.PyLong_FromUnsignedLong(info.processId));
    PySetDictItemString(dict, "thread_id", g_py.PyLong_FromUnsignedLong(info.threadId));
    PySetDictItemString(dict, "exception_code", g_py.PyLong_FromUnsignedLong(info.exceptionCode));
    PySetDictItemString(dict, "first_chance", g_py.PyBool_FromLong(info.firstChance != 0));
    PySetDictItemString(dict, "exception_address", g_py.PyLong_FromUnsignedLongLong(info.exceptionAddress));
    PySetDictItemString(dict, "instruction_pointer", g_py.PyLong_FromUnsignedLongLong(info.instructionPointer));
    PySetDictItemString(dict, "reason", g_py.PyUnicode_FromWideChar(info.reason, -1));
    return dict;
}

PyObject* BuildThreadDict(const WdblThreadInfo& info) {
    if (g_py.PyDict_New == nullptr || g_py.PyBool_FromLong == nullptr || g_py.PyLong_FromUnsignedLong == nullptr ||
        g_py.PyLong_FromUnsignedLongLong == nullptr || g_py.PyLong_FromLong == nullptr || g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python dict api is not available");
    }

    PyObject* dict = g_py.PyDict_New();
    if (dict == nullptr) {
        return nullptr;
    }

    PySetDictItemString(dict, "index", g_py.PyLong_FromUnsignedLong(info.index));
    PySetDictItemString(dict, "process_id", g_py.PyLong_FromUnsignedLong(info.processId));
    PySetDictItemString(dict, "thread_id", g_py.PyLong_FromUnsignedLong(info.threadId));
    PySetDictItemString(dict, "is_current", g_py.PyBool_FromLong(info.isCurrent != 0));
    PySetDictItemString(dict, "has_context", g_py.PyBool_FromLong(info.hasContext != 0));
    PySetDictItemString(dict, "teb", g_py.PyLong_FromUnsignedLongLong(info.teb));
    PySetDictItemString(dict, "instruction_pointer", g_py.PyLong_FromUnsignedLongLong(info.instructionPointer));
    PySetDictItemString(dict, "stack_pointer", g_py.PyLong_FromUnsignedLongLong(info.stackPointer));
    PySetDictItemString(dict, "priority", g_py.PyLong_FromLong(info.priority));
    PySetDictItemString(dict, "base_priority", g_py.PyLong_FromLong(info.basePriority));
    PySetDictItemString(dict, "delta_priority", g_py.PyLong_FromLong(info.deltaPriority));
    PySetDictItemString(dict, "symbol", g_py.PyUnicode_FromWideChar(info.symbol, -1));
    return dict;
}

void PyDecRef(PyObject* object);
int ResolveDefaultThreadIndex(const WdblDebuggerApi* api, void* context);

PyObject* BuildContextDict(const WdblDebuggerApi* api, void* context) {
    if (api == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    if (g_py.PyDict_New == nullptr) {
        return MakeRuntimeError(L"python dict api is not available");
    }

    PyObject* dict = g_py.PyDict_New();
    if (dict == nullptr) {
        return nullptr;
    }

    WdblStopInfo stopInfo = WdblStopInfo();
    stopInfo.size = sizeof(WdblStopInfo);
    if (api->getStopInfo != nullptr && api->getStopInfo(context, &stopInfo) != 0) {
        PySetDictItemString(dict, "stop_info", BuildStopInfoDict(stopInfo));
    }

    const int defaultThreadIndex = ResolveDefaultThreadIndex(api, context);
    if (api->getThreadInfo != nullptr) {
        WdblThreadInfo threadInfo = WdblThreadInfo();
        threadInfo.size = sizeof(WdblThreadInfo);
        if (api->getThreadInfo(context, static_cast<uint32_t>(defaultThreadIndex), &threadInfo) != 0) {
            PySetDictItemString(dict, "thread", BuildThreadDict(threadInfo));
        }
    }

    if (api->getRegisterInfo != nullptr) {
        WdblRegisterInfo registerInfo = WdblRegisterInfo();
        registerInfo.size = sizeof(WdblRegisterInfo);
        if (api->getRegisterInfo(context, static_cast<uint32_t>(defaultThreadIndex), &registerInfo) != 0) {
            PySetDictItemString(dict, "registers", BuildRegisterDict(registerInfo));
        }
    }

    if (api->getStackFrameInfo != nullptr && g_py.PyList_New != nullptr) {
        PyObject* stackFrames = g_py.PyList_New(0);
        if (stackFrames != nullptr) {
            for (unsigned long i = 0; i < 32; ++i) {
                WdblStackFrameInfo frameInfo = WdblStackFrameInfo();
                frameInfo.size = sizeof(WdblStackFrameInfo);
                if (api->getStackFrameInfo(context, static_cast<uint32_t>(defaultThreadIndex), static_cast<uint32_t>(i), &frameInfo) == 0) {
                    break;
                }
                PyObject* item = BuildStackFrameDict(frameInfo);
                if (item == nullptr) {
                    PyDecRef(stackFrames);
                    return dict;
                }
                if (g_py.PyList_Append != nullptr && g_py.PyList_Append(stackFrames, item) != 0) {
                    PyDecRef(item);
                    PyDecRef(stackFrames);
                    return dict;
                }
                PyDecRef(item);
            }
            PySetDictItemString(dict, "stack_frames", stackFrames);
        }
    }

    return dict;
}

int ResolveDefaultThreadIndex(const WdblDebuggerApi* api, void* context) {
    if (api == nullptr || api->getThreadCount == nullptr || api->getThreadInfo == nullptr) {
        return 0;
    }

    WdblStopInfo stopInfo = WdblStopInfo();
    stopInfo.size = sizeof(WdblStopInfo);
    if (api->getStopInfo != nullptr && api->getStopInfo(context, &stopInfo) != 0 && stopInfo.threadId != 0) {
        uint32_t count = 0;
        if (api->getThreadCount(context, &count) != 0) {
            for (uint32_t i = 0; i < count; ++i) {
                WdblThreadInfo info = WdblThreadInfo();
                info.size = sizeof(WdblThreadInfo);
                if (api->getThreadInfo(context, i, &info) != 0 && info.threadId == stopInfo.threadId) {
                    return static_cast<int>(i);
                }
            }
        }
    }
    return 0;
}

const WdblDebuggerApi* GetApi() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_state != nullptr ? g_state->api : nullptr;
}

void* GetContext() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_state != nullptr ? g_state->context : nullptr;
}

PyObject* MakeNone() {
    if (g_py.Py_BuildValue == nullptr) {
        return nullptr;
    }
    return g_py.Py_BuildValue("");
}

PyObject* MakeBool(bool value) {
    if (g_py.PyBool_FromLong == nullptr) {
        return nullptr;
    }
    return g_py.PyBool_FromLong(value ? 1 : 0);
}

void PyDecRef(PyObject* object) {
    if (object != nullptr && g_py.Py_DecRef != nullptr) {
        g_py.Py_DecRef(object);
    }
}

void PyIncRef(PyObject* object) {
    if (object != nullptr && g_py.Py_IncRef != nullptr) {
        g_py.Py_IncRef(object);
    }
}

PyObject* MakeRuntimeError(const wchar_t* message) {
    if (g_py.PyErr_SetString != nullptr && g_py.PyExc_RuntimeError != nullptr) {
        const std::string utf8 = WideToUtf8(message != nullptr ? std::wstring(message) : std::wstring());
        g_py.PyErr_SetString(g_py.PyExc_RuntimeError, utf8.c_str());
    }
    return nullptr;
}

bool PyObjectToWideString(PyObject* object, std::wstring& out) {
    out.clear();
    if (object == nullptr || g_py.PyObject_Str == nullptr || g_py.PyUnicode_AsWideCharString == nullptr || g_py.PyMem_Free == nullptr) {
        return false;
    }

    PyObject* textObject = g_py.PyObject_Str(object);
    if (textObject == nullptr) {
        return false;
    }

    Py_ssize_t length = 0;
    wchar_t* buffer = g_py.PyUnicode_AsWideCharString(textObject, &length);
    if (buffer == nullptr) {
        PyDecRef(textObject);
        return false;
    }

    out.assign(buffer, buffer + length);
    g_py.PyMem_Free(buffer);
    PyDecRef(textObject);
    return true;
}

void PySetDictItemString(PyObject* dict, const char* key, PyObject* value) {
    if (dict == nullptr || key == nullptr || value == nullptr || g_py.PyDict_SetItemString == nullptr) {
        return;
    }
    if (g_py.PyDict_SetItemString(dict, key, value) == 0) {
        PyDecRef(value);
    } else {
        PyDecRef(value);
    }
}

bool ReadMemoryBuffer(const WdblDebuggerApi* api, void* context, uint64_t address, void* buffer, uint32_t size) {
    if (api == nullptr || api->readMemory == nullptr || buffer == nullptr || size == 0) {
        return false;
    }
    uint32_t bytesRead = 0;
    return api->readMemory(context, address, buffer, size, &bytesRead) != 0 && bytesRead == size;
}

bool ReadAnsiStringFromMemory(const WdblDebuggerApi* api, void* context, uint64_t address, std::string& out, uint32_t maxBytes) {
    out.clear();
    if (maxBytes == 0) {
        return false;
    }

    const uint32_t chunkSize = 256;
    std::vector<char> buffer(chunkSize);
    for (uint32_t offset = 0; offset < maxBytes; ) {
        const uint32_t request = std::min<uint32_t>(chunkSize, maxBytes - offset);
        uint32_t bytesRead = 0;
        if (api == nullptr || api->readMemory == nullptr ||
            api->readMemory(context, address + offset, buffer.data(), request, &bytesRead) == 0 ||
            bytesRead == 0) {
            break;
        }
        for (uint32_t i = 0; i < bytesRead; ++i) {
            const char ch = buffer[i];
            if (ch == '\0') {
                return true;
            }
            out.push_back(ch);
        }
        offset += bytesRead;
        if (bytesRead < request) {
            break;
        }
    }
    return !out.empty();
}

bool ReadWideStringFromMemory(const WdblDebuggerApi* api, void* context, uint64_t address, std::wstring& out, uint32_t maxChars) {
    out.clear();
    if (maxChars == 0) {
        return false;
    }

    const uint32_t chunkChars = 128;
    std::vector<wchar_t> buffer(chunkChars);
    for (uint32_t offset = 0; offset < maxChars; ) {
        const uint32_t requestChars = std::min<uint32_t>(chunkChars, maxChars - offset);
        const uint32_t requestBytes = requestChars * static_cast<uint32_t>(sizeof(wchar_t));
        uint32_t bytesRead = 0;
        if (api == nullptr || api->readMemory == nullptr ||
            api->readMemory(context, address + static_cast<uint64_t>(offset) * sizeof(wchar_t), buffer.data(), requestBytes, &bytesRead) == 0 ||
            bytesRead == 0) {
            break;
        }

        const uint32_t charsRead = bytesRead / static_cast<uint32_t>(sizeof(wchar_t));
        for (uint32_t i = 0; i < charsRead; ++i) {
            const wchar_t ch = buffer[i];
            if (ch == L'\0') {
                return true;
            }
            out.push_back(ch);
        }

        offset += charsRead;
        if (bytesRead < requestBytes) {
            break;
        }
    }
    return !out.empty();
}

std::wstring GetModuleDirectory() {
    wchar_t path[MAX_PATH] = {};
    DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return L"";
    }
    std::wstring full(path);
    const size_t slash = full.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return L"";
    }
    return full.substr(0, slash);
}

std::wstring GetCurrentDirectoryPath() {
    wchar_t path[MAX_PATH] = {};
    DWORD len = GetCurrentDirectoryW(MAX_PATH, path);
    if (len == 0 || len >= MAX_PATH) {
        return L"";
    }
    return std::wstring(path);
}

bool DirectoryHasPythonDll(const std::wstring& dir) {
    if (dir.empty()) {
        return false;
    }

    const std::wstring dlls[] = {
        L"python3.dll",
        L"python314.dll",
        L"python313.dll",
        L"python312.dll",
        L"python311.dll",
        L"python310.dll"
    };

    for (size_t di = 0; di < 6; ++di) {
        const std::wstring& dll = dlls[di];
        const std::wstring full = dir + L"\\" + dll;
        DWORD attr = GetFileAttributesW(full.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            return true;
        }
    }
    return false;
}

std::wstring FindPythonRuntimeDirectory() {
    const std::wstring cwd = GetCurrentDirectoryPath();
    if (DirectoryHasPythonDll(cwd)) {
        return cwd;
    }

    const std::wstring exeDir = GetModuleDirectory();
    if (DirectoryHasPythonDll(exeDir)) {
        return exeDir;
    }

    wchar_t homeBuf[MAX_PATH] = {};
    DWORD homeLen = GetEnvironmentVariableW(L"PYTHONHOME", homeBuf, MAX_PATH);
    if (homeLen > 0 && homeLen < MAX_PATH) {
        const std::wstring home(homeBuf);
        if (DirectoryHasPythonDll(home)) {
            return home;
        }
    }

    wchar_t localAppData[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return L"";
    }

    const std::wstring roots[] = {
        std::wstring(localAppData) + L"\\Programs\\Python",
        std::wstring(localAppData) + L"\\Python"
    };

    for (size_t ri = 0; ri < 2; ++ri) {
        const std::wstring& root = roots[ri];
        WIN32_FIND_DATAW data = {};
        HANDLE find = FindFirstFileW((root + L"\\*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE) {
            continue;
        }
        do {
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                continue;
            }
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) {
                continue;
            }
            const std::wstring candidate = root + L"\\" + data.cFileName;
            if (DirectoryHasPythonDll(candidate)) {
                FindClose(find);
                return candidate;
            }
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }

    return L"";
}

bool ReadWholeFileUtf8(const std::wstring& path, std::string& out) {
    out.clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 0x7fffffff) {
        CloseHandle(file);
        return false;
    }

    out.resize(static_cast<size_t>(size.QuadPart));
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(file, &out[0], static_cast<DWORD>(out.size()), &bytesRead, nullptr);
    CloseHandle(file);
    if (!ok || bytesRead != out.size()) {
        out.clear();
        return false;
    }
    return true;
}

bool LoadPythonRuntime() {
    if (g_py.module != nullptr) {
        return true;
    }

    const std::wstring root = FindPythonRuntimeDirectory();
    if (root.empty()) {
        return false;
    }

    const std::wstring dlls[] = {
        L"python3.dll",
        L"python314.dll",
        L"python313.dll",
        L"python312.dll",
        L"python311.dll",
        L"python310.dll"
    };

    for (size_t di = 0; di < 6; ++di) {
        const std::wstring& dll = dlls[di];
        const std::wstring full = root + L"\\" + dll;
        HMODULE module = LoadLibraryW(full.c_str());
        if (module == nullptr) {
            continue;
        }

        g_py.module = module;
        g_py.PyImport_AppendInittab = LoadProc<PythonApi::FnPyImport_AppendInittab>(module, "PyImport_AppendInittab");
        g_py.Py_Initialize = LoadProc<PythonApi::FnPy_Initialize>(module, "Py_Initialize");
        g_py.Py_IsInitialized = LoadProc<PythonApi::FnPy_IsInitialized>(module, "Py_IsInitialized");
        g_py.Py_Finalize = LoadProc<PythonApi::FnPy_Finalize>(module, "Py_Finalize");
        g_py.PyImport_ImportModule = LoadProc<PythonApi::FnPyImport_ImportModule>(module, "PyImport_ImportModule");
        g_py.PyImport_AddModule = LoadProc<PythonApi::FnPyImport_AddModule>(module, "PyImport_AddModule");
        g_py.PyModule_GetDict = LoadProc<PythonApi::FnPyModule_GetDict>(module, "PyModule_GetDict");
        g_py.PyRun_SimpleString = LoadProc<PythonApi::FnPyRun_SimpleString>(module, "PyRun_SimpleString");
        g_py.PyErr_Print = LoadProc<PythonApi::FnPyErr_Print>(module, "PyErr_Print");
        g_py.PyErr_SetString = LoadProc<PythonApi::FnPyErr_SetString>(module, "PyErr_SetString");
        g_py.PyObject_Str = LoadProc<PythonApi::FnPyObject_Str>(module, "PyObject_Str");
        g_py.PyUnicode_AsWideCharString = LoadProc<PythonApi::FnPyUnicode_AsWideCharString>(module, "PyUnicode_AsWideCharString");
        g_py.PyMem_Free = LoadProc<PythonApi::FnPyMem_Free>(module, "PyMem_Free");
        g_py.PyBool_FromLong = LoadProc<PythonApi::FnPyBool_FromLong>(module, "PyBool_FromLong");
        g_py.PyLong_FromUnsignedLong = LoadProc<PythonApi::FnPyLong_FromUnsignedLong>(module, "PyLong_FromUnsignedLong");
        g_py.PyLong_FromUnsignedLongLong = LoadProc<PythonApi::FnPyLong_FromUnsignedLongLong>(module, "PyLong_FromUnsignedLongLong");
        g_py.PyLong_FromLong = LoadProc<PythonApi::FnPyLong_FromLong>(module, "PyLong_FromLong");
        g_py.PyDict_New = LoadProc<PythonApi::FnPyDict_New>(module, "PyDict_New");
        g_py.PyDict_SetItemString = LoadProc<PythonApi::FnPyDict_SetItemString>(module, "PyDict_SetItemString");
        g_py.PyList_New = LoadProc<PythonApi::FnPyList_New>(module, "PyList_New");
        g_py.PyList_Append = LoadProc<PythonApi::FnPyList_Append>(module, "PyList_Append");
        g_py.PyUnicode_FromWideChar = LoadProc<PythonApi::FnPyUnicode_FromWideChar>(module, "PyUnicode_FromWideChar");
        g_py.PyBytes_FromStringAndSize = LoadProc<PythonApi::FnPyBytes_FromStringAndSize>(module, "PyBytes_FromStringAndSize");
        g_py.PyObject_GetBuffer = LoadProc<PythonApi::FnPyObject_GetBuffer>(module, "PyObject_GetBuffer");
        g_py.PyBuffer_Release = LoadProc<PythonApi::FnPyBuffer_Release>(module, "PyBuffer_Release");
        g_py.PyArg_ParseTuple = LoadProc<PythonApi::FnPyArg_ParseTuple>(module, "PyArg_ParseTuple");
        g_py.Py_BuildValue = LoadProc<PythonApi::FnPy_BuildValue>(module, "Py_BuildValue");
        g_py.PyModule_Create2 = LoadProc<PythonApi::FnPyModule_Create2>(module, "PyModule_Create2");
        g_py.Py_DecRef = LoadProc<PythonApi::FnPy_DecRef>(module, "Py_DecRef");
        g_py.Py_IncRef = LoadProc<PythonApi::FnPy_IncRef>(module, "Py_IncRef");
        g_py.PyExc_RuntimeError = LoadGlobalPtr<PyObject>(module, "PyExc_RuntimeError");
        g_py.PyExc_ValueError = LoadGlobalPtr<PyObject>(module, "PyExc_ValueError");
        g_py.PyModuleDef_Type = reinterpret_cast<_typeobject*>(GetProcAddress(module, "PyModuleDef_Type"));

        const bool ok =
            g_py.PyImport_AppendInittab != nullptr &&
            g_py.Py_Initialize != nullptr &&
            g_py.Py_IsInitialized != nullptr &&
            g_py.Py_Finalize != nullptr &&
            g_py.PyImport_ImportModule != nullptr &&
            g_py.PyRun_SimpleString != nullptr &&
            g_py.PyErr_Print != nullptr &&
            g_py.PyErr_SetString != nullptr &&
            g_py.PyObject_Str != nullptr &&
            g_py.PyUnicode_AsWideCharString != nullptr &&
            g_py.PyMem_Free != nullptr &&
            g_py.PyBool_FromLong != nullptr &&
            g_py.PyLong_FromUnsignedLong != nullptr &&
            g_py.PyLong_FromUnsignedLongLong != nullptr &&
            g_py.PyLong_FromLong != nullptr &&
            g_py.PyDict_New != nullptr &&
            g_py.PyDict_SetItemString != nullptr &&
            g_py.PyList_New != nullptr &&
            g_py.PyList_Append != nullptr &&
            g_py.PyUnicode_FromWideChar != nullptr &&
            g_py.PyBytes_FromStringAndSize != nullptr &&
            g_py.PyObject_GetBuffer != nullptr &&
            g_py.PyBuffer_Release != nullptr &&
            g_py.PyArg_ParseTuple != nullptr &&
            g_py.Py_BuildValue != nullptr &&
            g_py.PyModule_Create2 != nullptr &&
            g_py.Py_DecRef != nullptr &&
            g_py.Py_IncRef != nullptr &&
            g_py.PyExc_RuntimeError != nullptr &&
            g_py.PyExc_ValueError != nullptr &&
            g_py.PyModuleDef_Type != nullptr;
        if (ok) {
            return true;
        }

        FreeLibrary(module);
        g_py = PythonApi();
    }

    return false;
}

PyObject* BridgeWriteStdout(PyObject*, PyObject* args);
PyObject* BridgeWriteStderr(PyObject*, PyObject* args);
PyObject* BridgeEmit(PyObject*, PyObject* args);
PyObject* BridgeEmitLine(PyObject*, PyObject* args);
PyObject* BridgeEmitColor(PyObject*, PyObject* args);
PyObject* BridgeEmitColorBg(PyObject*, PyObject* args);
PyObject* BridgeEmitInfo(PyObject*, PyObject* args);
PyObject* BridgeEmitWarn(PyObject*, PyObject* args);
PyObject* BridgeEmitError(PyObject*, PyObject* args);
PyObject* BridgeLaunch(PyObject*, PyObject* args);
PyObject* BridgeAttach(PyObject*, PyObject* args);
PyObject* BridgeDetach(PyObject*, PyObject*);
PyObject* BridgeContinue(PyObject*, PyObject*);
PyObject* BridgeSingleStep(PyObject*, PyObject*);
PyObject* BridgeStepOver(PyObject*, PyObject*);
PyObject* BridgeExecute(PyObject*, PyObject* args);
PyObject* BridgeReadMemory(PyObject*, PyObject* args);
PyObject* BridgeWriteMemory(PyObject*, PyObject* args);
PyObject* BridgeDumpMemory(PyObject*, PyObject* args);
PyObject* BridgeResolveSymbol(PyObject*, PyObject* args);
PyObject* BridgeResolveAddressExpression(PyObject*, PyObject* args);
PyObject* BridgeLoadSymbols(PyObject*, PyObject* args);
PyObject* BridgeDownloadSymbols(PyObject*, PyObject* args);
PyObject* BridgeSetSymbolSearchPath(PyObject*, PyObject* args);
PyObject* BridgeGetSymbolSearchPath(PyObject*, PyObject*);
PyObject* BridgeSelectThread(PyObject*, PyObject* args);
PyObject* BridgeSetRegisterValue(PyObject*, PyObject* args);
PyObject* BridgeWriteMemoryPatch(PyObject*, PyObject* args);
PyObject* BridgeUndoMemoryPatch(PyObject*, PyObject* args);
PyObject* BridgeExecuteCapture(PyObject*, PyObject* args);
PyObject* BridgeSaveCurrentStopSnapshot(PyObject*, PyObject*);
PyObject* BridgeSaveNamedSnapshot(PyObject*, PyObject* args);
PyObject* BridgeRestoreNamedSnapshot(PyObject*, PyObject* args);
PyObject* BridgeListNamedSnapshots(PyObject*, PyObject*);
PyObject* BridgeStepBackToPreviousSnapshot(PyObject*, PyObject*);
PyObject* BridgeAddSourceRoot(PyObject*, PyObject* args);
PyObject* BridgeRemoveSourceRoot(PyObject*, PyObject* args);
PyObject* BridgeClearSourceRoots(PyObject*, PyObject*);
PyObject* BridgeListSourceRoots(PyObject*, PyObject*);
PyObject* BridgeLoadScriptFile(PyObject*, PyObject* args);
PyObject* BridgeSetScriptBreakpoint(PyObject*, PyObject* args);
PyObject* BridgeRemoveScriptBreakpoint(PyObject*, PyObject* args);
PyObject* BridgeListScriptBreakpoints(PyObject*, PyObject*);
PyObject* BridgeConfigureExceptionIgnoreAll(PyObject*, PyObject* args);
PyObject* BridgeAddIgnoredExceptionCode(PyObject*, PyObject* args);
PyObject* BridgeRemoveIgnoredExceptionCode(PyObject*, PyObject* args);
PyObject* BridgeClearIgnoredExceptionCodes(PyObject*, PyObject* args);
PyObject* BridgeListExceptionSettings(PyObject*, PyObject*);
PyObject* BridgeAddRunStopExpression(PyObject*, PyObject* args);
PyObject* BridgeRemoveRunStopExpression(PyObject*, PyObject* args);
PyObject* BridgeClearRunStopExpressions(PyObject*, PyObject*);
PyObject* BridgeListRunStopExpressions(PyObject*, PyObject*);
PyObject* BridgeStepUntilCondition(PyObject*, PyObject* args);
PyObject* BridgeRunUntilCondition(PyObject*, PyObject* args);
PyObject* BridgeAutoStep(PyObject*, PyObject* args);
PyObject* BridgeAutoRun(PyObject*, PyObject* args);
PyObject* BridgeReadCString(PyObject*, PyObject* args);
PyObject* BridgeReadWString(PyObject*, PyObject* args);
PyObject* BridgeGetStopInfo(PyObject*, PyObject*);
PyObject* BridgeGetContext(PyObject*, PyObject*);
PyObject* BridgePrintStopInfo(PyObject*, PyObject*);
PyObject* BridgeGetThreadCount(PyObject*, PyObject*);
PyObject* BridgeGetThreadInfo(PyObject*, PyObject* args);
PyObject* BridgeGetRegisters(PyObject*, PyObject* args);
PyObject* BridgeGetStackFrames(PyObject*, PyObject* args);
PyObject* BridgePrintThreads(PyObject*, PyObject*);
PyObject* BridgePrintThread(PyObject*, PyObject* args);
PyObject* BridgePrintModules(PyObject*, PyObject*);
PyObject* BridgePrintBreakpoints(PyObject*, PyObject*);
PyObject* BridgePrintRegisters(PyObject*, PyObject*);
PyObject* BridgePrintStack(PyObject*, PyObject*);
PyObject* BridgePrintContext(PyObject*, PyObject*);
PyObject* BridgeGetModules(PyObject*, PyObject*);
PyObject* BridgeGetBreakpoints(PyObject*, PyObject*);
PyObject* BridgeAddSoftwareBreakpoint(PyObject*, PyObject* args);
PyObject* BridgeAddHardwareBreakpoint(PyObject*, PyObject* args);
PyObject* BridgeAddMemoryBreakpoint(PyObject*, PyObject* args);
PyObject* BridgeEnableBreakpoint(PyObject*, PyObject* args);
PyObject* BridgeDisableBreakpoint(PyObject*, PyObject* args);
PyObject* BridgeRemoveBreakpoint(PyObject*, PyObject* args);
PyObject* BridgeSetBreakpointCondition(PyObject*, PyObject* args);
PyObject* BridgeClearBreakpointCondition(PyObject*, PyObject* args);

bool ParseHardwareAccessArgument(const std::wstring& value, int32_t& outAccess) {
    const std::wstring lower = ToLowerCopy(TrimCopy(value));
    if (lower == L"e" || lower == L"x" || lower == L"exec" || lower == L"execute") {
        outAccess = 0;
        return true;
    }
    if (lower == L"w" || lower == L"write") {
        outAccess = 1;
        return true;
    }
    if (lower == L"r" || lower == L"read" || lower == L"access") {
        outAccess = 2;
        return true;
    }
    return false;
}

bool ParseMemoryAccessArgument(const std::wstring& value, uint32_t& outAccess) {
    const std::wstring lower = ToLowerCopy(TrimCopy(value));
    if (lower.empty()) {
        return false;
    }
    uint32_t mask = 0;
    for (size_t ci = 0; ci < lower.size(); ++ci) {
        wchar_t ch = lower[ci];
        if (ch == L'r') {
            mask |= 1u;
        } else if (ch == L'w') {
            mask |= 2u;
        } else if (ch == L'x' || ch == L'e') {
            mask |= 4u;
        }
    }
    if (mask == 0) {
        if (lower == L"read") {
            mask = 1u;
        } else if (lower == L"write") {
            mask = 2u;
        } else if (lower == L"execute") {
            mask = 4u;
        }
    }
    if (mask == 0) {
        return false;
    }
    outAccess = mask;
    return true;
}

bool ParseExceptionScopeArgument(const std::wstring& value, int32_t& outScope) {
    const std::wstring lower = ToLowerCopy(TrimCopy(value));
    if (lower == L"debug" || lower == L"debugging" || lower == L"d") {
        outScope = 0;
        return true;
    }
    if (lower == L"runtime" || lower == L"run" || lower == L"r") {
        outScope = 1;
        return true;
    }
    if (lower == L"step" || lower == L"stepping" || lower == L"s") {
        outScope = 2;
        return true;
    }
    return false;
}

class ScopedStreamCapture {
public:
    ScopedStreamCapture(std::wostream& stream, std::wstring& capture)
        : stream_(stream), previous_(stream.rdbuf()), capture_(capture), tee_(previous_, &capture_) {
        stream_.rdbuf(&tee_);
    }

    ~ScopedStreamCapture() {
        stream_.rdbuf(previous_);
    }

private:
    class TeeBuffer : public std::wstreambuf {
    public:
        TeeBuffer(std::wstreambuf* destination, std::wstring* capture)
            : destination_(destination), capture_(capture) {
        }

    protected:
        int_type overflow(int_type ch) override {
            if (traits_type::eq_int_type(ch, traits_type::eof())) {
                return traits_type::not_eof(ch);
            }
            const wchar_t wc = traits_type::to_char_type(ch);
            if (destination_ != nullptr) {
                destination_->sputc(wc);
            }
            if (capture_ != nullptr) {
                capture_->push_back(wc);
            }
            return ch;
        }

        int sync() override {
            if (destination_ != nullptr) {
                destination_->pubsync();
            }
            return 0;
        }

    private:
        std::wstreambuf* destination_;
        std::wstring* capture_;
    };

    std::wostream& stream_;
    std::wstreambuf* previous_;
    std::wstring& capture_;
    TeeBuffer tee_;
};

PyObject* MakeExecuteResultDict(bool ok, const std::wstring& output) {
    if (g_py.PyDict_New == nullptr || g_py.PyBool_FromLong == nullptr || g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python dict api is not available");
    }
    PyObject* dict = g_py.PyDict_New();
    if (dict == nullptr) {
        return nullptr;
    }
    PySetDictItemString(dict, "ok", g_py.PyBool_FromLong(ok ? 1 : 0));
    PySetDictItemString(dict, "output", g_py.PyUnicode_FromWideChar(output.c_str(), static_cast<Py_ssize_t>(output.size())));
    return dict;
}

PyObject* MakeResolvedAddressDict(uint64_t address, const std::wstring& text) {
    if (g_py.PyDict_New == nullptr || g_py.PyLong_FromUnsignedLongLong == nullptr || g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python dict api is not available");
    }
    PyObject* dict = g_py.PyDict_New();
    if (dict == nullptr) {
        return nullptr;
    }
    PySetDictItemString(dict, "address", g_py.PyLong_FromUnsignedLongLong(address));
    PySetDictItemString(dict, "text", g_py.PyUnicode_FromWideChar(text.c_str(), -1));
    return dict;
}

PyObject* MakeSymbolResultDict(const std::wstring& target, const std::wstring& pdbPath, bool downloaded) {
    if (g_py.PyDict_New == nullptr || g_py.PyBool_FromLong == nullptr || g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python dict api is not available");
    }
    PyObject* dict = g_py.PyDict_New();
    if (dict == nullptr) {
        return nullptr;
    }
    PySetDictItemString(dict, "target", g_py.PyUnicode_FromWideChar(target.c_str(), -1));
    PySetDictItemString(dict, "pdb_path", g_py.PyUnicode_FromWideChar(pdbPath.c_str(), -1));
    PySetDictItemString(dict, "downloaded", g_py.PyBool_FromLong(downloaded ? 1 : 0));
    return dict;
}

PyMethodDef kMethods[] = {
    {"write_stdout", BridgeWriteStdout, METH_VARARGS, nullptr},
    {"write_stderr", BridgeWriteStderr, METH_VARARGS, nullptr},
    {"emit", BridgeEmit, METH_VARARGS, nullptr},
    {"emit_line", BridgeEmitLine, METH_VARARGS, nullptr},
    {"emit_color", BridgeEmitColor, METH_VARARGS, nullptr},
    {"emit_color_bg", BridgeEmitColorBg, METH_VARARGS, nullptr},
    {"emit_info", BridgeEmitInfo, METH_VARARGS, nullptr},
    {"emit_warn", BridgeEmitWarn, METH_VARARGS, nullptr},
    {"emit_error", BridgeEmitError, METH_VARARGS, nullptr},
    {"launch", BridgeLaunch, METH_VARARGS, nullptr},
    {"attach", BridgeAttach, METH_VARARGS, nullptr},
    {"detach", BridgeDetach, METH_NOARGS, nullptr},
    {"continue_execution", BridgeContinue, METH_NOARGS, nullptr},
    {"single_step", BridgeSingleStep, METH_NOARGS, nullptr},
    {"step_over", BridgeStepOver, METH_NOARGS, nullptr},
    {"execute", BridgeExecute, METH_VARARGS, nullptr},
    {"execute_capture", BridgeExecuteCapture, METH_VARARGS, nullptr},
    {"read_memory", BridgeReadMemory, METH_VARARGS, nullptr},
    {"write_memory", BridgeWriteMemory, METH_VARARGS, nullptr},
    {"dump", BridgeDumpMemory, METH_VARARGS, nullptr},
    {"resolve_symbol", BridgeResolveSymbol, METH_VARARGS, nullptr},
    {"resolve_address_expression", BridgeResolveAddressExpression, METH_VARARGS, nullptr},
    {"load_symbols", BridgeLoadSymbols, METH_VARARGS, nullptr},
    {"download_symbols", BridgeDownloadSymbols, METH_VARARGS, nullptr},
    {"set_symbol_search_path", BridgeSetSymbolSearchPath, METH_VARARGS, nullptr},
    {"get_symbol_search_path", BridgeGetSymbolSearchPath, METH_NOARGS, nullptr},
    {"select_thread", BridgeSelectThread, METH_VARARGS, nullptr},
    {"set_register_value", BridgeSetRegisterValue, METH_VARARGS, nullptr},
    {"write_memory_patch", BridgeWriteMemoryPatch, METH_VARARGS, nullptr},
    {"undo_memory_patch", BridgeUndoMemoryPatch, METH_VARARGS, nullptr},
    {"save_current_stop_snapshot", BridgeSaveCurrentStopSnapshot, METH_NOARGS, nullptr},
    {"save_named_snapshot", BridgeSaveNamedSnapshot, METH_VARARGS, nullptr},
    {"restore_named_snapshot", BridgeRestoreNamedSnapshot, METH_VARARGS, nullptr},
    {"list_named_snapshots", BridgeListNamedSnapshots, METH_NOARGS, nullptr},
    {"step_back_to_previous_snapshot", BridgeStepBackToPreviousSnapshot, METH_NOARGS, nullptr},
    {"add_source_root", BridgeAddSourceRoot, METH_VARARGS, nullptr},
    {"remove_source_root", BridgeRemoveSourceRoot, METH_VARARGS, nullptr},
    {"clear_source_roots", BridgeClearSourceRoots, METH_NOARGS, nullptr},
    {"list_source_roots", BridgeListSourceRoots, METH_NOARGS, nullptr},
    {"load_script_file", BridgeLoadScriptFile, METH_VARARGS, nullptr},
    {"set_script_breakpoint", BridgeSetScriptBreakpoint, METH_VARARGS, nullptr},
    {"remove_script_breakpoint", BridgeRemoveScriptBreakpoint, METH_VARARGS, nullptr},
    {"list_script_breakpoints", BridgeListScriptBreakpoints, METH_NOARGS, nullptr},
    {"configure_exception_ignore_all", BridgeConfigureExceptionIgnoreAll, METH_VARARGS, nullptr},
    {"add_ignored_exception_code", BridgeAddIgnoredExceptionCode, METH_VARARGS, nullptr},
    {"remove_ignored_exception_code", BridgeRemoveIgnoredExceptionCode, METH_VARARGS, nullptr},
    {"clear_ignored_exception_codes", BridgeClearIgnoredExceptionCodes, METH_VARARGS, nullptr},
    {"list_exception_settings", BridgeListExceptionSettings, METH_NOARGS, nullptr},
    {"add_run_stop_expression", BridgeAddRunStopExpression, METH_VARARGS, nullptr},
    {"remove_run_stop_expression", BridgeRemoveRunStopExpression, METH_VARARGS, nullptr},
    {"clear_run_stop_expressions", BridgeClearRunStopExpressions, METH_NOARGS, nullptr},
    {"list_run_stop_expressions", BridgeListRunStopExpressions, METH_NOARGS, nullptr},
    {"step_until_condition", BridgeStepUntilCondition, METH_VARARGS, nullptr},
    {"run_until_condition", BridgeRunUntilCondition, METH_VARARGS, nullptr},
    {"auto_step", BridgeAutoStep, METH_VARARGS, nullptr},
    {"auto_run", BridgeAutoRun, METH_VARARGS, nullptr},
    {"read_cstr", BridgeReadCString, METH_VARARGS, nullptr},
    {"read_wstr", BridgeReadWString, METH_VARARGS, nullptr},
    {"add_software_breakpoint", BridgeAddSoftwareBreakpoint, METH_VARARGS, nullptr},
    {"add_hardware_breakpoint", BridgeAddHardwareBreakpoint, METH_VARARGS, nullptr},
    {"add_memory_breakpoint", BridgeAddMemoryBreakpoint, METH_VARARGS, nullptr},
    {"enable_breakpoint", BridgeEnableBreakpoint, METH_VARARGS, nullptr},
    {"disable_breakpoint", BridgeDisableBreakpoint, METH_VARARGS, nullptr},
    {"remove_breakpoint", BridgeRemoveBreakpoint, METH_VARARGS, nullptr},
    {"set_breakpoint_condition", BridgeSetBreakpointCondition, METH_VARARGS, nullptr},
    {"clear_breakpoint_condition", BridgeClearBreakpointCondition, METH_VARARGS, nullptr},
    {"get_stop_info", BridgeGetStopInfo, METH_NOARGS, nullptr},
    {"get_context", BridgeGetContext, METH_NOARGS, nullptr},
    {"print_stop_info", BridgePrintStopInfo, METH_NOARGS, nullptr},
    {"get_thread_count", BridgeGetThreadCount, METH_NOARGS, nullptr},
    {"get_thread_info", BridgeGetThreadInfo, METH_VARARGS, nullptr},
    {"get_registers", BridgeGetRegisters, METH_VARARGS, nullptr},
    {"get_stack_frames", BridgeGetStackFrames, METH_VARARGS, nullptr},
    {"get_stack", BridgeGetStackFrames, METH_VARARGS, nullptr},
    {"print_threads", BridgePrintThreads, METH_NOARGS, nullptr},
    {"print_thread", BridgePrintThread, METH_VARARGS, nullptr},
    {"print_modules", BridgePrintModules, METH_NOARGS, nullptr},
    {"print_breakpoints", BridgePrintBreakpoints, METH_NOARGS, nullptr},
    {"print_registers", BridgePrintRegisters, METH_NOARGS, nullptr},
    {"print_stack", BridgePrintStack, METH_NOARGS, nullptr},
    {"print_context", BridgePrintContext, METH_NOARGS, nullptr},
    {"get_modules", BridgeGetModules, METH_NOARGS, nullptr},
    {"get_breakpoints", BridgeGetBreakpoints, METH_NOARGS, nullptr},
    {nullptr, nullptr, 0, nullptr}
};

PyModuleDef kModuleDef = {
    { {1, nullptr}, nullptr, 0, nullptr },
    "z0dbg",
    "Z0BDbgCli Python bridge",
    -1,
    kMethods,
    nullptr,
    nullptr,
    nullptr,
    nullptr
};

PyObject* CreateModule() {
    if (g_py.PyModule_Create2 == nullptr) {
        return nullptr;
    }
    kModuleDef.m_base.ob_base.ob_type = g_py.PyModuleDef_Type;
    return g_py.PyModule_Create2(&kModuleDef, kPyModuleApiVersion);
}

bool RegisterMethods() {
    if (g_py.PyImport_AppendInittab == nullptr) {
        return false;
    }
    return g_py.PyImport_AppendInittab("z0dbg", &CreateModule) == 0;
}

}  // namespace

PythonBridge::PythonBridge()
    : api_(nullptr),
      context_(nullptr),
      runtimeModule_(nullptr),
      initialized_(false),
      moduleRegistered_(false) {
}

PythonBridge::~PythonBridge() {
    Shutdown();
}

void PythonBridge::SetOutputCallback(OutputCallback callback) {
    output_ = std::move(callback);
}

bool PythonBridge::IsInitialized() const {
    return initialized_;
}

bool PythonBridge::LoadRuntimeLibrary() {
    if (runtimeModule_ != nullptr) {
        return true;
    }
    if (!LoadPythonRuntime()) {
        return false;
    }
    runtimeLibraryPath_ = FindPythonRuntimeDirectory();
    runtimeModule_ = g_py.module;
    return runtimeModule_ != nullptr;
}

bool PythonBridge::RegisterModule() {
    if (moduleRegistered_) {
        return true;
    }
    if (!LoadRuntimeLibrary()) {
        return false;
    }
    if (!RegisterMethods()) {
        return false;
    }
    moduleRegistered_ = true;
    return true;
}

bool PythonBridge::EnsureInitialized() {
    if (initialized_) {
        return true;
    }
    if (api_ == nullptr || context_ == nullptr) {
        return false;
    }

    if (!LoadRuntimeLibrary()) {
        Emit(L"Python runtime not found.\r\n");
        return false;
    }
    if (!RegisterModule()) {
        Emit(L"Failed to register Python bridge module.\r\n");
        return false;
    }

    std::lock_guard<std::mutex> lock(g_stateMutex);
    static BridgeState state;
    state.api = api_;
    state.context = context_;
    state.owner = this;
    g_state = &state;

    if (g_py.Py_Initialize != nullptr) {
        g_py.Py_Initialize();
    }
    if (g_py.Py_IsInitialized == nullptr || g_py.Py_IsInitialized() == 0) {
        Emit(L"Failed to initialize Python.\r\n");
        return false;
    }

    if (g_py.PyImport_ImportModule == nullptr) {
        Emit(L"Failed to import z0dbg.\r\n");
        return false;
    }
    PyObject* module = g_py.PyImport_ImportModule("z0dbg");
    if (module == nullptr) {
        if (g_py.PyErr_Print != nullptr) {
            g_py.PyErr_Print();
        }
        Emit(L"Failed to import z0dbg.\r\n");
        return false;
    }
    PyDecRef(module);

    const char* bootstrap =
        "import sys\n"
        "import z0dbg\n"
        "class _Writer:\n"
        "    def __init__(self, fn):\n"
        "        self._fn = fn\n"
        "    def write(self, text):\n"
        "        if text:\n"
        "            self._fn(text)\n"
        "    def flush(self):\n"
        "        pass\n"
        "sys.stdout = _Writer(z0dbg.write_stdout)\n"
        "sys.stderr = _Writer(z0dbg.write_stderr)\n";
    if (g_py.PyRun_SimpleString == nullptr || g_py.PyRun_SimpleString(bootstrap) != 0) {
        if (g_py.PyErr_Print != nullptr) {
            g_py.PyErr_Print();
        }
        Emit(L"Failed to bootstrap Python stdout/stderr.\r\n");
        return false;
    }

    initialized_ = true;
    return true;
}

bool PythonBridge::Initialize(const WdblDebuggerApi* api, void* context) {
    api_ = api;
    context_ = context;
    return EnsureInitialized();
}

void PythonBridge::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (g_state != nullptr && g_state->owner == this) {
            g_state = nullptr;
        }
    }
    initialized_ = false;
    // Leave the embedded runtime loaded; process teardown will reclaim it safely.
}

bool PythonBridge::RunFile(const std::wstring& filePath, const std::vector<std::wstring>& args) {
    if (!EnsureInitialized()) {
        return false;
    }

    const std::wstring trimmed = TrimCopy(filePath);
    if (trimmed.empty()) {
        Emit(L"Usage: py run <script.py>\r\n");
        return false;
    }

    std::string bytes;
    if (!ReadWholeFileUtf8(trimmed, bytes)) {
        Emit(L"Failed to open Python script.\r\n");
        return false;
    }

    const std::wstring scriptDir = GetParentDirectory(trimmed);
    if (!scriptDir.empty() && g_py.PyRun_SimpleString != nullptr) {
        const std::string pathExpr = "import sys\nsys.path.insert(0, r'" + EscapePythonRawString(scriptDir) + "')\n";
        g_py.PyRun_SimpleString(pathExpr.c_str());
    }

    if (g_py.PyRun_SimpleString != nullptr) {
        const std::string argvExpr = BuildPythonArgvScript(trimmed, args);
        g_py.PyRun_SimpleString(argvExpr.c_str());
    }

    if (g_py.PyRun_SimpleString == nullptr || g_py.PyRun_SimpleString(bytes.c_str()) != 0) {
        if (g_py.PyErr_Print != nullptr) {
            g_py.PyErr_Print();
        }
        Emit(L"Python script failed.\r\n");
        return false;
    }
    return true;
}

bool PythonBridge::RunCode(const std::wstring& code, const std::wstring&) {
    if (!EnsureInitialized()) {
        return false;
    }

    const std::wstring trimmed = TrimCopy(code);
    if (trimmed.empty()) {
        Emit(L"Usage: py exec <code>\r\n");
        return false;
    }

    const std::string utf8 = WideToUtf8(trimmed);
    if (utf8.empty() || g_py.PyRun_SimpleString == nullptr || g_py.PyRun_SimpleString(utf8.c_str()) != 0) {
        if (g_py.PyErr_Print != nullptr) {
            g_py.PyErr_Print();
        }
        Emit(L"Python code failed.\r\n");
        return false;
    }
    return true;
}

void PythonBridge::Emit(const std::wstring& text) const {
    if (output_) {
        output_(text);
    }
}

namespace {

PyObject* BridgeWriteStdout(PyObject*, PyObject* args) {
    PyObject* textObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &textObject)) {
        return nullptr;
    }

    std::wstring text;
    if (!PyObjectToWideString(textObject, text)) {
        return MakeRuntimeError(L"failed to convert python text");
    }
    EmitText(text);
    return MakeNone();
}

PyObject* BridgeWriteStderr(PyObject*, PyObject* args) {
    return BridgeWriteStdout(nullptr, args);
}

PyObject* BridgeEmit(PyObject*, PyObject* args) {
    PyObject* textObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &textObject)) {
        return nullptr;
    }
    std::wstring text;
    if (!PyObjectToWideString(textObject, text)) {
        return MakeRuntimeError(L"failed to convert text");
    }
    EmitText(text);
    return MakeNone();
}

PyObject* BridgeEmitLine(PyObject*, PyObject* args) {
    PyObject* textObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &textObject)) {
        return nullptr;
    }
    std::wstring text;
    if (!PyObjectToWideString(textObject, text)) {
        return MakeRuntimeError(L"failed to convert text");
    }
    EmitText(text + L"\r\n");
    return MakeNone();
}

PyObject* BridgeEmitColor(PyObject*, PyObject* args) {
    PyObject* textObject;
    unsigned long long fg = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "OK", &textObject, &fg)) {
        return nullptr;
    }
    std::wstring text;
    if (!PyObjectToWideString(textObject, text)) {
        return MakeRuntimeError(L"failed to convert text");
    }
    EmitColoredText(text, fg, false, 0, false);
    return MakeNone();
}

PyObject* BridgeEmitColorBg(PyObject*, PyObject* args) {
    PyObject* textObject;
    unsigned long long fg = 0;
    unsigned long long bg = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "OKK", &textObject, &fg, &bg)) {
        return nullptr;
    }
    std::wstring text;
    if (!PyObjectToWideString(textObject, text)) {
        return MakeRuntimeError(L"failed to convert text");
    }
    EmitColoredText(text, fg, true, bg, false);
    return MakeNone();
}

PyObject* BridgeEmitInfo(PyObject*, PyObject* args) {
    PyObject* textObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &textObject)) {
        return nullptr;
    }
    std::wstring text;
    if (!PyObjectToWideString(textObject, text)) {
        return MakeRuntimeError(L"failed to convert text");
    }
    EmitColoredText(text, 0x00D0FF80ULL, false, 0, false);
    return MakeNone();
}

PyObject* BridgeEmitWarn(PyObject*, PyObject* args) {
    PyObject* textObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &textObject)) {
        return nullptr;
    }
    std::wstring text;
    if (!PyObjectToWideString(textObject, text)) {
        return MakeRuntimeError(L"failed to convert text");
    }
    EmitColoredText(text, 0x00FFD040ULL, false, 0, false);
    return MakeNone();
}

PyObject* BridgeEmitError(PyObject*, PyObject* args) {
    PyObject* textObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &textObject)) {
        return nullptr;
    }
    std::wstring text;
    if (!PyObjectToWideString(textObject, text)) {
        return MakeRuntimeError(L"failed to convert text");
    }
    EmitColoredText(text, 0x00FF8080ULL, false, 0, false);
    return MakeNone();
}

PyObject* BridgeLaunch(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->launch == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* textObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &textObject)) {
        return nullptr;
    }
    std::wstring commandLine;
    if (!PyObjectToWideString(textObject, commandLine)) {
        return MakeRuntimeError(L"failed to convert command line");
    }
    return MakeBool(api->launch(context, commandLine.c_str()) != 0);
}

PyObject* BridgeAttach(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->attach == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long long pid = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "K", &pid)) {
        return nullptr;
    }
    return MakeBool(api->attach(context, static_cast<uint32_t>(pid)) != 0);
}

PyObject* BridgeDetach(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->detach == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->detach(context) != 0);
}

PyObject* BridgeContinue(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->continueExecution == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->continueExecution(context) != 0);
}

PyObject* BridgeSingleStep(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->singleStep == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->singleStep(context) != 0);
}

PyObject* BridgeStepOver(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->stepOver == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->stepOver(context) != 0);
}

PyObject* BridgeExecute(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->executeCommand == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* textObject;
    int captureOutput = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O|p", &textObject, &captureOutput)) {
        return nullptr;
    }
    std::wstring command;
    if (!PyObjectToWideString(textObject, command)) {
        return MakeRuntimeError(L"failed to convert command");
    }

    if (captureOutput == 0) {
        return MakeBool(api->executeCommand(context, command.c_str()) != 0);
    }

    std::wstring captured;
    ScopedStreamCapture captureStdout(std::wcout, captured);
    ScopedStreamCapture captureStderr(std::wcerr, captured);
    const bool ok = api->executeCommand(context, command.c_str()) != 0;
    return MakeExecuteResultDict(ok, captured);
}

PyObject* BridgeExecuteCapture(PyObject*, PyObject* args) {
    PyObject* textObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &textObject)) {
        return nullptr;
    }
    PyObject* argv;
    if (g_py.Py_BuildValue == nullptr) {
        return MakeRuntimeError(L"python api is not available");
    }
    argv = g_py.Py_BuildValue("Op", textObject, 1);
    if (argv == nullptr) {
        return nullptr;
    }
    PyObject* result = BridgeExecute(nullptr, argv);
    PyDecRef(argv);
    return result;
}

PyObject* BridgeReadMemory(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->readMemory == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long long address = 0;
    unsigned long long size = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "KK", &address, &size)) {
        return nullptr;
    }
    if (size == 0 || size > static_cast<unsigned long long>(UINT32_MAX)) {
        return MakeRuntimeError(L"invalid size");
    }

    std::vector<unsigned char> buffer(static_cast<size_t>(size));
    uint32_t bytesRead = 0;
    if (api->readMemory(context, address, buffer.data(), static_cast<uint32_t>(buffer.size()), &bytesRead) == 0) {
        return MakeRuntimeError(L"read_memory failed");
    }
    if (g_py.PyBytes_FromStringAndSize == nullptr) {
        return MakeRuntimeError(L"python bytes api is not available");
    }
    return g_py.PyBytes_FromStringAndSize(reinterpret_cast<const char*>(buffer.data()), static_cast<Py_ssize_t>(bytesRead));
}

PyObject* BridgeResolveSymbol(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->resolveSymbol == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long long address = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "K", &address)) {
        return nullptr;
    }

    if (g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python unicode api is not available");
    }

    wchar_t buffer[512] = {0};
    if (api->resolveSymbol(context, address, buffer, static_cast<uint32_t>(sizeof(buffer) / sizeof(buffer[0]))) == 0) {
        return g_py.PyUnicode_FromWideChar(L"", 0);
    }
    return g_py.PyUnicode_FromWideChar(buffer, -1);
}

PyObject* BridgeResolveAddressExpression(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->resolveAddressExpression == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* expressionObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &expressionObject)) {
        return nullptr;
    }

    std::wstring expressionText;
    if (!PyObjectToWideString(expressionObject, expressionText)) {
        return MakeRuntimeError(L"invalid expression");
    }

    uint64_t address = 0;
    wchar_t buffer[512] = {0};
    if (api->resolveAddressExpression(context, expressionText.c_str(), &address, buffer, static_cast<uint32_t>(sizeof(buffer) / sizeof(buffer[0]))) == 0) {
        return MakeRuntimeError(L"resolve_address_expression failed");
    }
    return MakeResolvedAddressDict(address, buffer);
}

PyObject* BridgeLoadSymbols(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->loadSymbols == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* targetObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "|O", &targetObject)) {
        return nullptr;
    }

    std::wstring targetText;
    const wchar_t* target = nullptr;
    if (targetObject != nullptr && PyObjectToWideString(targetObject, targetText)) {
        const std::wstring trimmed = TrimCopy(targetText);
        if (!trimmed.empty() && trimmed != L"*") {
            target = targetText.c_str();
        }
    }

    wchar_t pdbPath[512] = {0};
    if (api->loadSymbols(context, target, pdbPath, static_cast<uint32_t>(sizeof(pdbPath) / sizeof(pdbPath[0]))) == 0) {
        return MakeRuntimeError(L"load_symbols failed");
    }
    const std::wstring normalizedTarget = target == nullptr ? L"*" : (targetText.empty() ? L"*" : targetText);
    return MakeSymbolResultDict(normalizedTarget, pdbPath, false);
}

PyObject* BridgeDownloadSymbols(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->downloadSymbols == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* targetObject;
    PyObject* cacheObject;
    PyObject* serverObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "|OOO", &targetObject, &cacheObject, &serverObject)) {
        return nullptr;
    }

    std::wstring targetText;
    std::wstring cacheText;
    std::wstring serverText;
    const wchar_t* target = nullptr;
    const wchar_t* cache = nullptr;
    const wchar_t* server = nullptr;
    if (targetObject != nullptr && PyObjectToWideString(targetObject, targetText)) {
        const std::wstring trimmed = TrimCopy(targetText);
        if (!trimmed.empty() && trimmed != L"*") {
            target = targetText.c_str();
        }
    }
    if (cacheObject != nullptr && PyObjectToWideString(cacheObject, cacheText)) {
        const std::wstring trimmed = TrimCopy(cacheText);
        if (!trimmed.empty()) {
            cache = cacheText.c_str();
        }
    }
    if (serverObject != nullptr && PyObjectToWideString(serverObject, serverText)) {
        const std::wstring trimmed = TrimCopy(serverText);
        if (!trimmed.empty()) {
            server = serverText.c_str();
        }
    }

    wchar_t pdbPath[512] = {0};
    if (api->downloadSymbols(context, target, cache, server, pdbPath, static_cast<uint32_t>(sizeof(pdbPath) / sizeof(pdbPath[0]))) == 0) {
        return MakeRuntimeError(L"download_symbols failed");
    }
    const std::wstring normalizedTarget = target == nullptr ? L"*" : (targetText.empty() ? L"*" : targetText);
    return MakeSymbolResultDict(normalizedTarget, pdbPath, true);
}

PyObject* BridgeSetSymbolSearchPath(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->setSymbolSearchPath == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* pathObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &pathObject)) {
        return nullptr;
    }

    std::wstring pathText;
    if (!PyObjectToWideString(pathObject, pathText)) {
        return MakeRuntimeError(L"invalid symbol path");
    }
    return MakeBool(api->setSymbolSearchPath(context, pathText.c_str()) != 0);
}

PyObject* BridgeGetSymbolSearchPath(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getSymbolSearchPath == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    if (g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python unicode api is not available");
    }

    wchar_t buffer[1024] = {0};
    if (api->getSymbolSearchPath(context, buffer, static_cast<uint32_t>(sizeof(buffer) / sizeof(buffer[0]))) == 0) {
        return MakeRuntimeError(L"get_symbol_search_path failed");
    }
    return g_py.PyUnicode_FromWideChar(buffer, -1);
}

PyObject* BridgeSelectThread(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->selectThread == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long index = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "k", &index)) {
        return nullptr;
    }
    return MakeBool(api->selectThread(context, static_cast<uint32_t>(index)) != 0);
}

PyObject* BridgeSetRegisterValue(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->setRegisterValue == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* assignmentObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &assignmentObject)) {
        return nullptr;
    }

    std::wstring assignmentText;
    if (!PyObjectToWideString(assignmentObject, assignmentText)) {
        return MakeRuntimeError(L"invalid assignment");
    }
    return MakeBool(api->setRegisterValue(context, assignmentText.c_str()) != 0);
}

PyObject* BridgeWriteMemoryPatch(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->writeMemoryPatch == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long long address = 0;
    PyObject* dataObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "KO", &address, &dataObject)) {
        return nullptr;
    }

    Py_buffer view = {};
    if (g_py.PyObject_GetBuffer == nullptr || g_py.PyBuffer_Release == nullptr || g_py.PyObject_GetBuffer(dataObject, &view, PyBUF_SIMPLE) != 0) {
        return MakeRuntimeError(L"invalid buffer");
    }

    const int32_t ok = api->writeMemoryPatch(
        context,
        address,
        view.buf,
        static_cast<uint32_t>(std::min<Py_ssize_t>(view.len, static_cast<Py_ssize_t>(UINT32_MAX))));
    g_py.PyBuffer_Release(&view);
    return MakeBool(ok != 0);
}

PyObject* BridgeUndoMemoryPatch(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->undoMemoryPatch == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long count = 1;
    if (g_py.PyArg_ParseTuple != nullptr && !g_py.PyArg_ParseTuple(args, "|k", &count)) {
        return nullptr;
    }
    return MakeBool(api->undoMemoryPatch(context, static_cast<uint32_t>(count)) != 0);
}

PyObject* BridgeAddSoftwareBreakpoint(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->addSoftwareBreakpoint == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* expressionObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &expressionObject)) {
        return nullptr;
    }

    std::wstring expressionText;
    if (!PyObjectToWideString(expressionObject, expressionText)) {
        return MakeRuntimeError(L"invalid address");
    }

    uint64_t address = 0;
    wchar_t resolved[512] = {0};
    if (api->resolveAddressExpression(context, expressionText.c_str(), &address, resolved, static_cast<uint32_t>(sizeof(resolved) / sizeof(resolved[0]))) == 0) {
        return MakeRuntimeError(L"resolve_address_expression failed");
    }

    int32_t breakpointId = -1;
    if (api->addSoftwareBreakpoint(context, address, &breakpointId) == 0) {
        return MakeRuntimeError(L"add_software_breakpoint failed");
    }
    if (g_py.PyLong_FromLong == nullptr) {
        return MakeRuntimeError(L"python long api is not available");
    }
    return g_py.PyLong_FromLong(breakpointId);
}

PyObject* BridgeAddHardwareBreakpoint(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->addHardwareBreakpoint == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* expressionObject = nullptr;
    PyObject* accessObject = nullptr;
    int length = 1;
    int slot = -1;
    unsigned long long threadId = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O|OiiK", &expressionObject, &accessObject, &length, &slot, &threadId)) {
        return nullptr;
    }

    std::wstring expressionText;
    if (!PyObjectToWideString(expressionObject, expressionText)) {
        return MakeRuntimeError(L"invalid address");
    }

    uint64_t address = 0;
    wchar_t resolved[512] = {0};
    if (api->resolveAddressExpression(context, expressionText.c_str(), &address, resolved, static_cast<uint32_t>(sizeof(resolved) / sizeof(resolved[0]))) == 0) {
        return MakeRuntimeError(L"resolve_address_expression failed");
    }

    std::wstring accessText = L"x";
    if (accessObject != nullptr && !PyObjectToWideString(accessObject, accessText)) {
        return MakeRuntimeError(L"invalid access");
    }

    int32_t access = 0;
    if (!ParseHardwareAccessArgument(accessText, access)) {
        return MakeRuntimeError(L"invalid hardware access");
    }
    if (slot < 0) {
        slot = 0;
    }

    int32_t breakpointId = -1;
    if (api->addHardwareBreakpoint(context, slot, address, access, length, static_cast<uint32_t>(threadId), &breakpointId) == 0) {
        return MakeRuntimeError(L"add_hardware_breakpoint failed");
    }
    if (g_py.PyLong_FromLong == nullptr) {
        return MakeRuntimeError(L"python long api is not available");
    }
    return g_py.PyLong_FromLong(breakpointId);
}

PyObject* BridgeAddMemoryBreakpoint(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->addMemoryBreakpoint == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* expressionObject;
    PyObject* sizeObject;
    PyObject* accessObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "OO|O", &expressionObject, &sizeObject, &accessObject)) {
        return nullptr;
    }

    std::wstring expressionText;
    if (!PyObjectToWideString(expressionObject, expressionText)) {
        return MakeRuntimeError(L"invalid address");
    }
    std::wstring sizeText;
    if (!PyObjectToWideString(sizeObject, sizeText)) {
        return MakeRuntimeError(L"invalid size");
    }

    uint64_t address = 0;
    wchar_t resolved[512] = {0};
    if (api->resolveAddressExpression(context, expressionText.c_str(), &address, resolved, static_cast<uint32_t>(sizeof(resolved) / sizeof(resolved[0]))) == 0) {
        return MakeRuntimeError(L"resolve_address_expression failed");
    }

    uint64_t size = 0;
    try {
        size = std::stoull(sizeText, nullptr, 0);
    } catch (...) {
        return MakeRuntimeError(L"invalid size");
    }

    std::wstring accessText = L"rw";
    if (accessObject != nullptr && !PyObjectToWideString(accessObject, accessText)) {
        return MakeRuntimeError(L"invalid access");
    }

    uint32_t access = 0;
    if (!ParseMemoryAccessArgument(accessText, access)) {
        return MakeRuntimeError(L"invalid memory access");
    }

    int32_t breakpointId = -1;
    if (api->addMemoryBreakpoint(context, address, size, access, &breakpointId) == 0) {
        return MakeRuntimeError(L"add_memory_breakpoint failed");
    }
    if (g_py.PyLong_FromLong == nullptr) {
        return MakeRuntimeError(L"python long api is not available");
    }
    return g_py.PyLong_FromLong(breakpointId);
}

PyObject* BridgeEnableBreakpoint(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->enableBreakpoint == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    int breakpointId = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "i", &breakpointId)) {
        return nullptr;
    }
    return MakeBool(api->enableBreakpoint(context, breakpointId) != 0);
}

PyObject* BridgeDisableBreakpoint(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->disableBreakpoint == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    int breakpointId = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "i", &breakpointId)) {
        return nullptr;
    }
    return MakeBool(api->disableBreakpoint(context, breakpointId) != 0);
}

PyObject* BridgeRemoveBreakpoint(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->removeBreakpoint == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    int breakpointId = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "i", &breakpointId)) {
        return nullptr;
    }
    return MakeBool(api->removeBreakpoint(context, breakpointId) != 0);
}

PyObject* BridgeSetBreakpointCondition(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->setBreakpointCondition == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    int breakpointId = 0;
    PyObject* expressionObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "iO", &breakpointId, &expressionObject)) {
        return nullptr;
    }

    std::wstring expressionText;
    if (!PyObjectToWideString(expressionObject, expressionText)) {
        return MakeRuntimeError(L"invalid condition");
    }
    return MakeBool(api->setBreakpointCondition(context, breakpointId, expressionText.c_str()) != 0);
}

PyObject* BridgeClearBreakpointCondition(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->clearBreakpointCondition == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    int breakpointId = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "i", &breakpointId)) {
        return nullptr;
    }
    return MakeBool(api->clearBreakpointCondition(context, breakpointId) != 0);
}

PyObject* BridgeSaveCurrentStopSnapshot(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->saveCurrentStopSnapshot == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->saveCurrentStopSnapshot(context) != 0);
}

PyObject* BridgeSaveNamedSnapshot(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->saveNamedSnapshot == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* nameObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &nameObject)) {
        return nullptr;
    }

    std::wstring name;
    if (!PyObjectToWideString(nameObject, name)) {
        return MakeRuntimeError(L"invalid snapshot name");
    }
    return MakeBool(api->saveNamedSnapshot(context, name.c_str()) != 0);
}

PyObject* BridgeRestoreNamedSnapshot(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->restoreNamedSnapshot == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* nameObject;
    int rerun = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O|p", &nameObject, &rerun)) {
        return nullptr;
    }

    std::wstring name;
    if (!PyObjectToWideString(nameObject, name)) {
        return MakeRuntimeError(L"invalid snapshot name");
    }
    return MakeBool(api->restoreNamedSnapshot(context, name.c_str(), rerun ? 1 : 0) != 0);
}

PyObject* BridgeListNamedSnapshots(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->listNamedSnapshots == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->listNamedSnapshots(context) != 0);
}

PyObject* BridgeStepBackToPreviousSnapshot(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->stepBackToPreviousSnapshot == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->stepBackToPreviousSnapshot(context) != 0);
}

PyObject* BridgeAddSourceRoot(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->addSourceRoot == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* pathObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &pathObject)) {
        return nullptr;
    }
    std::wstring path;
    if (!PyObjectToWideString(pathObject, path)) {
        return MakeRuntimeError(L"invalid source root path");
    }
    return MakeBool(api->addSourceRoot(context, path.c_str()) != 0);
}

PyObject* BridgeRemoveSourceRoot(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->removeSourceRoot == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* pathObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &pathObject)) {
        return nullptr;
    }
    std::wstring path;
    if (!PyObjectToWideString(pathObject, path)) {
        return MakeRuntimeError(L"invalid source root path");
    }
    return MakeBool(api->removeSourceRoot(context, path.c_str()) != 0);
}

PyObject* BridgeClearSourceRoots(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->clearSourceRoots == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->clearSourceRoots(context) != 0);
}

PyObject* BridgeListSourceRoots(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->listSourceRoots == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->listSourceRoots(context) != 0);
}

PyObject* BridgeLoadScriptFile(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->loadScriptFile == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* pathObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &pathObject)) {
        return nullptr;
    }
    std::wstring path;
    if (!PyObjectToWideString(pathObject, path)) {
        return MakeRuntimeError(L"invalid script path");
    }
    return MakeBool(api->loadScriptFile(context, path.c_str()) != 0);
}

PyObject* BridgeSetScriptBreakpoint(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->setScriptBreakpoint == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long line = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "k", &line)) {
        return nullptr;
    }
    return MakeBool(api->setScriptBreakpoint(context, static_cast<uint32_t>(line)) != 0);
}

PyObject* BridgeRemoveScriptBreakpoint(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->removeScriptBreakpoint == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long line = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "k", &line)) {
        return nullptr;
    }
    return MakeBool(api->removeScriptBreakpoint(context, static_cast<uint32_t>(line)) != 0);
}

PyObject* BridgeListScriptBreakpoints(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->listScriptBreakpoints == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->listScriptBreakpoints(context) != 0);
}

PyObject* BridgeConfigureExceptionIgnoreAll(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->configureExceptionIgnoreAll == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* scopeObject;
    int enabled = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "Op", &scopeObject, &enabled)) {
        return nullptr;
    }
    std::wstring scopeText;
    if (!PyObjectToWideString(scopeObject, scopeText)) {
        return MakeRuntimeError(L"invalid scope");
    }
    int32_t scope = 0;
    if (!ParseExceptionScopeArgument(scopeText, scope)) {
        return MakeRuntimeError(L"invalid scope");
    }
    return MakeBool(api->configureExceptionIgnoreAll(context, scope, enabled ? 1 : 0) != 0);
}

PyObject* BridgeAddIgnoredExceptionCode(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->addIgnoredExceptionCode == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* scopeObject;
    unsigned long code = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "Ok", &scopeObject, &code)) {
        return nullptr;
    }
    std::wstring scopeText;
    if (!PyObjectToWideString(scopeObject, scopeText)) {
        return MakeRuntimeError(L"invalid scope");
    }
    int32_t scope = 0;
    if (!ParseExceptionScopeArgument(scopeText, scope)) {
        return MakeRuntimeError(L"invalid scope");
    }
    return MakeBool(api->addIgnoredExceptionCode(context, scope, static_cast<uint32_t>(code)) != 0);
}

PyObject* BridgeRemoveIgnoredExceptionCode(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->removeIgnoredExceptionCode == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* scopeObject;
    unsigned long code = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "Ok", &scopeObject, &code)) {
        return nullptr;
    }
    std::wstring scopeText;
    if (!PyObjectToWideString(scopeObject, scopeText)) {
        return MakeRuntimeError(L"invalid scope");
    }
    int32_t scope = 0;
    if (!ParseExceptionScopeArgument(scopeText, scope)) {
        return MakeRuntimeError(L"invalid scope");
    }
    return MakeBool(api->removeIgnoredExceptionCode(context, scope, static_cast<uint32_t>(code)) != 0);
}

PyObject* BridgeClearIgnoredExceptionCodes(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->clearIgnoredExceptionCodes == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* scopeObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &scopeObject)) {
        return nullptr;
    }
    std::wstring scopeText;
    if (!PyObjectToWideString(scopeObject, scopeText)) {
        return MakeRuntimeError(L"invalid scope");
    }
    int32_t scope = 0;
    if (!ParseExceptionScopeArgument(scopeText, scope)) {
        return MakeRuntimeError(L"invalid scope");
    }
    return MakeBool(api->clearIgnoredExceptionCodes(context, scope) != 0);
}

PyObject* BridgeListExceptionSettings(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->listExceptionSettings == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->listExceptionSettings(context) != 0);
}

PyObject* BridgeAddRunStopExpression(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->addRunStopExpression == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* exprObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O", &exprObject)) {
        return nullptr;
    }
    std::wstring expr;
    if (!PyObjectToWideString(exprObject, expr)) {
        return MakeRuntimeError(L"invalid expression");
    }
    return MakeBool(api->addRunStopExpression(context, expr.c_str()) != 0);
}

PyObject* BridgeRemoveRunStopExpression(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->removeRunStopExpression == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long index = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "k", &index)) {
        return nullptr;
    }
    return MakeBool(api->removeRunStopExpression(context, static_cast<uint32_t>(index)) != 0);
}

PyObject* BridgeClearRunStopExpressions(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->clearRunStopExpressions == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->clearRunStopExpressions(context) != 0);
}

PyObject* BridgeListRunStopExpressions(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->listRunStopExpressions == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->listRunStopExpressions(context) != 0);
}

PyObject* BridgeStepUntilCondition(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->stepUntilCondition == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* exprObject;
    unsigned long long maxSteps = 1;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O|K", &exprObject, &maxSteps)) {
        return nullptr;
    }
    std::wstring expr;
    if (!PyObjectToWideString(exprObject, expr)) {
        return MakeRuntimeError(L"invalid condition");
    }
    return MakeBool(api->stepUntilCondition(context, expr.c_str(), maxSteps) != 0);
}

PyObject* BridgeRunUntilCondition(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->runUntilCondition == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* exprObject;
    unsigned long long maxPauses = 1;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O|K", &exprObject, &maxPauses)) {
        return nullptr;
    }
    std::wstring expr;
    if (!PyObjectToWideString(exprObject, expr)) {
        return MakeRuntimeError(L"invalid condition");
    }
    return MakeBool(api->runUntilCondition(context, expr.c_str(), maxPauses) != 0);
}

PyObject* BridgeAutoStep(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->autoStep == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long long steps = 1;
    unsigned long delayMs = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "K|k", &steps, &delayMs)) {
        return nullptr;
    }
    return MakeBool(api->autoStep(context, steps, delayMs) != 0);
}

PyObject* BridgeAutoRun(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->autoRun == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long long pauses = 1;
    unsigned long delayMs = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "K|k", &pauses, &delayMs)) {
        return nullptr;
    }
    return MakeBool(api->autoRun(context, pauses, delayMs) != 0);
}

PyObject* BridgeReadCString(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->readMemory == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long long address = 0;
    unsigned long maxBytes = 4096;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "K|k", &address, &maxBytes)) {
        return nullptr;
    }

    std::string text;
    if (!ReadAnsiStringFromMemory(api, context, address, text, maxBytes)) {
        return MakeRuntimeError(L"read_cstr failed");
    }
    if (g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python unicode api is not available");
    }
    return g_py.PyUnicode_FromWideChar(AnsiToWide(text).c_str(), -1);
}

PyObject* BridgeReadWString(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->readMemory == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long long address = 0;
    unsigned long maxChars = 2048;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "K|k", &address, &maxChars)) {
        return nullptr;
    }

    std::wstring text;
    if (!ReadWideStringFromMemory(api, context, address, text, maxChars)) {
        return MakeRuntimeError(L"read_wstr failed");
    }
    if (g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python unicode api is not available");
    }
    return g_py.PyUnicode_FromWideChar(text.c_str(), static_cast<Py_ssize_t>(text.size()));
}

PyObject* BridgeWriteMemory(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->writeMemory == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long long address = 0;
    PyObject* dataObject;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "KO", &address, &dataObject)) {
        return nullptr;
    }

    Py_buffer view = {};
    if (g_py.PyObject_GetBuffer == nullptr || g_py.PyBuffer_Release == nullptr || g_py.PyObject_GetBuffer(dataObject, &view, PyBUF_SIMPLE) != 0) {
        return MakeRuntimeError(L"invalid buffer");
    }

    uint32_t bytesWritten = 0;
    const int32_t ok = api->writeMemory(
        context,
        address,
        view.buf,
        static_cast<uint32_t>(std::min<Py_ssize_t>(view.len, static_cast<Py_ssize_t>(UINT32_MAX))),
        &bytesWritten);
    g_py.PyBuffer_Release(&view);
    if (ok == 0) {
        return MakeRuntimeError(L"write_memory failed");
    }
    if (g_py.PyLong_FromUnsignedLong == nullptr) {
        return MakeRuntimeError(L"python long api is not available");
    }
    return g_py.PyLong_FromUnsignedLong(bytesWritten);
}

PyObject* BridgeDumpMemory(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->executeCommand == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    PyObject* pathObject;
    unsigned long long address = 0;
    unsigned long long length = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "O|KK", &pathObject, &address, &length)) {
        return nullptr;
    }

    std::wstring path;
    if (!PyObjectToWideString(pathObject, path) || path.empty()) {
        return MakeRuntimeError(L"invalid file path");
    }

    std::wstringstream cmd;
    cmd << L"dump \"" << path << L"\"";
    if (address != 0 || length != 0) {
        cmd << L" " << L"0x" << std::hex << std::uppercase << address
            << L" " << L"0x" << std::hex << std::uppercase << length;
    }

    return MakeBool(api->executeCommand(context, cmd.str().c_str()) != 0);
}

PyObject* BridgeGetStopInfo(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getStopInfo == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    WdblStopInfo info = WdblStopInfo();
    info.size = sizeof(WdblStopInfo);
    if (api->getStopInfo(context, &info) == 0) {
        return MakeNone();
    }
    return BuildStopInfoDict(info);
}

PyObject* BridgeGetContext(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return BuildContextDict(api, context);
}

PyObject* BridgePrintStopInfo(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getStopInfo == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    WdblStopInfo info = WdblStopInfo();
    info.size = sizeof(WdblStopInfo);
    if (api->getStopInfo(context, &info) == 0) {
        EmitText(L"(no stop info)\r\n");
        return MakeNone();
    }

    EmitText(FormatStopInfoText(info));
    return MakeNone();
}

PyObject* BridgeGetThreadCount(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getThreadCount == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    uint32_t count = 0;
    if (api->getThreadCount(context, &count) == 0) {
        return MakeRuntimeError(L"get_thread_count failed");
    }
    if (g_py.PyLong_FromUnsignedLong == nullptr) {
        return MakeRuntimeError(L"python long api is not available");
    }
    return g_py.PyLong_FromUnsignedLong(count);
}

PyObject* BridgeGetThreadInfo(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getThreadInfo == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long index = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "k", &index)) {
        return nullptr;
    }

    WdblThreadInfo info = WdblThreadInfo();
    info.size = sizeof(WdblThreadInfo);
    if (api->getThreadInfo(context, static_cast<uint32_t>(index), &info) == 0) {
        return MakeRuntimeError(L"get_thread_info failed");
    }

    if (g_py.PyDict_New == nullptr || g_py.PyBool_FromLong == nullptr || g_py.PyLong_FromUnsignedLong == nullptr ||
        g_py.PyLong_FromUnsignedLongLong == nullptr || g_py.PyLong_FromLong == nullptr || g_py.PyUnicode_FromWideChar == nullptr) {
        return MakeRuntimeError(L"python dict api is not available");
    }

    PyObject* dict = g_py.PyDict_New();
    if (dict == nullptr) {
        return nullptr;
    }

    PySetDictItemString(dict, "index", g_py.PyLong_FromUnsignedLong(info.index));
    PySetDictItemString(dict, "process_id", g_py.PyLong_FromUnsignedLong(info.processId));
    PySetDictItemString(dict, "thread_id", g_py.PyLong_FromUnsignedLong(info.threadId));
    PySetDictItemString(dict, "is_current", g_py.PyBool_FromLong(info.isCurrent != 0));
    PySetDictItemString(dict, "has_context", g_py.PyBool_FromLong(info.hasContext != 0));
    PySetDictItemString(dict, "teb", g_py.PyLong_FromUnsignedLongLong(info.teb));
    PySetDictItemString(dict, "instruction_pointer", g_py.PyLong_FromUnsignedLongLong(info.instructionPointer));
    PySetDictItemString(dict, "stack_pointer", g_py.PyLong_FromUnsignedLongLong(info.stackPointer));
    PySetDictItemString(dict, "priority", g_py.PyLong_FromLong(info.priority));
    PySetDictItemString(dict, "base_priority", g_py.PyLong_FromLong(info.basePriority));
    PySetDictItemString(dict, "delta_priority", g_py.PyLong_FromLong(info.deltaPriority));
    PySetDictItemString(dict, "symbol", g_py.PyUnicode_FromWideChar(info.symbol, -1));
    return dict;
}

PyObject* BridgeGetRegisters(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getThreadInfo == nullptr || api->getRegisterInfo == nullptr || api->getThreadCount == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long index = static_cast<unsigned long>(ResolveDefaultThreadIndex(api, context));
    if (g_py.PyArg_ParseTuple != nullptr && !g_py.PyArg_ParseTuple(args, "|k", &index)) {
        return nullptr;
    }

    WdblRegisterInfo info = WdblRegisterInfo();
    info.size = sizeof(WdblRegisterInfo);
    if (api->getRegisterInfo(context, static_cast<uint32_t>(index), &info) == 0) {
        return MakeRuntimeError(L"get_registers failed");
    }
    return BuildRegisterDict(info);
}

PyObject* BridgeGetStackFrames(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getThreadInfo == nullptr || api->getStackFrameInfo == nullptr || api->getThreadCount == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long index = static_cast<unsigned long>(ResolveDefaultThreadIndex(api, context));
    unsigned long maxFrames = 32;
    if (g_py.PyArg_ParseTuple != nullptr && !g_py.PyArg_ParseTuple(args, "|kk", &index, &maxFrames)) {
        return nullptr;
    }
    if (maxFrames == 0) {
        maxFrames = 32;
    }

    if (g_py.PyList_New == nullptr) {
        return MakeRuntimeError(L"python list api is not available");
    }

    PyObject* list = g_py.PyList_New(0);
    if (list == nullptr) {
        return nullptr;
    }

    for (unsigned long i = 0; i < maxFrames; ++i) {
        WdblStackFrameInfo info = WdblStackFrameInfo();
        info.size = sizeof(WdblStackFrameInfo);
        if (api->getStackFrameInfo(context, static_cast<uint32_t>(index), static_cast<uint32_t>(i), &info) == 0) {
            break;
        }

        PyObject* item = BuildStackFrameDict(info);
        if (item == nullptr) {
            PyDecRef(list);
            return nullptr;
        }
        if (g_py.PyList_Append != nullptr && g_py.PyList_Append(list, item) != 0) {
            PyDecRef(item);
            PyDecRef(list);
            return nullptr;
        }
        PyDecRef(item);
    }

    return list;
}

PyObject* BridgePrintThreads(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getThreadCount == nullptr || api->getThreadInfo == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    uint32_t count = 0;
    if (api->getThreadCount(context, &count) == 0) {
        return MakeRuntimeError(L"get_thread_count failed");
    }

    std::wstringstream ss;
    ss << L"threads=" << count << L"\r\n";
    for (uint32_t i = 0; i < count; ++i) {
        WdblThreadInfo info = WdblThreadInfo();
        info.size = sizeof(WdblThreadInfo);
        if (api->getThreadInfo(context, i, &info) == 0) {
            ss << L"[" << i << L"] <unavailable>\r\n";
            continue;
        }
        ss << L"[" << i << L"] " << info.threadId;
        if (info.isCurrent != 0) {
            ss << L" current";
        }
        if (info.symbol[0] != L'\0') {
            ss << L" " << info.symbol;
        }
        ss << L"\r\n";
    }
    EmitText(ss.str());
    return MakeNone();
}

PyObject* BridgePrintThread(PyObject*, PyObject* args) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getThreadInfo == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    unsigned long index = 0;
    if (g_py.PyArg_ParseTuple == nullptr || !g_py.PyArg_ParseTuple(args, "k", &index)) {
        return nullptr;
    }

    WdblThreadInfo info = WdblThreadInfo();
    info.size = sizeof(WdblThreadInfo);
    if (api->getThreadInfo(context, static_cast<uint32_t>(index), &info) == 0) {
        return MakeRuntimeError(L"get_thread_info failed");
    }

    EmitText(FormatThreadInfoText(info));
    return MakeNone();
}

PyObject* BridgePrintModules(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->executeCommand == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->executeCommand(context, L"modules") != 0);
}

PyObject* BridgePrintBreakpoints(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->executeCommand == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->executeCommand(context, L"bl") != 0);
}

PyObject* BridgePrintRegisters(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->executeCommand == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->executeCommand(context, L"r") != 0);
}

PyObject* BridgePrintStack(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->executeCommand == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->executeCommand(context, L"k") != 0);
}

PyObject* BridgePrintContext(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->executeCommand == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }
    return MakeBool(api->executeCommand(context, L"context") != 0);
}

PyObject* BridgeGetModules(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getModuleCount == nullptr || api->getModuleInfo == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    uint32_t count = 0;
    if (api->getModuleCount(context, &count) == 0) {
        return MakeRuntimeError(L"get_module_count failed");
    }
    if (g_py.PyList_New == nullptr) {
        return MakeRuntimeError(L"python list api is not available");
    }

    PyObject* list = g_py.PyList_New(0);
    if (list == nullptr) {
        return nullptr;
    }

    for (uint32_t i = 0; i < count; ++i) {
        WdblModuleInfo info = WdblModuleInfo();
        info.size = sizeof(WdblModuleInfo);
        if (api->getModuleInfo(context, i, &info) == 0) {
            continue;
        }

        PyObject* item = g_py.PyDict_New != nullptr ? g_py.PyDict_New() : nullptr;
        if (item == nullptr) {
            PyDecRef(list);
            return nullptr;
        }
        PySetDictItemString(item, "index", g_py.PyLong_FromUnsignedLong(i));
        PySetDictItemString(item, "base_address", g_py.PyLong_FromUnsignedLongLong(info.baseAddress));
        PySetDictItemString(item, "image_size", g_py.PyLong_FromUnsignedLong(info.imageSize));
        PySetDictItemString(item, "image_path", g_py.PyUnicode_FromWideChar(info.imagePath, -1));
        PySetDictItemString(item, "module_name", g_py.PyUnicode_FromWideChar(info.moduleName, -1));
        if (g_py.PyList_Append != nullptr && g_py.PyList_Append(list, item) != 0) {
            PyDecRef(item);
            PyDecRef(list);
            return nullptr;
        }
        PyDecRef(item);
    }
    return list;
}

PyObject* BridgeGetBreakpoints(PyObject*, PyObject*) {
    const WdblDebuggerApi* api = GetApi();
    void* context = GetContext();
    if (api == nullptr || api->getBreakpointCount == nullptr || api->getBreakpointInfo == nullptr) {
        return MakeRuntimeError(L"debugger api is not available");
    }

    uint32_t count = 0;
    if (api->getBreakpointCount(context, &count) == 0) {
        return MakeRuntimeError(L"get_breakpoint_count failed");
    }
    if (g_py.PyList_New == nullptr) {
        return MakeRuntimeError(L"python list api is not available");
    }

    PyObject* list = g_py.PyList_New(0);
    if (list == nullptr) {
        return nullptr;
    }

    for (uint32_t i = 0; i < count; ++i) {
        WdblBreakpointInfo info = WdblBreakpointInfo();
        info.size = sizeof(WdblBreakpointInfo);
        if (api->getBreakpointInfo(context, i, &info) == 0) {
            continue;
        }

        PyObject* item = g_py.PyDict_New != nullptr ? g_py.PyDict_New() : nullptr;
        if (item == nullptr) {
            PyDecRef(list);
            return nullptr;
        }

        PySetDictItemString(item, "index", g_py.PyLong_FromUnsignedLong(i));
        PySetDictItemString(item, "id", g_py.PyLong_FromLong(info.id));
        PySetDictItemString(item, "kind", g_py.PyLong_FromUnsignedLong(info.kind));
        PySetDictItemString(item, "address", g_py.PyLong_FromUnsignedLongLong(info.address));
        PySetDictItemString(item, "slot", g_py.PyLong_FromLong(info.slot));
        PySetDictItemString(item, "thread_id", g_py.PyLong_FromUnsignedLong(info.threadId));
        PySetDictItemString(item, "enabled", g_py.PyBool_FromLong(info.enabled != 0));
        PySetDictItemString(item, "hit_count", g_py.PyLong_FromUnsignedLongLong(info.hitCount));
        PySetDictItemString(item, "length", g_py.PyLong_FromUnsignedLong(info.length));
        PySetDictItemString(item, "access", g_py.PyLong_FromUnsignedLong(info.access));
        PySetDictItemString(item, "condition", g_py.PyUnicode_FromWideChar(info.condition, -1));
        if (g_py.PyList_Append != nullptr && g_py.PyList_Append(list, item) != 0) {
            PyDecRef(item);
            PyDecRef(list);
            return nullptr;
        }
        PyDecRef(item);
    }
    return list;
}

}  // namespace
