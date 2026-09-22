#pragma once

#include "../Common/PluginApi.h"

#include <functional>
#include <string>
#include <vector>


class PythonBridge {
public:
    typedef std::function<void(const std::wstring&)> OutputCallback;

    PythonBridge();
    ~PythonBridge();

    void SetOutputCallback(OutputCallback callback);
    bool IsInitialized() const;
    bool Initialize(const WdblDebuggerApi* api, void* context);
    void Shutdown();
    bool RunFile(const std::wstring& filePath, const std::vector<std::wstring>& args = std::vector<std::wstring>());
    bool RunCode(const std::wstring& code, const std::wstring& fileName = L"<py>");
    void Emit(const std::wstring& text) const;

private:
    const WdblDebuggerApi* api_;
    void* context_;
    OutputCallback output_;
    void* runtimeModule_;
    std::wstring runtimeLibraryPath_;
    bool initialized_;
    bool moduleRegistered_;

    bool EnsureInitialized();
    bool RegisterModule();
    bool LoadRuntimeLibrary();
};
