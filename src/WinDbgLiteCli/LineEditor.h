#pragma once

#include <Windows.h>

#include <string>
#include <vector>

// A small, self-contained readline-style line editor for the WinDbgLite CLI.
//
// It takes over the console input handle, disables line buffering and echo so
// it can render the prompt + current buffer itself, and handles:
//   - printable character insertion (incl. UTF-16 code units)
//   - cursor movement with Home/End/Left/Right
//   - Backspace / Delete
//   - Up/Down to walk the command history
//   - Ctrl+C / Ctrl+D to cancel or exit
//   - Enter to submit
//
// History is kept in memory and can be persisted to a text file.
class LineEditor {
public:
    LineEditor(HANDLE input, HANDLE output);
    ~LineEditor();


    // Read a single edited line. Returns false on EOF (Ctrl+D on an empty
    // line) or a quit request (Ctrl+C on an empty line). On Ctrl+C while the
    // buffer is non-empty, the line is discarded and an empty result with
    // continue=true is signalled instead.
    enum Result {
        ResultSubmitted,
        ResultCancelled,
        ResultQuit
    };

    Result ReadLine(const std::wstring& prompt, std::wstring& outLine);

    // History management.
    void AddHistory(const std::wstring& line);
    void LoadHistory(const std::wstring& filePath);
    void SaveHistory(const std::wstring& filePath) const;
    void PrintHistory() const;

private:
    HANDLE input_;
    HANDLE output_;
    DWORD originalMode_;
    bool modeRestored_;

    std::vector<std::wstring> history_;
    size_t historyIndex_;
    std::wstring draft_; // line being edited before walking history

    void Render(const std::wstring& prompt, const std::wstring& buffer, size_t cursor) const;
    void WriteRaw(const std::wstring& text) const;
    void MoveCursorLeft(size_t count) const;
    void MoveCursorRight(size_t count) const;
    void ClearLine() const;

    static std::wstring NumberToWide(size_t value);
};
