#include "LineEditor.h"

#include <sstream>

LineEditor::LineEditor(HANDLE input, HANDLE output)
    : input_(input),
      output_(output),
      originalMode_(0),
      modeRestored_(false),
      historyIndex_(0) {
}

LineEditor::~LineEditor() {
    if (!modeRestored_) {
        SetConsoleMode(input_, originalMode_);
    }
}

std::wstring LineEditor::NumberToWide(size_t value) {
    std::wstringstream ss;
    ss << value;
    return ss.str();
}

void LineEditor::WriteRaw(const std::wstring& text) const {
    if (output_ == INVALID_HANDLE_VALUE || output_ == NULL) {
        return;
    }
    DWORD written = 0;
    WriteConsoleW(output_, text.c_str(), static_cast<DWORD>(text.size()), &written, NULL);
}

void LineEditor::ClearLine() const {
    // Clear the whole current line and move to its start.
    WriteRaw(L"\r\x1b[2K");
}

void LineEditor::MoveCursorLeft(size_t count) const {
    if (count == 0) {
        return;
    }
    WriteRaw(L"\x1b[" + NumberToWide(count) + L"D");
}

void LineEditor::MoveCursorRight(size_t count) const {
    if (count == 0) {
        return;
    }
    WriteRaw(L"\x1b[" + NumberToWide(count) + L"C");
}

void LineEditor::Render(const std::wstring& prompt, const std::wstring& buffer, size_t cursor) const {
    ClearLine();
    WriteRaw(prompt);
    WriteRaw(buffer);
    // Reposition the caret: after writing prompt+buffer the caret sits at the
    // end of the buffer; move it left to the logical cursor position.
    const size_t back = buffer.size() - cursor;
    MoveCursorLeft(back);
}

LineEditor::Result LineEditor::ReadLine(const std::wstring& prompt, std::wstring& outLine) {
    if (input_ == INVALID_HANDLE_VALUE || input_ == NULL) {
        return ResultQuit;
    }

    // Take over the console: disable line buffering and echo so we can manage
    // the buffer ourselves. Disable processed input so Ctrl+C arrives as a key
    // event instead of terminating the process.
    GetConsoleMode(input_, &originalMode_);
    DWORD newMode = originalMode_;
    newMode &= ~ENABLE_LINE_INPUT;
    newMode &= ~ENABLE_ECHO_INPUT;
    newMode &= ~ENABLE_PROCESSED_INPUT;
    SetConsoleMode(input_, newMode);
    modeRestored_ = false;

    std::wstring buffer;
    size_t cursor = 0;
    draft_.clear();
    historyIndex_ = history_.size();

    Render(prompt, buffer, cursor);

    INPUT_RECORD record;
    while (true) {
        DWORD available = 0;
        if (!ReadConsoleInputW(input_, &record, 1, &available) || available == 0) {
            break;
        }
        if (record.EventType != KEY_EVENT) {
            continue;
        }

        const KEY_EVENT_RECORD& key = record.Event.KeyEvent;
        if (!key.bKeyDown) {
            continue;
        }

        const wchar_t ch = key.uChar.UnicodeChar;
        const WORD vk = key.wVirtualKeyCode;

        if (ch == 0x03 /* Ctrl+C */ || ch == 0x04 /* Ctrl+D */) {
            if (buffer.empty()) {
                WriteRaw(L"\n");
                SetConsoleMode(input_, originalMode_);
                modeRestored_ = true;
                return ResultQuit;
            }
            // Discard the current line and start fresh.
            buffer.clear();
            cursor = 0;
            draft_.clear();
            historyIndex_ = history_.size();
            ClearLine();
            Render(prompt, buffer, cursor);
            continue;
        }

        switch (vk) {
            case VK_RETURN: {
                WriteRaw(L"\n");
                SetConsoleMode(input_, originalMode_);
                modeRestored_ = true;
                outLine = buffer;
                return ResultSubmitted;
            }
            case VK_BACK: {
                if (cursor > 0) {
                    buffer.erase(cursor - 1, 1);
                    --cursor;
                    Render(prompt, buffer, cursor);
                }
                break;
            }
            case VK_DELETE: {
                if (cursor < buffer.size()) {
                    buffer.erase(cursor, 1);
                    Render(prompt, buffer, cursor);
                }
                break;
            }
            case VK_LEFT: {
                if (cursor > 0) {
                    --cursor;
                    MoveCursorLeft(1);
                }
                break;
            }
            case VK_RIGHT: {
                if (cursor < buffer.size()) {
                    ++cursor;
                    MoveCursorRight(1);
                }
                break;
            }
            case VK_HOME: {
                MoveCursorLeft(cursor);
                cursor = 0;
                break;
            }
            case VK_END: {
                MoveCursorRight(buffer.size() - cursor);
                cursor = buffer.size();
                break;
            }
            case VK_UP: {
                if (historyIndex_ > 0) {
                    if (historyIndex_ == history_.size()) {
                        draft_ = buffer;
                    }
                    --historyIndex_;
                    buffer = history_[historyIndex_];
                    cursor = buffer.size();
                    Render(prompt, buffer, cursor);
                }
                break;
            }
            case VK_DOWN: {
                if (historyIndex_ < history_.size()) {
                    ++historyIndex_;
                    if (historyIndex_ == history_.size()) {
                        buffer = draft_;
                    } else {
                        buffer = history_[historyIndex_];
                    }
                    cursor = buffer.size();
                    Render(prompt, buffer, cursor);
                }
                break;
            }
            case VK_ESCAPE: {
                if (!buffer.empty()) {
                    buffer.clear();
                    cursor = 0;
                    Render(prompt, buffer, cursor);
                }
                break;
            }
            default: {
                if (ch != 0) {
                    buffer.insert(cursor, 1, ch);
                    ++cursor;
                    Render(prompt, buffer, cursor);
                }
                break;
            }
        }
    }

    SetConsoleMode(input_, originalMode_);
    modeRestored_ = true;
    return ResultQuit;
}

void LineEditor::AddHistory(const std::wstring& line) {
    if (line.empty()) {
        return;
    }
    if (!history_.empty() && history_.back() == line) {
        return;
    }
    history_.push_back(line);
    if (history_.size() > 1000) {
        history_.erase(history_.begin());
    }
    historyIndex_ = history_.size();
}

void LineEditor::LoadHistory(const std::wstring& filePath) {
    HANDLE h = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    std::wstring content;
    char buffer[8192];
    DWORD readBytes = 0;
    std::string raw;
    while (ReadFile(h, buffer, sizeof(buffer), &readBytes, NULL) && readBytes > 0) {
        raw.append(buffer, readBytes);
    }
    CloseHandle(h);

    // Interpret as UTF-8.
    int needed = MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), static_cast<int>(raw.size()), NULL, 0);
    if (needed > 0) {
        content.resize(needed);
        MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), static_cast<int>(raw.size()), &content[0], needed);
    }

    size_t pos = 0;
    while (pos < content.size()) {
        size_t end = content.find(L'\n', pos);
        if (end == std::wstring::npos) {
            end = content.size();
        }
        std::wstring line = content.substr(pos, end - pos);
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            history_.push_back(line);
        }
        pos = end + 1;
    }
    historyIndex_ = history_.size();
}

void LineEditor::SaveHistory(const std::wstring& filePath) const {
    HANDLE h = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    for (size_t i = 0; i < history_.size(); ++i) {
        std::wstring line = history_[i];
        line.push_back(L'\n');
        int needed = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), static_cast<int>(line.size()),
                                         NULL, 0, NULL, NULL);
        if (needed <= 0) {
            continue;
        }
        std::string bytes(needed, '\0');
        WideCharToMultiByte(CP_UTF8, 0, line.c_str(), static_cast<int>(line.size()),
                            &bytes[0], needed, NULL, NULL);
        DWORD written = 0;
        WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, NULL);
    }
    CloseHandle(h);
}

void LineEditor::PrintHistory() const {
    if (history_.empty()) {
        WriteRaw(L"(history is empty)\n");
        return;
    }
    for (size_t i = 0; i < history_.size(); ++i) {
        std::wstring line = NumberToWide(i + 1) + L"  " + history_[i];
        WriteRaw(line + L"\n");
    }
}
