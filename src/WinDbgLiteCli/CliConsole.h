#pragma once

#include <string>
#include <vector>

#include <Windows.h>

// Lightweight colored console output helper for the WinDbgLite CLI.
// Uses ANSI virtual-terminal sequences (enabled on the output handle) so the
// REPL can render a banner, prompts and messages in color, mimicking the
// look-and-feel of modern terminal CLIs such as Codex.
class CliConsole {
public:
    enum Color {
        ColorDefault = 0,
        ColorBlack,
        ColorRed,
        ColorGreen,
        ColorYellow,
        ColorBlue,
        ColorMagenta,
        ColorCyan,
        ColorWhite,
        ColorGray
    };

    CliConsole();
    ~CliConsole();

    // Initialize UTF-8 output codepage and enable VT processing.
    bool Initialize();

    // Write a wide string directly to the console output handle.
    void Write(const std::wstring& text) const;
    // Write with a foreground color.
    void WriteColored(const std::wstring& text, Color color) const;
    // Write with color and a trailing newline.
    void WriteLine(const std::wstring& text, Color color = ColorDefault) const;

    // Print the ASCII banner and a short welcome blurb.
    void PrintBanner() const;

    // Clear the whole screen and home the cursor.
    void ClearScreen() const;

    // Move to the start of the current line.
    void CarriageReturn() const;

    HANDLE OutputHandle() const { return output_; }

private:
    HANDLE output_;
    bool vtEnabled_;

    std::wstring AnsiColor(Color color) const;
};
