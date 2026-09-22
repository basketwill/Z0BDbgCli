#pragma once

#include <cstdint>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>

template <typename T>
char WdblHasCr0NpxStateTest(decltype(&T::Cr0NpxState));

template <typename T>
int WdblHasCr0NpxStateTest(...);

template <typename T>
struct WdblHasCr0NpxState {
    enum { value = sizeof(WdblHasCr0NpxStateTest<T>(0)) == sizeof(char) };
};

inline std::wstring WdblToHexCompat(uint64_t value, size_t width) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::setfill(L'0');
    if (width != 0) {
        ss << std::setw(static_cast<int>(width));
    }
    ss << value;
    return ss.str();
}

template <typename T, bool hasMember>
struct WdblCr0NpxStatePrinter;

template <typename T>
struct WdblCr0NpxStatePrinter<T, true> {
    static void Print(std::wostream& out, const T& floatSave) {
        out << L"  Cr0NpxState=" << WdblToHexCompat(static_cast<uint64_t>(floatSave.Cr0NpxState), 8) << L"\n";
    }
};

template <typename T>
struct WdblCr0NpxStatePrinter<T, false> {
    static void Print(std::wostream& out, const T&) {
        out << L"\n";
    }
};

template <typename T>
inline void PrintCr0NpxStateCompat(std::wostream& out, const T& floatSave) {
    WdblCr0NpxStatePrinter<T, WdblHasCr0NpxState<T>::value>::Print(out, floatSave);
}

#define WDBL_PRINT_CR0NPXSTATE_COMPAT(out_stream, float_save_value) \
    PrintCr0NpxStateCompat((out_stream), (float_save_value))
