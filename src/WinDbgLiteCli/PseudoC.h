#pragma once

#include <stdint.h>

#include <string>
#include <vector>

struct WdblPseudoInstruction {
    uint64_t address;
    std::wstring text;

    WdblPseudoInstruction()
        : address(0) {
    }
};

std::wstring WdblBuildPseudoC(const std::vector<WdblPseudoInstruction>& instructions);
