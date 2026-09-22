#include "PseudoC.h"

#include <algorithm>
#include <cwctype>
#include <map>
#include <set>
#include <sstream>

namespace {

std::wstring TrimText(const std::wstring& text) {
    size_t first = 0;
    while (first < text.size() && std::iswspace(text[first])) {
        ++first;
    }
    size_t last = text.size();
    while (last > first && std::iswspace(text[last - 1])) {
        --last;
    }
    return text.substr(first, last - first);
}

std::wstring LowerText(std::wstring text) {
    for (size_t i = 0; i < text.size(); ++i) {
        text[i] = static_cast<wchar_t>(std::towlower(text[i]));
    }
    return text;
}

bool StartsWith(const std::wstring& text, const std::wstring& prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

std::wstring ToHexText(uint64_t value) {
    std::wstringstream ss;
    ss << L"0x" << std::uppercase << std::hex << value;
    return ss.str();
}

bool ParseHexTarget(const std::wstring& text, uint64_t& out) {
    size_t pos = text.find(L"0x");
    if (pos == std::wstring::npos) {
        return false;
    }
    size_t end = pos + 2;
    while (end < text.size() && std::iswxdigit(text[end])) {
        ++end;
    }
    if (end <= pos + 2) {
        return false;
    }
    std::wstringstream ss;
    ss << std::hex << text.substr(pos + 2, end - pos - 2);
    ss >> out;
    return !ss.fail();
}

bool ParseDirectAddress(const std::wstring& text, uint64_t& out) {
    std::wstring value = TrimText(text);
    if (value.empty()) {
        return false;
    }
    if (ParseHexTarget(value, out)) {
        return true;
    }
    if (value.size() >= 2 && value[0] == L'[') {
        return false;
    }

    const size_t bang = value.find(L'!');
    if (bang != std::wstring::npos) {
        return false;
    }
    const size_t plus = value.find(L'+');
    if (plus != std::wstring::npos) {
        return false;
    }

    bool trailingH = false;
    if (!value.empty() && (value[value.size() - 1] == L'h' || value[value.size() - 1] == L'H')) {
        trailingH = true;
        value = value.substr(0, value.size() - 1);
    }
    if (value.empty()) {
        return false;
    }
    for (size_t i = 0; i < value.size(); ++i) {
        if (!std::iswxdigit(value[i])) {
            return false;
        }
    }
    const bool looksHexAddress = trailingH || value.size() >= 5;
    if (!looksHexAddress) {
        return false;
    }
    std::wstringstream ss;
    ss << std::hex << value;
    ss >> out;
    return !ss.fail();
}

std::vector<std::wstring> SplitOperands(const std::wstring& operands) {
    std::vector<std::wstring> out;
    int bracketDepth = 0;
    size_t start = 0;
    for (size_t i = 0; i < operands.size(); ++i) {
        const wchar_t ch = operands[i];
        if (ch == L'[' || ch == L'(') {
            ++bracketDepth;
        } else if ((ch == L']' || ch == L')') && bracketDepth > 0) {
            --bracketDepth;
        } else if (ch == L',' && bracketDepth == 0) {
            out.push_back(TrimText(operands.substr(start, i - start)));
            start = i + 1;
        }
    }
    out.push_back(TrimText(operands.substr(start)));
    return out;
}

struct ParsedInstruction {
    uint64_t address;
    std::wstring mnemonic;
    std::vector<std::wstring> operands;

    ParsedInstruction()
        : address(0) {
    }
};

ParsedInstruction ParseInstruction(const WdblPseudoInstruction& input) {
    ParsedInstruction out;
    out.address = input.address;
    std::wstring text = TrimText(input.text);
    const size_t semicolon = text.find(L';');
    if (semicolon != std::wstring::npos) {
        text = TrimText(text.substr(0, semicolon));
    }
    const size_t firstSpace = text.find_first_of(L" \t");
    if (firstSpace == std::wstring::npos) {
        out.mnemonic = LowerText(text);
        return out;
    }
    out.mnemonic = LowerText(TrimText(text.substr(0, firstSpace)));
    out.operands = SplitOperands(TrimText(text.substr(firstSpace + 1)));
    return out;
}

std::wstring StripSizePrefix(std::wstring value) {
    value = TrimText(value);
    static const wchar_t* prefixes[] = {
        L"byte ptr ",
        L"word ptr ",
        L"dword ptr ",
        L"qword ptr ",
        L"tbyte ptr ",
        L"xmmword ptr ",
        L"ymmword ptr ",
        L"ptr "
    };
    bool changed = true;
    while (changed) {
        changed = false;
        const std::wstring lower = LowerText(value);
        for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
            const std::wstring prefix(prefixes[i]);
            if (StartsWith(lower, prefix)) {
                value = TrimText(value.substr(prefix.size()));
                changed = true;
                break;
            }
        }
    }
    return value;
}

std::wstring RewriteMemoryOperand(const std::wstring& operand) {
    std::wstring value = StripSizePrefix(operand);
    if (value.size() >= 2 && value[0] == L'[' && value[value.size() - 1] == L']') {
        return L"*(" + TrimText(value.substr(1, value.size() - 2)) + L")";
    }
    return value;
}

std::wstring RewriteAddressOperand(const std::wstring& operand) {
    std::wstring value = StripSizePrefix(operand);
    if (value.size() >= 2 && value[0] == L'[' && value[value.size() - 1] == L']') {
        return TrimText(value.substr(1, value.size() - 2));
    }
    return value;
}

bool IsConditionalJump(const std::wstring& mnemonic) {
    if (mnemonic.empty() || mnemonic[0] != L'j' || mnemonic == L"jmp") {
        return false;
    }
    return true;
}

bool IsStopInstruction(const std::wstring& mnemonic) {
    return StartsWith(mnemonic, L"ret") || mnemonic == L"retn" || mnemonic == L"retf" ||
           mnemonic == L"int3" || mnemonic == L"ud2";
}

std::wstring InvertRelation(const std::wstring& relation) {
    if (relation == L"==") return L"!=";
    if (relation == L"!=") return L"==";
    if (relation == L"<") return L">=";
    if (relation == L"<=") return L">";
    if (relation == L">") return L"<=";
    if (relation == L">=") return L"<";
    return relation;
}

std::wstring RelationForJump(const std::wstring& mnemonic) {
    if (mnemonic == L"je" || mnemonic == L"jz") return L"==";
    if (mnemonic == L"jne" || mnemonic == L"jnz") return L"!=";
    if (mnemonic == L"ja" || mnemonic == L"jnbe" || mnemonic == L"jg" || mnemonic == L"jnle") return L">";
    if (mnemonic == L"jae" || mnemonic == L"jnb" || mnemonic == L"jge" || mnemonic == L"jnl") return L">=";
    if (mnemonic == L"jb" || mnemonic == L"jnae" || mnemonic == L"jl" || mnemonic == L"jnge") return L"<";
    if (mnemonic == L"jbe" || mnemonic == L"jna" || mnemonic == L"jle" || mnemonic == L"jng") return L"<=";
    if (mnemonic == L"js") return L"< 0";
    if (mnemonic == L"jns") return L">= 0";
    return L"?";
}

std::wstring BuildCondition(const ParsedInstruction& branch, const ParsedInstruction* previous) {
    const std::wstring relation = RelationForJump(branch.mnemonic);
    if (previous != NULL && previous->mnemonic == L"cmp" && previous->operands.size() >= 2) {
        return RewriteMemoryOperand(previous->operands[0]) + L" " + relation + L" " + RewriteMemoryOperand(previous->operands[1]);
    }
    if (previous != NULL && previous->mnemonic == L"test" && previous->operands.size() >= 2) {
        const std::wstring lhs = RewriteMemoryOperand(previous->operands[0]);
        const std::wstring rhs = RewriteMemoryOperand(previous->operands[1]);
        if (branch.mnemonic == L"je" || branch.mnemonic == L"jz") {
            return L"(" + lhs + L" & " + rhs + L") == 0";
        }
        if (branch.mnemonic == L"jne" || branch.mnemonic == L"jnz") {
            return L"(" + lhs + L" & " + rhs + L") != 0";
        }
        return L"(" + lhs + L" & " + rhs + L") " + relation;
    }
    if (relation == L"< 0" || relation == L">= 0") {
        return L"flags " + relation;
    }
    return L"flags " + relation + L" 0";
}

std::wstring LabelFor(uint64_t address) {
    std::wstringstream ss;
    ss << L"loc_" << std::uppercase << std::hex << address;
    return ss.str();
}

std::wstring CallName(const std::wstring& operand) {
    std::wstring value = TrimText(operand);
    const size_t comment = value.find(L';');
    if (comment != std::wstring::npos) {
        value = TrimText(value.substr(0, comment));
    }
    uint64_t target = 0;
    if (ParseDirectAddress(value, target)) {
        std::wstringstream ss;
        ss << L"sub_" << std::uppercase << std::hex << target;
        return ss.str();
    }
    return value.empty() ? L"sub_unknown" : value;
}

bool OperandContains(const ParsedInstruction& item, const std::wstring& needle) {
    const std::wstring lowerNeedle = LowerText(needle);
    for (size_t i = 0; i < item.operands.size(); ++i) {
        if (LowerText(item.operands[i]).find(lowerNeedle) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool AnyOperandContains(const ParsedInstruction& item, const std::wstring& a, const std::wstring& b) {
    return OperandContains(item, a) || OperandContains(item, b);
}

bool TextHasAny(const std::wstring& text, const std::wstring& a, const std::wstring& b) {
    return text.find(a) != std::wstring::npos || text.find(b) != std::wstring::npos;
}

std::wstring InstructionText(const ParsedInstruction& item) {
    std::wstringstream out;
    out << item.mnemonic;
    for (size_t i = 0; i < item.operands.size(); ++i) {
        out << (i == 0 ? L" " : L", ") << item.operands[i];
    }
    return LowerText(out.str());
}

std::wstring DetectStdFeatureAt(const std::vector<ParsedInstruction>& parsed, size_t index) {
    if (index >= parsed.size()) {
        return L"";
    }

    const ParsedInstruction& item = parsed[index];
    const std::wstring m = item.mnemonic;
    const std::wstring text = InstructionText(item);

    if (m == L"call" && !item.operands.empty()) {
        const std::wstring call = LowerText(item.operands[0]);
        if (call.find(L"entercriticalsection") != std::wstring::npos || call.find(L"mtx_lock") != std::wstring::npos) {
            return L"likely std::mutex/std::lock_guard lock";
        }
        if (call.find(L"leavecriticalsection") != std::wstring::npos || call.find(L"mtx_unlock") != std::wstring::npos) {
            return L"likely std::mutex/std::lock_guard unlock";
        }
        if (call.find(L"interlockedincrement") != std::wstring::npos || call.find(L"_mt_incref") != std::wstring::npos) {
            return L"likely std::shared_ptr/control block addref";
        }
        if (call.find(L"interlockeddecrement") != std::wstring::npos || call.find(L"_mt_decref") != std::wstring::npos) {
            return L"likely std::shared_ptr/control block release";
        }
        if (call.find(L"operator new") != std::wstring::npos || call.find(L"??2@") != std::wstring::npos) {
            return L"likely operator new allocation";
        }
        if (call.find(L"operator delete") != std::wstring::npos || call.find(L"??3@") != std::wstring::npos) {
            return L"likely operator delete free";
        }
        if (call.find(L"memcpy") != std::wstring::npos || call.find(L"memmove") != std::wstring::npos) {
            return L"likely std container/string buffer copy";
        }
        if (call.find(L"memcmp") != std::wstring::npos) {
            return L"likely std::string/vector compare";
        }
        if (call.find(L"memset") != std::wstring::npos) {
            return L"likely std container/string fill/init";
        }
        if (call.find(L"strlen") != std::wstring::npos || call.find(L"wcslen") != std::wstring::npos) {
            return L"likely std::basic_string length/assign from C string";
        }
        if (call.find(L"invalid_parameter") != std::wstring::npos || call.find(L"length_error") != std::wstring::npos) {
            return L"likely STL range/size validation failure path";
        }
        if (call.find(L"__rttidynamiccast") != std::wstring::npos || call.find(L"type_info") != std::wstring::npos) {
            return L"likely MSVC RTTI/dynamic_cast";
        }
        if (call.find(L"__security_check_cookie") != std::wstring::npos || call.find(L"__report_gsfailure") != std::wstring::npos) {
            return L"likely MSVC /GS security cookie check";
        }
        if (call.find(L"__scrt_common_main") != std::wstring::npos || call.find(L"_initterm") != std::wstring::npos) {
            return L"likely MSVC CRT startup/initializer path";
        }
        if (call.find(L"isdebuggerpresent") != std::wstring::npos || call.find(L"checkremotedebuggerpresent") != std::wstring::npos) {
            return L"likely anti-debug debugger presence check";
        }
        if (call.find(L"ntqueryinformationprocess") != std::wstring::npos) {
            return L"likely anti-debug process debug information query";
        }
        if (call.find(L"__cxxframehandler") != std::wstring::npos) {
            return L"likely MSVC C++ exception/unwind metadata";
        }
    }

    if (m == L"rdtsc" || text.find(L"queryperformancecounter") != std::wstring::npos ||
        text.find(L"gettickcount") != std::wstring::npos) {
        return L"likely timing anti-debug check";
    }

    if (text.find(L"gs:[60h]") != std::wstring::npos || text.find(L"fs:[30h]") != std::wstring::npos ||
        text.find(L"beingdebugged") != std::wstring::npos || text.find(L"ntglobalflag") != std::wstring::npos) {
        return L"likely PEB anti-debug flag check";
    }

    if ((m == L"lock" || text.find(L"lock inc") != std::wstring::npos || text.find(L"lock xadd") != std::wstring::npos) ||
        (m == L"xadd" && text.find(L"lock") != std::wstring::npos)) {
        return L"likely std::shared_ptr/control block atomic refcount";
    }

    if (m == L"mov" && item.operands.size() >= 2 && AnyOperandContains(item, L"+10h", L"+10") &&
        LowerText(item.operands[1]).find(L"0fh") != std::wstring::npos) {
        for (size_t j = index + 1; j < parsed.size() && j < index + 6; ++j) {
            if (parsed[j].mnemonic == L"mov" && parsed[j].operands.size() >= 2 &&
                AnyOperandContains(parsed[j], L"+18h", L"+18") &&
                (LowerText(parsed[j].operands[1]) == L"0" || LowerText(parsed[j].operands[1]) == L"0h")) {
                return L"likely MSVC std::basic_string SSO init/default constructor";
            }
        }
    }

    if ((m == L"cmp" || m == L"test") && item.operands.size() >= 2) {
        bool hasStringCapacity = false;
        bool hasStringSize = false;
        bool hasInlineLimit = false;
        for (size_t j = index; j < parsed.size() && j < index + 10; ++j) {
            const std::wstring nearby = InstructionText(parsed[j]);
            if (TextHasAny(nearby, L"+10h", L"+10]")) {
                hasStringCapacity = true;
            }
            if (TextHasAny(nearby, L"+18h", L"+18]")) {
                hasStringSize = true;
            }
            if (nearby.find(L"0fh") != std::wstring::npos || nearby.find(L"15") != std::wstring::npos) {
                hasInlineLimit = true;
            }
            if (IsConditionalJump(parsed[j].mnemonic) && hasStringCapacity && hasStringSize && hasInlineLimit) {
                return L"likely MSVC std::basic_string SSO/heap branch";
            }
        }
    }

    if ((m == L"cmp" || m == L"mov") && item.operands.size() >= 2) {
        bool hasEnd = false;
        bool hasCapacity = false;
        for (size_t j = index; j < parsed.size() && j < index + 8; ++j) {
            const std::wstring nearby = InstructionText(parsed[j]);
            if (nearby.find(L"+8") != std::wstring::npos || nearby.find(L"+8h") != std::wstring::npos) {
                hasEnd = true;
            }
            if (nearby.find(L"+10h") != std::wstring::npos || nearby.find(L"+10]") != std::wstring::npos) {
                hasCapacity = true;
            }
            if (IsConditionalJump(parsed[j].mnemonic) && hasEnd && hasCapacity) {
                return L"likely MSVC std::vector push_back/emplace_back capacity check";
            }
        }
    }

    if ((m == L"add" || m == L"lea") && item.operands.size() >= 2 && OperandContains(item, L"+8")) {
        return L"likely MSVC std::vector end pointer advance";
    }

    if ((m == L"sub" || m == L"sar" || m == L"shr") && item.operands.size() >= 2) {
        bool hasBeginEnd = false;
        bool hasElementScale = false;
        for (size_t j = index; j < parsed.size() && j < index + 8; ++j) {
            const std::wstring nearby = InstructionText(parsed[j]);
            if (nearby.find(L"+8") != std::wstring::npos || nearby.find(L"+10h") != std::wstring::npos) {
                hasBeginEnd = true;
            }
            if (nearby.find(L"3") != std::wstring::npos || nearby.find(L"4") != std::wstring::npos ||
                nearby.find(L"8") != std::wstring::npos) {
                hasElementScale = true;
            }
        }
        if (hasBeginEnd && hasElementScale) {
            return L"likely std::vector size/capacity calculation";
        }
    }

    if ((m == L"call" || m == L"jmp") && text.find(L"??1") != std::wstring::npos) {
        return L"likely C++ destructor call";
    }

    return L"";
}

std::wstring TranslateInstruction(
    const ParsedInstruction& item,
    const ParsedInstruction* previous,
    const std::map<uint64_t, std::wstring>& labels) {
    const std::wstring m = item.mnemonic;
    const std::vector<std::wstring>& op = item.operands;
    (void)labels;

    if (m == L"mov" && op.size() >= 2) {
        return RewriteMemoryOperand(op[0]) + L" = " + RewriteMemoryOperand(op[1]) + L";";
    }
    if (m == L"lea" && op.size() >= 2) {
        return RewriteMemoryOperand(op[0]) + L" = &(" + RewriteAddressOperand(op[1]) + L");";
    }
    if ((m == L"add" || m == L"sub" || m == L"and" || m == L"or") && op.size() >= 2) {
        std::wstring opText = L"+=";
        if (m == L"sub") {
            opText = L"-=";
        } else if (m == L"and") {
            opText = L"&=";
        } else if (m == L"or") {
            opText = L"|=";
        }
        return RewriteMemoryOperand(op[0]) + L" " + opText + L" " + RewriteMemoryOperand(op[1]) + L";";
    }
    if (m == L"xor" && op.size() >= 2) {
        const std::wstring lhs = RewriteMemoryOperand(op[0]);
        const std::wstring rhs = RewriteMemoryOperand(op[1]);
        if (LowerText(lhs) == LowerText(rhs)) {
            return lhs + L" = 0;";
        }
        return lhs + L" ^= " + rhs + L";";
    }
    if ((m == L"inc" || m == L"dec") && op.size() >= 1) {
        return RewriteMemoryOperand(op[0]) + (m == L"inc" ? L"++;" : L"--;");
    }
    if (m == L"push" && op.size() >= 1) {
        return L"push(" + RewriteMemoryOperand(op[0]) + L");";
    }
    if (m == L"pop" && op.size() >= 1) {
        return RewriteMemoryOperand(op[0]) + L" = pop();";
    }
    if (m == L"cmp" && op.size() >= 2) {
        return L"// compare " + RewriteMemoryOperand(op[0]) + L", " + RewriteMemoryOperand(op[1]);
    }
    if (m == L"test" && op.size() >= 2) {
        return L"// test " + RewriteMemoryOperand(op[0]) + L", " + RewriteMemoryOperand(op[1]);
    }
    if (IsConditionalJump(m) && op.size() >= 1) {
        uint64_t target = 0;
        std::wstring targetText = op[0];
        if (ParseDirectAddress(op[0], target)) {
            targetText = LabelFor(target);
        }
        return L"if (" + BuildCondition(item, previous) + L") goto " + targetText + L";";
    }
    if (m == L"jmp" && op.size() >= 1) {
        uint64_t target = 0;
        std::wstring targetText = op[0];
        if (ParseDirectAddress(op[0], target)) {
            targetText = LabelFor(target);
        }
        return L"goto " + targetText + L";";
    }
    if (m == L"call" && op.size() >= 1) {
        return L"rax = " + CallName(op[0]) + L"(rcx, rdx, r8, r9);";
    }
    if (StartsWith(m, L"ret")) {
        return L"return;";
    }
    if (m == L"nop") {
        return L"// nop";
    }
    if (m == L"int3") {
        return L"__debugbreak();";
    }
    if (m == L"ud2") {
        return L"__ud2();";
    }

    return L"// " + item.mnemonic + (op.empty() ? L"" : L" " + op[0]);
}

} // namespace

std::wstring WdblBuildPseudoC(const std::vector<WdblPseudoInstruction>& instructions) {
    std::vector<ParsedInstruction> parsed;
    parsed.reserve(instructions.size());
    std::set<uint64_t> instructionAddresses;
    std::set<uint64_t> targetAddresses;

    for (size_t i = 0; i < instructions.size(); ++i) {
        ParsedInstruction item = ParseInstruction(instructions[i]);
        if (item.mnemonic.empty()) {
            continue;
        }
        parsed.push_back(item);
        instructionAddresses.insert(item.address);
        if ((item.mnemonic == L"jmp" || IsConditionalJump(item.mnemonic)) && !item.operands.empty()) {
            uint64_t target = 0;
            if (ParseDirectAddress(item.operands[0], target)) {
                targetAddresses.insert(target);
            }
        }
    }

    std::map<uint64_t, std::wstring> labels;
    for (std::set<uint64_t>::const_iterator it = targetAddresses.begin(); it != targetAddresses.end(); ++it) {
        if (instructionAddresses.find(*it) != instructionAddresses.end()) {
            labels[*it] = LabelFor(*it);
        }
    }

    std::wstringstream out;
    out << L"// Minimal pseudo C generated from current disassembly.\n";
    out << L"// Types, calling convention, stack variables, and indirect calls are not recovered.\n";
    out << L"void sub_";
    if (parsed.empty()) {
        out << L"unknown";
    } else {
        out << std::uppercase << std::hex << parsed[0].address;
    }
    out << L"(void)\n";
    out << L"{\n";

    for (size_t i = 0; i < parsed.size(); ++i) {
        std::map<uint64_t, std::wstring>::const_iterator labelIt = labels.find(parsed[i].address);
        if (labelIt != labels.end()) {
            out << labelIt->second << L":\n";
        }
        const ParsedInstruction* previous = (i > 0) ? &parsed[i - 1] : NULL;
        const std::wstring line = TranslateInstruction(parsed[i], previous, labels);
        if (!line.empty()) {
            const std::wstring feature = DetectStdFeatureAt(parsed, i);
            out << L"    " << line << L"  // " << ToHexText(parsed[i].address);
            if (!feature.empty()) {
                out << L"; " << feature;
            }
            out << L"\n";
        }
        if (IsStopInstruction(parsed[i].mnemonic)) {
            break;
        }
    }

    out << L"}\n";
    return out.str();
}
