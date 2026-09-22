import time
import os
import traceback

import z0dbg


TARGET = r"C:\Users\Administrator\Desktop\Z0BPcTools3"
MAX_STEPS_TO_CALL = 200
WAIT_TIMEOUT_SECONDS = 15.0
MAX_UI_STEP_LOGS = 10
MAX_CAPTURE_OUTPUT_LINES = 10
OEP_SCAN_BYTES = 512
OEP_ZERO_PADDING_MIN = 8
CALL_PREFIX_BYTES = {
    0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65,
    0x66, 0x67, 0xF0, 0xF2, 0xF3,
}


def signed8(value):
    return value - 0x100 if value & 0x80 else value


def signed32(value):
    return value - 0x100000000 if value & 0x80000000 else value


def parse_disassembly_line_address(line):
    token = line.strip().split(None, 1)[0] if line.strip() else ""
    if token.lower().startswith("0x"):
        token = token[2:]
    token = token.replace("`", "")
    if not token:
        return None
    try:
        return int(token, 16)
    except ValueError:
        return None


def wait_for_pause(timeout=WAIT_TIMEOUT_SECONDS):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = z0dbg.get_stop_info()
        if info and info.get("paused"):
            return info
        time.sleep(0.05)
    return None


def wait_for_new_pause(previous_ip, timeout=WAIT_TIMEOUT_SECONDS):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = z0dbg.get_stop_info()
        if info and info.get("paused"):
            ip = info.get("instruction_pointer")
            if previous_ip is None or ip != previous_ip:
                return info
        time.sleep(0.05)
    return None


def wait_for_pause_at(address, reason_text=None, timeout=WAIT_TIMEOUT_SECONDS):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = z0dbg.get_stop_info()
        if info and info.get("paused"):
            ip = int(info.get("instruction_pointer") or 0)
            reason = str(info.get("reason") or "")
            if ip == address and (reason_text is None or reason_text in reason):
                return info
        time.sleep(0.05)
    return None


def wait_for_new_pause_at(address, previous_ip, reason_text=None, timeout=WAIT_TIMEOUT_SECONDS):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = z0dbg.get_stop_info()
        if info and info.get("paused"):
            ip = int(info.get("instruction_pointer") or 0)
            reason = str(info.get("reason") or "")
            if ip != previous_ip and ip == address and (reason_text is None or reason_text in reason):
                return info
        time.sleep(0.05)
    return None


def wait_for_any_pause(timeout=WAIT_TIMEOUT_SECONDS):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = z0dbg.get_stop_info()
        if info and info.get("paused"):
            return info
        time.sleep(0.05)
    return None


def current_stack_pointer():
    regs = z0dbg.get_registers()
    bits = int(regs.get("architecture_bits", 64))
    if bits == 32:
        sp = int(regs.get("esp") or regs.get("stack_pointer") or 0)
        length = 4
        name = "esp"
    else:
        sp = int(regs.get("rsp") or regs.get("stack_pointer") or 0)
        length = 8
        name = "rsp"
    return name, sp, length


def dump_output_path():
    directory, filename = os.path.split(TARGET)
    stem, ext = os.path.splitext(filename)
    if not stem:
        stem = filename
    return os.path.join(directory, f"{stem}_dump.exe")


def align_up(value, alignment):
    if alignment <= 0:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


def u16(data, offset):
    return int.from_bytes(data[offset:offset + 2], "little")


def u32(data, offset):
    return int.from_bytes(data[offset:offset + 4], "little")


def put_u32(data, offset, value):
    data[offset:offset + 4] = int(value & 0xFFFFFFFF).to_bytes(4, "little")


def put_u64(data, offset, value):
    data[offset:offset + 8] = int(value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def find_module_for_address(address):
    modules = z0dbg.get_modules()
    best = None
    for module in modules:
        base = int(module.get("base_address") or 0)
        size = int(module.get("image_size") or 0)
        if base <= address < base + size:
            if best is None or base > int(best.get("base_address") or 0):
                best = module
    if best:
        return best

    target_name = os.path.basename(TARGET).lower()
    for module in modules:
        image_path = str(module.get("image_path") or "").lower()
        module_name = str(module.get("module_name") or "").lower()
        if image_path.endswith(target_name) or module_name == target_name:
            return module
    return modules[0] if modules else None


def patch_dumped_pe(file_path, oep_va, module_base):
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) < 0x100 or data[0:2] != b"MZ":
        z0dbg.emit_error("dump patch failed: invalid MZ header\n")
        return False

    nt = u32(data, 0x3C)
    if nt + 0x108 > len(data) or data[nt:nt + 4] != b"PE\x00\x00":
        z0dbg.emit_error("dump patch failed: invalid PE header\n")
        return False

    file_header = nt + 4
    number_of_sections = u16(data, file_header + 2)
    optional_size = u16(data, file_header + 16)
    optional = file_header + 20
    section_table = optional + optional_size
    magic = u16(data, optional)

    if magic == 0x20B:
        image_base_offset = optional + 24
        data_dir_offset = optional + 112
    elif magic == 0x10B:
        image_base_offset = optional + 28
        data_dir_offset = optional + 96
    else:
        z0dbg.emit_error("dump patch failed: unknown optional header magic\n")
        return False

    oep_rva = int(oep_va - module_base)
    if oep_rva < 0:
        z0dbg.emit_error("dump patch failed: OEP is outside module\n")
        return False

    put_u32(data, optional + 16, oep_rva)
    if magic == 0x20B:
        put_u64(data, image_base_offset, module_base)
    else:
        put_u32(data, image_base_offset, module_base)

    section_alignment = u32(data, optional + 32)
    file_alignment = u32(data, optional + 36)
    max_image_end = 0
    for i in range(number_of_sections):
        sec = section_table + i * 40
        if sec + 40 > len(data):
            z0dbg.emit_error("dump patch failed: bad section table\n")
            return False

        virtual_size = u32(data, sec + 8)
        virtual_address = u32(data, sec + 12)
        raw_size = max(virtual_size, u32(data, sec + 16))
        raw_size = min(align_up(raw_size, file_alignment), max(0, len(data) - virtual_address))

        put_u32(data, sec + 16, raw_size)
        put_u32(data, sec + 20, virtual_address)
        max_image_end = max(max_image_end, virtual_address + align_up(max(virtual_size, raw_size), section_alignment))

    if max_image_end:
        put_u32(data, optional + 56, max_image_end)

    # The dump is a memory image. The relocation delta has already been applied in memory,
    # so pin the image base to the runtime base and clear the relocation directory.
    reloc_dir = data_dir_offset + 5 * 8
    if reloc_dir + 8 <= len(data):
        put_u32(data, reloc_dir, 0)
        put_u32(data, reloc_dir + 4, 0)

    with open(file_path, "wb") as f:
        f.write(data)

    z0dbg.emit_info(
        f"Patched dump PE: OEP RVA=0x{oep_rva:X}, ImageBase=0x{module_base:X}, "
        "reloc directory cleared\n"
    )
    return True


def parse_instruction_from_output(stop, output):
    ip = int(stop.get("instruction_pointer") or 0)
    if ip == 0:
        return ""
    first_instruction = ""
    for line in output.splitlines():
        stripped = line.strip()
        line_ip = parse_disassembly_line_address(stripped)
        if line_ip is None:
            continue

        if not first_instruction:
            first_instruction = stripped

        if line_ip == ip:
            return stripped
    return first_instruction


def current_instruction_text(stop):
    ok, output = capture_disassembly_text(stop)
    if not ok:
        return ""
    return parse_instruction_from_output(stop, output)


def capture_disassembly_text(stop):
    ip = int(stop.get("instruction_pointer") or 0)
    if ip == 0:
        return False, ""

    result = z0dbg.execute_capture(f"u 0x{ip:X} 1")
    if not result:
        return False, "<execute_capture returned empty result>"
    return bool(result.get("ok")), result.get("output") or ""


def current_instruction_bytes(stop, size=16):
    ip = int(stop.get("instruction_pointer") or 0)
    if ip == 0:
        return b""
    try:
        return z0dbg.read_memory(ip, size) or b""
    except Exception as exc:
        z0dbg.emit_warn(f"read_memory failed at 0x{ip:X}: {exc}\n")
        return b""


def find_zero_padded_direct_jmp(base, code):
    best = None
    limit = len(code)
    for offset in range(limit):
        opcode = code[offset]
        instr_len = 0
        target = 0

        if opcode == 0xE9 and offset + 5 <= limit:
            rel = int.from_bytes(code[offset + 1:offset + 5], "little", signed=False)
            instr_len = 5
            target = base + offset + instr_len + signed32(rel)
        elif opcode == 0xEB and offset + 2 <= limit:
            instr_len = 2
            target = base + offset + instr_len + signed8(code[offset + 1])
        else:
            continue

        zero_start = offset + instr_len
        zero_count = 0
        while zero_start + zero_count < limit and code[zero_start + zero_count] == 0:
            zero_count += 1

        if zero_count >= OEP_ZERO_PADDING_MIN:
            best = {
                "offset": offset,
                "address": base + offset,
                "target": target,
                "opcode": opcode,
                "zero_count": zero_count,
            }

    return best


def handle_upx_oep_after_hw_break(stop, hw_bp_id):
    previous_ip = stop.get("instruction_pointer")
    z0dbg.emit_info("Continuing after hardware breakpoint...\n")
    if not z0dbg.continue_execution():
        z0dbg.emit_error("continue_execution failed after hardware breakpoint\n")
        return

    z0dbg.emit_info("Continue requested after hardware breakpoint.\n")
    stop = wait_for_new_pause(previous_ip)
    if not stop:
        stop = wait_for_any_pause()
    if not stop:
        z0dbg.emit_error("target did not pause after g\n")
        return

    ip = int(stop.get("instruction_pointer") or 0)
    z0dbg.emit_info(f"Paused after hardware breakpoint: ip=0x{ip:X}\n")

    if hw_bp_id is not None:
        if z0dbg.remove_breakpoint(hw_bp_id):
            z0dbg.emit_info(f"Hardware breakpoint #{hw_bp_id} removed\n")
        else:
            z0dbg.emit_warn(f"failed to remove hardware breakpoint #{hw_bp_id}\n")

    try:
        code = z0dbg.read_memory(ip, OEP_SCAN_BYTES) or b""
    except Exception as exc:
        z0dbg.emit_error(f"read_memory failed at 0x{ip:X}: {exc}\n")
        return

    jmp = find_zero_padded_direct_jmp(ip, code)
    if not jmp:
        z0dbg.emit_warn("zero-padded direct JMP was not found in the next 512 bytes\n")
        return

    z0dbg.emit_info(
        f"UPX-like tail JMP found: 0x{jmp['address']:X} -> 0x{jmp['target']:X}, "
        f"zero padding={jmp['zero_count']} bytes\n"
    )

    bp_id = z0dbg.add_software_breakpoint(f"0x{jmp['target']:X}")
    z0dbg.emit_info(f"Software breakpoint #{bp_id} set at OEP candidate 0x{jmp['target']:X}\n")

    z0dbg.emit_info("Continuing to OEP candidate...\n")
    if not z0dbg.continue_execution():
        z0dbg.emit_error("continue_execution failed after OEP breakpoint\n")
        return

    z0dbg.emit_info("Continue requested to OEP candidate.\n")
    stop = wait_for_new_pause_at(jmp["target"], previous_ip, "Software breakpoint")
    if not stop:
        z0dbg.emit_error("target did not pause at OEP candidate\n")
        return

    oep_va = int(stop.get("instruction_pointer") or 0)
    z0dbg.emit_info(f"OEP candidate breakpoint hit: ip=0x{oep_va:X}\n")
    z0dbg.execute("u")

    z0dbg.emit_info("Dump step skipped for test.\n")


def is_call_opcode(code):
    if not code:
        return False

    i = 0
    while i < len(code):
        b = code[i]
        if b in CALL_PREFIX_BYTES or 0x40 <= b <= 0x4F:
            i += 1
            continue
        break

    if i >= len(code):
        return False

    opcode = code[i]
    if opcode == 0xE8 or opcode == 0x9A:
        return True

    if opcode == 0xFF and i + 1 < len(code):
        modrm = code[i + 1]
        return ((modrm >> 3) & 0x07) == 2

    return False


def current_instruction_is_call(instruction, code):
    text = instruction or ""
    if " CALL " in f" {text.upper()} ":
        return True
    return is_call_opcode(code)


def step_until_first_call(stop):
    for i in range(MAX_STEPS_TO_CALL + 1):
        ok, captured = capture_disassembly_text(stop)
        instruction = parse_instruction_from_output(stop, captured) if ok else ""
        code = current_instruction_bytes(stop, 16)
        if i < MAX_UI_STEP_LOGS:
            lines = captured.splitlines()
            z0dbg.emit_info(f"[{i}] execute_capture ok={ok}, lines={len(lines)}\n")
            if not captured:
                z0dbg.emit_warn(f"[{i}] execute_capture output is empty\n")
            for line in lines[:MAX_CAPTURE_OUTPUT_LINES]:
                z0dbg.emit_info(f"    {line}\n")
            if instruction:
                z0dbg.emit_info(f"[{i}] parsed: {instruction}\n")
            else:
                ip = int(stop.get("instruction_pointer") or 0)
                code_text = " ".join(f"{b:02X}" for b in code[:8])
                z0dbg.emit_info(f"[{i}] parsed empty, ip=0x{ip:X} bytes={code_text}\n")
        elif i == MAX_UI_STEP_LOGS:
            z0dbg.emit_info("step log limit reached, continuing silently...\n")

        if current_instruction_is_call(instruction, code):
            return stop, instruction

        if i == MAX_STEPS_TO_CALL:
            break

        previous_ip = stop.get("instruction_pointer")
        if not z0dbg.single_step():
            z0dbg.emit_error("single_step failed\n")
            return None, ""

        stop = wait_for_new_pause(previous_ip)
        if not stop:
            z0dbg.emit_error("target did not pause after single_step\n")
            return None, ""

    z0dbg.emit_error(f"CALL instruction not found after {MAX_STEPS_TO_CALL} single steps\n")
    return None, ""


def main():
    z0dbg.emit_info(f"Launching: {TARGET}\n")
    if not z0dbg.launch(TARGET):
        z0dbg.emit_error("launch failed\n")
        return

    stop = wait_for_pause()
    if not stop:
        z0dbg.emit_error("target did not pause after launch\n")
        return

    z0dbg.emit_info(
        f"Paused: tid={stop.get('thread_id')} "
        f"ip=0x{int(stop.get('instruction_pointer', 0)):X}\n"
    )

    stop, instruction = step_until_first_call(stop)
    if not stop:
        return

    z0dbg.emit_info(f"First CALL reached: {instruction}\n")

    sp_name, sp, length = current_stack_pointer()
    if sp == 0:
        z0dbg.emit_error(f"{sp_name} is zero, hardware breakpoint not set\n")
        return

    tid = int(stop.get("thread_id", 0))
    z0dbg.emit_info(f"Setting hardware write breakpoint on {sp_name}=0x{sp:X}, tid={tid}\n")
    bp_id = z0dbg.add_hardware_breakpoint(f"0x{sp:X}", "w", length, -1, tid)
    z0dbg.emit_info(f"Hardware breakpoint #{bp_id} set at 0x{sp:X}\n")
    z0dbg.emit_info("Entering OEP handling...\n")
    handle_upx_oep_after_hw_break(stop, bp_id)
    z0dbg.emit_info("OEP handling finished, sleeping 10s...\n")
    time.sleep(10)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        z0dbg.emit_error(traceback.format_exc())
        time.sleep(10)
