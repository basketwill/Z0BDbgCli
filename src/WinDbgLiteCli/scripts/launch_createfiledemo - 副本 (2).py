import time
import re

import z0dbg


TARGET = r"C:\Users\Administrator\Desktop\Z0BPcTools3"
MAX_STEPS_TO_CALL = 200
WAIT_TIMEOUT_SECONDS = 15.0
MAX_UI_STEP_LOGS = 10
INSTRUCTION_LINE_RE = re.compile(r"^\s*(?:0x)?([0-9a-fA-F`]+)\s+")
CALL_PREFIX_BYTES = {
    0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65,
    0x66, 0x67, 0xF0, 0xF2, 0xF3,
}


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


def current_instruction_text(stop):
    ip = int(stop.get("instruction_pointer") or 0)
    if ip == 0:
        return ""

    result = z0dbg.execute_capture(f"u 0x{ip:X} 16")
    if not result or not result.get("ok"):
        return ""

    output = result.get("output") or ""
    first_instruction = ""
    for line in output.splitlines():
        stripped = line.strip()
        match = INSTRUCTION_LINE_RE.match(stripped)
        if not match:
            continue

        try:
            line_ip = int(match.group(1).replace("`", ""), 16)
        except ValueError:
            continue

        if not first_instruction:
            first_instruction = stripped
        if line_ip == ip:
            return stripped
    return first_instruction


def current_instruction_bytes(stop, size=16):
    ip = int(stop.get("instruction_pointer") or 0)
    if ip == 0:
        return b""
    try:
        return z0dbg.read_memory(ip, size) or b""
    except Exception as exc:
        z0dbg.emit_warn(f"read_memory failed at 0x{ip:X}: {exc}\n")
        return b""


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


def current_instruction_is_call(stop):
    text = current_instruction_text(stop)
    if " CALL " in f" {text.upper()} ":
        return True
    return is_call_opcode(current_instruction_bytes(stop))


def step_until_first_call(stop):
    for i in range(MAX_STEPS_TO_CALL + 1):
        instruction = current_instruction_text(stop)
        if i < MAX_UI_STEP_LOGS:
            if instruction:
                z0dbg.emit_info(f"[{i}] {instruction}\n")
            else:
                ip = int(stop.get("instruction_pointer") or 0)
                code = current_instruction_bytes(stop, 8)
                code_text = " ".join(f"{b:02X}" for b in code)
                z0dbg.emit_info(f"[{i}] ip=0x{ip:X} bytes={code_text}\n")
        elif i == MAX_UI_STEP_LOGS:
            z0dbg.emit_info("step log limit reached, continuing silently...\n")

        if current_instruction_is_call(stop):
            return stop

        if i == MAX_STEPS_TO_CALL:
            break

        previous_ip = stop.get("instruction_pointer")
        if not z0dbg.single_step():
            z0dbg.emit_error("single_step failed\n")
            return None

        stop = wait_for_new_pause(previous_ip)
        if not stop:
            z0dbg.emit_error("target did not pause after single_step\n")
            return None

    z0dbg.emit_error(f"CALL instruction not found after {MAX_STEPS_TO_CALL} single steps\n")
    return None


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

    stop = step_until_first_call(stop)
    if not stop:
        return

    instruction = current_instruction_text(stop)
    z0dbg.emit_info(f"First CALL reached: {instruction}\n")

    sp_name, sp, length = current_stack_pointer()
    if sp == 0:
        z0dbg.emit_error(f"{sp_name} is zero, hardware breakpoint not set\n")
        return

    tid = int(stop.get("thread_id", 0))
    z0dbg.emit_info(f"Setting hardware write breakpoint on {sp_name}=0x{sp:X}, tid={tid}\n")
    bp_id = z0dbg.add_hardware_breakpoint(f"0x{sp:X}", "w", length, -1, tid)
    z0dbg.emit_info(f"Hardware breakpoint #{bp_id} set at 0x{sp:X}\n")
    z0dbg.print_breakpoints()


if __name__ == "__main__":
    main()
