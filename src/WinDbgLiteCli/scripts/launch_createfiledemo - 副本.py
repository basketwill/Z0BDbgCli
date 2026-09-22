import z0dbg
import time


TARGET = r"C:\Users\Administrator\Desktop\Z0BPcTools3"


def main():
    z0dbg.emit_info(f"Launching: {TARGET}\n")
    if not z0dbg.launch(TARGET):
        z0dbg.emit_error("launch failed\n")
        return

    z0dbg.emit_info("Setting deferred breakpoint: kernel32!CreateFileW\n")
    if not z0dbg.execute("bu kernel32!CreateFileW"):
        z0dbg.emit_error("failed to set breakpoint\n")
        return

    z0dbg.execute("bl")
    z0dbg.emit_info("Breakpoint armed.\n")
    z0dbg.execute("si")

    while True:
        time.sleep(2)
        stop_info = z0dbg.get_stop_info()
        if stop_info and stop_info.get("paused"):
            z0dbg.execute("g")
        


if __name__ == "__main__":
    main()
