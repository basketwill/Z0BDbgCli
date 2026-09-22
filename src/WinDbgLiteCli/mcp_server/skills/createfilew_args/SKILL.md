# CreateFileW Arguments

Use this skill when execution stops at `CreateFileW` on x64 Windows.

The workflow is read-only. It collects stop info, registers, stack, and tries to display the wide string pointed to by `RCX`, which is the first x64 Windows argument and normally maps to `lpFileName`.
