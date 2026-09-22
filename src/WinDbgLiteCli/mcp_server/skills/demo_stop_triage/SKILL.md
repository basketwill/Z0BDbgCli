# Demo Stop Triage

Use this skill when the debuggee is paused and you want a quick read-only snapshot of the current debugging state.

The skill collects:

- stop information
- thread list
- loaded modules
- breakpoints
- register state for one thread index
- stack frames for one thread index

Inputs:

- `execute`: keep `false` to preview the workflow, set `true` to run it.
- `threadIndex`: thread list index used for registers and stack.
- `maxFrames`: maximum stack frames to collect.

This demo skill does not continue execution, patch memory, set breakpoints, or terminate the debuggee.
