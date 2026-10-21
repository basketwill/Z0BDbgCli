#pragma once
#include <string>

enum McpOperationRisk { MCP_READ_ONLY = 0, MCP_MODIFY = 1, MCP_DANGEROUS = 2 };

static bool McpKnownDangerousTool(const std::string& tool)
{
    return tool == "run" || tool == "go" || tool == "step_into" || tool == "step_over" ||
        tool == "debug_open_process" || tool == "debug_attach_pid" || tool == "debug_detach" ||
        tool == "debug_stop" || tool == "debug_step_out" ||
        tool == "register_set" || tool == "set_register" || tool == "write_memory_patch" ||
        tool == "undo_memory_patch" || tool == "dump_memory_region" ||
        tool == "trace_into" || tool == "trace_over" || tool == "auto_step_into" || tool == "auto_step_over" ||
        tool == "resume_all_threads" || tool == "suspend_all_threads" || tool == "close_process" ||
        tool == "write_memory" || tool == "execute_debugger_command" ||
        tool == "restore_named_snapshot" || tool == "step_back_snapshot" ||
        tool == "step_until_condition" || tool == "run_until_condition" ||
        tool == "auto_step" || tool == "auto_run" ||
        tool == "assemble" || tool == "delete_all_breakpoints" ||
        tool == "delete_breakpoint_range" || tool == "plugin_write_ini_int" ||
        tool == "plugin_write_ini_string" || tool == "set_trace_pause_on_commands" || tool == "plugin_module_changed";
}

static bool McpKnownModifyTool(const std::string& tool)
{
    return tool == "pause" || tool == "set_cpu" || tool == "set_disasm" ||
        tool == "set_software_breakpoint" || tool == "set_software_breakpoint_ext" ||
        tool == "set_memory_breakpoint" || tool == "set_hardware_breakpoint" ||
        tool == "set_temp_breakpoint" || tool == "plugin_temp_breakpoint" ||
        tool == "delete_software_breakpoint" || tool == "enable_breakpoint" ||
        tool == "disable_breakpoint" || tool == "select_thread" ||
        tool == "set_breakpoint_condition" || tool == "clear_breakpoint_condition" ||
        tool == "set_symbol_path" || tool == "load_symbols" || tool == "download_symbols" ||
        tool == "save_stop_snapshot" || tool == "save_named_snapshot" ||
        tool == "add_source_root" || tool == "remove_source_root" || tool == "clear_source_roots" ||
        tool == "load_script_file" || tool == "set_script_breakpoint" || tool == "remove_script_breakpoint" ||
        tool == "set_exception_ignore_all" || tool == "add_ignored_exception" ||
        tool == "remove_ignored_exception" || tool == "clear_ignored_exceptions" ||
        tool == "add_run_stop_expression" || tool == "remove_run_stop_expression" ||
        tool == "clear_run_stop_expressions" ||
        tool == "delete_memory_breakpoint" ||
        tool == "delete_hardware_breakpoint" || tool == "insert_name" || tool == "comment_address" ||
        tool == "set_trace_condition" || tool == "set_trace_count" || tool == "set_dump_type" || tool == "dump_backup" ||
        tool == "redraw_disasm" || tool == "redraw_registers" || tool == "redraw_list" || tool == "redraw_all" ||
        tool == "show_memory" || tool == "show_breakpoints" || tool == "show_hardware_breakpoints" ||
        tool == "show_threads" || tool == "show_trace" || tool == "show_windows" || tool == "show_patches" || tool == "show_watch";
}

static const char* McpRiskName(int risk)
{
    return risk == MCP_READ_ONLY ? "read_only" : risk == MCP_MODIFY ? "modify" : "dangerous";
}

static bool McpReadOnlyTool(const std::string& tool)
{
    return tool == "static_pe_info" || tool == "static_macho_info" || tool == "static_list_sections" ||
        tool == "static_list_imports" || tool == "static_list_exports" ||
        tool == "static_list_strings" || tool == "static_read_bytes" || tool == "static_disassemble" ||
        tool == "get_status" || tool == "get_cpu_thread_id" || tool == "get_debug_context" || tool == "get_event_capabilities" || tool == "get_isolation_policy" || tool == "wait_debug_event" || tool == "debug_find_process" ||
        tool == "thread_list" || tool == "thread_get" || tool == "module_list" || tool == "module_get" ||
        tool == "register_get" || tool == "register_list" || tool == "stack_get_pointers" ||
        tool == "stack_read" || tool == "breakpoint_list" || tool == "breakpoint_get" ||
        tool == "read_memory" || tool == "list_memory" ||
        tool == "find_memory" || tool == "find_data_ptr" ||
        tool == "get_breakpoint_type" || tool == "get_breakpoint_type_count" ||
        tool == "get_next_breakpoint" || tool == "disassemble" ||
        tool == "evaluate" || tool == "resolve_symbol" || tool == "resolve_expression" ||
        tool == "get_symbol_path" || tool == "list_named_snapshots" ||
        tool == "list_source_roots" || tool == "list_script_breakpoints" ||
        tool == "list_exception_settings" || tool == "list_run_stop_expressions" ||
        tool == "find_name" || tool == "decode_address" ||
        tool == "decode_name" || tool == "simple_address" || tool == "find_label" ||
        tool == "find_module" || tool == "find_thread" || tool == "find_data" ||
        tool == "find_decode" || tool == "find_strings" || tool == "find_references" ||
        tool == "find_import_by_name" || tool == "find_file_offset" ||
        tool == "follow_call" || tool == "walk_reference" ||
        tool == "walk_reference_ex" || tool == "is_prefix" ||
        tool == "get_last_error" || tool == "get_cpu_disasm_dump" ||
        tool == "get_cpu_disasm_table" || tool == "plugin_read_ini_int" ||
        tool == "plugin_read_ini_string";
}
