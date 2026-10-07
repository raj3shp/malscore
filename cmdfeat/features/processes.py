"""Process inspection, control and tracing features (section 12 of the spec)."""

from __future__ import annotations

import re
from typing import Dict

from ..context import CommandContext
from ..schema import F, KIND_INDICATOR, KIND_STRUCTURAL

LISTING_TOOLS = ("ps", "top", "htop", "btop", "atop", "pgrep", "pidof", "pstree", "lsof")
TERMINATION_TOOLS = ("kill", "pkill", "killall", "xkill", "skill")
DEBUGGER_TOOLS = ("gdb", "lldb", "radare2", "r2", "objdump", "readelf", "nm", "edb")
TRACING_TOOLS = ("strace", "ltrace", "ptrace", "bpftrace", "perf", "systemtap", "stap", "dtrace")

PROC_PID_RE = re.compile(r"/proc/(\d+|self)\b")
SIGNAL_RE = re.compile(r"(?:^|\s)-(?:9|15|SIGKILL|SIGTERM|SIGSTOP|SIGCONT|KILL|TERM)\b")

FEATURES = [
    F("process_inspection", "bool", "process", KIND_INDICATOR, "A process listing/inspection tool is used."),
    F("process_listing", "bool", "process", KIND_INDICATOR, "ps/top/pgrep-style listing."),
    F("process_termination", "bool", "process", KIND_INDICATOR, "A process is signalled or killed."),
    F("kill_signal", "str", "process", KIND_INDICATOR, "Signal argument passed to a kill-style tool.", ""),
    F("forceful_kill", "bool", "process", KIND_INDICATOR, "SIGKILL (-9) is used."),
    F("debugger_used", "bool", "process", KIND_INDICATOR, "A debugger or binary analysis tool is used."),
    F("tracing_used", "bool", "process", KIND_INDICATOR, "A syscall/dynamic tracing tool is used."),
    F("attaches_to_pid", "bool", "process", KIND_INDICATOR, "A tracer/debugger attaches to an existing pid (-p)."),
    F("proc_inspection", "bool", "process", KIND_INDICATOR, "A /proc path is referenced."),
    F("proc_self_access", "bool", "process", KIND_INDICATOR, "/proc/self is referenced."),
    F("proc_cmdline_access", "bool", "process", KIND_INDICATOR, "/proc/<pid>/cmdline or environ is referenced."),
    F("proc_mem_access", "bool", "process", KIND_INDICATOR, "/proc/<pid>/mem or maps is referenced."),
    F("proc_net_access", "bool", "process", KIND_INDICATOR, "/proc/net is referenced."),
    F("pid_reference", "bool", "process", KIND_INDICATOR, "An explicit pid appears in the command."),
    F("pid_reference_count", "int", "process", KIND_STRUCTURAL, "Explicit pid references."),
    F("process_tree_related", "bool", "process", KIND_INDICATOR, "Process ancestry is inspected (pstree, ps -ef, /proc/*/stat)."),
    F("job_control", "bool", "process", KIND_INDICATOR, "Shell job control (jobs/fg/bg/disown/nohup) is used."),
]


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute process-related features for one event."""
    text = ctx.scan_text
    proc_paths = [p.lowered for p in ctx.paths if p.lowered.startswith("/proc")]
    kill_executions = ctx.executions_of(*TERMINATION_TOOLS)
    signal_match = SIGNAL_RE.search(" ".join(a for e in kill_executions for a in e.args))
    tracer_executions = ctx.executions_of(*TRACING_TOOLS, *DEBUGGER_TOOLS)

    ps_args = " ".join(a for e in ctx.executions_of("ps") for a in e.args)
    return {
        "process_inspection": int(ctx.uses(*LISTING_TOOLS)),
        "process_listing": int(ctx.uses("ps", "top", "htop", "btop", "atop", "pgrep", "pstree")),
        "process_termination": int(bool(kill_executions)),
        "kill_signal": signal_match.group(0).strip() if signal_match else "",
        "forceful_kill": int(bool(kill_executions) and ("-9" in text or "SIGKILL" in text)),
        "debugger_used": int(ctx.uses(*DEBUGGER_TOOLS)),
        "tracing_used": int(ctx.uses(*TRACING_TOOLS) or ctx.any_wrapper("strace", "ltrace")),
        "attaches_to_pid": int(any("-p" in e.args or "--pid" in e.args for e in tracer_executions)),
        "proc_inspection": int(bool(proc_paths)),
        "proc_self_access": int(any(p.startswith("/proc/self") for p in proc_paths)),
        "proc_cmdline_access": int(any(p.endswith(("/cmdline", "/environ")) for p in proc_paths)),
        "proc_mem_access": int(any(p.endswith(("/mem", "/maps", "/smaps")) for p in proc_paths)),
        "proc_net_access": int(any(p.startswith("/proc/net") for p in proc_paths)),
        "pid_reference": int(bool(PROC_PID_RE.search(text))
                             or any("-p" in e.args for e in kill_executions + tracer_executions)),
        "pid_reference_count": len(PROC_PID_RE.findall(text)),
        "process_tree_related": int(
            ctx.uses("pstree") or "-ef" in ps_args or "--forest" in ps_args
            or any(p.endswith("/stat") or p.endswith("/status") for p in proc_paths)
        ),
        "job_control": int(ctx.uses("jobs", "fg", "bg", "disown", "nohup", "setsid")
                           or ctx.any_wrapper("nohup", "setsid")),
    }
