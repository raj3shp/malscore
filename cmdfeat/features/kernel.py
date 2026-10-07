"""Kernel module and kernel parameter features (section 13 of the spec)."""

from __future__ import annotations

from typing import Dict

from ..context import CommandContext
from ..schema import F, KIND_INDICATOR

MODULE_TOOLS = ("insmod", "modprobe", "rmmod", "lsmod", "depmod", "modinfo", "kmod")
PARAM_TOOLS = ("sysctl", "tuned-adm")

FEATURES = [
    F("kernel_module_operation", "bool", "kernel", KIND_INDICATOR, "A kernel module tool is used."),
    F("kernel_module_load", "bool", "kernel", KIND_INDICATOR, "A module is loaded (insmod/modprobe)."),
    F("kernel_module_unload", "bool", "kernel", KIND_INDICATOR, "A module is unloaded (rmmod/modprobe -r)."),
    F("kernel_module_inspection", "bool", "kernel", KIND_INDICATOR, "Modules are listed or described (lsmod/modinfo)."),
    F("kernel_parameter_operation", "bool", "kernel", KIND_INDICATOR, "sysctl or /proc/sys is used."),
    F("kernel_parameter_write", "bool", "kernel", KIND_INDICATOR, "A kernel parameter is set (sysctl -w, write to /proc/sys)."),
    F("kernel_configuration", "bool", "kernel", KIND_INDICATOR, "Kernel configuration paths (/boot, /etc/sysctl*) are referenced."),
    F("kernel_inspection", "bool", "kernel", KIND_INDICATOR, "Kernel state is inspected (dmesg, uname -a, /sys, /proc/sys)."),
    F("kernel_module_path", "bool", "kernel", KIND_INDICATOR, "A .ko module file or /lib/modules path is referenced."),
]


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute kernel-related features for one event."""
    paths = [p.lowered for p in ctx.paths]
    modprobe_args = [a for e in ctx.executions_of("modprobe") for a in e.args]
    sysctl_args = [a for e in ctx.executions_of("sysctl") for a in e.args]
    proc_sys = any(p.startswith("/proc/sys") for p in paths)

    return {
        "kernel_module_operation": int(ctx.uses(*MODULE_TOOLS)),
        "kernel_module_load": int(ctx.uses("insmod") or (ctx.uses("modprobe") and "-r" not in modprobe_args)),
        "kernel_module_unload": int(ctx.uses("rmmod") or "-r" in modprobe_args),
        "kernel_module_inspection": int(ctx.uses("lsmod", "modinfo", "depmod")),
        "kernel_parameter_operation": int(ctx.uses(*PARAM_TOOLS) or proc_sys),
        "kernel_parameter_write": int(
            any(a in ("-w", "--write") or "=" in a for a in sysctl_args)
            or any(p.startswith("/proc/sys") and pr.from_redirect for p, pr in
                   [(x.lowered, x) for x in ctx.paths])
        ),
        "kernel_configuration": int(
            any(p.startswith(("/boot", "/etc/sysctl", "/etc/default/grub", "/etc/modules")) for p in paths)
        ),
        "kernel_inspection": int(
            ctx.uses("dmesg", "lsmod", "uname", "sysctl")
            or any(p.startswith(("/sys", "/proc/sys", "/proc/version", "/proc/cmdline")) for p in paths)
        ),
        "kernel_module_path": int(any(p.endswith(".ko") or p.startswith("/lib/modules") for p in paths)),
    }
