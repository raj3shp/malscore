"""Container, namespace and mount features (section 14 of the spec)."""

from __future__ import annotations

from typing import Dict

from ..context import SHELLS, CommandContext
from ..schema import F, KIND_INDICATOR

CONTAINER_TOOLS = ("docker", "podman", "nerdctl", "kubectl", "crictl", "ctr", "lxc",
                   "lxc-attach", "machinectl", "helm", "oc", "singularity", "apptainer")
NAMESPACE_TOOLS = ("nsenter", "unshare", "setns")
MOUNT_TOOLS = ("mount", "umount", "findmnt", "mountpoint", "losetup")
SOCKET_PATHS = ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd",
                "/var/run/containerd", "/run/crio", "/var/run/crio", "/run/podman")

FEATURES = [
    F("container_tool", "bool", "container", KIND_INDICATOR, "A container or orchestration CLI is used."),
    F("container_tool_name", "str", "container", KIND_INDICATOR, "First container tool basename.", ""),
    F("container_subcommand", "str", "container", KIND_INDICATOR, "First positional subcommand of the container tool.", ""),
    F("container_shell", "bool", "container", KIND_INDICATOR, "A shell is started inside a container (exec/run + sh)."),
    F("container_exec", "bool", "container", KIND_INDICATOR, "'exec' into a running container/pod."),
    F("container_run", "bool", "container", KIND_INDICATOR, "A new container is started."),
    F("container_privileged_flag", "bool", "container", KIND_INDICATOR, "'--privileged' is requested."),
    F("container_host_namespace", "bool", "container", KIND_INDICATOR, "Host PID/network/IPC namespace requested."),
    F("container_host_mount", "bool", "container", KIND_INDICATOR, "A host path (especially /) is bind-mounted into a container."),
    F("docker_socket_access", "bool", "container", KIND_INDICATOR, "A container runtime socket path is referenced."),
    F("namespace_operation", "bool", "container", KIND_INDICATOR, "nsenter/unshare/setns is used."),
    F("mount_namespace", "bool", "container", KIND_INDICATOR, "Mount namespace flag is used."),
    F("network_namespace", "bool", "container", KIND_INDICATOR, "Network namespace flag is used."),
    F("pid_namespace", "bool", "container", KIND_INDICATOR, "PID namespace flag is used."),
    F("chroot_operation", "bool", "container", KIND_INDICATOR, "chroot is used."),
    F("mount_operation", "bool", "container", KIND_INDICATOR, "A filesystem mount tool is used."),
    F("mount_bind", "bool", "container", KIND_INDICATOR, "A bind mount is requested."),
    F("kubernetes_operation", "bool", "container", KIND_INDICATOR, "kubectl/oc/helm is used."),
    F("kubernetes_namespace", "str", "container", KIND_INDICATOR, "Value of kubectl -n/--namespace.", ""),
    F("kubernetes_secret_access", "bool", "container", KIND_INDICATOR, "A kubernetes secret is read or described."),
]


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute container/namespace features for one event."""
    container_executions = [e for e in ctx.executions if e.basename in CONTAINER_TOOLS]
    first = container_executions[0] if container_executions else None
    args = [a for e in container_executions for a in e.args]
    lowered = " ".join(args)
    subcommand = first.positionals[0] if first and first.positionals else ""

    namespace_args = [a for e in ctx.executions_of(*NAMESPACE_TOOLS) for a in e.args]
    mount_args = [a for e in ctx.executions_of(*MOUNT_TOOLS) for a in e.args]
    kube_ns = ""
    for execution in ctx.executions_of("kubectl", "oc"):
        for index, token in enumerate(execution.args):
            if token in ("-n", "--namespace") and index + 1 < len(execution.args):
                kube_ns = execution.args[index + 1]
            elif token.startswith("--namespace="):
                kube_ns = token.split("=", 1)[1]

    container_shell = False
    if container_executions:
        payload = " ".join(ctx.remote_payloads)
        if any(shell in payload.split() for shell in SHELLS) or \
                any(a.rsplit("/", 1)[-1] in SHELLS for a in args):
            container_shell = True
    if any(e.nested and e.basename in SHELLS for e in ctx.executions) and container_executions:
        container_shell = True

    return {
        "container_tool": int(bool(container_executions)),
        "container_tool_name": first.basename if first else "",
        "container_subcommand": subcommand,
        "container_shell": int(container_shell),
        "container_exec": int("exec" in args or "attach" in args),
        "container_run": int(any(a in ("run", "create", "start") for a in args)),
        "container_privileged_flag": int("--privileged" in args),
        "container_host_namespace": int(any(
            a.startswith(("--pid=host", "--net=host", "--network=host", "--ipc=host", "--userns=host"))
            for a in args
        ) or "hostPID" in lowered or "hostNetwork" in lowered),
        "container_host_mount": int(any(
            a.startswith(("-v", "--volume", "--mount")) or ":/" in a for a in args
        ) and any(a.startswith(("/", "-v /", "--volume=/")) for a in args)),
        "docker_socket_access": int(any(sock in ctx.lower for sock in SOCKET_PATHS)),
        "namespace_operation": int(ctx.uses(*NAMESPACE_TOOLS)),
        "mount_namespace": int(any(a in ("-m", "--mount") for a in namespace_args)),
        "network_namespace": int(any(a in ("-n", "--net", "--network") for a in namespace_args)),
        "pid_namespace": int(any(a in ("-p", "--pid") for a in namespace_args)),
        "chroot_operation": int(ctx.uses("chroot") or ctx.any_wrapper("chroot")),
        "mount_operation": int(ctx.uses(*MOUNT_TOOLS)),
        "mount_bind": int(any(a in ("--bind", "-B", "--rbind") or a == "bind" for a in mount_args)),
        "kubernetes_operation": int(ctx.uses("kubectl", "oc", "helm")),
        "kubernetes_namespace": kube_ns,
        "kubernetes_secret_access": int(
            ctx.uses("kubectl", "oc") and ("secret" in args or "secrets" in args)
        ),
    }
