"""Network indicator features (section 6 of the spec).

Networking tools are *behavioural* features, not verdicts: ``curl`` is the most
normal command in the world on a developer's box and unusual on a finance
analyst's.  The extractor therefore records what was used and what it pointed
at, and leaves scoring to a later stage.
"""

from __future__ import annotations

from typing import Dict, List

from ..context import CommandContext
from ..schema import F, KIND_INDICATOR, KIND_STRUCTURAL
from ..textutil import COMMON_PORTS, classify_ip, domain_suffix

TRANSFER_TOOLS = ("curl", "wget", "aria2c", "fetch", "ftp", "tftp", "sftp", "scp",
                  "rsync", "rclone", "lftp", "httpie", "http", "axel")
SOCKET_TOOLS = ("nc", "ncat", "netcat", "socat", "telnet", "openssl", "cryptcat")
REMOTE_SHELL_TOOLS = ("ssh", "sshpass", "mosh", "telnet", "rsh", "rlogin")
CAPTURE_TOOLS = ("tcpdump", "tshark", "wireshark", "dumpcap", "ngrep", "termshark")
SCAN_TOOLS = ("nmap", "masscan", "zmap", "hping3", "fping", "arp-scan", "nikto")
DNS_TOOLS = ("dig", "nslookup", "host", "resolvectl", "drill", "delv")
NET_CONFIG_TOOLS = ("ip", "ifconfig", "route", "arp", "ss", "netstat", "iptables",
                    "nft", "firewall-cmd", "ufw", "ethtool", "brctl", "tc")
REACHABILITY_TOOLS = ("ping", "ping6", "traceroute", "tracepath", "mtr", "nping")
NETWORK_TOOLS = (TRANSFER_TOOLS + SOCKET_TOOLS + REMOTE_SHELL_TOOLS + CAPTURE_TOOLS
                 + SCAN_TOOLS + DNS_TOOLS + NET_CONFIG_TOOLS + REACHABILITY_TOOLS)

DOWNLOAD_FLAGS = frozenset({"-o", "--output", "-O", "--remote-name", "--output-dir", "-P",
                            "--directory-prefix", "-d"})
UPLOAD_FLAGS = frozenset({"-T", "--upload-file", "-F", "--form", "--data-binary", "-d",
                          "--data", "--data-raw", "--post-file"})

FEATURES = [
    F("has_url", "bool", "network", KIND_STRUCTURAL, "A URL is present."),
    F("url_count", "int", "network", KIND_STRUCTURAL, "URLs found."),
    F("url_scheme", "str", "network", KIND_STRUCTURAL, "Scheme of the first URL.", ""),
    F("has_http_url", "bool", "network", KIND_STRUCTURAL, "A plain http:// URL is present."),
    F("has_https_url", "bool", "network", KIND_STRUCTURAL, "An https:// URL is present."),
    F("has_ftp_url", "bool", "network", KIND_STRUCTURAL, "An ftp:// or ftps:// URL is present."),
    F("has_websocket_url", "bool", "network", KIND_STRUCTURAL, "A ws:// or wss:// URL is present."),
    F("has_file_url", "bool", "network", KIND_STRUCTURAL, "A file:// URL is present."),
    F("url_has_ip_host", "bool", "network", KIND_INDICATOR, "A URL addresses a raw IP instead of a hostname."),
    F("url_path_present", "bool", "network", KIND_STRUCTURAL, "The first URL has a path component."),
    F("url_path_depth", "int", "network", KIND_STRUCTURAL, "Path components in the first URL."),
    F("url_query_present", "bool", "network", KIND_STRUCTURAL, "The first URL has a query string."),
    F("url_query_param_count", "int", "network", KIND_STRUCTURAL, "Query parameters in the first URL."),
    F("url_fragment_present", "bool", "network", KIND_STRUCTURAL, "The first URL has a fragment."),
    F("has_ipv4", "bool", "network", KIND_STRUCTURAL, "An IPv4 literal is present."),
    F("has_ipv6", "bool", "network", KIND_STRUCTURAL, "An IPv6 literal is present."),
    F("ipv4_count", "int", "network", KIND_STRUCTURAL, "IPv4 literals."),
    F("ipv6_count", "int", "network", KIND_STRUCTURAL, "IPv6 literals."),
    F("ip_count", "int", "network", KIND_STRUCTURAL, "IP literals of either family."),
    F("has_private_ip", "bool", "network", KIND_INDICATOR, "An RFC1918 / unique-local address is referenced."),
    F("has_loopback_ip", "bool", "network", KIND_INDICATOR, "A loopback address is referenced."),
    F("has_link_local_ip", "bool", "network", KIND_INDICATOR, "A link-local address (incl. 169.254.169.254) is referenced."),
    F("has_multicast_ip", "bool", "network", KIND_INDICATOR, "A multicast address is referenced."),
    F("has_public_ip", "bool", "network", KIND_INDICATOR, "A globally routable IP is referenced."),
    F("has_localhost", "bool", "network", KIND_STRUCTURAL, "'localhost' appears in the command."),
    F("has_domain", "bool", "network", KIND_STRUCTURAL, "A hostname/domain is present."),
    F("domain_count", "int", "network", KIND_STRUCTURAL, "Distinct domains."),
    F("primary_domain", "str", "network", KIND_STRUCTURAL, "First domain found.", ""),
    F("domain_suffix", "str", "network", KIND_STRUCTURAL, "Last label of the first domain.", ""),
    F("has_user_at_host", "bool", "network", KIND_STRUCTURAL, "A 'user@host' target is present."),
    F("remote_target_count", "int", "network", KIND_STRUCTURAL, "'user@host' targets."),
    F("has_explicit_port", "bool", "network", KIND_STRUCTURAL, "An explicit port number is present."),
    F("port_count", "int", "network", KIND_STRUCTURAL, "Distinct ports referenced."),
    F("max_port", "int", "network", KIND_STRUCTURAL, "Highest port referenced."),
    F("has_nonstandard_port", "bool", "network", KIND_INDICATOR, "A port outside the common-service list is referenced."),
    F("network_tool_used", "bool", "network", KIND_STRUCTURAL, "A networking tool is executed."),
    F("network_tool_name", "str", "network", KIND_STRUCTURAL, "First networking tool basename.", ""),
    F("network_tool_count", "int", "network", KIND_STRUCTURAL, "Networking tool executions."),
    F("uses_transfer_tool", "bool", "network", KIND_STRUCTURAL, "curl/wget/scp/rsync-class tool used."),
    F("uses_socket_tool", "bool", "network", KIND_STRUCTURAL, "nc/socat/telnet-class tool used."),
    F("uses_remote_shell_tool", "bool", "network", KIND_STRUCTURAL, "ssh-class tool used."),
    F("uses_capture_tool", "bool", "network", KIND_STRUCTURAL, "Packet capture tool used."),
    F("uses_scan_tool", "bool", "network", KIND_STRUCTURAL, "Network scanning tool used."),
    F("uses_dns_tool", "bool", "network", KIND_STRUCTURAL, "DNS lookup tool used."),
    F("uses_net_config_tool", "bool", "network", KIND_STRUCTURAL, "Network configuration/inspection tool used."),
    F("uses_reachability_tool", "bool", "network", KIND_STRUCTURAL, "ping/traceroute-class tool used."),
    F("network_download", "bool", "network", KIND_INDICATOR, "The command retrieves remote content."),
    F("network_upload", "bool", "network", KIND_INDICATOR, "The command sends local content to a remote endpoint."),
]


def _is_download(execution) -> bool:
    base = execution.basename
    args = execution.args
    if base in ("wget", "aria2c", "axel", "fetch", "tftp"):
        return True
    if base == "curl":
        return not any(flag in UPLOAD_FLAGS for flag in args)
    if base == "scp":
        positionals = execution.positionals
        return bool(positionals) and "@" in positionals[0] or ":" in (positionals[0] if positionals else "")
    if base in ("rsync", "rclone", "sftp", "lftp", "ftp"):
        positionals = execution.positionals
        return len(positionals) >= 2 and (":" in positionals[0] or "@" in positionals[0])
    return False


def _is_upload(execution) -> bool:
    base = execution.basename
    args = execution.args
    if base == "curl":
        return any(flag in UPLOAD_FLAGS for flag in args)
    if base in ("scp", "rsync", "rclone", "sftp", "lftp"):
        positionals = execution.positionals
        return len(positionals) >= 2 and (":" in positionals[-1] or "@" in positionals[-1])
    if base in ("nc", "ncat", "netcat", "socat"):
        return any(op.endswith("<") for e in [execution] if e.command
                   for op, _t in e.command.redirects)
    if base == "tftp":
        return "put" in args
    return False


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute network indicator features for one event."""
    urls = ctx.urls
    first_url = urls[0] if urls else None
    schemes = {u.scheme for u in urls}
    all_ips: List[str] = list(ctx.ipv4s) + list(ctx.ipv6s)
    classes = [classify_ip(ip) for ip in all_ips]

    net_executions = [e for e in ctx.executions if e.basename in NETWORK_TOOLS]
    downloads = [e for e in ctx.executions if _is_download(e)]
    uploads = [e for e in ctx.executions if _is_upload(e)]
    ports = ctx.ports

    return {
        "has_url": int(bool(urls)),
        "url_count": len(urls),
        "url_scheme": first_url.scheme if first_url else "",
        "has_http_url": int("http" in schemes),
        "has_https_url": int("https" in schemes),
        "has_ftp_url": int(bool(schemes & {"ftp", "ftps", "sftp"})),
        "has_websocket_url": int(bool(schemes & {"ws", "wss"})),
        "has_file_url": int("file" in schemes),
        "url_has_ip_host": int(any(u.host_is_ip for u in urls)),
        "url_path_present": int(bool(first_url and first_url.path not in ("", "/"))),
        "url_path_depth": first_url.path_depth if first_url else 0,
        "url_query_present": int(bool(first_url and first_url.query)),
        "url_query_param_count": first_url.query_param_count if first_url else 0,
        "url_fragment_present": int(bool(first_url and first_url.fragment)),
        "has_ipv4": int(bool(ctx.ipv4s)),
        "has_ipv6": int(bool(ctx.ipv6s)),
        "ipv4_count": len(ctx.ipv4s),
        "ipv6_count": len(ctx.ipv6s),
        "ip_count": len(all_ips),
        "has_private_ip": int(any(c.get("private") for c in classes)),
        "has_loopback_ip": int(any(c.get("loopback") for c in classes)),
        "has_link_local_ip": int(any(c.get("link_local") for c in classes)),
        "has_multicast_ip": int(any(c.get("multicast") for c in classes)),
        "has_public_ip": int(any(c.get("public") for c in classes)),
        "has_localhost": int("localhost" in ctx.lower),
        "has_domain": int(bool(ctx.domains)),
        "domain_count": len(set(ctx.domains)),
        "primary_domain": ctx.domains[0] if ctx.domains else "",
        "domain_suffix": domain_suffix(ctx.domains[0]) if ctx.domains else "",
        "has_user_at_host": int(bool(ctx.user_at_hosts)),
        "remote_target_count": len(ctx.user_at_hosts),
        "has_explicit_port": int(bool(ports)),
        "port_count": len(ports),
        "max_port": max(ports) if ports else 0,
        "has_nonstandard_port": int(any(p not in COMMON_PORTS for p in ports)),
        "network_tool_used": int(bool(net_executions)),
        "network_tool_name": net_executions[0].basename if net_executions else "",
        "network_tool_count": len(net_executions),
        "uses_transfer_tool": int(ctx.uses(*TRANSFER_TOOLS)),
        "uses_socket_tool": int(ctx.uses(*SOCKET_TOOLS)),
        "uses_remote_shell_tool": int(ctx.uses(*REMOTE_SHELL_TOOLS)),
        "uses_capture_tool": int(ctx.uses(*CAPTURE_TOOLS)),
        "uses_scan_tool": int(ctx.uses(*SCAN_TOOLS)),
        "uses_dns_tool": int(ctx.uses(*DNS_TOOLS)),
        "uses_net_config_tool": int(ctx.uses(*NET_CONFIG_TOOLS)),
        "uses_reachability_tool": int(ctx.uses(*REACHABILITY_TOOLS)),
        "network_download": int(bool(downloads)),
        "network_upload": int(bool(uploads)),
    }
