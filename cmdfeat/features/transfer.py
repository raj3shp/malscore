"""Data transfer features (section 19 of the spec).

Named after the mechanism, not the intent: ``outbound_transfer_indicator``
means "local data is being sent somewhere remote", which is what backups,
deploys and exfiltration all look like structurally.
"""

from __future__ import annotations

from typing import Dict

from ..context import CommandContext
from ..schema import F, KIND_INDICATOR, KIND_STRUCTURAL

TRANSFER_TOOLS = ("curl", "wget", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat",
                  "ftp", "lftp", "tftp", "rclone", "aws", "gsutil", "az", "s3cmd", "mc",
                  "gcloud", "b2", "dropbox_uploader.sh", "httpie")
CLOUD_TOOLS = ("aws", "gsutil", "gcloud", "az", "s3cmd", "rclone", "mc", "b2")
REMOTE_COPY_TOOLS = ("scp", "rsync", "sftp", "lftp")
CLOUD_STORAGE_HINTS = ("s3://", "gs://", "az://", "blob.core.windows.net", "s3.amazonaws.com",
                       "storage.googleapis.com", "r2.cloudflarestorage.com")

FEATURES = [
    F("data_transfer_tool", "bool", "transfer", KIND_STRUCTURAL, "A data transfer tool is used."),
    F("data_transfer_tool_name", "str", "transfer", KIND_STRUCTURAL, "First transfer tool basename.", ""),
    F("remote_copy", "bool", "transfer", KIND_INDICATOR, "scp/rsync/sftp-style remote copy."),
    F("upload_indicator", "bool", "transfer", KIND_INDICATOR, "Local data is sent to a remote destination."),
    F("download_indicator", "bool", "transfer", KIND_INDICATOR, "Remote data is fetched to the local host."),
    F("outbound_transfer_indicator", "bool", "transfer", KIND_INDICATOR, "Any outbound movement of local data."),
    F("cloud_storage_operation", "bool", "transfer", KIND_INDICATOR, "A cloud storage CLI or URI is used."),
    F("cloud_storage_uri", "str", "transfer", KIND_INDICATOR, "First cloud storage URI found.", ""),
    F("transfer_destination_remote", "bool", "transfer", KIND_INDICATOR, "The destination argument is a remote target."),
    F("transfer_source_local_path", "str", "transfer", KIND_INDICATOR, "Local path being transferred, when identifiable.", ""),
    F("transfer_over_socket_tool", "bool", "transfer", KIND_INDICATOR, "Data is moved with nc/socat rather than a protocol client."),
    F("archive_to_transfer_pipeline", "bool", "transfer", KIND_INDICATOR, "An archive tool is piped into a transfer tool."),
]

ARCHIVE_TOOLS = ("tar", "gzip", "zip", "7z", "xz", "bzip2", "zstd", "cpio")


def _is_remote(token: str) -> bool:
    if "@" in token and ":" in token:
        return True
    if token.startswith(("s3://", "gs://", "az://", "http://", "https://", "ftp://", "sftp://")):
        return True
    if ":" in token and not token.startswith("/") and "://" not in token:
        host = token.split(":", 1)[0]
        return bool(host) and "/" not in host and not host.isdigit()
    return False


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute data-transfer features for one event."""
    executions = ctx.executions_of(*TRANSFER_TOOLS)
    first = executions[0] if executions else None
    cloud_uri = ""
    for word in ctx.all_words:
        if any(hint in word.lower() for hint in CLOUD_STORAGE_HINTS):
            cloud_uri = word
            break

    upload = False
    download = False
    destination_remote = False
    source_local = ""
    for execution in executions:
        positionals = execution.positionals
        if execution.basename in REMOTE_COPY_TOOLS and len(positionals) >= 2:
            source, destination = positionals[0], positionals[-1]
            if _is_remote(destination) and not _is_remote(source):
                upload = destination_remote = True
                source_local = source_local or source
            elif _is_remote(source) and not _is_remote(destination):
                download = True
        if execution.basename in CLOUD_TOOLS:
            if any(a in ("cp", "sync", "mv", "put", "upload") for a in execution.args):
                remote_last = positionals and _is_remote(positionals[-1])
                upload = upload or bool(remote_last)
                download = download or (not remote_last and any(_is_remote(p) for p in positionals))
                destination_remote = destination_remote or bool(remote_last)
        if execution.basename == "curl":
            if any(a in ("-T", "--upload-file", "-F", "--form", "--data-binary", "--post-file")
                   for a in execution.args):
                upload = True
            else:
                download = True
        if execution.basename in ("wget", "aria2c", "tftp", "axel"):
            download = True
        if execution.basename in ("nc", "ncat", "netcat", "socat"):
            if execution.command is not None:
                for op, _target in execution.command.redirects:
                    if op.endswith("<"):
                        upload = True
            if execution.command is not None and execution.command.pipeline_index > 0:
                upload = True

    archive_to_transfer = False
    for archive in ctx.executions_of(*ARCHIVE_TOOLS):
        if archive.command is None or archive.command.pipeline_length <= 1:
            continue
        for transfer in executions:
            if transfer.command is None:
                continue
            if (transfer.command.pipeline_id == archive.command.pipeline_id
                    and transfer.command.pipeline_index > archive.command.pipeline_index):
                archive_to_transfer = True

    return {
        "data_transfer_tool": int(bool(executions)),
        "data_transfer_tool_name": first.basename if first else "",
        "remote_copy": int(ctx.uses(*REMOTE_COPY_TOOLS)),
        "upload_indicator": int(upload),
        "download_indicator": int(download),
        "outbound_transfer_indicator": int(upload or archive_to_transfer or destination_remote),
        "cloud_storage_operation": int(bool(cloud_uri) or ctx.uses(*CLOUD_TOOLS)),
        "cloud_storage_uri": cloud_uri,
        "transfer_destination_remote": int(destination_remote),
        "transfer_source_local_path": source_local,
        "transfer_over_socket_tool": int(ctx.uses("nc", "ncat", "netcat", "socat", "cryptcat")),
        "archive_to_transfer_pipeline": int(archive_to_transfer),
    }
