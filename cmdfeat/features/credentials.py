"""Credential and secret reference features (section 16 of the spec).

Keyword matching is kept deliberately narrow: ``password`` inside a long
argument value is a hit, but ``passwd`` as a *tool* is handled by the privilege
module, and words such as "key" alone are too common to count.  False positives
here are expensive because they push benign commands into the "sensitive" tail.
"""

from __future__ import annotations

import re
from typing import Dict

from ..context import CommandContext
from ..schema import F, KIND_INDICATOR

PASSWORD_KEYWORDS = ("password", "passwd=", "passwort", "pass=", "--password", "-p=",
                     "pgpassword", "mysql_pwd")
SECRET_KEYWORDS = ("secret", "client_secret", "secret_key", "secretkey")
TOKEN_KEYWORDS = ("token", "access_token", "refresh_token", "bearer", "id_token", "jwt")
API_KEY_KEYWORDS = ("api_key", "apikey", "api-key", "access_key", "accesskey", "x-api-key")
CREDENTIAL_KEYWORDS = ("credential", "credentials", "cred=", "auth=", "authorization:")
PRIVATE_KEY_KEYWORDS = ("private_key", "privatekey", "id_rsa", "id_dsa", "id_ecdsa",
                        "id_ed25519", "begin rsa private key", "begin openssh private key")
CLOUD_KEYWORDS = ("aws_access_key_id", "aws_secret_access_key", "aws_session_token",
                  ".aws/credentials", "google_application_credentials", "gcloud auth",
                  "azure_client_secret", "service_account.json", ".kube/config", "kubeconfig")

KEY_EXTENSIONS = frozenset({"pem", "key", "p12", "pfx", "jks", "keystore", "crt", "cer", "asc", "gpg", "ppk"})
CREDENTIAL_FILES = frozenset({"shadow", "gshadow", "passwd", ".netrc", ".pgpass",
                              ".git-credentials", "credentials", "config", ".htpasswd"})
ENV_CREDENTIAL_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*)\s*="
)

FEATURES = [
    F("credential_reference", "bool", "credentials", KIND_INDICATOR, "The command references credentials of any kind."),
    F("credential_keyword_count", "int", "credentials", KIND_INDICATOR, "Credential-related keyword hits."),
    F("password_reference", "bool", "credentials", KIND_INDICATOR, "A password keyword appears."),
    F("secret_reference", "bool", "credentials", KIND_INDICATOR, "A secret keyword appears."),
    F("token_reference", "bool", "credentials", KIND_INDICATOR, "A token/bearer keyword appears."),
    F("api_key_reference", "bool", "credentials", KIND_INDICATOR, "An API key keyword appears."),
    F("private_key_reference", "bool", "credentials", KIND_INDICATOR, "A private key file or keyword appears."),
    F("cloud_credential_reference", "bool", "credentials", KIND_INDICATOR, "Cloud provider credentials are referenced."),
    F("ssh_key_reference", "bool", "credentials", KIND_INDICATOR, "SSH key material is referenced."),
    F("kube_config_reference", "bool", "credentials", KIND_INDICATOR, "A kubeconfig is referenced."),
    F("certificate_reference", "bool", "credentials", KIND_INDICATOR, "A certificate/key file extension is referenced."),
    F("shadow_file_reference", "bool", "credentials", KIND_INDICATOR, "/etc/shadow or /etc/gshadow is referenced."),
    F("credential_file_reference", "bool", "credentials", KIND_INDICATOR, "A known credential file is referenced."),
    F("credential_env_assignment", "bool", "credentials", KIND_INDICATOR, "An environment variable with a credential-like name is assigned."),
    F("credential_in_argument", "bool", "credentials", KIND_INDICATOR, "A credential value appears inline in an argument (e.g. --password=...)."),
    F("secret_manager_tool", "bool", "credentials", KIND_INDICATOR, "A secret manager CLI (vault, sops, pass, gpg) is used."),
]


def _hits(text: str, keywords) -> int:
    return sum(1 for keyword in keywords if keyword in text)


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute credential-reference features for one event."""
    text = ctx.lower
    paths = ctx.paths
    extensions = {p.extension for p in paths if p.extension}
    basenames = {p.basename.lower() for p in paths}

    password = _hits(text, PASSWORD_KEYWORDS)
    secret = _hits(text, SECRET_KEYWORDS)
    token = _hits(text, TOKEN_KEYWORDS)
    api_key = _hits(text, API_KEY_KEYWORDS)
    credential = _hits(text, CREDENTIAL_KEYWORDS)
    private_key = _hits(text, PRIVATE_KEY_KEYWORDS)
    cloud = _hits(text, CLOUD_KEYWORDS)

    inline_value = any(
        any(keyword in arg.lower() for keyword in ("password=", "token=", "secret=", "apikey=", "api_key="))
        and arg.split("=", 1)[-1] not in ("", '""', "''")
        for arg in ctx.args
    ) or any(
        flag in ("-p", "--password", "--token", "--api-key") and index + 1 < len(execution.args)
        for execution in ctx.executions
        for index, flag in enumerate(execution.args)
    )

    total = password + secret + token + api_key + credential + private_key + cloud
    ssh_key = bool(private_key) or bool(ctx.path_matches("~/.ssh", "/etc/ssh", "/root/.ssh"))
    shadow = "/etc/shadow" in text or "/etc/gshadow" in text
    return {
        "credential_reference": int(bool(total) or ssh_key or shadow
                                    or bool(basenames & CREDENTIAL_FILES)
                                    or bool(extensions & KEY_EXTENSIONS)),
        "credential_keyword_count": total,
        "password_reference": int(bool(password)),
        "secret_reference": int(bool(secret)),
        "token_reference": int(bool(token)),
        "api_key_reference": int(bool(api_key)),
        "private_key_reference": int(bool(private_key) or bool(extensions & {"pem", "key", "ppk"})),
        "cloud_credential_reference": int(bool(cloud)),
        "ssh_key_reference": int(ssh_key),
        "kube_config_reference": int(".kube/config" in text or "kubeconfig" in text),
        "certificate_reference": int(bool(extensions & KEY_EXTENSIONS)),
        "shadow_file_reference": int(shadow),
        "credential_file_reference": int(bool(basenames & CREDENTIAL_FILES)),
        "credential_env_assignment": int(bool(ENV_CREDENTIAL_RE.search(ctx.scan_text))),
        "credential_in_argument": int(bool(inline_value)),
        "secret_manager_tool": int(ctx.uses("vault", "sops", "pass", "gpg", "gpg2", "keyctl",
                                            "secret-tool", "op", "bw")),
    }
