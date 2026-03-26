from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

SENSITIVE_PATH_PATTERN = re.compile(
    r"(^|/)(\.env(\..*)?|\.npmrc|\.pypirc|id_rsa|id_ed25519|known_hosts|authorized_keys|credentials|config\.json|secrets?)(/|$)|(^|/)\.(aws|ssh|gnupg)(/|$)",
    re.IGNORECASE,
)

HIGH_RISK_WRITE_PATTERN = re.compile(
    r"(^|/)(\.github/workflows/.+\.(yml|yaml)|Dockerfile|docker-compose\.ya?ml|package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements.*\.txt|pyproject\.toml|Pipfile|Gemfile|go\.mod|Cargo\.toml|pom\.xml|build\.gradle(\.kts)?|terraform\.tfvars|\.env(\..*)?)$",
    re.IGNORECASE,
)

MANIFEST_LANGUAGE_MAP = [
    (re.compile(r"package(-lock)?\.json$|pnpm-lock\.yaml$|yarn\.lock$", re.IGNORECASE), "npm"),
    (re.compile(r"requirements.*\.txt$|pyproject\.toml$|Pipfile$", re.IGNORECASE), "python"),
    (re.compile(r"Gemfile$", re.IGNORECASE), "ruby"),
    (re.compile(r"go\.mod$", re.IGNORECASE), "go"),
    (re.compile(r"Cargo\.toml$", re.IGNORECASE), "rust"),
    (re.compile(r"pom\.xml$|build\.gradle(\.kts)?$", re.IGNORECASE), "java"),
]

PROMPT_INJECTION_PATTERN = re.compile(
    r"(ignore\s+(all\s+)?(any\s+)?(previous\s+)?instructions|reveal (your|the) system prompt|developer instructions|exfiltrat(e|ion)|print .*secret|show .*token|bypass guardrails|jailbreak)",
    re.IGNORECASE,
)

DESTRUCTIVE_COMMAND_PATTERN = re.compile(
    r"(?:"
    r"rm\s+(?:-[a-zA-Z]*f[a-zA-Z]*\s+|(?:-[a-zA-Z]+\s+)*)(?:/\s*$|/\s+)"  # rm -rf / (root only, not /tmp/foo)
    r"|sudo\s+rm\b"
    r"|chmod\s+777\b"
    r"|chown\s+-R\b"
    r"|mkfs\b"
    r"|dd\s+if=.*of=/dev/"
    r"|shutdown\b"
    r"|reboot\b"
    r"|launchctl\s+unload\b"
    r")",
    re.IGNORECASE,
)

REMOTE_EXEC_PATTERN = re.compile(r"\b(curl|wget)\b[^|;\n]*\|\s*(bash|sh)\b", re.IGNORECASE)

SECRET_EXFIL_PATTERN = re.compile(
    r"\b(cat|sed|grep|awk)\b[^\n]*(\.env|id_rsa|id_ed25519|\.npmrc|\.pypirc|\.aws|\.ssh)[^\n]*(curl|wget|nc|scp|ftp|http)",
    re.IGNORECASE,
)

SUSPICIOUS_NETWORK_PATTERN = re.compile(
    r"(webhook\.site|ngrok-free\.app|ngrok\.io|pastebin\.com|discord(app)?\.com/api/webhooks|transfer\.sh)",
    re.IGNORECASE,
)

DOS_PATTERN = re.compile(
    r"(?:"
    r":\(\)\s*\{.*\|.*&\s*\}\s*;"       # fork bomb
    r"|while\s+true\s*;?\s*do\b"         # infinite loops
    r"|yes\s*\|"                          # yes pipe flood
    r"|dd\s+if=/dev/(zero|urandom)\b"    # disk fill / random flood
    r"|cat\s+/dev/urandom\b"             # random flood
    r"|\b(stress|stress-ng)\b"            # stress test tools
    r"|ulimit\s+-[a-z]+\s+unlimited"      # removing resource limits
    r")",
    re.IGNORECASE,
)

RCE_CANARY_PATTERN = re.compile(
    r"(?:"
    r"bash\s+-i\s+>&\s*/dev/tcp/"                        # bash reverse shell
    r"|/dev/tcp/\d"                                       # /dev/tcp connection
    r"|nc\s+.*-[a-z]*l[a-z]*\s*.*-p"                     # netcat listener
    r"|python3?\s+-c\s+.*(?:exec|eval|import\s+os)"       # python exec/eval
    r"|perl\s+-e\s+.*(?:socket|exec)"                     # perl reverse shell
    r"|echo\s+.*\|\s*crontab"                              # cron injection
    r"|\*\s+\*\s+\*\s+\*\s+\*.*crontab"                  # cron wildcard injection
    r"|\b(ncat|socat)\b.*(?:exec|listen|EXEC)"            # ncat/socat with exec
    r"|mkfifo\s+.*\bsh\b"                                  # named pipe shell
    r")",
    re.IGNORECASE,
)

DB_MODIFICATION_PATTERN = re.compile(
    r"(?:"
    r"\b(DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE|DELETE\s+FROM|UPDATE\s+\w+\s+SET|ALTER\s+TABLE|INSERT\s+INTO)\b"
    r"|(?:mysql|psql|sqlite3)\s+.*(?:-e\s+|-c\s+)['\"]?\s*(?:DROP|DELETE|UPDATE|ALTER|INSERT|TRUNCATE)"
    r")",
    re.IGNORECASE,
)

DB_ACCESS_PATTERN = re.compile(
    r"(?:"
    r"\b(pg_dump|mysqldump|mongodump|redis-cli\s+--rdb)\b"
    r"|sqlite3\s+.*\.dump"
    r"|\bSELECT\b[^;]*\bFROM\b[^;]*\b(users?|accounts?|credentials?|passwords?|secrets?|tokens?|sessions?|admins?)\b"
    r"|\bCOPY\b.*\bTO\b\s+['\"]"
    r")",
    re.IGNORECASE,
)

PRIVESC_PATTERN = re.compile(
    r"(?:"
    r"chmod\s+[ugo+]*s\s"                  # SUID/SGID
    r"|chmod\s+[0-7]*[4-7][0-7]{2}[0-7]\s" # setuid via octal (4xxx, 6xxx)
    r"|\bsetcap\b"                          # capability escalation
    r"|\bvisudo\b|/etc/sudoers"             # sudoers manipulation
    r"|usermod\s+.*-[a-zA-Z]*G\s+.*sudo"   # add user to sudo group
    r"|\b(useradd|adduser)\b"               # user creation
    r"|\bnsenter\b"                          # namespace enter (container escape)
    r"|\bpkexec\b"                           # polkit execution
    r"|chattr\s+\+i\b"                       # immutable flag
    r")",
    re.IGNORECASE,
)

PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:"
    r"(\.\./){2,}"                                        # directory traversal chains
    r"|/etc/(passwd|shadow|hosts|sudoers)"                 # sensitive system files
    r"|/proc/self/(environ|cmdline|maps|root)"             # proc filesystem
    r"|/proc/\d+/(environ|cmdline|maps)"                   # proc by PID
    r")",
    re.IGNORECASE,
)


def infer_manifest_language(file_path: str = "") -> Optional[str]:
    for pattern, language in MANIFEST_LANGUAGE_MAP:
        if pattern.search(file_path):
            return language
    return None


def is_manifest_path(file_path: str = "") -> bool:
    return infer_manifest_language(file_path) is not None


def evaluate_event(event: Dict[str, Any], index: int, session_id: str = "") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    event_type = str(event.get("type", "")).lower()
    command = str(event.get("command", ""))
    file_path = str(event.get("path", ""))
    url = str(event.get("url", ""))
    combined_text = "\n".join(
        str(value)
        for value in [
            event.get("prompt"),
            event.get("response"),
            event.get("content"),
            event.get("stdout"),
            event.get("stderr"),
        ]
        if value
    )

    if event_type in {"prompt", "tool_result"} and PROMPT_INJECTION_PATTERN.search(combined_text):
        findings.append(
            _finding(
                finding_id=f"prompt-injection-{index}",
                severity="HIGH",
                category="prompt_injection",
                title="Prompt-injection or system-prompt extraction pattern detected",
                evidence=_truncate(combined_text),
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and DESTRUCTIVE_COMMAND_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"destructive-command-{index}",
                severity="CRITICAL",
                category="destructive_command",
                title="Potentially destructive shell command detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and REMOTE_EXEC_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"remote-exec-{index}",
                severity="HIGH",
                category="remote_execution",
                title="Remote fetch-and-execute pattern detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and SECRET_EXFIL_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"secret-exfil-{index}",
                severity="CRITICAL",
                category="secret_exfiltration",
                title="Likely secret exfiltration command detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type in {"file_read", "file_write"} and SENSITIVE_PATH_PATTERN.search(file_path):
        findings.append(
            _finding(
                finding_id=f"sensitive-path-{index}",
                severity="HIGH" if event_type == "file_read" else "CRITICAL",
                category="secret_access",
                title=f"{'Sensitive file access' if event_type == 'file_read' else 'Sensitive file write'} detected",
                evidence=file_path,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "file_write" and HIGH_RISK_WRITE_PATTERN.search(file_path):
        findings.append(
            _finding(
                finding_id=f"risky-write-{index}",
                severity="HIGH" if is_manifest_path(file_path) else "MEDIUM",
                category="risky_write",
                title="Write to high-risk file path detected",
                evidence=file_path,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "network" and SUSPICIOUS_NETWORK_PATTERN.search(url):
        findings.append(
            _finding(
                finding_id=f"suspicious-network-{index}",
                severity="HIGH",
                category="secret_exfiltration",
                title="Network call to a suspicious sink detected",
                evidence=url,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and DOS_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"dos-{index}",
                severity="CRITICAL",
                category="dos_resource_exhaustion",
                title="Denial-of-service or resource exhaustion pattern detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and RCE_CANARY_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"rce-canary-{index}",
                severity="CRITICAL",
                category="rce_canary",
                title="Remote code execution or reverse shell pattern detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and DB_MODIFICATION_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"db-modification-{index}",
                severity="HIGH",
                category="db_modification",
                title="Database modification command detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and DB_ACCESS_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"db-access-{index}",
                severity="HIGH",
                category="db_access",
                title="Database dump or sensitive table access detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and PRIVESC_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"privesc-{index}",
                severity="CRITICAL",
                category="privilege_escalation",
                title="Privilege escalation pattern detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    _check_path = file_path if event_type == "file_read" else command
    if event_type in {"shell", "file_read"} and _check_path and PATH_TRAVERSAL_PATTERN.search(_check_path):
        findings.append(
            _finding(
                finding_id=f"path-traversal-{index}",
                severity="HIGH",
                category="path_traversal",
                title="Path traversal or sensitive system file access detected",
                evidence=_check_path,
                event_index=index,
                session_id=session_id,
            )
        )

    return findings


def _finding(
    *,
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    evidence: str,
    event_index: int,
    session_id: str = "",
) -> Dict[str, Any]:
    prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
    return {
        "id": prefixed_id,
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "eventIndex": event_index,
    }


def _truncate(value: str, max_length: int = 220) -> str:
    text = str(value).strip()
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."
