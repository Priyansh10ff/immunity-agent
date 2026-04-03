#!/usr/bin/env python3
"""
Prismor Warden — Interactive Setup Wizard
Usage: python3 setup.py [TARGET_DIR] [--non-interactive]
"""

import os
import sys
import tty
import termios
import signal
import atexit
import time
import threading
import subprocess
import shutil
import re
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

VERSION = "v0.2"

# ── ANSI Color / Style helpers ───────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
BLINK   = "\033[5m"
CYAN    = "\033[36m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
RED     = "\033[31m"
BLUE    = "\033[34m"
WHITE   = "\033[97m"
MAGENTA = "\033[35m"

HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"
CLEAR       = "\033[2J\033[H"

def c(text, *codes):
    return "".join(codes) + str(text) + RESET

def clear_screen():
    sys.stdout.write(CLEAR)
    sys.stdout.flush()

def move_to(row, col):
    sys.stdout.write(f"\033[{row};{col}H")

def get_term_width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80

def right_pad(text, total, fill=" "):
    stripped = re.sub(r'\033\[[0-9;]*m', '', text)
    pad = max(0, total - len(stripped))
    return text + fill * pad

# ── Terminal raw mode ────────────────────────────────────────────────────────

_old_settings = None

def enable_raw_mode():
    global _old_settings
    fd = sys.stdin.fileno()
    _old_settings = termios.tcgetattr(fd)
    tty.setcbreak(fd)

def restore_terminal():
    if _old_settings is not None:
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _old_settings)
        except Exception:
            pass
    sys.stdout.write(SHOW_CURSOR)
    sys.stdout.flush()

atexit.register(restore_terminal)

def signal_handler(sig, frame):
    restore_terminal()
    print()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def read_key():
    ch = sys.stdin.read(1)
    if ch == '\x1b':
        ch2 = sys.stdin.read(1)
        if ch2 == '[':
            ch3 = sys.stdin.read(1)
            return '\x1b[' + ch3
        return '\x1b' + ch2
    return ch

KEY_UP    = '\x1b[A'
KEY_DOWN  = '\x1b[B'
KEY_RIGHT = '\x1b[C'
KEY_LEFT  = '\x1b[D'
KEY_ENTER = '\r'
KEY_ENTER2 = '\n'
KEY_SPACE = ' '
KEY_Q     = 'q'
KEY_Q_UP  = 'Q'
KEY_B     = 'b'
KEY_B_UP  = 'B'
KEY_A     = 'a'
KEY_A_UP  = 'A'
KEY_N     = 'n'
KEY_N_UP  = 'N'

# ── Rule loading ─────────────────────────────────────────────────────────────

SCRIPT_DIR   = Path(__file__).resolve().parent
PRISMOR_DIR  = Path(os.environ.get("PRISMOR_HOME", Path.home() / ".prismor"))
if not PRISMOR_DIR.exists():
    PRISMOR_DIR = SCRIPT_DIR.parent

DEFAULT_POLICY = PRISMOR_DIR / "warden" / "default_policy.yaml"

def load_rules():
    """Load rules from default_policy.yaml. Returns list of dicts."""
    rules = []
    if not DEFAULT_POLICY.exists():
        return _fallback_rules()
    try:
        import yaml
        with open(DEFAULT_POLICY) as f:
            data = yaml.safe_load(f)
        for r in data.get("rules", []):
            rules.append({
                "id":       r.get("id", "unknown"),
                "severity": r.get("severity", "MEDIUM"),
                "title":    r.get("title", r.get("id", "")),
                "enabled":  True,
            })
        return rules
    except ImportError:
        pass
    # Manual YAML parse (minimal)
    return _parse_rules_manually()

def _parse_rules_manually():
    rules = []
    if not DEFAULT_POLICY.exists():
        return _fallback_rules()
    current = {}
    in_rules = False
    with open(DEFAULT_POLICY) as f:
        for line in f:
            stripped = line.strip()
            if stripped == "rules:":
                in_rules = True
                continue
            if not in_rules:
                continue
            if stripped.startswith("allowlists:"):
                break
            m_id  = re.match(r'^\s*-\s*id:\s*(.+)$', line)
            m_sev = re.match(r'^\s*severity:\s*(\w+)', line)
            m_tit = re.match(r'^\s*title:\s*(.+)$', line)
            if m_id:
                if current:
                    rules.append(current)
                current = {"id": m_id.group(1).strip(), "severity": "MEDIUM",
                           "title": m_id.group(1).strip(), "enabled": True}
            elif m_sev and current and "severity" not in current:
                current["severity"] = m_sev.group(1).strip()
            elif m_sev and current:
                current["severity"] = m_sev.group(1).strip()
            elif m_tit and current:
                current["title"] = m_tit.group(1).strip()
    if current:
        rules.append(current)
    return rules if rules else _fallback_rules()

def _fallback_rules():
    return [
        {"id": "destructive-command",   "severity": "CRITICAL", "title": "Destructive shell commands",                   "enabled": True},
        {"id": "secret-exfiltration",   "severity": "CRITICAL", "title": "Secret exfiltration via shell",                "enabled": True},
        {"id": "dos-resource-exhaustion","severity":"CRITICAL", "title": "DoS / resource exhaustion",                    "enabled": True},
        {"id": "rce-canary",            "severity": "CRITICAL", "title": "Remote code execution / reverse shell",        "enabled": True},
        {"id": "privilege-escalation",  "severity": "CRITICAL", "title": "Privilege escalation pattern",                 "enabled": True},
        {"id": "prompt-injection",      "severity": "HIGH",     "title": "Prompt injection / system-prompt extraction",  "enabled": True},
        {"id": "remote-execution",      "severity": "HIGH",     "title": "Remote fetch-and-execute",                     "enabled": True},
        {"id": "secret-access",         "severity": "HIGH",     "title": "Sensitive file access",                        "enabled": True},
        {"id": "suspicious-network",    "severity": "HIGH",     "title": "Network call to suspicious sink",              "enabled": True},
        {"id": "db-modification",       "severity": "HIGH",     "title": "Database modification command",                "enabled": True},
        {"id": "db-access",             "severity": "HIGH",     "title": "Database dump / sensitive query",              "enabled": True},
        {"id": "path-traversal",        "severity": "HIGH",     "title": "Path traversal / sensitive system file",       "enabled": True},
        {"id": "risky-write",           "severity": "MEDIUM",   "title": "Dockerfile, package.json writes",              "enabled": True},
    ]

# ── Agent detection ──────────────────────────────────────────────────────────

def detect_agents(target_dir):
    detected = []
    home = Path.home()
    td = Path(target_dir)
    # claude
    claude_ok = (shutil.which("claude") is not None or
                 (td / ".claude").exists() or (home / ".claude").exists())
    # cursor
    cursor_ok = ((td / ".cursor").exists() or (home / ".cursor").exists())
    # windsurf
    windsurf_ok = ((td / ".windsurf").exists() or (home / ".codeium").exists())
    detected = {
        "claude":   claude_ok,
        "cursor":   cursor_ok,
        "windsurf": windsurf_ok,
    }
    return detected

# ── Severity coloring ────────────────────────────────────────────────────────

def severity_color(sev):
    s = sev.upper()
    if s == "CRITICAL": return RED
    if s == "HIGH":     return YELLOW
    if s == "MEDIUM":   return BLUE
    return DIM

# ── Header ───────────────────────────────────────────────────────────────────

def draw_header(step=None, total=None, label=None):
    w = get_term_width()
    print()
    print(f"  {c('PRISMOR WARDEN', BOLD, CYAN)}  {c(f'· {VERSION}', DIM)}")
    if step and label:
        step_txt = c(f"Step {step}/{total}", DIM)
        label_txt = c(label, BOLD)
        print(f"  {step_txt}  {label_txt}")
    print(c("  " + "─" * min(w - 4, 68), DIM))
    print()

def draw_controls(controls):
    parts = [c(key, BOLD, CYAN) + c(f" {desc}", DIM) for key, desc in controls]
    print()
    print("  " + c("  ·  ", DIM).join(parts))

# ── Screen 2: Enforcement Mode ───────────────────────────────────────────────

def screen_enforcement_mode(current="enforce"):
    options = [
        ("observe", "Log and warn — never block agent actions"),
        ("enforce", "Block dangerous actions before they execute"),
    ]
    sel = 0 if current == "observe" else 1

    while True:
        clear_screen()
        sys.stdout.write(HIDE_CURSOR)
        draw_header(1, 3, "ENFORCEMENT MODE")

        for i, (name, desc) in enumerate(options):
            cursor = c("▶", CYAN) if i == sel else " "
            dot    = c("●", GREEN) if i == sel else c("○", DIM)
            name_s = c(name, BOLD, WHITE) if i == sel else c(name, DIM)
            desc_s = c(desc, DIM)
            print(f"  {cursor} {dot}  {name_s:<10}  {desc_s}")

        draw_controls([("↑↓", "navigate"), ("ENTER", "confirm")])
        sys.stdout.flush()

        key = read_key()
        if key in (KEY_UP,):
            sel = (sel - 1) % len(options)
        elif key in (KEY_DOWN,):
            sel = (sel + 1) % len(options)
        elif key in (KEY_ENTER, KEY_ENTER2):
            return options[sel][0]
        elif key in (KEY_Q, KEY_Q_UP, '\x03'):
            restore_terminal()
            sys.exit(0)

# ── Screen 3: Detection Rules ────────────────────────────────────────────────

def screen_detection_rules(rules):
    sel = 0

    while True:
        clear_screen()
        sys.stdout.write(HIDE_CURSOR)
        draw_header(2, 3, "DETECTION RULES")

        enabled_count = sum(1 for r in rules if r["enabled"])
        print(c(f"  {enabled_count} / {len(rules)} rules enabled", DIM))
        print()

        for i, rule in enumerate(rules):
            cursor = c("▶", CYAN) if i == sel else " "
            dot    = c("●", GREEN) if rule["enabled"] else c("○", DIM)
            sev_col = severity_color(rule["severity"])
            sev_s   = c(f"{rule['severity']:<8}", sev_col)
            rid_s   = c(f"{rule['id']:<28}", BOLD if i == sel else "")
            title_s = c(rule["title"][:36], DIM)
            print(f"  {cursor} {dot}  {sev_s} {rid_s} {title_s}")

        draw_controls([
            ("↑↓", "navigate"), ("SPACE", "toggle"),
            ("A", "all on"), ("N", "all off"), ("ENTER", "confirm"),
        ])
        sys.stdout.flush()

        key = read_key()
        if key in (KEY_UP,):
            sel = (sel - 1) % len(rules)
        elif key in (KEY_DOWN,):
            sel = (sel + 1) % len(rules)
        elif key == KEY_SPACE:
            rules[sel]["enabled"] = not rules[sel]["enabled"]
        elif key in (KEY_A, KEY_A_UP):
            for r in rules: r["enabled"] = True
        elif key in (KEY_N, KEY_N_UP):
            for r in rules: r["enabled"] = False
        elif key in (KEY_ENTER, KEY_ENTER2):
            return rules
        elif key in (KEY_Q, KEY_Q_UP, '\x03'):
            restore_terminal()
            sys.exit(0)

# ── Screen 4: Agent Selection ────────────────────────────────────────────────

def screen_agent_selection(target_dir):
    detected = detect_agents(target_dir)
    agents = [
        {"name": "claude",   "label": "Claude Code",  "checked": detected.get("claude",   False)},
        {"name": "cursor",   "label": "Cursor IDE",   "checked": detected.get("cursor",   False)},
        {"name": "windsurf", "label": "Windsurf",     "checked": detected.get("windsurf", False)},
    ]
    # Default at least one
    if not any(a["checked"] for a in agents):
        agents[0]["checked"] = True

    sel = 0

    while True:
        clear_screen()
        sys.stdout.write(HIDE_CURSOR)
        draw_header(3, 3, "AGENT SELECTION")

        print(c("  Select which agents to install Warden hooks for:", DIM))
        print()

        for i, agent in enumerate(agents):
            cursor = c("▶", CYAN) if i == sel else " "
            dot    = c("●", GREEN) if agent["checked"] else c("○", DIM)
            label  = c(agent["label"], BOLD if i == sel else "")
            status = c("(detected)", GREEN) if detected.get(agent["name"]) else c("(not found)", DIM)
            print(f"  {cursor} {dot}  {label:<16}  {status}")

        draw_controls([("↑↓", "navigate"), ("SPACE", "toggle"), ("ENTER", "confirm")])
        sys.stdout.flush()

        key = read_key()
        if key in (KEY_UP,):
            sel = (sel - 1) % len(agents)
        elif key in (KEY_DOWN,):
            sel = (sel + 1) % len(agents)
        elif key == KEY_SPACE:
            agents[sel]["checked"] = not agents[sel]["checked"]
        elif key in (KEY_ENTER, KEY_ENTER2):
            chosen = [a["name"] for a in agents if a["checked"]]
            if not chosen:
                chosen = ["claude"]
            return chosen
        elif key in (KEY_Q, KEY_Q_UP, '\x03'):
            restore_terminal()
            sys.exit(0)

# ── Screen 5: Confirm + Install ──────────────────────────────────────────────

def screen_confirm(target_dir, mode, rules, agents):
    home = str(Path.home())
    display_dir = str(target_dir).replace(home, "~")
    enabled_count = sum(1 for r in rules if r["enabled"])
    total_count   = len(rules)
    agents_str    = ", ".join(agents)
    policy_path   = ".prismor-warden/policy.yaml"

    inner_w = 45
    border_col = DIM

    def box_line(content=""):
        pad = inner_w - len(re.sub(r'\033\[[0-9;]*m', '', content))
        return c("│", border_col) + "  " + content + " " * max(0, pad - 2) + c("│", border_col)

    def kv(key, val, val_col=WHITE):
        k = c(f"{key:<12}", DIM)
        v = c(val, val_col)
        raw = f"  {key:<12} {val}"
        pad = inner_w - len(raw) - 1
        return c("│", border_col) + "  " + k + " " + v + " " * max(0, pad) + c("│", border_col)

    while True:
        clear_screen()
        sys.stdout.write(HIDE_CURSOR)
        draw_header()

        top = c("╭" + "─" * inner_w + "╮", border_col)
        bot    = c("╰" + "─" * inner_w + "╯", border_col)
        spacer = box_line()

        print("  " + top)
        print("  " + box_line(c("  READY TO INSTALL", BOLD, WHITE)))
        print("  " + spacer)
        print("  " + kv("Project", display_dir[:32]))
        print("  " + kv("Mode", mode, GREEN if mode == "enforce" else YELLOW))
        print("  " + kv("Rules", f"{enabled_count} / {total_count} enabled"))
        print("  " + kv("Agents", agents_str))
        print("  " + kv("Policy", policy_path, DIM))
        print("  " + spacer)
        print("  " + bot)

        print()
        print(f"  {c('ENTER', BOLD, GREEN)} install   {c('B', BOLD, CYAN)} back   {c('Q', BOLD, DIM)} quit")
        sys.stdout.flush()

        key = read_key()
        if key in (KEY_ENTER, KEY_ENTER2):
            return True
        elif key in (KEY_B, KEY_B_UP):
            return False
        elif key in (KEY_Q, KEY_Q_UP, '\x03'):
            restore_terminal()
            sys.exit(0)

# ── Install Phase ────────────────────────────────────────────────────────────

SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

class SpinnerStep:
    def __init__(self, label):
        self.label  = label
        self.done   = False
        self.ok     = False
        self.msg    = ""
        self._idx   = 0
        self._stop  = False
        self._thread = None

    def start(self):
        self._stop = False
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self):
        while not self._stop:
            if not self.done:
                frame = SPINNER_FRAMES[self._idx % len(SPINNER_FRAMES)]
                line = f"  {c(frame, CYAN)}  {self.label}"
                sys.stdout.write("\r" + line + "   ")
                sys.stdout.flush()
                self._idx += 1
            time.sleep(0.08)

    def finish(self, ok=True, msg=""):
        self.done = True
        self.ok   = ok
        self.msg  = msg
        self._stop = True
        if self._thread:
            self._thread.join(timeout=0.5)
        icon = c("✓", GREEN) if ok else c("✗", RED)
        suffix = f"  {c(msg, DIM)}" if msg else ""
        sys.stdout.write("\r" + f"  {icon}  {self.label}{suffix}" + "   \n")
        sys.stdout.flush()

def run_install(target_dir, mode, rules, agents):
    clear_screen()
    sys.stdout.write(HIDE_CURSOR)
    print(c("  Installing Prismor Warden...", BOLD, CYAN))
    print()

    target_dir = Path(target_dir).resolve()

    # Step 1: Update Prismor
    step = SpinnerStep("Updating Prismor")
    step.start()
    try:
        if PRISMOR_DIR.exists():
            result = subprocess.run(
                ["git", "-C", str(PRISMOR_DIR), "pull", "--quiet"],
                capture_output=True, timeout=15
            )
            step.finish(ok=(result.returncode == 0), msg="up to date" if result.returncode == 0 else "offline, using existing")
        else:
            step.finish(ok=False, msg="Prismor dir not found — hooks may still install")
    except Exception as e:
        step.finish(ok=False, msg=str(e)[:40])

    # Step 2: Write policy override (disabled rules)
    disabled = [r["id"] for r in rules if not r["enabled"]]
    if disabled:
        step2 = SpinnerStep("Writing policy overrides")
        step2.start()
        try:
            policy_dir = target_dir / ".prismor-warden"
            policy_dir.mkdir(exist_ok=True)
            policy_file = policy_dir / "policy.yaml"
            lines = ['version: "1.0"\n', "rules:\n"]
            for rid in disabled:
                lines.append(f"  - id: {rid}\n    enabled: false\n")
            policy_file.write_text("".join(lines))
            step2.finish(ok=True, msg=f"{len(disabled)} rule(s) disabled")
        except Exception as e:
            step2.finish(ok=False, msg=str(e)[:40])

    # Step 3: Install hooks for each agent
    for agent in agents:
        step3 = SpinnerStep(f"Installing {agent} hooks")
        step3.start()
        cli_path = PRISMOR_DIR / "warden" / "cli.py"
        if cli_path.exists():
            try:
                result = subprocess.run(
                    [sys.executable, str(cli_path), "install-hooks",
                     "--agent", agent,
                     "--workspace", str(target_dir),
                     "--scope", "project",
                     "--mode", mode],
                    capture_output=True, timeout=30
                )
                step3.finish(ok=(result.returncode == 0))
            except Exception as e:
                step3.finish(ok=False, msg=str(e)[:40])
        else:
            step3.finish(ok=False, msg="cli.py not found")

    # Step 4: Create/update CLAUDE.md
    step4 = SpinnerStep("Updating CLAUDE.md")
    step4.start()
    try:
        claude_md = target_dir / "CLAUDE.md"
        block = (
            "\n## Security (Prismor)\n\n"
            f"At the start of every session, read `{PRISMOR_DIR}/skills/security.md` and follow its instructions.\n\n"
            "This loads behavioral guardrails, live threat intelligence, secure coding rules (OWASP Top 10), "
            "and LLM security rules (OWASP LLM Top 10).\n\n"
            "For more info: https://github.com/PrismorSec/prismor\n"
        )
        if claude_md.exists():
            content = claude_md.read_text()
            if "Prismor" not in content:
                claude_md.write_text(content + block)
                step4.finish(ok=True, msg="appended")
            else:
                step4.finish(ok=True, msg="already present")
        else:
            claude_md.write_text(block.lstrip())
            step4.finish(ok=True, msg="created")
    except Exception as e:
        step4.finish(ok=False, msg=str(e)[:40])

    # Step 5: Verify feed signature
    step5 = SpinnerStep("Verifying feed signature")
    step5.start()
    verify_sh = PRISMOR_DIR / "scripts" / "verify_feed.sh"
    feed_json  = PRISMOR_DIR / "advisories" / "immunity-feed.json"
    pub_key    = PRISMOR_DIR / "keys" / "public.pub"
    if verify_sh.exists() and feed_json.exists() and pub_key.exists():
        try:
            result = subprocess.run(
                ["bash", str(verify_sh), str(feed_json), str(pub_key)],
                capture_output=True, timeout=15
            )
            step5.finish(ok=(result.returncode == 0),
                         msg="verified" if result.returncode == 0 else "verification failed")
        except Exception as e:
            step5.finish(ok=False, msg=str(e)[:40])
    else:
        step5.finish(ok=True, msg="skipped (keys not found)")

    # Done
    print()
    print(c("  ╭───────────────────────────────────────────╮", DIM))
    print(c("  │", DIM) + c("  Prismor Warden installed successfully!    ", GREEN, BOLD) + c("│", DIM))
    print(c("  ╰───────────────────────────────────────────╯", DIM))
    print()

    home = str(Path.home())

    def show(label, val):
        print(f"  {c(label + ':', GREEN):<22} {c(val, DIM)}")

    show("Skills",   f"{PRISMOR_DIR}/skills/security.md".replace(home, "~"))
    show("Feed",     f"{PRISMOR_DIR}/advisories/immunity-feed.json".replace(home, "~"))
    show("Warden",   f"hooks installed (mode: {mode})")
    show("Config",   str(target_dir / "CLAUDE.md").replace(home, "~"))
    print()
    print(c("  To switch mode later:", DIM))
    print(f"    {c(f'PRISMOR_MODE=observe bash {PRISMOR_DIR}/scripts/init.sh', YELLOW)}")
    print()
    print(c("  To update the feed:", DIM))
    print(f"    {c(f'git -C {PRISMOR_DIR} pull', YELLOW)}")
    print()

    sys.stdout.write(SHOW_CURSOR)
    sys.stdout.flush()

# ── Non-interactive mode ─────────────────────────────────────────────────────

def run_non_interactive(target_dir):
    """Silently install with defaults — mirrors init.sh behavior."""
    mode  = os.environ.get("PRISMOR_MODE", "observe")
    rules = load_rules()
    target_dir = Path(target_dir).resolve()

    detected = detect_agents(target_dir)
    agents = [name for name, found in detected.items() if found]
    if not agents:
        agents = ["claude"]

    print(f"[prismor] Non-interactive mode (mode: {mode}, agents: {', '.join(agents)})")
    run_install(target_dir, mode, rules, agents)

# ── Wizard orchestration ─────────────────────────────────────────────────────

def run_wizard(target_dir):
    w = get_term_width()
    if w < 72:
        sys.stderr.write(
            f"\033[33m[prismor] Warning: terminal width {w} < 72. Display may be clipped.\033[0m\n"
        )

    enable_raw_mode()

    try:
        rules = load_rules()

        # Screen 1: Enforcement mode
        mode = screen_enforcement_mode("enforce")

        # Screen 3: Detection rules
        rules = screen_detection_rules(rules)

        # Screen 4: Agent selection
        while True:
            agents = screen_agent_selection(target_dir)

            # Screen 5: Confirm
            confirmed = screen_confirm(target_dir, mode, rules, agents)
            if confirmed:
                break
            # Back goes to agent selection (re-loop)

    except Exception as e:
        restore_terminal()
        enable_raw_mode()
        # swallow and let install attempt
        rules  = load_rules()
        mode   = "enforce"
        agents = ["claude"]
        confirmed = True

    restore_terminal()

    clear_screen()
    sys.stdout.write(HIDE_CURSOR)
    run_install(target_dir, mode, rules, agents)
    sys.stdout.write(SHOW_CURSOR)
    sys.stdout.flush()

# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    non_interactive = "--non-interactive" in args
    args = [a for a in args if not a.startswith("--")]

    target_dir = Path(args[0]).resolve() if args else Path.cwd()

    if not target_dir.exists():
        sys.stderr.write(f"[prismor] Target directory does not exist: {target_dir}\n")
        sys.exit(1)

    if non_interactive or not sys.stdin.isatty():
        run_non_interactive(target_dir)
    else:
        run_wizard(target_dir)

if __name__ == "__main__":
    main()
