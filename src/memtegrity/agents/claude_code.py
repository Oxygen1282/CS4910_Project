"""Claude Code: its protected files, its session-record format, and its settings schema.

Everything Claude-Code-specific lives here or in ``memtegrity.hooks`` (the hook protocol).
Sources: code.claude.com/docs/en/memory, /sub-agents, /settings, /hooks.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from memtegrity.enums import SurfaceKind
from memtegrity.surfaces import AgentProfile, Root, Surface

AGENT = "claude-code"

INSTR, MEM, CONF = SurfaceKind.INSTRUCTIONS, SurfaceKind.MEMORY, SurfaceKind.CONFIG

AUTO_MEMORY = Surface(AGENT, MEM, "Claude auto memory", ".claude/projects/*/memory/**")

SURFACES: tuple[Surface, ...] = (
    # Config first: these change what runs automatically or what Claude may do.
    Surface(AGENT, CONF, "Claude Code settings", ".claude/settings.json"),
    Surface(AGENT, CONF, "Claude Code local settings", ".claude/settings.local.json"),
    Surface(AGENT, CONF, "project MCP servers", ".mcp.json"),
    Surface(AGENT, CONF, "Claude Code user state (MCP servers, trust)", "~/.claude.json"),
    # Memory: notes Claude writes for itself and reloads every session.
    AUTO_MEMORY,
    Surface(AGENT, MEM, "subagent memory", ".claude/agent-memory/**"),
    Surface(AGENT, MEM, "subagent local memory", ".claude/agent-memory-local/**"),
    # Instructions: loaded as guidance (project, parent folders, subfolders, ~/.claude, managed).
    Surface(AGENT, INSTR, "CLAUDE.md", "CLAUDE.md"),
    Surface(AGENT, INSTR, "CLAUDE.local.md", "CLAUDE.local.md"),
    Surface(AGENT, INSTR, "Claude Code rules", ".claude/rules/**/*.md"),
    Surface(AGENT, INSTR, "Claude Code subagent definition", ".claude/agents/**/*.md"),
    Surface(AGENT, INSTR, "Claude Code command", ".claude/commands/**/*.md"),
    Surface(AGENT, INSTR, "Claude Code skill", ".claude/skills/**/*.md"),
    Surface(AGENT, INSTR, "Claude Code output style", ".claude/output-styles/**/*.md"),
    # Installed plugins' skills, agents and commands load into sessions too.
    Surface(AGENT, INSTR, "plugin skill", ".claude/plugins/**/skills/**/*.md"),
    Surface(AGENT, INSTR, "plugin subagent definition", ".claude/plugins/**/agents/**/*.md"),
    Surface(AGENT, INSTR, "plugin command", ".claude/plugins/**/commands/**/*.md"),
)

_SETTINGS_FILES = (".claude/settings.json", ".claude/settings.local.json")
_AUTO_MEMORY = Surface(AGENT, MEM, "Claude auto memory (custom directory)", "**")


def _config_dir() -> Path:
    env = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(os.path.expanduser(env)) if env else Path.home() / ".claude"


def _custom_memory_dirs(project_dir: Path | None) -> list[Path]:
    """``autoMemoryDirectory`` from any settings scope (project, local, user)."""
    candidates = [_config_dir() / "settings.json"]
    if project_dir is not None:
        candidates += [project_dir / rel for rel in _SETTINGS_FILES]
    found = []
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue  # unreadable settings can't widen what we trust; skip
        value = data.get("autoMemoryDirectory") if isinstance(data, dict) else None
        if isinstance(value, str) and value.strip():
            p = Path(os.path.expanduser(value))
            found.append(p if p.is_absolute() else (project_dir or Path.cwd()) / p)
    return found


def roots(project_dir: Path | None) -> list[Root]:
    """Protected folders known only at runtime."""
    out = [Root(d, _AUTO_MEMORY) for d in _custom_memory_dirs(project_dir)]
    config_dir = _config_dir()
    if config_dir != Path.home() / ".claude":  # CLAUDE_CONFIG_DIR moves auto memory too
        out.append(Root(config_dir / "projects", AUTO_MEMORY, tail="*/memory/**"))
    return out


PROFILE = AgentProfile(
    agent=AGENT,
    surfaces=SURFACES,
    roots=roots,
    pinned=(
        "CLAUDE.md",
        ".claude/CLAUDE.md",
        "CLAUDE.local.md",
        "AGENTS.md",
        ".claude/settings.json",
        "~/.claude/CLAUDE.md",
        "~/.claude/settings.json",
    ),
)


# =========================================================================== session record
# Claude Code transcript (JSONL): human messages are ``type: "user"`` entries with text
# content; tool output is a ``tool_result`` block in a ``user`` entry, linked by
# ``tool_use_id`` to the ``tool_use`` block in the preceding ``assistant`` entry.
# ``isSidechain`` entries are subagent traffic (written by the agent, not the human).

_TRANSCRIPT_TAIL_BYTES = 2_000_000
_REMOTE_TOOLS = frozenset({"WebFetch", "WebSearch"})
_REMOTE_CMD_RX = re.compile(
    r"\b(?:curl|wget|gh|http|https|aws|gcloud|az|ssh|scp|rsync)\b|\bgit\s+(?:clone|pull|fetch)\b"
)
_WRAPPED_RX = re.compile(
    r"<(pasted_content|system-reminder)[^>]*>(.*?)</\1[^>]*>", re.DOTALL | re.IGNORECASE
)


def _read_tail(path: Path) -> list[str]:
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - _TRANSCRIPT_TAIL_BYTES))
        data = fh.read()
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[1:] if size > _TRANSCRIPT_TAIL_BYTES else lines  # drop partial first line


def _result_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
        )
    return ""


def evidence_from_transcript(transcript_path: str | None, project_dir: Path | None):
    """Turn a Claude Code transcript into agent-neutral ``provenance.Evidence``.

    Returns ``None`` if there is no readable transcript (provenance is then skipped, never
    guessed). Pasted blocks and system reminders inside user messages count as content the
    agent read, not as the user's own words. Tool output from reading protected files is
    left out, so a file isn't "external evidence" for edits to itself.
    """
    from memtegrity.paths import classify
    from memtegrity.provenance import Evidence, Trust

    if not transcript_path:
        return None
    try:
        lines = _read_tail(Path(transcript_path))
    except OSError:
        return None

    tools: dict[str, tuple[str, dict]] = {}
    ev = Evidence()
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        kind, message = entry.get("type"), entry.get("message")
        content = message.get("content") if isinstance(message, dict) else None

        if kind == "assistant" and isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                    tools[str(b.get("id"))] = (str(b.get("name", "")), inp)

        elif kind == "user":
            blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
            for b in blocks if isinstance(blocks, list) else []:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "text":
                    text = str(b.get("text", ""))
                    for _tag, inner in _WRAPPED_RX.findall(text):
                        ev.external.append((Trust.LOCAL, inner))
                    own = _WRAPPED_RX.sub(" ", text)
                    if entry.get("isSidechain") or entry.get("isMeta"):
                        ev.external.append((Trust.LOCAL, own))
                    elif own.strip():
                        ev.user_texts.append(own)
                elif b.get("type") == "tool_result":
                    name, inp = tools.get(str(b.get("tool_use_id")), ("", {}))
                    if name in ("Write", "Edit"):
                        continue
                    target = inp.get("file_path")
                    if name == "Read" and isinstance(target, str) and classify(target, project_dir):
                        continue
                    remote = (
                        name in _REMOTE_TOOLS
                        or name.startswith("mcp__")
                        or (name == "Bash" and _REMOTE_CMD_RX.search(str(inp.get("command", ""))))
                    )
                    trust = Trust.REMOTE if remote else Trust.LOCAL
                    ev.external.append((trust, _result_text(b.get("content"))))

        elif kind == "attachment" and isinstance(entry.get("rendered"), str):
            ev.external.append((Trust.LOCAL, entry["rendered"]))

    return ev


# =========================================================================== settings schema
# Structural checks on Claude Code settings / MCP config. Text rules can't see that
# ``{"hooks": ...}`` means "run this command automatically"; these can. Motivated by
# CVE-2025-59536 (repo settings hooks → code execution) and CVE-2026-21852 (repo settings
# redirecting API traffic → API key exfiltration).

_API_REDIRECT_ENV = frozenset(
    {
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_URL",
        "ANTHROPIC_BEDROCK_BASE_URL",
        "ANTHROPIC_VERTEX_BASE_URL",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NODE_EXTRA_CA_CERTS",
    }
)
_PROGRAM_SETTINGS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")


def _collect(obj: object, key: str) -> dict:
    """Merge every ``key`` dict found anywhere in ``obj`` (``~/.claude.json`` nests
    ``mcpServers`` per project)."""
    out: dict = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, dict):
                out.update(v)
            else:
                out.update(_collect(v, key))
    elif isinstance(obj, list):
        for v in obj:
            out.update(_collect(v, key))
    return out


def _strings(obj: object) -> set[str]:
    if isinstance(obj, str):
        return {obj}
    if isinstance(obj, dict):
        return set().union(*(_strings(v) for v in obj.values())) if obj else set()
    if isinstance(obj, list):
        return set().union(*(_strings(v) for v in obj)) if obj else set()
    return set()


def _hook_commands(settings: dict) -> set[str]:
    hooks = settings.get("hooks")
    return {s for s in _strings(hooks)} if isinstance(hooks, dict) else set()


def assess_config(before: str, after: str) -> list:
    """Findings (``RuleHit``s, no line numbers) for a change to Claude Code settings or MCP
    config. Also runs the text rules over every newly added string value."""
    from memtegrity.models import RiskCategory as Cat
    from memtegrity.models import RuleHit
    from memtegrity.rules import run_rules, snippet

    hits: list[RuleHit] = []

    def add(rule_id: str, desc: str, severity: int, cat: Cat, evidence: str) -> None:
        hits.append(
            RuleHit(
                rule_id=rule_id,
                description=desc,
                severity=severity,
                category=cat,
                matched_text=snippet(evidence),
            )
        )

    try:
        old = json.loads(before) if before.strip() else {}
    except ValueError:
        old = {}
    try:
        new = json.loads(after) if after.strip() else {}
    except ValueError:
        add("config.unparseable", "settings would not be valid JSON", 45, Cat.OTHER, after[:60])
        return hits
    if not isinstance(old, dict):
        old = {}
    if not isinstance(new, dict):
        add("config.unparseable", "settings would not be a JSON object", 45, Cat.OTHER, "")
        return hits

    # Attacks on the guard itself.
    if new.get("disableAllHooks") is True and old.get("disableAllHooks") is not True:
        add(
            "config.tamper.disable_hooks",
            "turns off all hooks, including Memtegrity",
            90,
            Cat.TAMPERING,
            "disableAllHooks: true",
        )
    old_plugins, new_plugins = old.get("enabledPlugins") or {}, new.get("enabledPlugins") or {}
    if isinstance(old_plugins, dict) and isinstance(new_plugins, dict):
        for plugin_id, enabled in old_plugins.items():
            if (
                str(plugin_id).split("@")[0] == "memtegrity"
                and enabled
                and not new_plugins.get(plugin_id)
            ):
                add(
                    "config.tamper.disable_plugin",
                    "disables the Memtegrity plugin",
                    90,
                    Cat.TAMPERING,
                    str(plugin_id),
                )

    # Things that run programs automatically.
    for cmd in sorted(_hook_commands(new) - _hook_commands(old)):
        add(
            "config.new_hook",
            "adds a hook (a command that runs automatically)",
            60,
            Cat.CODE_EXECUTION,
            cmd,
        )
    for key_name in _PROGRAM_SETTINGS:
        if new.get(key_name) and new.get(key_name) != old.get(key_name):
            add(
                "config.credential_helper",
                f"sets {key_name} (runs a program for credentials)",
                60,
                Cat.CODE_EXECUTION,
                str(new.get(key_name)),
            )
    if new.get("statusLine") and new.get("statusLine") != old.get("statusLine"):
        add(
            "config.status_line",
            "sets a status-line command (runs a program)",
            35,
            Cat.CODE_EXECUTION,
            json.dumps(new.get("statusLine"))[:60],
        )
    new_servers = set(_collect(new, "mcpServers")) - set(_collect(old, "mcpServers"))
    if new_servers:
        add(
            "config.new_mcp_server",
            "adds an MCP server (a program that gives the agent tools)",
            50,
            Cat.CODE_EXECUTION,
            ", ".join(sorted(new_servers)),
        )
    if new.get("enableAllProjectMcpServers") is True and not old.get("enableAllProjectMcpServers"):
        add(
            "config.auto_approve_mcp",
            "auto-approves every MCP server the project defines",
            60,
            Cat.SECURITY_WEAKENING,
            "enableAllProjectMcpServers: true",
        )

    # Permissions.
    p_old = old.get("permissions") if isinstance(old.get("permissions"), dict) else {}
    p_new = new.get("permissions") if isinstance(new.get("permissions"), dict) else {}
    if p_new.get("defaultMode") == "bypassPermissions" != p_old.get("defaultMode"):
        add(
            "config.bypass_permissions",
            "turns off permission prompts (bypassPermissions)",
            75,
            Cat.SECURITY_WEAKENING,
            "defaultMode: bypassPermissions",
        )
    added_allow = set(map(str, p_new.get("allow") or [])) - set(map(str, p_old.get("allow") or []))
    broad = {a for a in added_allow if a.strip() in {"*", "Bash", "Bash(*)", "Bash(:*)"}}
    if broad:
        add(
            "config.broad_allow",
            "allows every shell command without asking",
            60,
            Cat.SECURITY_WEAKENING,
            ", ".join(sorted(broad)),
        )
    elif added_allow:
        add(
            "config.allow_rule",
            "adds a permission allow rule",
            25,
            Cat.SECURITY_WEAKENING,
            ", ".join(sorted(added_allow)),
        )
    removed_deny = set(map(str, p_old.get("deny") or [])) - set(map(str, p_new.get("deny") or []))
    if removed_deny:
        add(
            "config.removed_deny",
            "removes a permission deny rule",
            45,
            Cat.SECURITY_WEAKENING,
            ", ".join(sorted(removed_deny)),
        )
    if new.get("skipDangerousModePermissionPrompt") and not old.get(
        "skipDangerousModePermissionPrompt"
    ):
        add(
            "config.skip_danger_prompt",
            "skips the dangerous-mode warning",
            60,
            Cat.SECURITY_WEAKENING,
            "skipDangerousModePermissionPrompt",
        )

    # Environment and memory location.
    e_old = old.get("env") if isinstance(old.get("env"), dict) else {}
    e_new = new.get("env") if isinstance(new.get("env"), dict) else {}
    for name, value in e_new.items():
        if e_old.get(name) == value:
            continue
        if name.upper() in _API_REDIRECT_ENV:
            add(
                "config.redirect_api",
                "redirects API/network traffic (can leak your API key)",
                75,
                Cat.EXFILTRATION,
                f"{name}={value}",
            )
        else:
            add(
                "config.env",
                "sets an environment variable for every session",
                20,
                Cat.OTHER,
                f"{name}={value}",
            )
    if new.get("autoMemoryDirectory") and new.get("autoMemoryDirectory") != old.get(
        "autoMemoryDirectory"
    ):
        add(
            "config.memory_redirect",
            "moves where Claude's memory is stored and loaded from",
            50,
            Cat.TAMPERING,
            str(new.get("autoMemoryDirectory")),
        )

    # Text rules over new string values (curl | bash in a hook, hidden text, new hosts...).
    new_strings = sorted(_strings(new) - _strings(old))
    hits += run_rules([(None, s) for s in new_strings], before=before)
    return hits
