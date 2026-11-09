"""Instruction files of other AI coding agents, plus shared cross-agent standards.

Real-time enforcement is Claude-Code-only for this project, but these files are still
protected when *Claude Code* writes them: an injected instruction can make Claude poison
the files your teammates' other agents load (cross-agent propagation), and the repo
scanner (``memtegrity scan``) checks them for every agent.

Adding real-time support for one of these agents later = an adapter for its hook protocol;
its files are already listed here. Config files of these agents are not listed yet.
"""

from memtegrity.enums import SurfaceKind
from memtegrity.surfaces import SHARED, AgentProfile, Surface

INSTR = SurfaceKind.INSTRUCTIONS

SHARED_PROFILE = AgentProfile(
    agent=SHARED,
    surfaces=(Surface(SHARED, INSTR, "AGENTS.md (shared agent instructions)", "AGENTS.md"),),
)

PROFILES: tuple[AgentProfile, ...] = (
    AgentProfile(
        "copilot",
        (
            Surface("copilot", INSTR, "Copilot instructions", ".github/copilot-instructions.md"),
            Surface(
                "copilot",
                INSTR,
                "Copilot path instructions",
                ".github/instructions/**/*.instructions.md",
            ),
        ),
    ),
    AgentProfile(
        "cursor",
        (
            Surface("cursor", INSTR, "Cursor rules (legacy)", ".cursorrules"),
            Surface("cursor", INSTR, "Cursor rules", ".cursor/rules/**/*.mdc"),
            Surface("cursor", INSTR, "Cursor rules", ".cursor/rules/**/*.md"),
        ),
    ),
    AgentProfile(
        "windsurf",
        (
            Surface("windsurf", INSTR, "Windsurf rules (legacy)", ".windsurfrules"),
            Surface("windsurf", INSTR, "Windsurf rules", ".windsurf/rules/**/*.md"),
        ),
    ),
    AgentProfile("gemini-cli", (Surface("gemini-cli", INSTR, "GEMINI.md", "GEMINI.md"),)),
    AgentProfile(
        "cline",
        (
            Surface("cline", INSTR, "Cline rules", ".clinerules"),
            Surface("cline", INSTR, "Cline rules", ".clinerules/**/*.md"),
        ),
    ),
)
