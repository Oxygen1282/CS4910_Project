"""The AI judge: a provider-neutral interface plus what every implementation shares.

Agent-neutral core. The engine only knows ``Judge``: "here is a change to a protected file,
what do you make of it?" → ``JudgeResult`` (or ``None`` = no opinion). The Claude
implementation lives in ``llm_risk.py``; another model or provider plugs in by providing the
same callable. Nothing here imports ``anthropic`` or Pydantic, so the hooks' fast path stays
fast.

Shared by every implementation:

* **Switch:** ``$MEMTEGRITY_JUDGE=off`` disables the judge (rules only).
* **Cache:** one answer per (model, request) in ``<data>/judge-cache/``, so the same change
  judged by PreToolUse, then FileChanged, then the next session doesn't pay twice.
* **Cost cap:** at most ``judge_max_calls_per_session`` paid calls per session.

The judge is an extra signal, never a dependency: no key, a timeout, a refusal or an API error
all mean "no opinion", and the verdict comes from the rules (``scoring.combine``).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from memtegrity import paths
from memtegrity.config import DEFAULT_SETTINGS, Settings

if TYPE_CHECKING:
    from memtegrity.models import LLMRisk, RuleHit
    from memtegrity.surfaces import Surface

JUDGE_ENV = "MEMTEGRITY_JUDGE"
"""``off`` (or ``0``, ``false``, ``no``) disables the judge."""


@dataclass
class JudgeResult:
    """What one judge call produced."""

    risk: LLMRisk | None = None
    """The judge's score, or ``None`` if it gave none (refusal, error, cap reached)."""
    refused: bool = False
    """The model declined to judge (``stop_reason == "refusal"``)."""
    error: str | None = None
    """Why there is no ``risk``, for diagnostics (never shown to the agent)."""
    cached: bool = False
    """Answered from the cache: no API call, no cost."""
    model: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Judge(Protocol):
    """Anything that can judge a change. Implementations must never raise and must never
    return a lower-risk answer because the change *asked* for one: the blend in
    ``scoring.combine`` limits how far a judge can lower a rule verdict anyway."""

    def __call__(
        self, *, diff: str, path: str, surface: Surface, rule_hits: list[RuleHit]
    ) -> JudgeResult | None: ...


def enabled() -> bool:
    """False if the user switched the judge off with ``$MEMTEGRITY_JUDGE``."""
    value = os.environ.get(JUDGE_ENV, "").strip().lower()
    return value not in {"off", "0", "false", "no", "disabled"}


# --------------------------------------------------------------------------- cache


def cache_key(model: str, request: dict[str, Any]) -> str:
    """Stable hash of what decides the answer: the model and the exact request content."""
    blob = json.dumps({"model": model, "request": request}, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _cache_file(key: str) -> Path:
    return paths.data_dir() / "judge-cache" / f"{key}.json"


def cache_get(key: str) -> dict[str, Any] | None:
    """The cached answer (``{"risk": {...} | None, "refused": bool}``), or ``None``."""
    try:
        data = json.loads(_cache_file(key).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def cache_put(key: str, value: dict[str, Any]) -> None:
    """Remember an answer. Errors and timeouts are never cached (they may pass); answers and
    refusals are (asking again would cost the same and give the same)."""
    target = _cache_file(key)
    with contextlib.suppress(OSError):
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f"{target.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(value), encoding="utf-8")
        tmp.replace(target)  # atomic: a concurrent reader never sees half a file


# --------------------------------------------------------------------------- cost cap


def _budget_file(session_id: str | None) -> Path:
    from memtegrity.markers import _safe

    return paths.data_dir() / "judge-calls" / f"{_safe(session_id)}.count"


def calls_made(session_id: str | None) -> int:
    try:
        return _budget_file(session_id).stat().st_size
    except OSError:
        return 0


def take_call(session_id: str | None, settings: Settings = DEFAULT_SETTINGS) -> bool:
    """Reserve one paid call for this session. False once the cap is reached.

    One byte is appended per call and the count is the file size: appends are atomic enough
    across the parallel hook processes, with no locking."""
    if calls_made(session_id) >= settings.judge_max_calls_per_session:
        return False
    path = _budget_file(session_id)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("ab") as fh:
            fh.write(b".")
    except OSError:
        return False  # can't count, so don't spend
    return True


# --------------------------------------------------------------------------- default judge


def default_judge(session_id: str | None = None, settings: Settings = DEFAULT_SETTINGS):
    """The judge the hooks use: Claude, if switched on and a key is configured; else ``None``
    (rules only). Cheap: imports nothing heavy until the judge is actually called."""
    if not enabled():
        return None
    from memtegrity import llm_risk

    key = llm_risk.load_api_key()
    if key is None:
        return None
    return llm_risk.ClaudeJudge(api_key=key, session_id=session_id, settings=settings)


def status() -> str:
    """One line for the user: is the judge on, and if not, why."""
    if not enabled():
        return f"off (${JUDGE_ENV}=off)"
    from memtegrity import llm_risk

    if llm_risk.load_api_key() is None:
        return (
            "off (no API key: add ANTHROPIC_API_KEY to "
            + " or ".join(p.as_posix() for p in llm_risk.env_files())
            + ")"
        )
    return f"on ({DEFAULT_SETTINGS.scoring_model})"
