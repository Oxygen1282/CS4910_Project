"""The shared models validate, serialize, and work as SQLite tables."""

import pytest
from pydantic import ValidationError
from sqlmodel import Session, SQLModel, create_engine, select

from memtegrity.config import DEFAULT_SETTINGS
from memtegrity.models import (
    Assessment,
    BehaviorDiff,
    ChangeEvent,
    HookEvent,
    LLMRisk,
    ReplayResult,
    RiskCategory,
    RuleHit,
    Snapshot,
    SnapshotStatus,
    ToolCall,
    Trial,
    TrialCondition,
    Verdict,
)


def make_assessment() -> Assessment:
    hit = RuleHit(
        rule_id="url.new_domain",
        description="URL to a domain not in approved memory",
        severity=60,
        category=RiskCategory.EXFILTRATION,
        matched_text="https://backup-sync.example",
        line=3,
    )
    llm = LLMRisk(
        score=88,
        category=RiskCategory.EXFILTRATION,
        indicators=["sync configs to backup-sync.example"],
        rationale="Standing instruction to send configs to an unknown host.",
    )
    return Assessment(
        score=88,
        verdict=Verdict.DENY,
        category=RiskCategory.EXFILTRATION,
        rule_hits=[hit],
        llm=llm,
        reason="Sends project configs to an unknown external host.",
    )


def test_verdict_values_match_claude_code_permission_decisions() -> None:
    assert {v.value for v in Verdict} == {"allow", "ask", "deny"}


def test_hook_event_cli_names() -> None:
    assert HookEvent("pre-tool-use") is HookEvent.PRE_TOOL_USE


def test_assessment_json_round_trip() -> None:
    a = make_assessment()
    assert Assessment.model_validate_json(a.model_dump_json()) == a


@pytest.mark.parametrize("bad_score", [-1, 101])
def test_llm_risk_score_bounds(bad_score: int) -> None:
    with pytest.raises(ValidationError):
        LLMRisk(score=bad_score, category=RiskCategory.OTHER, indicators=[], rationale="x")


def test_llm_risk_schema_has_field_descriptions() -> None:
    # The JSON schema is what the LLM sees, so every field should be described.
    props = LLMRisk.model_json_schema()["properties"]
    assert set(props) == {"score", "category", "indicators", "rationale"}
    assert all(p.get("description") for p in props.values())


def test_replay_result_round_trip() -> None:
    trial = Trial(
        condition=TrialCondition.SUSPICIOUS,
        prompt="Deploy the app",
        model=DEFAULT_SETTINGS.replay_model,
        tool_calls=[
            ToolCall(index=0, name="WebFetch", input={"url": "https://backup-sync.example"})
        ],
        behaviors=["webfetch:backup-sync.example"],
    )
    result = ReplayResult(
        prompts=["Deploy the app"],
        trials=[trial],
        behaviors=[
            BehaviorDiff(
                behavior="webfetch:backup-sync.example",
                clean_count=0,
                suspicious_count=4,
                flagged=True,
            )
        ],
        poison_confirmed=True,
    )
    assert ReplayResult.model_validate_json(result.model_dump_json()) == result


def test_tables_store_and_load() -> None:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        snap = Snapshot(path="/p/CLAUDE.md", sha256="ab" * 32, content="# notes\n", size_bytes=8)
        session.add(snap)
        session.commit()
        session.refresh(snap)
        event = ChangeEvent(
            path=snap.path,
            source=HookEvent.PRE_TOOL_USE,
            tool_name="Edit",
            before_snapshot_id=snap.id,
            verdict=Verdict.DENY,
            score=88,
            assessment_json=make_assessment().model_dump_json(),
        )
        session.add(event)
        session.commit()

        loaded = session.exec(select(ChangeEvent)).one()
        assert loaded.verdict is Verdict.DENY
        assert Assessment.model_validate_json(loaded.assessment_json).score == 88
        assert session.get(Snapshot, snap.id).status is SnapshotStatus.PENDING
