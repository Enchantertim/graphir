"""Structured investigation logging — makes the agent's reasoning visible.

Every tool call, reasoning step, verification, self-correction, and finding
is logged as structured JSON. Judges can replay the investigation from the log.

Log entry types:
  tool_call       — MCP tool was invoked
  reasoning       — agent decided what to do next and why
  finding         — a finding was produced
  verification    — dual-path verification was executed
  correction      — a finding was flagged as FP/hallucination/retracted
  self_correction — agent caught its own error and corrected
  ingestion       — data was ingested into the graph

Each entry includes:
  timestamp, entry_type, detail, duration_ms, data (type-specific payload)
"""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


class InvestigationLog:
    """Structured, append-only investigation log."""

    def __init__(self, investigation_id: str | None = None,
                 log_dir: str = "logs"):
        self.investigation_id = investigation_id or str(uuid.uuid4())[:12]
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / f"investigation-{self.investigation_id}.jsonl"
        self._start_time = time.time()

        # Reload entries from disk if log file exists (survives MCP server restarts)
        self.entries: list[dict] = []
        if self.log_path.exists():
            try:
                with open(self.log_path) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            self.entries.append(json.loads(line))
            except (json.JSONDecodeError, IOError):
                pass  # Start fresh if file is corrupted

    def _make_entry(self, entry_type: str, detail: str,
                    duration_ms: int = 0, **data) -> dict:
        entry = {
            "investigation_id": self.investigation_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_s": round(time.time() - self._start_time, 2),
            "entry_type": entry_type,
            "detail": detail,
            "duration_ms": duration_ms,
            "data": data,
        }
        self.entries.append(entry)
        self._write_entry(entry)
        return entry

    def _write_entry(self, entry: dict):
        """Append entry to JSONL file."""
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    # --- Logging methods ---

    def log_tool_call(self, tool: str, params: dict, result_summary: str,
                      duration_ms: int = 0) -> dict:
        """Log an MCP tool invocation."""
        return self._make_entry(
            "tool_call",
            f"Called {tool}",
            duration_ms=duration_ms,
            tool=tool,
            params=params,
            result_summary=result_summary[:500],
        )

    def log_reasoning(self, thought: str, next_step: str,
                      evidence: str = "") -> dict:
        """Log an agent reasoning step — what it decided and why."""
        return self._make_entry(
            "reasoning",
            thought,
            next_step=next_step,
            evidence=evidence,
        )

    def log_finding(self, description: str, confidence: str,
                    tactic: str = "", technique: str = "",
                    supporting_entities: list[str] | None = None,
                    claim_summary: dict | None = None) -> dict:
        """Log a finding with its confidence level."""
        return self._make_entry(
            "finding",
            description,
            confidence=confidence,
            tactic=tactic,
            technique=technique,
            supporting_entities=supporting_entities or [],
            claim_summary=claim_summary or {},
        )

    def log_verification(self, claim: str, confidence: str,
                         predicates_passed: list[str],
                         predicates_failed: list[str],
                         divergences: list[dict] | None = None) -> dict:
        """Log a verification result — which predicates passed/failed."""
        return self._make_entry(
            "verification",
            f"{claim} → {confidence}",
            confidence=confidence,
            predicates_passed=predicates_passed,
            predicates_failed=predicates_failed,
            divergences=divergences or [],
        )

    def log_correction(self, correction_type: str, reason: str,
                       original_claim: str, entity: str,
                       corrected_by: str = "agent",
                       original_confidence: str = "",
                       new_confidence: str = "") -> dict:
        """Log a correction (FP, hallucination, retraction, downgrade)."""
        return self._make_entry(
            "correction",
            f"{correction_type}: {original_claim}",
            correction_type=correction_type,
            reason=reason,
            entity=entity,
            corrected_by=corrected_by,
            original_confidence=original_confidence,
            new_confidence=new_confidence,
        )

    def log_self_correction(self, original_claim: str, corrected_claim: str,
                            reason: str, method: str) -> dict:
        """Log a self-correction — agent caught its own error."""
        return self._make_entry(
            "self_correction",
            f"Corrected: {original_claim} → {corrected_claim}",
            original_claim=original_claim,
            corrected_claim=corrected_claim,
            reason=reason,
            correction_method=method,
        )

    def log_ingestion(self, source: str, events_processed: int,
                      duration_s: float, errors: int = 0) -> dict:
        """Log a data ingestion event."""
        return self._make_entry(
            "ingestion",
            f"Ingested {events_processed} events from {source}",
            duration_ms=int(duration_s * 1000),
            source=source,
            events_processed=events_processed,
            errors=errors,
        )

    # --- Summary ---

    def get_summary(self) -> dict:
        """Get investigation log summary — useful for judges and reports."""
        from collections import Counter
        type_counts = Counter(e["entry_type"] for e in self.entries)

        corrections = [e for e in self.entries if e["entry_type"] == "correction"]
        self_corrections = [e for e in self.entries if e["entry_type"] == "self_correction"]
        findings = [e for e in self.entries if e["entry_type"] == "finding"]
        verifications = [e for e in self.entries if e["entry_type"] == "verification"]

        confidence_counts = Counter(
            e["data"].get("confidence", "") for e in findings
        )

        return {
            "investigation_id": self.investigation_id,
            "log_path": str(self.log_path),
            "total_entries": len(self.entries),
            "elapsed_s": round(time.time() - self._start_time, 2),
            "by_type": dict(type_counts),
            "findings": {
                "total": len(findings),
                "by_confidence": dict(confidence_counts),
            },
            "verifications": len(verifications),
            "corrections": len(corrections),
            "self_corrections": len(self_corrections),
        }

    def to_json(self) -> str:
        """Export full log as JSON array."""
        return json.dumps(self.entries, indent=2, default=str)
