"""Provenance and result chain tracking for graphir.

Implements three Parallel Sysplex-inspired principles:
1. Data Origin Recording & Propagation — every graph entity carries its source
2. Result Chain Provability — every finding traces back to raw artifacts
3. Dual-Path Verification — LLM inference vs graph structural validation

Verification is done at the ATOMIC CLAIM level, not narrative level.
Each claim has mechanical confidence transitions.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    INFERENCE = "INFERENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class DivergenceReason(str, Enum):
    """Why dual paths diverged — captures the specific failure mode."""
    ABSENT_DATA = "absent_data"             # Required evidence not in graph
    CONTRADICTORY = "contradictory"         # Evidence exists but contradicts claim
    TEMPORAL_IMPLAUSIBLE = "temporal_implausible"  # Timestamps don't support sequence
    SCOPE_TOO_BROAD = "scope_too_broad"     # Query returned noise, not signal
    RESOLUTION_FAILURE = "resolution_failure"  # Entity couldn't be resolved in graph
    CHAIN_BROKEN = "chain_broken"           # Provenance chain is broken
    QUERY_ERROR = "query_error"             # Cypher query failed (syntax/runtime error)


class CorrectionStrategy(str, Enum):
    """Bounded set of re-examination strategies (Critique #5)."""
    BROADEN_TIME_WINDOW = "broaden_time_window"
    ALTERNATE_TOOL = "alternate_tool"           # Same artifact, different parser/tool
    COMPLEMENTARY_ARTIFACT = "complementary_artifact"  # Different artifact type
    TIGHTEN_ENTITY_SCOPE = "tighten_entity_scope"
    VERIFY_RESOLUTION = "verify_resolution"     # Re-check host/user identity
    ESCALATE = "escalate"                       # Stop and flag for human


# ---------------------------------------------------------------------------
# 1. Data Origin Recording
# ---------------------------------------------------------------------------

@dataclass
class Origin:
    """Provenance metadata attached to every graph entity."""
    tool: str
    params: dict
    artifact: str
    timestamp: str
    parser: str = ""
    data_type: str = ""
    source_line: int = 0
    artifact_hash: str = ""

    def to_props(self) -> dict:
        return {
            "_origin_tool": self.tool,
            "_origin_params": json.dumps(self.params, default=str),
            "_origin_artifact": self.artifact,
            "_origin_timestamp": self.timestamp,
            "_origin_parser": self.parser,
            "_origin_data_type": self.data_type,
            "_origin_source_line": self.source_line,
        }


def make_origin(event: dict, source_file: str, line_num: int = 0) -> Origin:
    """Create an Origin from a Plaso event and source file path."""
    ts = event.get("timestamp", 0)
    if isinstance(ts, (int, float)) and ts > 0:
        try:
            dt = datetime.fromtimestamp(ts / 1_000_000, tz=timezone.utc)
            ts_str = dt.isoformat().replace("+00:00", "Z")
        except (ValueError, OSError):
            ts_str = str(ts)
    else:
        ts_str = str(ts)

    artifact = source_file
    pathspec = event.get("pathspec", {})
    if isinstance(pathspec, dict):
        artifact = pathspec.get("location", source_file)

    return Origin(
        tool="ingest_timeline",
        params={"source_file": source_file},
        artifact=artifact,
        timestamp=ts_str,
        parser=event.get("parser", ""),
        data_type=event.get("data_type", ""),
        source_line=line_num,
        artifact_hash=event.get("sha256_hash", ""),
    )


# ---------------------------------------------------------------------------
# 2. Result Chain Provability
# ---------------------------------------------------------------------------

@dataclass
class ChainLink:
    """One link in a result chain."""
    step: str
    detail: str
    timestamp: str
    duration_ms: int = 0
    data: dict = field(default_factory=dict)


@dataclass
class ResultChain:
    """Complete provenance chain for a finding."""
    chain_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    links: list[ChainLink] = field(default_factory=list)
    is_provable: bool = True
    broken_at: str | None = None

    def add_link(self, step: str, detail: str, **data) -> "ResultChain":
        self.links.append(ChainLink(
            step=step, detail=detail,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data,
        ))
        return self

    def add_tool_call(self, tool: str, params: dict, result_summary: str,
                      duration_ms: int = 0) -> "ResultChain":
        self.links.append(ChainLink(
            step="mcp_tool_call", detail=f"Called {tool}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_ms=duration_ms,
            data={"tool": tool, "params": params, "result_summary": result_summary},
        ))
        return self

    def add_graph_query(self, cypher: str, result_count: int,
                        entities: list[str] | None = None) -> "ResultChain":
        self.links.append(ChainLink(
            step="graph_query",
            detail=f"Cypher query returned {result_count} results",
            timestamp=datetime.now(timezone.utc).isoformat(),
            data={"cypher": cypher, "result_count": result_count,
                  "entities_referenced": entities or []},
        ))
        return self

    def mark_broken(self, at_step: str, reason: str):
        self.is_provable = False
        self.broken_at = at_step
        self.add_link("chain_break", f"Chain broken at {at_step}: {reason}")

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "is_provable": self.is_provable,
            "broken_at": self.broken_at,
            "links": [asdict(link) for link in self.links],
        }


# ---------------------------------------------------------------------------
# 3. Atomic Claims and Dual-Path Verification
# ---------------------------------------------------------------------------

@dataclass
class Predicate:
    """A single structural predicate to check against the graph.

    Each predicate is a specific, falsifiable condition — NOT a restatement
    of the inference. Predicates check prerequisites the LLM didn't explicitly
    reason about (Critique #1: independence from inference path).

    If expect_field is set, the query MUST return data AND the named field
    must be True for at least one row. If data is returned but expect_field
    is False for all rows, the predicate is CONTRADICTORY (not ABSENT).
    This distinguishes "I can't find it" from "I found it, and you're wrong."
    """
    name: str                          # e.g., "auth_edge_exists"
    description: str                   # Human-readable
    cypher: str                        # Verification query
    params: dict = field(default_factory=dict)
    required: bool = True              # Must pass for CONFIRMED
    expect_field: str = ""             # If set, check this boolean field in results
    result: list | None = None         # Populated after execution
    passed: bool | None = None         # Populated after evaluation
    failure_reason: DivergenceReason | None = None
    failure_detail: str = ""


@dataclass
class AtomicClaim:
    """A single, independently verifiable claim (Critique #2).

    NOT a narrative. A claim like "PsExec lateral movement after cred dump"
    decomposes into multiple AtomicClaims, each verified independently.
    The narrative is composed from claim states.
    """
    claim_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    statement: str = ""                 # What is being claimed
    tactic: str = ""
    technique: str = ""
    confidence: Confidence = Confidence.INSUFFICIENT_EVIDENCE
    chain: ResultChain = field(default_factory=ResultChain)

    # Dual-path state
    inference_basis: str = ""           # Why the LLM believes this
    predicates: list[Predicate] = field(default_factory=list)

    # Divergence tracking (Critique #4: rich metadata)
    divergence_count: int = 0
    divergences: list[dict] = field(default_factory=list)
    correction_applied: CorrectionStrategy | None = None
    correction_detail: str = ""

    def add_predicate(self, name: str, description: str, cypher: str,
                      required: bool = True, **params) -> "AtomicClaim":
        """Add a structural predicate to verify."""
        self.predicates.append(Predicate(
            name=name, description=description,
            cypher=cypher, params=params, required=required,
        ))
        return self

    def evaluate(self) -> Confidence:
        """Mechanical confidence transition (Critique #3).

        CONFIRMED requires ALL of:
          - Source chain intact (all predicates have provenance)
          - ALL required predicates pass
          - No material contradiction

        INFERENCE requires:
          - Reasoning plausible (inference_basis is non-empty)
          - At least one predicate partially supports
          - Structural validation incomplete OR source re-check ambiguous

        INSUFFICIENT_EVIDENCE if:
          - Source chain broken
          - Required predicates absent
          - Re-examination failed
        """
        if not self.predicates:
            self.confidence = Confidence.INSUFFICIENT_EVIDENCE
            return self.confidence

        required_preds = [p for p in self.predicates if p.required]
        optional_preds = [p for p in self.predicates if not p.required]

        # Check for chain breaks
        broken = [p for p in self.predicates
                  if p.failure_reason == DivergenceReason.CHAIN_BROKEN]
        if broken:
            self.confidence = Confidence.INSUFFICIENT_EVIDENCE
            self._record_divergence(broken[0], "Provenance chain broken")
            return self.confidence

        # Check required predicates
        required_passed = [p for p in required_preds if p.passed is True]
        required_failed = [p for p in required_preds if p.passed is False]
        required_unknown = [p for p in required_preds if p.passed is None]

        # Check for contradictions
        contradictions = [p for p in self.predicates
                         if p.failure_reason == DivergenceReason.CONTRADICTORY]
        if contradictions:
            self.confidence = Confidence.INSUFFICIENT_EVIDENCE
            self._record_divergence(
                contradictions[0], "Material contradiction found")
            return self.confidence

        # Mechanical transitions
        if (len(required_passed) == len(required_preds)
                and len(required_preds) > 0):
            # All required predicates pass, no contradictions
            self.confidence = Confidence.CONFIRMED
        elif required_failed:
            # Required predicate(s) failed
            for p in required_failed:
                self._record_divergence(p, f"Required predicate failed: {p.name}")

            if len(required_failed) == len(required_preds):
                # ALL required predicates failed — no structural support at all
                self.confidence = Confidence.INSUFFICIENT_EVIDENCE
            elif self.divergence_count >= 2:
                # Second+ divergence — downgrade
                self.confidence = Confidence.INSUFFICIENT_EVIDENCE
            else:
                # Some required passed, some failed — partial support
                self.confidence = Confidence.INFERENCE
        elif self.inference_basis and any(p.passed for p in self.predicates):
            # Plausible inference with partial support
            self.confidence = Confidence.INFERENCE
        else:
            self.confidence = Confidence.INSUFFICIENT_EVIDENCE

        return self.confidence

    def _record_divergence(self, predicate: Predicate, detail: str):
        """Record a divergence with full metadata (Critique #4)."""
        self.divergence_count += 1
        self.divergences.append({
            "divergence_number": self.divergence_count,
            "predicate": predicate.name,
            "reason": predicate.failure_reason.value if predicate.failure_reason else "unknown",
            "detail": detail,
            "failure_detail": predicate.failure_detail,
            "cypher": predicate.cypher,
            "params": predicate.params,
            "suggested_correction": self._suggest_correction(predicate),
        })

    def _suggest_correction(self, predicate: Predicate) -> str:
        """Suggest a bounded correction strategy (Critique #5)."""
        reason = predicate.failure_reason
        if reason == DivergenceReason.ABSENT_DATA:
            return CorrectionStrategy.COMPLEMENTARY_ARTIFACT.value
        elif reason == DivergenceReason.SCOPE_TOO_BROAD:
            return CorrectionStrategy.TIGHTEN_ENTITY_SCOPE.value
        elif reason == DivergenceReason.TEMPORAL_IMPLAUSIBLE:
            return CorrectionStrategy.BROADEN_TIME_WINDOW.value
        elif reason == DivergenceReason.RESOLUTION_FAILURE:
            return CorrectionStrategy.VERIFY_RESOLUTION.value
        elif reason == DivergenceReason.CONTRADICTORY:
            return CorrectionStrategy.ALTERNATE_TOOL.value
        else:
            return CorrectionStrategy.ESCALATE.value

    def to_dict(self) -> dict:
        return {
            "claim_id": self.claim_id,
            "statement": self.statement,
            "tactic": self.tactic,
            "technique": self.technique,
            "confidence": self.confidence.value,
            "inference_basis": self.inference_basis,
            "predicates": [
                {
                    "name": p.name,
                    "description": p.description,
                    "required": p.required,
                    "passed": p.passed,
                    "failure_reason": p.failure_reason.value if p.failure_reason else None,
                    "failure_detail": p.failure_detail,
                }
                for p in self.predicates
            ],
            "divergence_count": self.divergence_count,
            "divergences": self.divergences,
            "correction_applied": self.correction_applied.value if self.correction_applied else None,
            "chain": self.chain.to_dict(),
        }


@dataclass
class Finding:
    """A compound finding composed of atomic claims (Critique #2).

    The narrative is built from verified atomic claims. Confidence is
    the MINIMUM of all constituent claim confidences.
    """
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    narrative: str = ""
    claims: list[AtomicClaim] = field(default_factory=list)

    @property
    def confidence(self) -> Confidence:
        """Finding confidence = minimum of all claim confidences."""
        if not self.claims:
            return Confidence.INSUFFICIENT_EVIDENCE
        levels = [c.confidence for c in self.claims]
        if Confidence.INSUFFICIENT_EVIDENCE in levels:
            return Confidence.INSUFFICIENT_EVIDENCE
        if Confidence.INFERENCE in levels:
            return Confidence.INFERENCE
        return Confidence.CONFIRMED

    @property
    def claim_summary(self) -> dict:
        """Count claims by confidence level."""
        from collections import Counter
        counts = Counter(c.confidence.value for c in self.claims)
        return dict(counts)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "narrative": self.narrative,
            "confidence": self.confidence.value,
            "claim_summary": self.claim_summary,
            "claims": [c.to_dict() for c in self.claims],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


# ---------------------------------------------------------------------------
# Predicate Templates — structural checks independent of LLM inference
# ---------------------------------------------------------------------------

LATERAL_MOVEMENT_PREDICATES = [
    {
        "name": "auth_edge_exists",
        "description": "Authentication edge (LOGGED_ON) exists between user and target host",
        "cypher": """
            MATCH (u:User)-[r:LOGGED_ON]->(h:Host)
            WHERE u.name = $username AND h.hostname = $target_host
            RETURN u.name, h.hostname, r.logon_type, r.timestamp, r.src_ip
            LIMIT 10
        """,
        "required": True,
    },
    {
        "name": "network_logon_type",
        "description": "Logon type is 3/9/10 (Network/NewCredentials/RDP) — not interactive/service/batch. Aggregates all logon types to detect CONTRADICTORY.",
        "cypher": """
            MATCH (u:User)-[r:LOGGED_ON]->(h:Host)
            WHERE u.name = $username AND h.hostname = $target_host
            WITH collect(DISTINCT r.logon_type) AS all_types
            WITH all_types,
                 [t IN all_types WHERE t IN [3, 9, 10]] AS matching_types,
                 [t IN all_types WHERE NOT t IN [3, 9, 10]] AS other_types
            RETURN all_types, matching_types, other_types,
                   size(matching_types) > 0 AS is_expected
        """,
        "required": True,
        "expect_field": "is_expected",
    },
    {
        "name": "source_host_connection",
        "description": "Network connection exists from source to target host",
        "cypher": """
            MATCH (src)-[:CONNECTED_TO]->(dst:Host {hostname: $target_host})
            RETURN src.hostname AS src_host, src.ip AS src_ip,
                   dst.hostname AS dst_host
            LIMIT 5
        """,
        "required": False,
    },
    {
        "name": "temporal_plausibility",
        "description": "Logon event timestamp is within plausible investigation window",
        "cypher": """
            MATCH (u:User)-[r:LOGGED_ON]->(h:Host {hostname: $target_host})
            WHERE u.name = $username
            WITH r.timestamp AS ts
            ORDER BY ts
            WITH collect(ts) AS timestamps
            RETURN size(timestamps) AS logon_count,
                   head(timestamps) AS first_logon,
                   last(timestamps) AS last_logon
        """,
        "required": False,
    },
]

PROCESS_CHAIN_PREDICATES = [
    {
        "name": "spawned_edge_exists",
        "description": "SPAWNED edge exists from parent to child process",
        "cypher": """
            MATCH (parent:Process)-[:SPAWNED]->(child:Process)
            WHERE parent.name CONTAINS $parent_name
              AND child.name CONTAINS $child_name
            RETURN parent.name, child.name, child.cmdline, child.timestamp
            LIMIT 10
        """,
        "required": True,
    },
    {
        "name": "process_executed_on_host",
        "description": "Child process has EXECUTED_ON edge to a host",
        "cypher": """
            MATCH (p:Process)-[:EXECUTED_ON]->(h:Host)
            WHERE p.name CONTAINS $child_name
            RETURN p.name, h.hostname, p.timestamp
            LIMIT 5
        """,
        "required": False,
    },
    {
        "name": "multi_source_execution",
        "description": "Execution evidence from multiple sources — checks both Process instances (4688) and Executable binaries (prefetch/amcache/shimcache)",
        "cypher": """
            OPTIONAL MATCH (h1:Host)-[:EXECUTED_ON]-(p:Process)
            WHERE p.name CONTAINS $child_name
            WITH collect({type: 'process_4688', name: p.name, ts: p.timestamp}) AS proc_evidence
            OPTIONAL MATCH (h2:Host)-[r:HAS_EXECUTABLE]->(x:Executable)
            WHERE x.name CONTAINS $child_name
            WITH proc_evidence, collect({type: r.source, name: x.name, hash: x.sha1, ts: x.first_seen}) AS exec_evidence
            WITH proc_evidence + exec_evidence AS all_evidence
            UNWIND all_evidence AS e
            WHERE e.name IS NOT NULL
            RETURN e.type AS source, e.name AS name, e.ts AS timestamp, e.hash AS hash
            ORDER BY e.ts
        """,
        "required": False,
    },
]

CREDENTIAL_ACCESS_PREDICATES = [
    {
        "name": "lsass_access_edge",
        "description": "Process has ACCESSED edge to lsass.exe",
        "cypher": """
            MATCH (p:Process)-[:ACCESSED]->(target:Process)
            WHERE p.name CONTAINS $process_name
              AND target.name = 'lsass.exe'
            RETURN p.name, p.cmdline, p.timestamp,
                   p._origin_data_type AS origin
            LIMIT 5
        """,
        "required": True,
    },
    {
        "name": "non_system_accessor",
        "description": "Accessing process is NOT a known system process",
        "cypher": """
            MATCH (p:Process)-[:ACCESSED]->(target:Process {name: 'lsass.exe'})
            WHERE p.name CONTAINS $process_name
              AND NOT p.name IN ['svchost.exe', 'csrss.exe', 'services.exe',
                                  'wininit.exe', 'lsass.exe']
            RETURN p.name, p.user
            LIMIT 5
        """,
        "required": True,
    },
    {
        "name": "execution_evidence",
        "description": "Credential tool has execution evidence — checks Process instances and Executable binaries",
        "cypher": """
            OPTIONAL MATCH (p:Process)
            WHERE p.name CONTAINS $process_name
            WITH collect({type: 'process', name: p.name, ts: p.timestamp}) AS procs
            OPTIONAL MATCH (x:Executable)
            WHERE x.name CONTAINS $process_name
            WITH procs, collect({type: 'executable', name: x.name, hash: x.sha1, ts: x.first_seen}) AS execs
            WITH procs + execs AS evidence
            UNWIND evidence AS e
            WHERE e.name IS NOT NULL
            RETURN e
        """,
        "required": False,
    },
]

PERSISTENCE_SERVICE_PREDICATES = [
    {
        "name": "service_event_exists",
        "description": "Service installation event (7045/4697) or registry service entry exists",
        "cypher": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE (e.service_name = $service_name
                   OR e.service_name CONTAINS $service_name
                   OR e.service_path CONTAINS $service_name)
              AND e.event_id IN [7045, 4697, 'registry_service']
            RETURN e.event_id, e.service_name, e.service_path,
                   e.timestamp, e._origin_data_type AS origin
            LIMIT 10
        """,
        "required": True,
    },
    {
        "name": "service_binary_exists",
        "description": "Service binary has execution or file evidence in graph",
        "cypher": """
            OPTIONAL MATCH (h:Host)-[r:EXECUTED]->(p:Process)
            WHERE p.name CONTAINS $service_name OR p.path CONTAINS $service_name
            WITH collect({name: p.name, path: p.path, source: r.source, ts: r.timestamp}) AS procs
            OPTIONAL MATCH (f:File)
            WHERE f.name CONTAINS $service_name OR f.path CONTAINS $service_name
            WITH procs, collect({name: f.name, path: f.path}) AS files
            WITH procs + files AS evidence
            UNWIND evidence AS e
            WHERE e.name IS NOT NULL
            RETURN e
            LIMIT 5
        """,
        "required": False,
    },
    {
        "name": "temporal_after_access",
        "description": "Service install occurred within a bounded window after a logon (default 14 days — APTs may dwell for days before persistence)",
        "cypher": """
            MATCH (e:Event)-[:ON_HOST]->(h:Host)
            WHERE (e.service_name = $service_name OR e.service_name CONTAINS $service_name
                   OR e.service_path CONTAINS $service_name)
              AND e.event_id IN [7045, 4697, 'registry_service']
            WITH min(e.timestamp) AS service_ts
            MATCH (u:User)-[r:LOGGED_ON]->(h2:Host)
            WHERE r.timestamp >= service_ts - duration('P14D')
              AND r.timestamp < service_ts
            RETURN service_ts,
                   min(r.timestamp) AS nearest_logon,
                   duration.between(min(r.timestamp), service_ts) AS delta
            LIMIT 1
        """,
        "required": False,
    },
]

# Map finding types to their predicate templates
PREDICATE_TEMPLATES = {
    "lateral_movement": LATERAL_MOVEMENT_PREDICATES,
    "process_chain": PROCESS_CHAIN_PREDICATES,
    "credential_access": CREDENTIAL_ACCESS_PREDICATES,
    "persistence_service": PERSISTENCE_SERVICE_PREDICATES,
}
