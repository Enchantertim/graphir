"""Dual-Path Verification Engine (Parallel Sysplex Principle #3).

Path 1 (Inference):  LLM reasons about tool output → produces finding
Path 2 (Verification): Graph structural query validates the finding independently

Key design decisions:
1. Path 2 checks prerequisites the LLM DIDN'T explicitly reason about.
2. Verification operates on ATOMIC CLAIMS, not narratives.
3. An atomic claim groups ALL relevant predicates (required + supporting).
   One claim = "lateral movement occurred", verified by auth edge + logon type
   + source connection + temporal plausibility. NOT one claim per predicate.
4. Confidence transitions are MECHANICAL (code-enforced rules).
5. Divergence metadata captures exactly what failed and why.
6. Re-examination follows bounded correction strategies.
"""

import json
import logging

from graphir.provenance import (
    AtomicClaim,
    Confidence,
    CorrectionStrategy,
    DivergenceReason,
    Finding,
    Predicate,
    PREDICATE_TEMPLATES,
)

logger = logging.getLogger(__name__)


class VerificationEngine:
    """Verifies atomic claims via dual-path comparison against the graph."""

    def __init__(self, run_cypher_fn):
        self.run_cypher = run_cypher_fn

    # ------------------------------------------------------------------
    # Core: verify a single atomic claim (execute all its predicates)
    # ------------------------------------------------------------------

    def verify_claim(self, claim: AtomicClaim) -> AtomicClaim:
        """Execute all predicates and evaluate confidence mechanically."""
        for pred in claim.predicates:
            self._execute_predicate(pred)
        claim.evaluate()
        return claim

    def _execute_predicate(self, pred: Predicate):
        """Run a single predicate query and evaluate pass/fail."""
        try:
            results = self.run_cypher(pred.cypher, pred.params)
            pred.result = results

            if not results:
                pred.passed = False
                pred.failure_reason = DivergenceReason.ABSENT_DATA
                pred.failure_detail = (
                    f"Predicate '{pred.name}' returned 0 results. "
                    f"Required structural evidence not found in graph."
                )
            else:
                pred.passed = True

        except Exception as e:
            pred.passed = False
            pred.failure_reason = DivergenceReason.RESOLUTION_FAILURE
            pred.failure_detail = f"Query failed: {e}"

    # ------------------------------------------------------------------
    # Decomposition strategies
    # ------------------------------------------------------------------

    def verify_single_claim(self, finding_type: str, params: dict,
                            statement: str) -> Finding:
        """Verify a single atomic claim with ALL predicates for its type.

        This is the correct default: one claim ("lateral movement occurred")
        verified by multiple independent predicates (auth edge, logon type,
        source connection, temporal plausibility).

        Use decompose_compound() when the narrative contains multiple
        distinct claims that should be verified independently.
        """
        finding = Finding(narrative=statement)

        templates = PREDICATE_TEMPLATES.get(finding_type, [])
        if not templates:
            claim = AtomicClaim(
                statement=statement,
                inference_basis=f"No predicate template for type: {finding_type}",
            )
            claim.evaluate()
            finding.claims.append(claim)
            return finding

        # One claim, all predicates
        claim = AtomicClaim(
            statement=statement,
            tactic=params.get("tactic", ""),
            technique=params.get("technique", ""),
            inference_basis=statement,
        )
        for tmpl in templates:
            claim.add_predicate(
                name=tmpl["name"],
                description=tmpl["description"],
                cypher=tmpl["cypher"],
                required=tmpl.get("required", True),
                **params,
            )

        self.verify_claim(claim)
        finding.claims.append(claim)
        return finding

    def decompose_compound(self, claim_specs: list[dict], params: dict,
                           narrative: str) -> Finding:
        """Decompose a compound narrative into multiple atomic claims.

        Use this when the LLM produces a compound statement like
        "PsExec lateral movement after credential dump" that should be
        split into independently verified claims.

        Args:
            claim_specs: List of claim definitions, each with:
                - statement: what this specific claim asserts
                - finding_type: key into PREDICATE_TEMPLATES
                - params_override: optional per-claim param overrides
            params: Default parameters for all claims
            narrative: The original compound narrative
        """
        finding = Finding(narrative=narrative)

        for spec in claim_specs:
            ft = spec.get("finding_type", "")
            templates = PREDICATE_TEMPLATES.get(ft, [])
            if not templates:
                continue

            claim_params = {**params, **spec.get("params_override", {})}
            claim = AtomicClaim(
                statement=spec.get("statement", ""),
                tactic=claim_params.get("tactic", ""),
                technique=claim_params.get("technique", ""),
                inference_basis=narrative,
            )
            for tmpl in templates:
                claim.add_predicate(
                    name=tmpl["name"],
                    description=tmpl["description"],
                    cypher=tmpl["cypher"],
                    required=tmpl.get("required", True),
                    **claim_params,
                )
            self.verify_claim(claim)
            finding.claims.append(claim)

        return finding

    # ------------------------------------------------------------------
    # Convenience methods for common finding types
    # ------------------------------------------------------------------

    def verify_lateral_movement(self, username: str, target_host: str,
                                 narrative: str) -> Finding:
        return self.verify_single_claim(
            "lateral_movement",
            {"username": username, "target_host": target_host,
             "tactic": "Lateral Movement", "technique": "T1021"},
            narrative,
        )

    def verify_process_chain(self, parent_name: str, child_name: str,
                              narrative: str) -> Finding:
        return self.verify_single_claim(
            "process_chain",
            {"parent_name": parent_name, "child_name": child_name,
             "tactic": "Execution", "technique": "T1059"},
            narrative,
        )

    def verify_credential_access(self, process_name: str,
                                  narrative: str) -> Finding:
        return self.verify_single_claim(
            "credential_access",
            {"process_name": process_name,
             "tactic": "Credential Access", "technique": "T1003.001"},
            narrative,
        )

    def verify_persistence(self, service_name: str,
                           narrative: str) -> Finding:
        return self.verify_single_claim(
            "persistence_service",
            {"service_name": service_name,
             "tactic": "Persistence", "technique": "T1543.003"},
            narrative,
        )

    # ------------------------------------------------------------------
    # Provenance tracing (Principle #2)
    # ------------------------------------------------------------------

    def trace_origin(self, entity_name: str) -> dict:
        """Trace an entity back to its raw source artifact.

        Searches by exact name, hostname, service_name, and partial match
        (CONTAINS) for process paths where only the executable name is known.
        """
        results = self.run_cypher("""
            MATCH (n)
            WHERE n.name = $name OR n.hostname = $name OR n.service_name = $name
               OR n.name CONTAINS $name
            RETURN labels(n)[0] AS type, n.name AS name,
                   n._origin_tool AS tool,
                   n._origin_artifact AS artifact,
                   n._origin_parser AS parser,
                   n._origin_data_type AS data_type,
                   n._origin_source_line AS source_line
            LIMIT 10
        """, {"name": entity_name})

        if not results:
            return {
                "entity": entity_name,
                "provable": False,
                "reason": "Entity not found in graph",
            }

        provable_results = [r for r in results if r.get("tool") is not None]
        unprovable_results = [r for r in results if r.get("tool") is None]

        return {
            "entity": entity_name,
            "provable": len(provable_results) > 0,
            "chain_intact": all(r.get("artifact") is not None for r in provable_results) if provable_results else False,
            "total_matches": len(results),
            "with_origin": len(provable_results),
            "without_origin": len(unprovable_results),
            "origins": provable_results[:5],
            "unprovable_entities": [
                {"type": r.get("type"), "name": r.get("name")}
                for r in unprovable_results[:3]
            ],
        }

    def check_chain_integrity(self) -> dict:
        """Audit all graph entities for provenance completeness."""
        results = self.run_cypher("""
            MATCH (n)
            WHERE NOT n:Host
            WITH labels(n)[0] AS label,
                 n._origin_tool IS NOT NULL AS has_origin,
                 n._origin_artifact IS NOT NULL AS has_artifact
            RETURN label,
                   count(*) AS total,
                   sum(CASE WHEN has_origin THEN 1 ELSE 0 END) AS with_origin,
                   sum(CASE WHEN has_artifact THEN 1 ELSE 0 END) AS with_artifact
            ORDER BY total DESC
        """)

        total = sum(r["total"] for r in results)
        with_origin = sum(r["with_origin"] for r in results)

        return {
            "total_entities": total,
            "with_complete_origin": with_origin,
            "provenance_coverage": f"{with_origin / total * 100:.1f}%" if total else "N/A",
            "by_type": results,
        }
