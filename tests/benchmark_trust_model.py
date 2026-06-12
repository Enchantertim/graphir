"""Trust-model benchmark: measure the verifier's downgrade behavior, not hunt recall.

Most accuracy testing asks "does the tool find true evil?" This benchmark asks the
inverse question that defines graphir's thesis: when the agent asserts something
FALSE, does the verification engine refuse to confirm it?

Claim sets (run against the SANS 508 multi-host graph):
  TRUE     — claims with full structural support; expect CONFIRMED (or INFERENCE)
  FALSE    — fabricated entities OR false pairings of two real entities;
             expect INSUFFICIENT_EVIDENCE, never CONFIRMED
  PARTIAL  — real entity, incomplete evidence chain (e.g. credential tool present
             on disk but no lsass ACCESSED edge); expect a downgrade, never CONFIRMED

Key metric: false-confirmation rate (target: 0.0%).

Usage:
    .venv/bin/python tests/benchmark_trust_model.py [--json results.json]
"""

import argparse
import json
import os
import sys

from neo4j import GraphDatabase

from graphir.verification import VerificationEngine

NEO4J_URI = os.environ.get("GRAPHIR_NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("GRAPHIR_NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("GRAPHIR_NEO4J_PASSWORD", "graphir-hackathon")

# (claim_id, expectation, finding_type, params, narrative)
# expectation: "confirm" = CONFIRMED/INFERENCE acceptable; "downgrade" = must NOT be CONFIRMED
CLAIMS = [
    # ---- TRUE: full structural support in the SANS 508 graph ----
    ("T1", "confirm", "lateral_movement",
     {"username": "vibranium", "target_host": "CONTROLLER.SHIELDBASE.LOCAL"},
     "vibranium moved laterally to the domain controller via network logon"),
    ("T2", "confirm", "lateral_movement",
     {"username": "vibranium", "target_host": "WKS-WIN764BITB.SHIELDBASE.LOCAL"},
     "vibranium moved laterally to workstation WKS-WIN764BITB"),
    ("T3", "confirm", "lateral_movement",
     {"username": "vibranium", "target_host": "WKS-WIN732BITA.SHIELDBASE.LOCAL"},
     "vibranium moved laterally to workstation WKS-WIN732BITA"),
    ("T4", "confirm", "persistence_service",
     {"service_name": "F-Response"},
     "F-Response service was installed on the domain controller"),

    # ---- FALSE: fabricated entities ----
    ("F1", "downgrade", "lateral_movement",
     {"username": "blackwidow_adm", "target_host": "CONTROLLER.SHIELDBASE.LOCAL"},
     "blackwidow_adm moved laterally to the domain controller"),
    ("F2", "downgrade", "lateral_movement",
     {"username": "vibranium", "target_host": "FILESERVER-99"},
     "vibranium moved laterally to FILESERVER-99"),
    ("F3", "downgrade", "process_chain",
     {"parent_name": "winword.exe", "child_name": "powershell.exe"},
     "winword.exe spawned powershell.exe (macro execution)"),
    ("F4", "downgrade", "credential_access",
     {"process_name": "procdump.exe"},
     "procdump.exe dumped lsass memory for credential theft"),
    ("F5", "downgrade", "persistence_service",
     {"service_name": "UpdaterProSvc"},
     "Malicious service UpdaterProSvc installed for persistence"),

    # ---- FALSE: false pairing of two REAL entities (hardest case) ----
    ("F6", "downgrade", "lateral_movement",
     {"username": "vibranium", "target_host": "WIN-8SU7N7ICS47"},
     "vibranium moved laterally to WIN-8SU7N7ICS47 (real user, real host, no logon)"),
    ("F7", "downgrade", "lateral_movement",
     {"username": "nfury", "target_host": "DC"},
     "nfury moved laterally to host DC (real user, real host, no logon)"),

    # ---- PARTIAL: real entity, incomplete evidence chain ----
    ("P1", "downgrade", "credential_access",
     {"process_name": "hydrakatz.exe"},
     "hydrakatz.exe (Mimikatz variant, present on disk on 2 hosts) accessed lsass "
     "— no ACCESSED edge exists; requires memory analysis"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", help="write full results to this JSON file")
    args = parser.parse_args()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    def run_cypher(query: str, params: dict | None = None) -> list[dict]:
        with driver.session() as session:
            return [r.data() for r in session.run(query, params or {})]

    engine = VerificationEngine(run_cypher)

    results = []
    for claim_id, expectation, finding_type, params, narrative in CLAIMS:
        verify = {
            "lateral_movement": lambda: engine.verify_lateral_movement(
                params["username"], params["target_host"], narrative),
            "process_chain": lambda: engine.verify_process_chain(
                params["parent_name"], params["child_name"], narrative),
            "credential_access": lambda: engine.verify_credential_access(
                params.get("process_name", ""), narrative),
            "persistence_service": lambda: engine.verify_persistence(
                params.get("service_name", ""), narrative),
        }[finding_type]
        finding = verify()
        confidence = str(finding.confidence)
        predicates = [
            {"name": p.name, "passed": p.passed}
            for c in finding.claims for p in c.predicates
        ]
        if expectation == "confirm":
            ok = confidence in ("CONFIRMED", "INFERENCE")
        else:
            ok = confidence != "CONFIRMED"
        results.append({
            "id": claim_id, "expectation": expectation,
            "finding_type": finding_type, "narrative": narrative,
            "confidence": confidence, "ok": ok, "predicates": predicates,
        })
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {claim_id} ({expectation}/{finding_type}): {confidence}")
        for p in predicates:
            print(f"         {'+' if p['passed'] else '-'} {p['name']}")

    driver.close()

    true_claims = [r for r in results if r["expectation"] == "confirm"]
    false_claims = [r for r in results if r["id"].startswith("F")]
    partial_claims = [r for r in results if r["id"].startswith("P")]
    false_confirmed = [r for r in false_claims + partial_claims
                       if r["confidence"] == "CONFIRMED"]

    summary = {
        "true_claims_confirmed": f"{sum(r['ok'] for r in true_claims)}/{len(true_claims)}",
        "false_claims_downgraded": f"{sum(r['ok'] for r in false_claims)}/{len(false_claims)}",
        "partial_claims_downgraded": f"{sum(r['ok'] for r in partial_claims)}/{len(partial_claims)}",
        "false_confirmation_rate": f"{len(false_confirmed)}/{len(false_claims) + len(partial_claims)}",
    }
    print("\n=== Trust-model summary ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"summary": summary, "results": results}, f, indent=2, default=str)
        print(f"\nFull results written to {args.json}")

    return 1 if false_confirmed or not all(r["ok"] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
