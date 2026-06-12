"""Temporal integrity — detect clock tampering from EVTX write-order vs timestamps.

EVTX assigns every record a monotonic RecordNumber at write time, independent of
the system clock. In an untampered log, ordering records by RecordNumber within a
single (host, provider) channel yields monotonically non-decreasing timestamps.

When the clock is moved — manually inside the guest, or below it at the
hypervisor/host RTC (VM time compression) — that invariant breaks:
  - INVERSION: RecordNumber increases but timestamp goes backward. On a single
    sequential channel this is essentially impossible without clock manipulation.
  - FORWARD JUMP: an improbably large calendar gap between two adjacent records
    (e.g. weeks "elapse" between consecutive writes) — the fast-forward signature
    of compressed time.

This is the timeline-level scar of host-side clock control: the timestamps lie,
but the RecordNumber sequence does not. It is how staged/time-compressed images
(and clock-tampering anti-forensics) are caught without the raw VMDK.

Honest scope: this proves the clock was manipulated; it cannot recover the true
wall-clock or see VMDK-container/snapshot manipulation (that needs the raw image).
"""

# Defaults. INVERSION_MIN_SECONDS floors out NTP jitter (sub-minute backward
# corrections are routine); only larger backward steps count as tampering.
# FORWARD_JUMP_DAYS flags large forward gaps (lower confidence — sparse provider
# channels gap naturally, so forward jumps are supporting, inversions are headline).
_INVERSION_MIN_SECONDS = 60
_FORWARD_JUMP_DAYS = 7

# Shared core: within each (host, provider) channel, order by RecordNumber (true
# write order) and pair adjacent records. A provider writes to one .evtx channel,
# so its record-number subsequence is monotonic and timestamps must be
# non-decreasing — backward movement is the tamper signal.
_PAIR_CTE = """
    MATCH (e:Event)-[:ON_HOST]->(h:Host)
    WHERE e.record_number IS NOT NULL AND e.timestamp IS NOT NULL
      AND e.source IS NOT NULL AND e.source <> ''
    WITH h.hostname AS host, e.source AS provider, e
    ORDER BY e.record_number
    WITH host, provider,
         collect({rn: e.record_number, ts: e.timestamp}) AS recs
    WHERE size(recs) >= 3
    UNWIND range(1, size(recs) - 1) AS i
    WITH host, provider, recs[i-1] AS a, recs[i] AS b
    WHERE a.rn < b.rn
    WITH host, provider, a, b,
         duration.inSeconds(a.ts, b.ts).seconds AS delta_s,
         duration.inSeconds(a.ts, b.ts).seconds / 86400.0 AS delta_days
"""


def detail_query(inversion_min_seconds: int = _INVERSION_MIN_SECONDS,
                 forward_jump_days: int = _FORWARD_JUMP_DAYS) -> str:
    """Per-anomaly rows (thresholds baked in as literals so find_evil can run it)."""
    return _PAIR_CTE + f"""
    WHERE delta_s < -{int(inversion_min_seconds)} OR delta_days > {int(forward_jump_days)}
    RETURN host, provider,
           a.rn AS rec_before, b.rn AS rec_after,
           a.ts AS ts_before, b.ts AS ts_after,
           round(delta_days * 10) / 10 AS delta_days,
           CASE WHEN delta_s < 0 THEN 'INVERSION' ELSE 'FORWARD_JUMP' END AS anomaly
    ORDER BY anomaly, abs(delta_days) DESC
    LIMIT 200
"""


def summary_query(inversion_min_seconds: int = _INVERSION_MIN_SECONDS,
                  forward_jump_days: int = _FORWARD_JUMP_DAYS) -> str:
    """Per-host counts: inversions (headline) + forward jumps (supporting)."""
    return _PAIR_CTE + f"""
    WITH host,
         sum(CASE WHEN delta_s < -{int(inversion_min_seconds)} THEN 1 ELSE 0 END) AS inversions,
         sum(CASE WHEN delta_days > {int(forward_jump_days)} THEN 1 ELSE 0 END) AS forward_jumps,
         max(CASE WHEN delta_days > 0 THEN delta_days ELSE 0 END) AS max_forward_jump_days,
         min(delta_days) AS worst_inversion_days
    WHERE inversions > 0 OR forward_jumps > 0
    RETURN host, inversions, forward_jumps,
           round(max_forward_jump_days * 10) / 10 AS max_forward_jump_days,
           round(worst_inversion_days * 10) / 10 AS worst_inversion_days
    ORDER BY inversions DESC, forward_jumps DESC
"""


def backfill_record_numbers(run_cypher, batch_size: int = 5000) -> int:
    """One-time migration: parse RecordNumber from message text into a property.

    For graphs ingested before record_number was a first-class field. Paged in
    Python to stay within Neo4j transaction memory limits. Idempotent.
    """
    import re
    rx = re.compile(r"Record Number:\s*(\d+)")
    total = 0
    while True:
        rows = run_cypher(
            """
            MATCH (e:Event)
            WHERE e.record_number IS NULL AND e.message CONTAINS 'Record Number:'
            RETURN e.event_hash AS hash, e.message AS msg
            LIMIT $limit
            """,
            {"limit": batch_size},
        )
        if not rows:
            break
        updates = []
        for r in rows:
            m = rx.search(r["msg"] or "")
            if m:
                updates.append({"hash": r["hash"], "rn": int(m.group(1))})
        if not updates:
            break
        run_cypher(
            """
            UNWIND $updates AS u
            MATCH (e:Event {event_hash: u.hash})
            SET e.record_number = u.rn
            """,
            {"updates": updates},
        )
        total += len(updates)
        if len(rows) < batch_size:
            break
    return total
