"""Batched Plaso JSON-L ingestion into Neo4j.

High-performance ingestion using UNWIND-based batch Cypher.
Replaces the per-event ingestion for large datasets.

Design: events are classified into buckets by type, accumulated into
batches of N, then flushed as single UNWIND Cypher statements.
A 1000-event batch is ~1000x faster than 1000 individual transactions.
"""

import json
import logging
import re
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from graphir.provenance import make_origin

logger = logging.getLogger(__name__)

# Event IDs we want to route specially
LOGON_EIDS = {4624, 4625, 4634, 4648}
PROCESS_EIDS = {4688, 4689}
SERVICE_EIDS = {7045, 4697}

# Plaso data types we ingest (priority set)
PRIORITY_DATA_TYPES = {
    "windows:evtx:record",
    "windows:prefetch:execution",
    "windows:registry:amcache",
    "windows:registry:appcompatcache",
    "windows:registry:bam",
    "windows:registry:service",
    "windows:registry:run",
    "windows:registry:userassist",
    "windows:registry:sam_users",
    "windows:registry:key_value",
    "windows:lnk:link",
    "fs:ntfs:usn_change",
}


def _normalize_hostname(name: str) -> str:
    if not name:
        return name
    return name.split(".")[0].upper()


def _parse_ts(ts_value) -> str | None:
    if ts_value is None:
        return None
    if isinstance(ts_value, (int, float)):
        try:
            dt = datetime.fromtimestamp(ts_value / 1_000_000, tz=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except (ValueError, OSError):
            return None
    return str(ts_value)


def _safe_index(lst, idx):
    if not lst or idx >= len(lst):
        return None
    val = lst[idx]
    if val in (None, "", "-"):
        return None
    return str(val)


def _extract_xml(xml, field):
    if not xml:
        return None
    for pat in [
        rf"<Data Name=['\"]?{field}['\"]?>([^<]*)</Data>",
        rf"<{field}>([^<]*)</{field}>",
    ]:
        m = re.search(pat, xml, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


class BatchIngester:
    """High-performance batched ingestion of Plaso JSONL into Neo4j."""

    BATCH_SIZE = 500

    def __init__(self, run_cypher_fn, default_hostname: str = "unknown"):
        self.run_cypher = run_cypher_fn
        self.default_hostname = default_hostname
        self._discovered_hostname = None
        self._source_file = ""

        # Batch accumulators per type
        self._batches: dict[str, list[dict]] = defaultdict(list)

        self.stats = {
            "events_processed": 0,
            "nodes_created": 0,
            "edges_created": 0,
            "errors": 0,
            "skipped": 0,
            "batches_flushed": 0,
        }

    def _get_hostname(self, event: dict) -> str:
        cn = event.get("computer_name")
        if cn:
            cn = _normalize_hostname(cn)
            if not self._discovered_hostname:
                self._discovered_hostname = cn
                logger.info("Auto-discovered hostname: %s", cn)
            return cn
        return self._discovered_hostname or self.default_hostname

    def ingest_file(self, path: str, priority_only: bool = True,
                    max_events: int = 0) -> dict:
        filepath = Path(path)
        if not filepath.exists():
            return {"error": f"File not found: {path}"}

        self._source_file = str(filepath)
        self.stats = {k: 0 for k in self.stats}
        ingested = 0

        with open(filepath) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)

                    if priority_only:
                        dt = event.get("data_type", "")
                        if dt not in PRIORITY_DATA_TYPES:
                            self.stats["skipped"] += 1
                            continue

                    ts = event.get("timestamp", 0)
                    if ts <= 0:
                        self.stats["skipped"] += 1
                        continue

                    self._classify_and_accumulate(event, line_num)
                    self.stats["events_processed"] += 1
                    ingested += 1

                    if max_events and ingested >= max_events:
                        break

                except json.JSONDecodeError:
                    self.stats["errors"] += 1
                except Exception as e:
                    self.stats["errors"] += 1
                    if self.stats["errors"] <= 10:
                        logger.warning("Error line %d: %s", line_num, e)

                if line_num % 100_000 == 0:
                    logger.info(
                        "Scanned %d lines, ingested %d, skipped %d, errors %d, batches %d",
                        line_num, self.stats["events_processed"],
                        self.stats["skipped"], self.stats["errors"],
                        self.stats["batches_flushed"],
                    )

        # Flush remaining
        self._flush_all()
        return self.stats

    def _classify_and_accumulate(self, event: dict, line_num: int):
        """Classify event and add to the appropriate batch."""
        dt = event.get("data_type", "").lower()
        hostname = self._get_hostname(event)
        ts = _parse_ts(event.get("timestamp"))
        if not ts:
            self.stats["skipped"] += 1
            return

        origin = {
            "_origin_tool": "ingest_timeline",
            "_origin_artifact": self._source_file,
            "_origin_parser": event.get("parser", ""),
            "_origin_data_type": event.get("data_type", ""),
            "_origin_source_line": line_num,
        }

        if dt == "windows:evtx:record":
            eid = event.get("event_identifier")
            strings = event.get("strings", []) or []
            xml = event.get("xml_string", "")

            # Deterministic hash for idempotent ingestion — same event = same hash
            record_num = event.get("record_number", "")
            event_hash = hashlib.sha256(
                f"{eid}:{ts}:{event.get('source_name','')}:{record_num}:{hostname}".encode()
            ).hexdigest()[:16]

            # Always add to generic events batch
            self._batches["evtx_event"].append({
                "hostname": hostname,
                "event_id": eid,
                "event_hash": event_hash,
                "source_name": event.get("source_name", ""),
                "ts": ts,
                "message": str(event.get("message", ""))[:2000],
                "channel": event.get("channel", ""),
                **origin,
            })

            # Route to specialized batches by event ID
            if eid in LOGON_EIDS:
                username = (_safe_index(strings, 5)
                            or _extract_xml(xml, "TargetUserName") or "unknown")
                domain = (_safe_index(strings, 6)
                          or _extract_xml(xml, "TargetDomainName") or "")
                logon_type = (_safe_index(strings, 8)
                              or _extract_xml(xml, "LogonType") or "0")
                src_ip = (_safe_index(strings, 18)
                          or _extract_xml(xml, "IpAddress") or "")
                user_sid = (_safe_index(strings, 4)
                            or _extract_xml(xml, "TargetUserSid")
                            or f"{domain}\\{username}")

                try:
                    logon_type = int(logon_type)
                except (ValueError, TypeError):
                    logon_type = 0

                self._batches["logon"].append({
                    "hostname": hostname,
                    "sid": user_sid,
                    "username": username,
                    "domain": domain,
                    "ts": ts,
                    "logon_type": logon_type,
                    "src_ip": src_ip,
                })

                if src_ip and src_ip not in ("-", "::1", "127.0.0.1", ""):
                    self._batches["logon_connection"].append({
                        "src_ip": src_ip,
                        "hostname": hostname,
                        "ts": ts,
                        "username": username,
                    })

            elif eid in PROCESS_EIDS:
                proc_name = (_safe_index(strings, 5)
                             or _extract_xml(xml, "NewProcessName") or "unknown")
                parent_name = (_safe_index(strings, 7)
                               or _extract_xml(xml, "ParentProcessName") or "")
                cmdline = (_safe_index(strings, 8)
                           or _extract_xml(xml, "CommandLine") or "")
                proc_id = (_safe_index(strings, 4)
                           or _extract_xml(xml, "NewProcessId"))
                username = (_safe_index(strings, 1)
                            or _extract_xml(xml, "SubjectUserName") or "")

                proc_short = Path(proc_name).name if proc_name else "unknown"
                parent_short = Path(parent_name).name if parent_name else ""

                self._batches["process"].append({
                    "hostname": hostname,
                    "proc_name": proc_short,
                    "proc_path": proc_name,
                    "pid": str(proc_id) if proc_id else "",
                    "cmdline": str(cmdline),
                    "ts": ts,
                    "username": username,
                    "parent_name": parent_short,
                    "parent_path": parent_name,
                    **origin,
                })

            elif eid in SERVICE_EIDS:
                svc_name = (_extract_xml(xml, "ServiceName")
                            or _safe_index(strings, 0) or "")
                svc_path = (_extract_xml(xml, "ImagePath")
                            or _safe_index(strings, 1) or "")

                self._batches["service"].append({
                    "hostname": hostname,
                    "service_name": svc_name,
                    "service_path": svc_path,
                    "ts": ts,
                    **origin,
                })

        elif dt == "windows:prefetch:execution":
            executable = event.get("executable", "")
            proc_name = Path(executable).name if executable else "unknown"
            self._batches["prefetch"].append({
                "hostname": hostname,
                "proc_name": proc_name,
                "path": executable or event.get("display_name", ""),
                "ts": ts,
                "run_count": event.get("run_count", 0),
                **origin,
            })

        elif dt == "windows:registry:amcache":
            fpath = event.get("full_path", "") or event.get("path", "")
            proc_name = Path(fpath).name if fpath else "unknown"
            self._batches["amcache"].append({
                "hostname": hostname,
                "proc_name": proc_name,
                "path": fpath,
                "sha1": event.get("sha1", ""),
                "ts": ts,
                **origin,
            })

        elif dt in ("windows:registry:appcompatcache", "windows:registry:bam"):
            fpath = event.get("path", "") or event.get("display_name", "")
            proc_name = Path(fpath).name if fpath else "unknown"
            self._batches["shimcache"].append({
                "hostname": hostname,
                "proc_name": proc_name,
                "path": fpath,
                "ts": ts,
                **origin,
            })

        elif dt == "windows:registry:service":
            self._batches["registry_service"].append({
                "hostname": hostname,
                "service_name": event.get("name", ""),
                "image_path": event.get("image_path", ""),
                "start_type": event.get("start_type", -1),
                "ts": ts,
                **origin,
            })

        elif dt == "windows:registry:sam_users":
            rid = event.get("account_rid", "")
            self._batches["sam_user"].append({
                "hostname": hostname,
                "username": event.get("username", "unknown"),
                "fullname": event.get("fullname", ""),
                "sid": f"S-1-5-21-{hostname}-{rid}" if rid else event.get("username", ""),
                "login_count": event.get("login_count", 0),
                "ts": ts,
            })

        elif dt == "windows:lnk:link":
            target = event.get("local_path", "") or event.get("linked_path", "")
            if target:
                self._batches["lnk"].append({
                    "hostname": hostname,
                    "target": target,
                    "file_name": Path(target).name,
                    "lnk_path": event.get("display_name", ""),
                    "ts": ts,
                    **origin,
                })

        else:
            # Generic: registry key_value, usn_change, etc. — just count, skip graph for now
            self.stats["skipped"] += 1
            self.stats["events_processed"] -= 1  # undo the count
            return

        # Check if any batch needs flushing
        for batch_type, batch in self._batches.items():
            if len(batch) >= self.BATCH_SIZE:
                self._flush_batch(batch_type)

    def _flush_all(self):
        for batch_type in list(self._batches.keys()):
            if self._batches[batch_type]:
                self._flush_batch(batch_type)

    def _flush_batch(self, batch_type: str):
        batch = self._batches[batch_type]
        if not batch:
            return

        try:
            query = BATCH_QUERIES.get(batch_type)
            if not query:
                logger.warning("No batch query for type: %s", batch_type)
                self._batches[batch_type] = []
                return

            self.run_cypher(query, {"batch": batch})
            self.stats["batches_flushed"] += 1

            # Rough estimate of nodes/edges created
            size = len(batch)
            if batch_type == "evtx_event":
                self.stats["nodes_created"] += size
                self.stats["edges_created"] += size
            elif batch_type == "logon":
                self.stats["nodes_created"] += size
                self.stats["edges_created"] += size
            elif batch_type == "process":
                self.stats["nodes_created"] += size
                self.stats["edges_created"] += size * 2
            else:
                self.stats["nodes_created"] += size
                self.stats["edges_created"] += size

        except Exception as e:
            self.stats["errors"] += len(batch)
            logger.warning("Batch flush error (%s, %d items): %s",
                          batch_type, len(batch), e)

        self._batches[batch_type] = []


# ---------------------------------------------------------------------------
# Batch Cypher queries — one UNWIND per event type
# ---------------------------------------------------------------------------

BATCH_QUERIES = {
    "evtx_event": """
        UNWIND $batch AS evt
        MERGE (h:Host {hostname: evt.hostname})
        MERGE (e:Event {event_hash: evt.event_hash})
        ON CREATE SET
            e.event_id = evt.event_id,
            e.source = evt.source_name,
            e.timestamp = datetime(evt.ts),
            e.message = evt.message,
            e.channel = evt.channel,
            e._origin_tool = evt._origin_tool,
            e._origin_artifact = evt._origin_artifact,
            e._origin_parser = evt._origin_parser,
            e._origin_data_type = evt._origin_data_type,
            e._origin_source_line = evt._origin_source_line
        MERGE (e)-[:ON_HOST]->(h)
    """,

    "logon": """
        UNWIND $batch AS evt
        MERGE (h:Host {hostname: evt.hostname})
        MERGE (u:User {sid: evt.sid})
        ON CREATE SET u.name = evt.username, u.domain = evt.domain
        CREATE (u)-[:LOGGED_ON {
            timestamp: datetime(evt.ts),
            logon_type: evt.logon_type,
            src_ip: evt.src_ip
        }]->(h)
    """,

    "logon_connection": """
        UNWIND $batch AS evt
        MERGE (src:Host {ip: evt.src_ip})
        MERGE (dst:Host {hostname: evt.hostname})
        CREATE (src)-[:CONNECTED_TO {
            timestamp: datetime(evt.ts),
            type: 'logon',
            user: evt.username
        }]->(dst)
    """,

    "process": """
        UNWIND $batch AS evt
        MERGE (h:Host {hostname: evt.hostname})
        CREATE (p:Process {
            name: evt.proc_name,
            path: evt.proc_path,
            pid: evt.pid,
            cmdline: evt.cmdline,
            timestamp: datetime(evt.ts),
            user: evt.username,
            _origin_tool: evt._origin_tool,
            _origin_artifact: evt._origin_artifact,
            _origin_parser: evt._origin_parser,
            _origin_data_type: evt._origin_data_type,
            _origin_source_line: evt._origin_source_line
        })
        CREATE (p)-[:EXECUTED_ON {timestamp: datetime(evt.ts)}]->(h)
        WITH p, evt, h
        WHERE evt.parent_name <> ''
        MERGE (parent:Process {name: evt.parent_name})
        ON CREATE SET parent.path = evt.parent_path,
                      parent._origin_tool = 'inferred_parent',
                      parent._origin_artifact = evt._origin_artifact,
                      parent._origin_parser = 'derived_from_child',
                      parent._origin_data_type = evt._origin_data_type,
                      parent._origin_derived_from_child_line = evt._origin_source_line
        CREATE (parent)-[:SPAWNED {timestamp: datetime(evt.ts)}]->(p)
    """,

    "service": """
        UNWIND $batch AS evt
        MERGE (h:Host {hostname: evt.hostname})
        CREATE (e:Event {
            event_id: 7045,
            service_name: evt.service_name,
            service_path: evt.service_path,
            timestamp: datetime(evt.ts),
            _origin_tool: evt._origin_tool,
            _origin_artifact: evt._origin_artifact,
            _origin_parser: evt._origin_parser,
            _origin_data_type: evt._origin_data_type,
            _origin_source_line: evt._origin_source_line
        })
        CREATE (e)-[:ON_HOST {timestamp: datetime(evt.ts)}]->(h)
    """,

    # Prefetch, Amcache, Shimcache → Executable nodes (not Process instances).
    # Process nodes are per-execution (from 4688 events). Executable nodes are
    # per-binary — they represent the file on disk, not a running instance.

    "prefetch": """
        UNWIND $batch AS evt
        MERGE (h:Host {hostname: evt.hostname})
        MERGE (x:Executable {name: evt.proc_name})
        ON CREATE SET x.path = evt.path, x.first_seen = datetime(evt.ts)
        SET x.run_count = evt.run_count,
            x.last_executed = datetime(evt.ts),
            x._origin_tool = evt._origin_tool,
            x._origin_artifact = evt._origin_artifact,
            x._origin_parser = evt._origin_parser,
            x._origin_data_type = evt._origin_data_type,
            x._origin_source_line = evt._origin_source_line
        MERGE (h)-[:HAS_EXECUTABLE {source: 'prefetch'}]->(x)
    """,

    "amcache": """
        UNWIND $batch AS evt
        MERGE (h:Host {hostname: evt.hostname})
        MERGE (x:Executable {name: evt.proc_name})
        ON CREATE SET x.path = evt.path, x.first_seen = datetime(evt.ts)
        SET x.sha1 = evt.sha1,
            x._origin_tool = evt._origin_tool,
            x._origin_artifact = evt._origin_artifact,
            x._origin_parser = evt._origin_parser,
            x._origin_data_type = evt._origin_data_type,
            x._origin_source_line = evt._origin_source_line
        MERGE (h)-[:HAS_EXECUTABLE {source: 'amcache'}]->(x)
    """,

    "shimcache": """
        UNWIND $batch AS evt
        MERGE (h:Host {hostname: evt.hostname})
        MERGE (x:Executable {name: evt.proc_name})
        ON CREATE SET x.path = evt.path, x.first_seen = datetime(evt.ts)
        SET x._origin_tool = evt._origin_tool,
            x._origin_artifact = evt._origin_artifact,
            x._origin_parser = evt._origin_parser,
            x._origin_data_type = evt._origin_data_type,
            x._origin_source_line = evt._origin_source_line
        MERGE (h)-[:HAS_EXECUTABLE {source: 'shimcache'}]->(x)
    """,

    "registry_service": """
        UNWIND $batch AS evt
        MERGE (h:Host {hostname: evt.hostname})
        CREATE (e:Event {
            event_id: 'registry_service',
            service_name: evt.service_name,
            service_path: evt.image_path,
            start_type: evt.start_type,
            timestamp: datetime(evt.ts),
            _origin_tool: evt._origin_tool,
            _origin_artifact: evt._origin_artifact,
            _origin_parser: evt._origin_parser,
            _origin_data_type: evt._origin_data_type,
            _origin_source_line: evt._origin_source_line
        })
        CREATE (e)-[:ON_HOST {timestamp: datetime(evt.ts)}]->(h)
    """,

    "sam_user": """
        UNWIND $batch AS evt
        MERGE (u:User {sid: evt.sid})
        ON CREATE SET u.name = evt.username, u.fullname = evt.fullname
        SET u.login_count = evt.login_count
        WITH u, evt
        MERGE (h:Host {hostname: evt.hostname})
        MERGE (u)-[:LOGGED_ON {timestamp: datetime(evt.ts), source: 'sam'}]->(h)
    """,

    "lnk": """
        UNWIND $batch AS evt
        MERGE (h:Host {hostname: evt.hostname})
        MERGE (f:File {path: evt.target})
        ON CREATE SET f.name = evt.file_name, f.timestamp = datetime(evt.ts)
        MERGE (h)-[:ACCESSED {timestamp: datetime(evt.ts), source: 'lnk',
                               lnk_path: evt.lnk_path}]->(f)
    """,
}
