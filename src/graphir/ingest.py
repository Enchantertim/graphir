"""Plaso JSON-L ingestion into Neo4j investigation graph.

Reads Plaso jsonl (log2timeline) output and creates graph vertices/edges.
This is NOT the IronBox GraphHunt ingester — it's a clean-room, minimal
implementation for the SANS Find Evil! hackathon.

Every graph entity carries data origin metadata (_origin_*) for full
provenance traceability (Parallel Sysplex Principle #1).

Schema:
  Vertices: Host, User, Process, File, Connection, Event
  Edges:    EXECUTED, SPAWNED, ACCESSED, CONNECTED_TO, LOGGED_ON, MODIFIED
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from graphir.provenance import Origin, make_origin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Plaso event → graph mapping
# ---------------------------------------------------------------------------

# Windows Security Event IDs we care about
LOGON_EVENT_IDS = {4624, 4625, 4634, 4648}
SERVICE_EVENT_IDS = {7045, 4697}
PROCESS_EVENT_IDS = {4688, 4689}
OBJECT_ACCESS_EVENT_IDS = {4663, 4656}
SCHEDULED_TASK_EVENT_IDS = {4698, 4702}
LOG_CLEAR_EVENT_IDS = {1102, 104}
POWERSHELL_EVENT_IDS = {4103, 4104, 400, 800}

# Logon type mapping
LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


def _parse_timestamp(ts_value) -> str | None:
    """Normalize various timestamp formats to ISO 8601."""
    if ts_value is None:
        return None
    if isinstance(ts_value, (int, float)):
        # Plaso uses microseconds since epoch
        try:
            dt = datetime.fromtimestamp(ts_value / 1_000_000, tz=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except (ValueError, OSError):
            return None
    if isinstance(ts_value, str):
        return ts_value
    return str(ts_value)


def _safe_str(value, max_len: int = 2000) -> str | None:
    """Safely convert a value to a bounded string."""
    if value is None:
        return None
    s = str(value)
    return s[:max_len] if len(s) > max_len else s


class GraphIngester:
    """Ingests Plaso JSON-L events into Neo4j as graph nodes and edges."""

    def __init__(self, run_cypher_fn, default_hostname: str = "unknown"):
        self._run_cypher_raw = run_cypher_fn
        self.default_hostname = default_hostname
        self._discovered_hostname = None
        self._current_origin: Origin | None = None
        self._source_file: str = ""
        self.stats = {
            "events_processed": 0,
            "nodes_created": 0,
            "edges_created": 0,
            "errors": 0,
            "skipped": 0,
        }

    def run_cypher(self, query: str, params: dict | None = None):
        """Execute Cypher with origin metadata automatically merged.

        Every CREATE/MERGE gets _origin_* properties attached so that
        every graph entity carries its provenance (Principle #1).
        """
        params = dict(params or {})
        if self._current_origin:
            params.update(self._current_origin.to_props())
        return self._run_cypher_raw(query, params)

    @staticmethod
    def _normalize_hostname(name: str) -> str:
        """Normalize FQDN to short hostname.

        'ATGEWINB0114.root.local' → 'ATGEWINB0114'
        'ATGEWINB0114' → 'ATGEWINB0114'
        """
        if not name:
            return name
        return name.split(".")[0].upper()

    def _get_hostname(self, event: dict) -> str:
        """Get hostname from event, with auto-discovery fallback.

        Plaso only populates computer_name on EVTX records. For all other
        artifact types, we use the first computer_name discovered from EVTX.
        All hostnames are normalized to short uppercase form.
        """
        cn = event.get("computer_name")
        if cn:
            cn = self._normalize_hostname(cn)
            if not self._discovered_hostname:
                self._discovered_hostname = cn
                logger.info("Auto-discovered hostname: %s", cn)
            return cn
        return self._discovered_hostname or self.default_hostname

    # Data types we prioritize for graph construction (forensically relevant)
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

    def ingest_file(self, path: str, priority_only: bool = True,
                    max_events: int = 0) -> dict:
        """Ingest a Plaso JSON-L file into the graph.

        Args:
            path: Path to the Plaso NJSON/JSONL file.
            priority_only: If True, only ingest forensically-important data types
                          (EVTX, prefetch, amcache, shimcache, registry, LNK, USN).
                          Skips browser artifacts, fs:stat, etc. Default True.
            max_events: Stop after ingesting this many events (0 = no limit).
        """
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

                    # Filter by priority data types if requested
                    if priority_only:
                        data_type = event.get("data_type", "")
                        if data_type not in self.PRIORITY_DATA_TYPES:
                            self.stats["skipped"] += 1
                            continue

                    # Skip events with null/epoch-zero timestamps
                    ts = event.get("timestamp", 0)
                    if ts <= 0:
                        self.stats["skipped"] += 1
                        continue

                    # Set origin for this event (Principle #1: Data Origin Recording)
                    self._current_origin = make_origin(
                        event, self._source_file, line_num
                    )

                    self._ingest_event(event)
                    self.stats["events_processed"] += 1
                    ingested += 1

                    if max_events and ingested >= max_events:
                        logger.info("Reached max_events limit (%d)", max_events)
                        break

                except json.JSONDecodeError:
                    self.stats["errors"] += 1
                except Exception as e:
                    self.stats["errors"] += 1
                    if self.stats["errors"] <= 10:
                        logger.warning("Error at line %d: %s", line_num, e)

                if line_num % 50_000 == 0:
                    logger.info(
                        "Scanned %d lines, ingested %d, skipped %d, errors %d",
                        line_num, self.stats["events_processed"],
                        self.stats["skipped"], self.stats["errors"],
                    )

        self._current_origin = None
        return self.stats

    def _ingest_event(self, event: dict):
        """Route a single Plaso event to the appropriate handler.

        Routes primarily by data_type (most reliable), falls back to parser name.
        Plaso data_type examples: 'windows:evtx:record', 'windows:prefetch:execution',
        'windows:registry:amcache', 'windows:registry:appcompatcache', etc.
        """
        data_type = event.get("data_type", "").lower()
        parser = event.get("parser", "").lower()

        # Route by data_type first (authoritative)
        if data_type == "windows:evtx:record":
            self._handle_evtx(event)
        elif data_type == "windows:prefetch:execution":
            self._handle_prefetch(event)
        elif data_type == "windows:registry:amcache":
            self._handle_amcache(event)
        elif data_type in ("windows:registry:appcompatcache", "windows:registry:bam"):
            self._handle_shimcache(event)
        elif data_type == "windows:lnk:link":
            self._handle_lnk(event)
        elif data_type == "windows:registry:sam_users":
            self._handle_sam_user(event)
        elif data_type == "windows:registry:service":
            self._handle_registry_service(event)
        elif data_type in ("windows:registry:run", "windows:registry:userassist"):
            self._handle_persistence_registry(event)
        elif "registry" in data_type or "winreg" in parser:
            self._handle_registry(event)
        elif "srum" in data_type or "firewall" in data_type:
            self._handle_network(event)
        # Fallback to parser name
        elif "evtx" in parser or "winevtx" in parser:
            self._handle_evtx(event)
        elif "prefetch" in parser:
            self._handle_prefetch(event)
        elif "amcache" in parser:
            self._handle_amcache(event)
        elif "lnk" in parser or "winlnk" in parser:
            self._handle_lnk(event)
        elif "mft" in parser or "ntfs" in data_type or "usnjrnl" in data_type:
            self._handle_filesystem(event)
        else:
            self._handle_generic(event)

    # --- EVTX (Windows Event Logs) ---

    def _handle_evtx(self, event: dict):
        ts = _parse_timestamp(event.get("timestamp"))
        event_id = event.get("event_identifier") or event.get("event_id")
        source_name = event.get("source_name", "")
        computer = self._get_hostname(event)
        message = _safe_str(event.get("message", ""))

        # Always create the event node with origin tracking
        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            CREATE (e:Event {
                event_id: $event_id,
                source: $source_name,
                timestamp: datetime($ts),
                message: $message,
                channel: $channel,
                _origin_tool: $_origin_tool,
                _origin_artifact: $_origin_artifact,
                _origin_parser: $_origin_parser,
                _origin_data_type: $_origin_data_type,
                _origin_source_line: $_origin_source_line
            })
            CREATE (e)-[:ON_HOST {timestamp: datetime($ts)}]->(h)
        """, {
            "hostname": computer,
            "event_id": event_id,
            "source_name": source_name,
            "ts": ts,
            "message": message,
            "channel": event.get("channel", ""),
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

        if event_id in LOGON_EVENT_IDS:
            self._handle_logon_event(event, ts, computer)
        elif event_id in PROCESS_EVENT_IDS:
            self._handle_process_event(event, ts, computer)
        elif event_id in SERVICE_EVENT_IDS:
            self._handle_service_event(event, ts, computer)

    def _handle_logon_event(self, event: dict, ts: str, computer: str):
        """Create User and LOGGED_ON edges from logon events.

        For Event ID 4624, Plaso's strings[] array maps positionally:
          [0]=SubjectUserSid, [1]=SubjectUserName, [2]=SubjectDomainName, [3]=SubjectLogonId,
          [4]=TargetUserSid, [5]=TargetUserName, [6]=TargetDomainName, [7]=TargetLogonId,
          [8]=LogonType, [9]=LogonProcessName, [10]=AuthenticationPackageName,
          [11]=WorkstationName, ..., [18]=IpAddress, [19]=IpPort
        """
        strings = event.get("strings", []) or []
        xml = event.get("xml_string", "") or event.get("message", "")

        # Try strings[] first (most reliable), then named fields, then XML
        username = (
            _safe_index(strings, 5)
            or event.get("target_user_name")
            or _extract_xml_field(xml, "TargetUserName")
            or "unknown"
        )
        domain = (
            _safe_index(strings, 6)
            or event.get("target_domain_name")
            or _extract_xml_field(xml, "TargetDomainName")
            or ""
        )
        logon_type = (
            _safe_index(strings, 8)
            or event.get("logon_type")
            or _extract_xml_field(xml, "LogonType")
        )
        src_ip = (
            _safe_index(strings, 18)
            or event.get("ip_address")
            or _extract_xml_field(xml, "IpAddress")
            or ""
        )
        user_sid = (
            _safe_index(strings, 4)
            or event.get("target_user_sid")
            or _extract_xml_field(xml, "TargetUserSid")
            or f"{domain}\\{username}"
        )

        try:
            logon_type = int(logon_type) if logon_type else 0
        except (ValueError, TypeError):
            logon_type = 0

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            MERGE (u:User {sid: $sid})
            ON CREATE SET u.name = $username, u.domain = $domain
            CREATE (u)-[:LOGGED_ON {
                timestamp: datetime($ts),
                logon_type: $logon_type,
                logon_type_name: $logon_type_name,
                src_ip: $src_ip
            }]->(h)
        """, {
            "hostname": computer,
            "sid": user_sid,
            "username": username,
            "domain": domain,
            "ts": ts,
            "logon_type": logon_type,
            "logon_type_name": LOGON_TYPES.get(logon_type, "Unknown"),
            "src_ip": src_ip,
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

        # If source IP exists, create connection
        if src_ip and src_ip not in ("-", "::1", "127.0.0.1", ""):
            self.run_cypher("""
                MERGE (src:Host {ip: $src_ip})
                MERGE (dst:Host {hostname: $hostname})
                CREATE (src)-[:CONNECTED_TO {
                    timestamp: datetime($ts),
                    type: 'logon',
                    user: $username
                }]->(dst)
            """, {
                "src_ip": src_ip,
                "hostname": computer,
                "ts": ts,
                "username": username,
            })
            self.stats["edges_created"] += 1

    def _handle_process_event(self, event: dict, ts: str, computer: str):
        """Create Process nodes and SPAWNED edges from 4688 events.

        For Event ID 4688, Plaso's strings[] array maps positionally:
          [0]=SubjectUserSid, [1]=SubjectUserName, [2]=SubjectDomainName, [3]=SubjectLogonId,
          [4]=NewProcessId, [5]=NewProcessName, [6]=TokenElevationType,
          [7]=ParentProcessName, [8]=CommandLine, [9]=TargetUserSid,
          [10]=TargetUserName, [11]=TargetDomainName, [12]=TargetLogonId,
          [13]=MandatoryLabel
        """
        strings = event.get("strings", []) or []
        xml = event.get("xml_string", "") or event.get("message", "")

        proc_name = (
            _safe_index(strings, 5)
            or event.get("new_process_name")
            or _extract_xml_field(xml, "NewProcessName")
            or "unknown"
        )
        proc_id = (
            _safe_index(strings, 4)
            or event.get("new_process_id")
            or _extract_xml_field(xml, "NewProcessId")
        )
        parent_name = (
            _safe_index(strings, 7)
            or event.get("parent_process_name")
            or _extract_xml_field(xml, "ParentProcessName")
            or ""
        )
        parent_id = event.get("process_id") or _extract_xml_field(xml, "ProcessId")
        cmdline = (
            _safe_index(strings, 8)
            or event.get("command_line")
            or _extract_xml_field(xml, "CommandLine")
            or ""
        )
        username = (
            _safe_index(strings, 1)
            or event.get("target_user_name")
            or _extract_xml_field(xml, "SubjectUserName")
            or ""
        )

        # Normalize process names to just the executable
        proc_short = Path(proc_name).name if proc_name else "unknown"
        parent_short = Path(parent_name).name if parent_name else ""

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            CREATE (p:Process {
                name: $proc_name,
                path: $proc_path,
                pid: $pid,
                cmdline: $cmdline,
                timestamp: datetime($ts),
                user: $username
            })
            CREATE (p)-[:EXECUTED_ON {timestamp: datetime($ts)}]->(h)
        """, {
            "hostname": computer,
            "proc_name": proc_short,
            "proc_path": proc_name,
            "pid": _safe_str(proc_id),
            "cmdline": _safe_str(cmdline),
            "ts": ts,
            "username": username,
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

        # Create parent → child SPAWNED edge if parent exists
        if parent_short:
            self.run_cypher("""
                MERGE (parent:Process {name: $parent_name})
                ON CREATE SET parent.path = $parent_path, parent.timestamp = datetime($ts)
                SET parent.pid = CASE WHEN $parent_pid IS NOT NULL THEN $parent_pid ELSE parent.pid END
                WITH parent
                MATCH (child:Process {name: $child_name})
                WHERE child.timestamp = datetime($ts)
                CREATE (parent)-[:SPAWNED {timestamp: datetime($ts)}]->(child)
            """, {
                "parent_name": parent_short,
                "parent_path": parent_name,
                "parent_pid": _safe_str(parent_id),
                "child_name": proc_short,
                "ts": ts,
            })
            self.stats["edges_created"] += 1

    def _handle_service_event(self, event: dict, ts: str, computer: str):
        """Handle service installation events (7045, 4697)."""
        xml = event.get("xml_string", "") or event.get("message", "")

        service_name = (
            event.get("service_name")
            or _extract_xml_field(xml, "ServiceName")
            or "unknown"
        )
        service_path = (
            event.get("service_file_name")
            or _extract_xml_field(xml, "ImagePath")
            or ""
        )

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            CREATE (e:Event {
                event_id: $event_id,
                service_name: $service_name,
                service_path: $service_path,
                timestamp: datetime($ts)
            })
            CREATE (e)-[:ON_HOST {timestamp: datetime($ts)}]->(h)
        """, {
            "hostname": computer,
            "event_id": event.get("event_identifier", 7045),
            "service_name": service_name,
            "service_path": service_path,
            "ts": ts,
        })
        self.stats["nodes_created"] += 1
        self.stats["edges_created"] += 1

    # --- SAM Users ---

    def _handle_sam_user(self, event: dict):
        """Create User nodes from SAM user account entries."""
        ts = _parse_timestamp(event.get("timestamp"))
        username = event.get("username", "unknown")
        rid = event.get("account_rid", "")
        fullname = event.get("fullname", "")
        login_count = event.get("login_count", 0)
        computer = self._get_hostname(event)
        ts_desc = event.get("timestamp_desc", "")

        sid = f"S-1-5-21-{computer}-{rid}" if rid else username

        self.run_cypher("""
            MERGE (u:User {sid: $sid})
            ON CREATE SET u.name = $username, u.fullname = $fullname,
                          u.login_count = $login_count
            ON MATCH SET u.login_count = $login_count
            WITH u
            MERGE (h:Host {hostname: $hostname})
            MERGE (u)-[:LOGGED_ON {timestamp: datetime($ts), source: 'sam'}]->(h)
        """, {
            "sid": sid,
            "username": username,
            "fullname": fullname,
            "login_count": login_count,
            "hostname": computer,
            "ts": ts,
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

    # --- Registry Services ---

    def _handle_registry_service(self, event: dict):
        """Create Process/Event nodes from registry service entries."""
        ts = _parse_timestamp(event.get("timestamp"))
        service_name = event.get("name", "") or event.get("service_name", "unknown")
        image_path = event.get("image_path", "")
        start_type = event.get("start_type", -1)
        service_type = event.get("service_type", -1)
        service_dll = event.get("service_dll", "")
        computer = self._get_hostname(event)

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            CREATE (e:Event {
                event_id: 'registry_service',
                service_name: $service_name,
                service_path: $image_path,
                service_dll: $service_dll,
                start_type: $start_type,
                service_type: $service_type,
                timestamp: datetime($ts),
                source: 'registry'
            })
            CREATE (e)-[:ON_HOST {timestamp: datetime($ts)}]->(h)
        """, {
            "hostname": computer,
            "service_name": service_name,
            "image_path": image_path,
            "service_dll": service_dll,
            "start_type": start_type,
            "service_type": service_type,
            "ts": ts,
        })
        self.stats["nodes_created"] += 1
        self.stats["edges_created"] += 1

        # If image_path points to an executable, create a Process node
        if image_path:
            proc_name = Path(image_path.split()[0].strip('"')).name
            self.run_cypher("""
                MERGE (p:Process {name: $proc_name})
                ON CREATE SET p.path = $image_path, p.timestamp = datetime($ts)
                WITH p
                MERGE (h:Host {hostname: $hostname})
                MERGE (h)-[:EXECUTED {timestamp: datetime($ts), source: 'service_registry',
                                       service_name: $service_name}]->(p)
            """, {
                "proc_name": proc_name,
                "image_path": image_path,
                "hostname": computer,
                "ts": ts,
                "service_name": service_name,
            })
            self.stats["nodes_created"] += 1
            self.stats["edges_created"] += 1

    # --- Persistence Registry (Run keys, UserAssist) ---

    def _handle_persistence_registry(self, event: dict):
        """Handle Run/RunOnce keys and UserAssist entries — persistence indicators."""
        ts = _parse_timestamp(event.get("timestamp"))
        key_path = event.get("key_path", "")
        computer = self._get_hostname(event)
        data_type = event.get("data_type", "")

        if data_type == "windows:registry:userassist":
            value_name = event.get("value_name", "")
            exec_count = event.get("number_of_executions", 0)
            proc_name = Path(value_name).name if value_name else "unknown"

            self.run_cypher("""
                MERGE (h:Host {hostname: $hostname})
                MERGE (p:Process {name: $proc_name})
                ON CREATE SET p.path = $value_name, p.timestamp = datetime($ts)
                SET p.userassist_count = $exec_count
                MERGE (h)-[:EXECUTED {timestamp: datetime($ts), source: 'userassist'}]->(p)
            """, {
                "hostname": computer,
                "proc_name": proc_name,
                "value_name": value_name,
                "ts": ts,
                "exec_count": exec_count,
            })
        else:
            # Run/RunOnce keys
            entries = event.get("entries", []) or []
            values = _safe_str(entries if entries else event.get("values", ""))

            self.run_cypher("""
                MERGE (h:Host {hostname: $hostname})
                CREATE (e:Event {
                    event_id: 'persistence_run_key',
                    key_path: $key_path,
                    values: $values,
                    timestamp: datetime($ts),
                    is_persistence: true,
                    source: 'registry'
                })
                CREATE (e)-[:ON_HOST {timestamp: datetime($ts)}]->(h)
            """, {
                "hostname": computer,
                "key_path": key_path,
                "values": values,
                "ts": ts,
            })

        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

    # --- Prefetch ---

    def _handle_prefetch(self, event: dict):
        ts = _parse_timestamp(event.get("timestamp"))
        executable = event.get("executable", "") or ""
        run_count = event.get("run_count", 0)
        computer = self._get_hostname(event)
        path = event.get("path", "") or event.get("display_name", "")

        proc_name = Path(executable).name if executable else Path(path).stem

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            MERGE (p:Process {name: $proc_name})
            ON CREATE SET p.path = $path, p.timestamp = datetime($ts)
            SET p.run_count = $run_count
            MERGE (h)-[:EXECUTED {timestamp: datetime($ts), source: 'prefetch'}]->(p)
        """, {
            "hostname": computer,
            "proc_name": proc_name,
            "path": executable or path,
            "ts": ts,
            "run_count": run_count,
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

    # --- Amcache ---

    def _handle_amcache(self, event: dict):
        ts = _parse_timestamp(event.get("timestamp"))
        path = event.get("full_path", "") or event.get("path", "") or event.get("display_name", "")
        sha1 = event.get("sha1", "") or ""
        computer = self._get_hostname(event)
        proc_name = Path(path).name if path else "unknown"

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            MERGE (p:Process {name: $proc_name})
            ON CREATE SET p.path = $path, p.hash = $sha1, p.timestamp = datetime($ts)
            MERGE (h)-[:EXECUTED {timestamp: datetime($ts), source: 'amcache'}]->(p)
        """, {
            "hostname": computer,
            "proc_name": proc_name,
            "path": path,
            "sha1": sha1,
            "ts": ts,
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

    # --- Shimcache ---

    def _handle_shimcache(self, event: dict):
        ts = _parse_timestamp(event.get("timestamp"))
        path = event.get("path", "") or event.get("display_name", "")
        computer = self._get_hostname(event)
        proc_name = Path(path).name if path else "unknown"

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            MERGE (p:Process {name: $proc_name})
            ON CREATE SET p.path = $path, p.timestamp = datetime($ts)
            MERGE (h)-[:EXECUTED {timestamp: datetime($ts), source: 'shimcache'}]->(p)
        """, {
            "hostname": computer,
            "proc_name": proc_name,
            "path": path,
            "ts": ts,
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

    # --- LNK files ---

    def _handle_lnk(self, event: dict):
        ts = _parse_timestamp(event.get("timestamp"))
        target = event.get("local_path", "") or event.get("linked_path", "")
        computer = self._get_hostname(event)
        lnk_name = event.get("display_name", "") or event.get("path", "")

        if not target:
            self.stats["skipped"] += 1
            return

        file_name = Path(target).name

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            MERGE (f:File {path: $target})
            ON CREATE SET f.name = $file_name, f.timestamp = datetime($ts)
            MERGE (h)-[:ACCESSED {timestamp: datetime($ts), source: 'lnk', lnk_path: $lnk_name}]->(f)
        """, {
            "hostname": computer,
            "target": target,
            "file_name": file_name,
            "ts": ts,
            "lnk_name": lnk_name,
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

    # --- Registry ---

    def _handle_registry(self, event: dict):
        ts = _parse_timestamp(event.get("timestamp"))
        key_path = event.get("key_path", "") or event.get("keypath", "") or event.get("display_name", "")
        values = _safe_str(event.get("values", ""))
        computer = self._get_hostname(event)

        if not key_path:
            self.stats["skipped"] += 1
            return

        # Check for persistence-related registry keys
        is_persistence = any(pattern in key_path.lower() for pattern in [
            "\\run", "\\runonce", "\\services\\", "\\currentversion\\image",
            "\\winlogon", "\\userinit", "\\shell", "\\appinit",
            "\\scheduled", "\\explorer\\shell",
        ])

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            CREATE (e:Event {
                event_id: 'registry_mod',
                key_path: $key_path,
                values: $values,
                timestamp: datetime($ts),
                is_persistence: $is_persistence,
                source: 'registry'
            })
            CREATE (e)-[:ON_HOST {timestamp: datetime($ts)}]->(h)
        """, {
            "hostname": computer,
            "key_path": key_path,
            "values": values,
            "ts": ts,
            "is_persistence": is_persistence,
        })
        self.stats["nodes_created"] += 1
        self.stats["edges_created"] += 1

    # --- Filesystem (MFT, USN Journal) ---

    def _handle_filesystem(self, event: dict):
        ts = _parse_timestamp(event.get("timestamp"))
        filename = event.get("filename", "") or event.get("name", "")
        path = event.get("display_name", "") or event.get("path", "")
        computer = self._get_hostname(event)

        if not filename and not path:
            self.stats["skipped"] += 1
            return

        file_name = filename or Path(path).name

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            MERGE (f:File {path: $path})
            ON CREATE SET f.name = $file_name, f.timestamp = datetime($ts)
            SET f.extension = $ext
            MERGE (h)-[:MODIFIED {timestamp: datetime($ts), source: 'filesystem'}]->(f)
        """, {
            "hostname": computer,
            "path": path or filename,
            "file_name": file_name,
            "ts": ts,
            "ext": Path(file_name).suffix.lower() if file_name else "",
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

    # --- Network (SRUM, etc.) ---

    def _handle_network(self, event: dict):
        ts = _parse_timestamp(event.get("timestamp"))
        dst_ip = event.get("dest_ip", "") or event.get("destination_ip", "")
        dst_port = event.get("dest_port", "") or event.get("destination_port", "")
        src_ip = event.get("source_ip", "")
        protocol = event.get("protocol", "")
        computer = self._get_hostname(event)

        if not dst_ip:
            self.stats["skipped"] += 1
            return

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            MERGE (c:Connection {dst_ip: $dst_ip, dst_port: $dst_port})
            ON CREATE SET c.protocol = $protocol, c.timestamp = datetime($ts)
            CREATE (h)-[:CONNECTED_TO {timestamp: datetime($ts)}]->(c)
        """, {
            "hostname": computer,
            "dst_ip": dst_ip,
            "dst_port": str(dst_port),
            "protocol": protocol,
            "ts": ts,
        })
        self.stats["nodes_created"] += 2
        self.stats["edges_created"] += 1

    # --- Generic fallback ---

    def _handle_generic(self, event: dict):
        ts = _parse_timestamp(event.get("timestamp"))
        if not ts:
            self.stats["skipped"] += 1
            return

        computer = self._get_hostname(event)
        data_type = event.get("data_type", "unknown")
        message = _safe_str(event.get("message", ""))

        self.run_cypher("""
            MERGE (h:Host {hostname: $hostname})
            CREATE (e:Event {
                event_id: $data_type,
                timestamp: datetime($ts),
                message: $message,
                source: $parser
            })
            CREATE (e)-[:ON_HOST {timestamp: datetime($ts)}]->(h)
        """, {
            "hostname": computer,
            "data_type": data_type,
            "ts": ts,
            "message": message,
            "parser": event.get("parser", "unknown"),
        })
        self.stats["nodes_created"] += 1
        self.stats["edges_created"] += 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_index(lst: list, idx: int) -> str | None:
    """Safely get a string value from a list by index."""
    if not lst or idx >= len(lst):
        return None
    val = lst[idx]
    if val in (None, "", "-"):
        return None
    return str(val)


def _extract_xml_field(xml_string: str, field_name: str) -> str | None:
    """Extract a value from Event XML Data field."""
    if not xml_string:
        return None
    # Match <Data Name="FieldName">value</Data> or simple <FieldName>value</FieldName>
    patterns = [
        rf"<Data Name=['\"]?{field_name}['\"]?>([^<]*)</Data>",
        rf"<{field_name}>([^<]*)</{field_name}>",
    ]
    for pattern in patterns:
        match = re.search(pattern, xml_string, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None
