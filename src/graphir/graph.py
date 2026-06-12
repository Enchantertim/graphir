"""Neo4j graph schema and constraint setup for graphir."""

SCHEMA_CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.hostname IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.sid IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (x:Executable) REQUIRE x.path IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (p:Process) ON (p.pid, p.timestamp)",
    "CREATE INDEX IF NOT EXISTS FOR (p:Process) ON (p.name)",
    "CREATE INDEX IF NOT EXISTS FOR (f:File) ON (f.path)",
    "CREATE INDEX IF NOT EXISTS FOR (c:Connection) ON (c.dst_ip, c.dst_port)",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Event) REQUIRE e.event_hash IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (e:Event) ON (e.event_id)",
    "CREATE INDEX IF NOT EXISTS FOR (x:Executable) ON (x.path)",
    "CREATE INDEX IF NOT EXISTS FOR (c:Correction) ON (c.correction_id)",
    "CREATE INDEX IF NOT EXISTS FOR ()-[r:SPAWNED]-() ON (r.timestamp)",
    "CREATE INDEX IF NOT EXISTS FOR ()-[r:EXECUTED]-() ON (r.timestamp)",
    "CREATE INDEX IF NOT EXISTS FOR ()-[r:ACCESSED]-() ON (r.timestamp)",
    "CREATE INDEX IF NOT EXISTS FOR ()-[r:CONNECTED_TO]-() ON (r.timestamp)",
    "CREATE INDEX IF NOT EXISTS FOR ()-[r:LOGGED_ON]-() ON (r.timestamp)",
    "CREATE INDEX IF NOT EXISTS FOR ()-[r:MODIFIED]-() ON (r.timestamp)",
]

VERTEX_TYPES = {
    "Host": ["hostname", "ip", "os", "domain"],
    "User": ["name", "sid", "domain", "is_admin"],
    "Process": ["name", "pid", "ppid", "cmdline", "path", "timestamp", "hash", "user"],
    "Executable": ["name", "path", "sha1", "run_count", "first_seen", "last_executed"],
    "File": ["name", "path", "hash", "size", "timestamp", "extension"],
    "Connection": ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "timestamp"],
    "Event": ["event_id", "source", "channel", "timestamp", "message", "data"],
    "Correction": ["correction_id", "type", "reason", "original_claim", "corrected_by", "timestamp"],
    "Finding": ["finding_id", "phase", "tactic", "technique", "confidence", "summary", "investigation_id"],
    "ThreatIntel": ["source", "family", "detections", "total_engines", "detection_rate", "sha256", "first_seen_vt"],
}

EDGE_TYPES = {
    "EXECUTED_ON": "Process executed on a Host (from 4688 events)",
    "SPAWNED": "Process spawned another Process",
    "ACCESSED": "Process accessed a File or another Process",
    "CONNECTED_TO": "Process/Host made a network connection",
    "LOGGED_ON": "User logged onto a Host",
    "MODIFIED": "Process modified a File or Registry key",
    "HAS_EXECUTABLE": "Host has evidence of an Executable (prefetch/amcache/shimcache)",
    "ON_HOST": "Event occurred on a Host",
    "CORRECTS": "Correction applies to an entity",
    "ENRICHED_BY": "Executable enriched with threat intelligence (VT, capa, yara)",
    "SAME_BINARY": "Executable (binary identity) is the same binary as File (filesystem instance with MACB)",
    "SUPPORTED_BY": "Finding is evidenced by an entity (L0 investigation layer, written by reconstruct_attack)",
}


def init_schema(run_cypher_fn):
    """Create constraints and indexes in Neo4j."""
    for stmt in SCHEMA_CONSTRAINTS:
        run_cypher_fn(stmt)


def link_binaries(run_cypher_fn) -> dict:
    """Connect Executable (binary identity) to File (filesystem instance).

    Executables come from execution artifacts (prefetch/amcache/shimcache) with
    paths like '\\??\\C:\\windows\\system32\\foo.exe'; Files come from fs:stat
    MACB with paths like 'NTFS:\\windows\\system32\\foo.exe'. Without this edge
    the two evidence trees never touch and a hunt cannot join "this binary
    executed" to "this file was born on the incident date".

    Matches on basename + parent directory suffix to avoid false joins on
    common names across different directories. Idempotent (MERGE).
    """
    result = run_cypher_fn(r"""
        MATCH (x:Executable)
        WITH x, split(toLower(replace(x.path, '/', '\\')), '\\') AS parts
        WITH x, parts[-1] AS base,
             CASE WHEN size(parts) >= 2 THEN parts[-2] ELSE '' END AS parent
        WHERE base <> ''
        MATCH (f:File)
        WHERE toLower(f.path) ENDS WITH '\\' + base
          AND (parent = '' OR toLower(f.path) ENDS WITH '\\' + parent + '\\' + base)
        MERGE (x)-[r:SAME_BINARY]->(f)
        RETURN count(DISTINCT x) AS executables_linked,
               count(DISTINCT f) AS files_linked
    """)
    return result[0] if result else {"executables_linked": 0, "files_linked": 0}
