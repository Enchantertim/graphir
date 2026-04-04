"""Neo4j graph schema and constraint setup for graphir."""

SCHEMA_CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.hostname IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.sid IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (x:Executable) REQUIRE x.name IS UNIQUE",
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
}


def init_schema(run_cypher_fn):
    """Create constraints and indexes in Neo4j."""
    for stmt in SCHEMA_CONSTRAINTS:
        run_cypher_fn(stmt)
